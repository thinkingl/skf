/*
 * SoftSKF - a local-file backed software SKF implementation.
 *
 * Storage: one SQLite database per soft token.  Sensitive objects are
 * encrypted with AES-256-GCM keys derived from the application PIN or from
 * the device auth key.  SM1/SSF33 are intentionally unsupported and return
 * SAR_NOTSUPPORTYETERR.
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdarg.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <dirent.h>
#include <time.h>
#include <signal.h>
#include <pthread.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/time.h>

#include "skf.h"
#include "sqlite3.h"

#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/hmac.h>
#include <openssl/kdf.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/obj_mac.h>
#include <openssl/bn.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/crypto.h>
#include <openssl/err.h>

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

#define SOFTSKF_FORMAT_VERSION 1
#define SOFTSKF_PIN_KDF_ITER   100000
#define SOFTSKF_SALT_LEN       16
#define SOFTSKF_GCM_NONCE_LEN  12
#define SOFTSKF_GCM_TAG_LEN    16
#define SOFTSKF_MAX_FILE_SIZE  (1024 * 1024)
#define SOFTSKF_TOTAL_SPACE    (1024 * 1024)
#define SOFTSKF_MAX_APPS       64
#define SOFTSKF_MAX_CONTAINERS 64

enum {
    SOFT_HANDLE_DEV = 1,
    SOFT_HANDLE_APP,
    SOFT_HANDLE_CTN,
    SOFT_HANDLE_SYM,
    SOFT_HANDLE_HASH,
    SOFT_HANDLE_MAC,
    SOFT_HANDLE_AGREE
};

typedef struct {
    int type;
} SOFT_HDR;

typedef struct SOFT_DEV {
    int type;
    sqlite3 *db;
    char name[64];
    char path[PATH_MAX];
    unsigned char store_key[32];
    unsigned char dak[16];
    int authed;
    unsigned char challenge[16];
    int challenge_len;
    int auth_retry;
    int auth_max_retry;
    int auth_locked;
    pthread_mutex_t lock;
    int lock_inited;
} SOFT_DEV;

typedef struct SOFT_APP {
    int type;
    SOFT_DEV *dev;
    sqlite3_int64 id;
    char name[64];
    unsigned char ak[32];
    int user_logged;
    int admin_logged;
} SOFT_APP;

typedef struct SOFT_CTN {
    int type;
    SOFT_APP *app;
    sqlite3_int64 id;
    char name[64];
    int ctype;                 /* 0 empty, 1 ECC, 2 RSA */
    int bits;
    unsigned char pub_blob[512];
    int pub_len;
} SOFT_CTN;

typedef struct SOFT_SYM {
    int type;
    SOFT_DEV *dev;
    ULONG alg;
    unsigned char key[32];
    int keylen;
    int initialized;
    int enc;
    int is_mac;
    EVP_CIPHER_CTX *ctx;
    BLOCKCIPHERPARAM param;
    unsigned char *buf;
    size_t buflen;
} SOFT_SYM;

typedef struct SOFT_HASH {
    int type;
    EVP_MD_CTX *ctx;
    const EVP_MD *md;
} SOFT_HASH;

typedef struct SOFT_MAC {
    int type;
    SOFT_DEV *dev;
    unsigned char key[16];
    unsigned char iv[16];
    unsigned char state[16];
    unsigned char buf[16];
    int buflen;
    int finalized;
    int padding;
} SOFT_MAC;

typedef struct SOFT_AGREE {
    int type;
    SOFT_DEV *dev;
    ULONG alg;
    unsigned char static_priv[32];
    ECCPUBLICKEYBLOB static_pub;
    unsigned char eph_priv[32];
    ECCPUBLICKEYBLOB eph_pub;
    unsigned char id[32];
    int idlen;
} SOFT_AGREE;

static volatile sig_atomic_t g_cancel_wait;

/* ------------------------------------------------------------------ */
/* Small utilities                                                     */
/* ------------------------------------------------------------------ */

static void zero_mem(void *p, size_t n)
{
    if (p && n)
        OPENSSL_cleanse(p, n);
}

static int get_home(char *out, size_t outlen)
{
    const char *env = getenv("SOFTSKF_HOME");
    if (env && *env) {
        if (strlen(env) + 1 > outlen)
            return -1;
        snprintf(out, outlen, "%s", env);
        return 0;
    }
    const char *home = getenv("HOME");
    if (!home || !*home)
        home = ".";
    if (strlen(home) + strlen("/.softskf") + 1 > outlen)
        return -1;
    snprintf(out, outlen, "%s/.softskf", home);
    return 0;
}

static int path_join(char *out, size_t outlen, const char *a, const char *b)
{
    if (snprintf(out, outlen, "%s/%s", a, b) >= (int)outlen)
        return -1;
    return 0;
}

static int ensure_dir(const char *path)
{
    struct stat st;
    if (stat(path, &st) == 0) {
        if (S_ISDIR(st.st_mode))
            return 0;
        return -1;
    }
    if (mkdir(path, 0700) != 0 && errno != EEXIST)
        return -1;
    return 0;
}

static int ensure_dir_mode(const char *path, mode_t mode)
{
    if (ensure_dir(path) != 0)
        return -1;
    chmod(path, mode);
    return 0;
}

static int read_file(const char *path, unsigned char *buf, size_t len)
{
    int fd = open(path, O_RDONLY);
    if (fd < 0)
        return -1;
    size_t done = 0;
    while (done < len) {
        ssize_t n = read(fd, buf + done, len - done);
        if (n <= 0) {
            close(fd);
            return -1;
        }
        done += (size_t)n;
    }
    close(fd);
    return 0;
}

static int write_file_atomic(const char *path, const unsigned char *buf,
                             size_t len, mode_t mode)
{
    char tmp[PATH_MAX];
    if (snprintf(tmp, sizeof(tmp), "%s.tmp.%ld", path, (long)getpid()) >=
        (int)sizeof(tmp))
        return -1;
    int fd = open(tmp, O_WRONLY | O_CREAT | O_TRUNC, mode);
    if (fd < 0)
        return -1;
    size_t done = 0;
    while (done < len) {
        ssize_t n = write(fd, buf + done, len - done);
        if (n <= 0) {
            close(fd);
            unlink(tmp);
            return -1;
        }
        done += (size_t)n;
    }
    if (fsync(fd) != 0) {
        close(fd);
        unlink(tmp);
        return -1;
    }
    close(fd);
    chmod(tmp, mode);
    if (rename(tmp, path) != 0) {
        unlink(tmp);
        return -1;
    }
    return 0;
}

static int rand_bytes(unsigned char *buf, size_t len)
{
    if (!buf || len == 0)
        return 0;
    if (RAND_bytes(buf, (int)len) == 1)
        return 0;
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0)
        return -1;
    size_t done = 0;
    while (done < len) {
        ssize_t n = read(fd, buf + done, len - done);
        if (n <= 0) {
            close(fd);
            return -1;
        }
        done += (size_t)n;
    }
    close(fd);
    return 0;
}

static void hex_encode(const unsigned char *in, size_t len, char *out)
{
    static const char hex[] = "0123456789ABCDEF";
    for (size_t i = 0; i < len; i++) {
        out[i * 2] = hex[in[i] >> 4];
        out[i * 2 + 1] = hex[in[i] & 0x0f];
    }
    out[len * 2] = '\0';
}

static int hmac_sha256(const unsigned char *key, size_t keylen,
                       const unsigned char *data, size_t datalen,
                       unsigned char out[32])
{
    unsigned int outlen = 0;
    if (!HMAC(EVP_sha256(), key, (int)keylen, data, datalen, out, &outlen))
        return -1;
    return outlen == 32 ? 0 : -1;
}

static int hkdf_sha256(const unsigned char *ikm, size_t ikmlen,
                       const unsigned char *salt, size_t saltlen,
                       const unsigned char *info, size_t infolen,
                       unsigned char *out, size_t outlen)
{
    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);
    int ok = 0;
    if (!pctx)
        return -1;
    if (EVP_PKEY_derive_init(pctx) == 1 &&
        EVP_PKEY_CTX_set_hkdf_md(pctx, EVP_sha256()) == 1 &&
        EVP_PKEY_CTX_set1_hkdf_salt(pctx, salt, (int)saltlen) == 1 &&
        EVP_PKEY_CTX_set1_hkdf_key(pctx, ikm, (int)ikmlen) == 1 &&
        EVP_PKEY_CTX_add1_hkdf_info(pctx, info, (int)infolen) == 1 &&
        EVP_PKEY_derive(pctx, out, &outlen) == 1)
        ok = 1;
    EVP_PKEY_CTX_free(pctx);
    return ok ? 0 : -1;
}

static int aes_gcm_seal(const unsigned char key[32],
                        const unsigned char nonce[SOFTSKF_GCM_NONCE_LEN],
                        const unsigned char *aad, size_t aadlen,
                        const unsigned char *in, size_t inlen,
                        unsigned char *out, unsigned char tag[16])
{
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int len = 0, total = 0, ok = 0;
    if (!ctx)
        return -1;
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1)
        goto out;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN,
                            SOFTSKF_GCM_NONCE_LEN, NULL) != 1)
        goto out;
    if (EVP_EncryptInit_ex(ctx, NULL, NULL, key, nonce) != 1)
        goto out;
    if (aadlen && EVP_EncryptUpdate(ctx, NULL, &len, aad, (int)aadlen) != 1)
        goto out;
    if (inlen && EVP_EncryptUpdate(ctx, out, &len, in, (int)inlen) != 1)
        goto out;
    total = len;
    if (EVP_EncryptFinal_ex(ctx, out + total, &len) != 1)
        goto out;
    total += len;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag) != 1)
        goto out;
    ok = 1;
out:
    EVP_CIPHER_CTX_free(ctx);
    return ok ? 0 : -1;
}

static int aes_gcm_open(const unsigned char key[32],
                        const unsigned char nonce[SOFTSKF_GCM_NONCE_LEN],
                        const unsigned char *aad, size_t aadlen,
                        const unsigned char *in, size_t inlen,
                        const unsigned char tag[16],
                        unsigned char *out)
{
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int len = 0, total = 0, ok = 0;
    if (!ctx)
        return -1;
    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1)
        goto out;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN,
                            SOFTSKF_GCM_NONCE_LEN, NULL) != 1)
        goto out;
    if (EVP_DecryptInit_ex(ctx, NULL, NULL, key, nonce) != 1)
        goto out;
    if (aadlen && EVP_DecryptUpdate(ctx, NULL, &len, aad, (int)aadlen) != 1)
        goto out;
    if (inlen && EVP_DecryptUpdate(ctx, out, &len, in, (int)inlen) != 1)
        goto out;
    total = len;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16,
                            (void *)tag) != 1)
        goto out;
    if (EVP_DecryptFinal_ex(ctx, out + total, &len) != 1)
        goto out;
    total += len;
    ok = 1;
out:
    EVP_CIPHER_CTX_free(ctx);
    return ok ? 0 : -1;
}

static int derive_pin_key(const char *pin, const unsigned char *salt,
                          int saltlen, unsigned char key[32])
{
    if (!pin || !salt || saltlen <= 0)
        return -1;
    if (PKCS5_PBKDF2_HMAC(pin, (int)strlen(pin), salt, saltlen,
                          SOFTSKF_PIN_KDF_ITER, EVP_sha256(), 32, key) != 1)
        return -1;
    return 0;
}

static int pin_verifier(const unsigned char key[32], unsigned char out[32])
{
    static const unsigned char label[] = "SoftSKF PIN verify v1";
    return hmac_sha256(key, 32, label, sizeof(label) - 1, out);
}

static int wrap_with_key(const unsigned char kek[32],
                         const char *aad,
                         const unsigned char *in, size_t inlen,
                         unsigned char *nonce, unsigned char *out,
                         unsigned char tag[16])
{
    if (rand_bytes(nonce, SOFTSKF_GCM_NONCE_LEN) != 0)
        return -1;
    return aes_gcm_seal(kek, nonce, (const unsigned char *)aad,
                        aad ? strlen(aad) : 0, in, inlen, out, tag);
}

static int unwrap_with_key(const unsigned char kek[32],
                           const char *aad,
                           const unsigned char *nonce,
                           const unsigned char *in, size_t inlen,
                           const unsigned char tag[16],
                           unsigned char *out)
{
    return aes_gcm_open(kek, nonce, (const unsigned char *)aad,
                        aad ? strlen(aad) : 0, in, inlen, tag, out);
}

static int object_key(const unsigned char ak[32],
                      const char *kind, sqlite3_int64 id,
                      unsigned char out[32])
{
    unsigned char info[64];
    int n = snprintf((char *)info, sizeof(info), "SoftSKF %s %lld",
                     kind, (long long)id);
    if (n < 0 || n >= (int)sizeof(info))
        return -1;
    return hkdf_sha256(ak, 32, NULL, 0, info, (size_t)n, out, 32);
}

static const EVP_CIPHER *cipher_for_alg(ULONG alg)
{
    switch (alg) {
    case SGD_SM4_ECB: return EVP_sm4_ecb();
    case SGD_SM4_CBC: return EVP_sm4_cbc();
    case SGD_SM4_CFB: return EVP_sm4_cfb128();
    case SGD_SM4_OFB: return EVP_sm4_ofb();
    default: return NULL;
    }
}

static int sm4_ecb_block(const unsigned char key[16],
                         const unsigned char in[16],
                         unsigned char out[16], int enc)
{
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int len = 0, total = 0, ok = 0;
    if (!ctx)
        return -1;
    if ((enc ? EVP_EncryptInit_ex(ctx, EVP_sm4_ecb(), NULL, key, NULL)
             : EVP_DecryptInit_ex(ctx, EVP_sm4_ecb(), NULL, key, NULL)) != 1)
        goto out;
    if (EVP_CIPHER_CTX_set_padding(ctx, 0) != 1)
        goto out;
    if ((enc ? EVP_EncryptUpdate(ctx, out, &len, in, 16)
             : EVP_DecryptUpdate(ctx, out, &len, in, 16)) != 1)
        goto out;
    total = len;
    if ((enc ? EVP_EncryptFinal_ex(ctx, out + total, &len)
             : EVP_DecryptFinal_ex(ctx, out + total, &len)) != 1)
        goto out;
    total += len;
    ok = (total == 16);
out:
    EVP_CIPHER_CTX_free(ctx);
    return ok ? 0 : -1;
}

/* ------------------------------------------------------------------ */
/* SQLite helpers                                                      */
/* ------------------------------------------------------------------ */

static const char *schema_sql =
    "PRAGMA journal_mode=WAL;"
    "PRAGMA foreign_keys=ON;"
    "CREATE TABLE IF NOT EXISTS token("
    " id INTEGER PRIMARY KEY CHECK(id=1),"
    " format_version INTEGER NOT NULL,"
    " name TEXT NOT NULL UNIQUE,"
    " serial TEXT NOT NULL,"
    " label TEXT NOT NULL,"
    " created_at INTEGER NOT NULL,"
    " total_space INTEGER NOT NULL,"
    " auth_enc BLOB NOT NULL,"
    " auth_nonce BLOB NOT NULL,"
    " auth_tag BLOB NOT NULL,"
    " auth_retry INTEGER NOT NULL DEFAULT 0,"
    " auth_max_retry INTEGER NOT NULL DEFAULT 15,"
    " auth_locked INTEGER NOT NULL DEFAULT 0"
    ");"
    "CREATE TABLE IF NOT EXISTS app("
    " id INTEGER PRIMARY KEY AUTOINCREMENT,"
    " name TEXT NOT NULL UNIQUE,"
    " admin_salt BLOB NOT NULL,"
    " admin_verifier BLOB NOT NULL,"
    " admin_nonce BLOB NOT NULL,"
    " admin_tag BLOB NOT NULL,"
    " admin_ak BLOB NOT NULL,"
    " admin_retry INTEGER NOT NULL DEFAULT 0,"
    " admin_max_retry INTEGER NOT NULL DEFAULT 15,"
    " admin_locked INTEGER NOT NULL DEFAULT 0,"
    " user_salt BLOB NOT NULL,"
    " user_verifier BLOB NOT NULL,"
    " user_nonce BLOB NOT NULL,"
    " user_tag BLOB NOT NULL,"
    " user_ak BLOB NOT NULL,"
    " user_retry INTEGER NOT NULL DEFAULT 0,"
    " user_max_retry INTEGER NOT NULL DEFAULT 15,"
    " user_locked INTEGER NOT NULL DEFAULT 0,"
    " default_admin INTEGER NOT NULL DEFAULT 1,"
    " default_user INTEGER NOT NULL DEFAULT 1,"
    " create_file_rights INTEGER NOT NULL DEFAULT 0,"
    " created_at INTEGER NOT NULL"
    ");"
    "CREATE TABLE IF NOT EXISTS file("
    " id INTEGER PRIMARY KEY AUTOINCREMENT,"
    " app_id INTEGER NOT NULL REFERENCES app(id) ON DELETE CASCADE,"
    " name TEXT NOT NULL,"
    " size INTEGER NOT NULL,"
    " read_rights INTEGER NOT NULL,"
    " write_rights INTEGER NOT NULL,"
    " nonce BLOB NOT NULL,"
    " tag BLOB NOT NULL,"
    " content BLOB NOT NULL,"
    " created_at INTEGER NOT NULL,"
    " UNIQUE(app_id,name)"
    ");"
    "CREATE TABLE IF NOT EXISTS container("
    " id INTEGER PRIMARY KEY AUTOINCREMENT,"
    " app_id INTEGER NOT NULL REFERENCES app(id) ON DELETE CASCADE,"
    " name TEXT NOT NULL,"
    " ctype INTEGER NOT NULL DEFAULT 0,"
    " bits INTEGER NOT NULL DEFAULT 0,"
    " pub_blob BLOB,"
    " priv_nonce BLOB,"
    " priv_tag BLOB,"
    " priv_blob BLOB,"
    " sign_cert BLOB,"
    " enc_cert BLOB,"
    " created_at INTEGER NOT NULL,"
    " UNIQUE(app_id,name)"
    ");"
    "CREATE INDEX IF NOT EXISTS idx_file_app ON file(app_id);"
    "CREATE INDEX IF NOT EXISTS idx_ctn_app ON container(app_id);";

static int db_open(const char *path, sqlite3 **out)
{
    sqlite3 *db = NULL;
    int rc = sqlite3_open_v2(path, &db,
                             SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE,
                             NULL);
    if (rc != SQLITE_OK) {
        if (db)
            sqlite3_close(db);
        return -1;
    }
    sqlite3_busy_timeout(db, 5000);
    sqlite3_exec(db, "PRAGMA foreign_keys=ON;", NULL, NULL, NULL);
    *out = db;
    return 0;
}

static int db_exec(sqlite3 *db, const char *sql)
{
    char *err = NULL;
    int rc = sqlite3_exec(db, sql, NULL, NULL, &err);
    if (rc != SQLITE_OK) {
        if (err)
            sqlite3_free(err);
        return -1;
    }
    return 0;
}

static int db_prepare(sqlite3 *db, const char *sql, sqlite3_stmt **st)
{
    return sqlite3_prepare_v2(db, sql, -1, st, NULL) == SQLITE_OK ? 0 : -1;
}

static int db_bind_blob(sqlite3_stmt *st, int idx, const void *p, int n)
{
    return sqlite3_bind_blob(st, idx, p, n, SQLITE_TRANSIENT) == SQLITE_OK
               ? 0 : -1;
}

static int db_bind_text(sqlite3_stmt *st, int idx, const char *s)
{
    return sqlite3_bind_text(st, idx, s ? s : "", -1, SQLITE_TRANSIENT) ==
                   SQLITE_OK ? 0 : -1;
}

static int db_bind_int(sqlite3_stmt *st, int idx, sqlite3_int64 v)
{
    return sqlite3_bind_int64(st, idx, v) == SQLITE_OK ? 0 : -1;
}

static int db_column_blob_dup(sqlite3_stmt *st, int col,
                              unsigned char **out, int *outlen)
{
    const void *p = sqlite3_column_blob(st, col);
    int n = sqlite3_column_bytes(st, col);
    *out = NULL;
    *outlen = 0;
    if (!p || n <= 0)
        return 0;
    unsigned char *copy = malloc((size_t)n);
    if (!copy)
        return -1;
    memcpy(copy, p, (size_t)n);
    *out = copy;
    *outlen = n;
    return 0;
}

static int db_column_text_copy(sqlite3_stmt *st, int col,
                               char *out, size_t outlen)
{
    const unsigned char *p = sqlite3_column_text(st, col);
    if (!p) {
        if (outlen)
            out[0] = '\0';
        return 0;
    }
    snprintf(out, outlen, "%s", (const char *)p);
    return 0;
}

static int db_begin(sqlite3 *db)
{
    return db_exec(db, "BEGIN IMMEDIATE;");
}

static int db_commit(sqlite3 *db)
{
    return db_exec(db, "COMMIT;");
}

static int db_rollback(sqlite3 *db)
{
    return db_exec(db, "ROLLBACK;");
}

/* ------------------------------------------------------------------ */
/* Token metadata                                                      */
/* ------------------------------------------------------------------ */

static int token_dir(char *out, size_t outlen, const char *name)
{
    char home[PATH_MAX];
    if (get_home(home, sizeof(home)) != 0)
        return -1;
    return path_join(out, outlen, home, name);
}

static int token_db_path(char *out, size_t outlen, const char *name)
{
    char dir[PATH_MAX];
    if (token_dir(dir, sizeof(dir), name) != 0)
        return -1;
    return path_join(out, outlen, dir, "token.db");
}

static int token_key_path(char *out, size_t outlen, const char *name)
{
    char dir[PATH_MAX];
    if (token_dir(dir, sizeof(dir), name) != 0)
        return -1;
    return path_join(out, outlen, dir, "token.key");
}

static int token_exists(const char *name)
{
    char path[PATH_MAX];
    struct stat st;
    if (token_db_path(path, sizeof(path), name) != 0)
        return 0;
    return stat(path, &st) == 0 && S_ISREG(st.st_mode);
}

/* ------------------------------------------------------------------ */
/* Device lifecycle                                                    */
/* ------------------------------------------------------------------ */

static SOFT_DEV *dev_open(const char *name)
{
    if (!name || !*name || strlen(name) >= sizeof(((SOFT_DEV *)0)->name))
        return NULL;

    char keypath[PATH_MAX], dbpath[PATH_MAX];
    if (token_key_path(keypath, sizeof(keypath), name) != 0 ||
        token_db_path(dbpath, sizeof(dbpath), name) != 0)
        return NULL;

    unsigned char store_key[32];
    if (read_file(keypath, store_key, sizeof(store_key)) != 0)
        return NULL;

    sqlite3 *db = NULL;
    if (db_open(dbpath, &db) != 0) {
        zero_mem(store_key, sizeof(store_key));
        return NULL;
    }

    sqlite3_stmt *st = NULL;
    if (db_prepare(db,
        "SELECT label, serial, auth_enc, auth_nonce, auth_tag,"
        " auth_retry, auth_max_retry, auth_locked FROM token WHERE id=1",
        &st) != 0) {
        sqlite3_close(db);
        zero_mem(store_key, sizeof(store_key));
        return NULL;
    }

    SOFT_DEV *d = calloc(1, sizeof(*d));
    if (!d) {
        sqlite3_finalize(st);
        sqlite3_close(db);
        zero_mem(store_key, sizeof(store_key));
        return NULL;
    }
    d->type = SOFT_HANDLE_DEV;
    d->db = db;
    snprintf(d->name, sizeof(d->name), "%s", name);
    memcpy(d->store_key, store_key, sizeof(store_key));
    zero_mem(store_key, sizeof(store_key));

    int ok = 0;
    if (sqlite3_step(st) == SQLITE_ROW) {
        unsigned char *enc = NULL, *nonce = NULL, *tag = NULL;
        int enclen = 0, noncelen = 0, taglen = 0;
        if (db_column_blob_dup(st, 2, &enc, &enclen) == 0 &&
            db_column_blob_dup(st, 3, &nonce, &noncelen) == 0 &&
            db_column_blob_dup(st, 4, &tag, &taglen) == 0 &&
            enclen == 16 && noncelen == SOFTSKF_GCM_NONCE_LEN &&
            taglen == SOFTSKF_GCM_TAG_LEN &&
            unwrap_with_key(d->store_key, "token-auth-key", nonce,
                            enc, (size_t)enclen, tag, d->dak) == 0) {
            d->auth_retry = sqlite3_column_int(st, 5);
            d->auth_max_retry = sqlite3_column_int(st, 6);
            d->auth_locked = sqlite3_column_int(st, 7);
            if (d->auth_max_retry <= 0)
                d->auth_max_retry = 15;
            ok = 1;
        }
        free(enc);
        free(nonce);
        free(tag);
    }
    sqlite3_finalize(st);

    if (!ok) {
        zero_mem(d->dak, sizeof(d->dak));
        zero_mem(d->store_key, sizeof(d->store_key));
        sqlite3_close(db);
        free(d);
        return NULL;
    }

    if (pthread_mutex_init(&d->lock, NULL) == 0)
        d->lock_inited = 1;
    return d;
}

static void dev_free(SOFT_DEV *d)
{
    if (!d)
        return;
    if (d->lock_inited) {
        pthread_mutex_destroy(&d->lock);
        d->lock_inited = 0;
    }
    if (d->db) {
        sqlite3_close(d->db);
        d->db = NULL;
    }
    zero_mem(d->dak, sizeof(d->dak));
    zero_mem(d->store_key, sizeof(d->store_key));
    free(d);
}

ULONG SKF_EnumDev(BOOL bPresent, LPSTR szNameList, ULONG *pulSize)
{
    (void)bPresent;
    if (!pulSize)
        return SAR_INVALIDPARAMERR;

    char home[PATH_MAX];
    if (get_home(home, sizeof(home)) != 0)
        return SAR_FAIL;

    DIR *dir = opendir(home);
    if (!dir) {
        *pulSize = 1;
        return SAR_OK;
    }

    char names[SOFTSKF_MAX_APPS][64];
    int count = 0;
    struct dirent *ent;
    while ((ent = readdir(dir)) != NULL) {
        if (ent->d_name[0] == '.')
            continue;
        if (!token_exists(ent->d_name))
            continue;
        if (count >= SOFTSKF_MAX_APPS)
            break;
        size_t nlen = strnlen(ent->d_name, sizeof(names[count]));
        if (nlen >= sizeof(names[count]))
            continue;
        memcpy(names[count], ent->d_name, nlen);
        names[count][nlen] = '\0';
        count++;
    }
    closedir(dir);

    int need = 1;
    for (int i = 0; i < count; i++)
        need += (int)strlen(names[i]) + 1;

    if (!szNameList) {
        *pulSize = (ULONG)need;
        return SAR_OK;
    }
    if (*pulSize < (ULONG)need) {
        *pulSize = (ULONG)need;
        return SAR_BUFFER_TOO_SMALL;
    }

    char *p = szNameList;
    for (int i = 0; i < count; i++) {
        size_t n = strlen(names[i]) + 1;
        memcpy(p, names[i], n);
        p += n;
    }
    *p = '\0';
    *pulSize = (ULONG)need;
    return SAR_OK;
}

ULONG SKF_ConnectDev(LPSTR szName, DEVHANDLE *phDev)
{
    if (!szName || !phDev)
        return SAR_INVALIDPARAMERR;
    SOFT_DEV *d = dev_open(szName);
    if (!d)
        return SAR_FILE_NOT_EXIST;
    *phDev = (DEVHANDLE)d;
    return SAR_OK;
}

ULONG SKF_DisConnectDev(DEVHANDLE hDev)
{
    SOFT_DEV *d = (SOFT_DEV *)hDev;
    if (!d || d->type != SOFT_HANDLE_DEV)
        return SAR_INVALIDHANDLEERR;
    dev_free(d);
    return SAR_OK;
}

ULONG SKF_GetDevState(LPSTR szDevName, ULONG *pulDevState)
{
    if (!szDevName || !pulDevState)
        return SAR_INVALIDPARAMERR;
    *pulDevState = token_exists(szDevName) ? 1 : 0;
    return SAR_OK;
}

ULONG SKF_SetLabel(DEVHANDLE hDev, LPSTR szLabel)
{
    SOFT_DEV *d = (SOFT_DEV *)hDev;
    if (!d || d->type != SOFT_HANDLE_DEV)
        return SAR_INVALIDHANDLEERR;
    if (!szLabel)
        return SAR_INVALIDPARAMERR;
    if (strlen(szLabel) >= 32)
        return SAR_NAMELENERR;

    sqlite3_stmt *st = NULL;
    if (db_prepare(d->db, "UPDATE token SET label=? WHERE id=1", &st) != 0)
        return SAR_FAIL;
    db_bind_text(st, 1, szLabel);
    int rc = sqlite3_step(st);
    sqlite3_finalize(st);
    return rc == SQLITE_DONE ? SAR_OK : SAR_FAIL;
}

ULONG SKF_GetDevInfo(DEVHANDLE hDev, DEVINFO *pDevInfo)
{
    SOFT_DEV *d = (SOFT_DEV *)hDev;
    if (!d || d->type != SOFT_HANDLE_DEV || !pDevInfo)
        return SAR_INVALIDPARAMERR;

    memset(pDevInfo, 0, sizeof(*pDevInfo));
    pDevInfo->Version.major = 1;
    pDevInfo->Version.minor = 0;
    snprintf(pDevInfo->Manufacturer, sizeof(pDevInfo->Manufacturer),
             "SoftSKF");
    snprintf(pDevInfo->Issuer, sizeof(pDevInfo->Issuer), "SoftSKF");
    pDevInfo->HWVersion.major = 1;
    pDevInfo->FirmwareVersion.major = SOFTSKF_FORMAT_VERSION;
    pDevInfo->AlgSymCap = SGD_SM4 | SGD_ECB | SGD_CBC | SGD_CFB |
                          SGD_OFB | SGD_MAC;
    pDevInfo->AlgAsymCap = SGD_RSA | SGD_SM2;
    pDevInfo->AlgHashCap = SGD_SM3 | SGD_SHA1 | SGD_SHA256;
    pDevInfo->DevAuthAlgId = SGD_SM4_ECB;
    pDevInfo->TotalSpace = SOFTSKF_TOTAL_SPACE;
    pDevInfo->FreeSpace = SOFTSKF_TOTAL_SPACE;
    pDevInfo->MaxECCBufferSize = 256;
    pDevInfo->MaxBufferSize = 64 * 1024;

    sqlite3_stmt *st = NULL;
    if (db_prepare(d->db, "SELECT label, serial, total_space FROM token WHERE id=1",
                   &st) == 0 && sqlite3_step(st) == SQLITE_ROW) {
        db_column_text_copy(st, 0, pDevInfo->Label, sizeof(pDevInfo->Label));
        db_column_text_copy(st, 1, pDevInfo->SerialNumber,
                            sizeof(pDevInfo->SerialNumber));
        pDevInfo->TotalSpace = (ULONG)sqlite3_column_int64(st, 2);
        sqlite3_finalize(st);
    } else {
        sqlite3_finalize(st);
        return SAR_FAIL;
    }

    sqlite3_stmt *fs = NULL;
    if (db_prepare(d->db, "SELECT COALESCE(SUM(size),0) FROM file", &fs) == 0 &&
        sqlite3_step(fs) == SQLITE_ROW) {
        sqlite3_int64 used = sqlite3_column_int64(fs, 0);
        if (used < 0)
            used = 0;
        if ((sqlite3_int64)pDevInfo->TotalSpace > used)
            pDevInfo->FreeSpace = pDevInfo->TotalSpace - (ULONG)used;
        else
            pDevInfo->FreeSpace = 0;
    }
    sqlite3_finalize(fs);
    return SAR_OK;
}

ULONG SKF_LockDev(DEVHANDLE hDev, ULONG ulTimeOut)
{
    SOFT_DEV *d = (SOFT_DEV *)hDev;
    if (!d || d->type != SOFT_HANDLE_DEV || !d->lock_inited)
        return SAR_INVALIDHANDLEERR;

    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    ts.tv_sec += (time_t)(ulTimeOut / 1000);
    ts.tv_nsec += (long)(ulTimeOut % 1000) * 1000000L;
    if (ts.tv_nsec >= 1000000000L) {
        ts.tv_sec++;
        ts.tv_nsec -= 1000000000L;
    }
    int rc = pthread_mutex_timedlock(&d->lock, &ts);
    if (rc == 0)
        return SAR_OK;
    if (rc == ETIMEDOUT)
        return SAR_TIMEOUTERR;
    return SAR_FAIL;
}

ULONG SKF_UnlockDev(DEVHANDLE hDev)
{
    SOFT_DEV *d = (SOFT_DEV *)hDev;
    if (!d || d->type != SOFT_HANDLE_DEV || !d->lock_inited)
        return SAR_INVALIDHANDLEERR;
    return pthread_mutex_unlock(&d->lock) == 0 ? SAR_OK : SAR_FAIL;
}

ULONG SKF_Transmit(DEVHANDLE hDev, BYTE *pbCommand, ULONG ulCommandLen,
                   BYTE *pbData, ULONG *pulDataLen)
{
    (void)hDev; (void)pbCommand; (void)ulCommandLen;
    (void)pbData; (void)pulDataLen;
    return SAR_NOTSUPPORTYETERR;
}

static int list_devices_string(char *out, size_t outlen)
{
    ULONG need = 0;
    if (SKF_EnumDev(TRUE, NULL, &need) != SAR_OK || need == 0 || need > outlen)
        return -1;
    char *tmp = malloc(need);
    if (!tmp)
        return -1;
    ULONG got = need;
    if (SKF_EnumDev(TRUE, tmp, &got) != SAR_OK) {
        free(tmp);
        return -1;
    }
    memcpy(out, tmp, need);
    free(tmp);
    return 0;
}

ULONG SKF_WaitForDevEvent(LPSTR szDevName, ULONG *pulDevNameLen,
                          ULONG *pulEvent)
{
    if (!szDevName || !pulDevNameLen || !pulEvent)
        return SAR_INVALIDPARAMERR;

    g_cancel_wait = 0;
    char before[4096], after[4096];
    if (list_devices_string(before, sizeof(before)) != 0)
        before[0] = '\0';

    for (int i = 0; i < 150; i++) {
        if (g_cancel_wait)
            return SAR_NOT_EVENTERR;
        struct timespec ts = {0, 200 * 1000 * 1000L};
        nanosleep(&ts, NULL);
        if (list_devices_string(after, sizeof(after)) != 0)
            after[0] = '\0';
        if (strcmp(before, after) != 0) {
            const char *name = after[0] ? after : before;
            size_t n = strlen(name) + 1;
            if (*pulDevNameLen < n) {
                *pulDevNameLen = (ULONG)n;
                return SAR_BUFFER_TOO_SMALL;
            }
            memcpy(szDevName, name, n);
            *pulDevNameLen = (ULONG)n;
            *pulEvent = 1;
            return SAR_OK;
        }
    }
    return SAR_TIMEOUTERR;
}

ULONG SKF_CancelWaitForDevEvent(void)
{
    g_cancel_wait = 1;
    return SAR_OK;
}

/* ------------------------------------------------------------------ */
/* Applications and PINs                                               */
/* ------------------------------------------------------------------ */

static int app_exists(SOFT_DEV *d, const char *name)
{
    sqlite3_stmt *st = NULL;
    if (db_prepare(d->db, "SELECT id FROM app WHERE name=?", &st) != 0)
        return 0;
    db_bind_text(st, 1, name);
    int found = sqlite3_step(st) == SQLITE_ROW;
    sqlite3_finalize(st);
    return found;
}

static ULONG app_create_internal(SOFT_DEV *d, const char *name,
                                 const char *admin_pin, int admin_max,
                                 const char *user_pin, int user_max,
                                 DWORD rights, SOFT_APP **out)
{
    if (!d || !name || !admin_pin || !user_pin)
        return SAR_INVALIDPARAMERR;
    if (!*admin_pin || !*user_pin)
        return SAR_PIN_LEN_RANGE;
    size_t nlen = strlen(name);
    if (nlen == 0 || nlen >= 32)
        return SAR_NAMELENERR;
    if (app_exists(d, name))
        return SAR_APPLICATION_EXISTS;

    unsigned char ak[32];
    unsigned char admin_salt[SOFTSKF_SALT_LEN], user_salt[SOFTSKF_SALT_LEN];
    unsigned char admin_key[32], user_key[32];
    unsigned char admin_verifier[32], user_verifier[32];
    unsigned char admin_nonce[SOFTSKF_GCM_NONCE_LEN];
    unsigned char user_nonce[SOFTSKF_GCM_NONCE_LEN];
    unsigned char admin_ak[32], user_ak[32];
    unsigned char admin_tag[SOFTSKF_GCM_TAG_LEN];
    unsigned char user_tag[SOFTSKF_GCM_TAG_LEN];
    char admin_aad[96], user_aad[96];

    if (rand_bytes(ak, sizeof(ak)) != 0 ||
        rand_bytes(admin_salt, sizeof(admin_salt)) != 0 ||
        rand_bytes(user_salt, sizeof(user_salt)) != 0)
        return SAR_GENRANDERR;
    if (derive_pin_key(admin_pin, admin_salt, sizeof(admin_salt), admin_key) != 0 ||
        derive_pin_key(user_pin, user_salt, sizeof(user_salt), user_key) != 0)
        return SAR_FAIL;
    if (pin_verifier(admin_key, admin_verifier) != 0 ||
        pin_verifier(user_key, user_verifier) != 0)
        goto fail;

    snprintf(admin_aad, sizeof(admin_aad), "app:%s:admin", name);
    snprintf(user_aad, sizeof(user_aad), "app:%s:user", name);
    if (wrap_with_key(admin_key, admin_aad, ak, sizeof(ak), admin_nonce,
                      admin_ak, admin_tag) != 0 ||
        wrap_with_key(user_key, user_aad, ak, sizeof(ak), user_nonce,
                      user_ak, user_tag) != 0)
        goto fail;

    if (admin_max <= 0) admin_max = 6;
    if (user_max <= 0) user_max = 6;

    sqlite3_stmt *st = NULL;
    if (db_prepare(d->db,
        "INSERT INTO app(name,admin_salt,admin_verifier,admin_nonce,admin_tag,"
        "admin_ak,admin_retry,admin_max_retry,admin_locked,"
        "user_salt,user_verifier,user_nonce,user_tag,user_ak,"
        "user_retry,user_max_retry,user_locked,default_admin,default_user,"
        "create_file_rights,created_at) VALUES(?,?,?,?,?,?,0,?,0,?,?,?,?,?,0,?,0,0,0,?,?)",
        &st) != 0)
        goto fail;

    db_bind_text(st, 1, name);
    db_bind_blob(st, 2, admin_salt, sizeof(admin_salt));
    db_bind_blob(st, 3, admin_verifier, sizeof(admin_verifier));
    db_bind_blob(st, 4, admin_nonce, sizeof(admin_nonce));
    db_bind_blob(st, 5, admin_tag, sizeof(admin_tag));
    db_bind_blob(st, 6, admin_ak, sizeof(admin_ak));
    db_bind_int(st, 7, admin_max);
    db_bind_blob(st, 8, user_salt, sizeof(user_salt));
    db_bind_blob(st, 9, user_verifier, sizeof(user_verifier));
    db_bind_blob(st, 10, user_nonce, sizeof(user_nonce));
    db_bind_blob(st, 11, user_tag, sizeof(user_tag));
    db_bind_blob(st, 12, user_ak, sizeof(user_ak));
    db_bind_int(st, 13, user_max);
    db_bind_int(st, 14, (sqlite3_int64)rights);
    db_bind_int(st, 15, (sqlite3_int64)time(NULL));
    int rc = sqlite3_step(st);
    sqlite3_finalize(st);
    if (rc != SQLITE_DONE)
        goto fail;

    sqlite3_int64 id = sqlite3_last_insert_rowid(d->db);
    if (out) {
        SOFT_APP *a = calloc(1, sizeof(*a));
        if (!a)
            goto fail;
        a->type = SOFT_HANDLE_APP;
        a->dev = d;
        a->id = id;
        snprintf(a->name, sizeof(a->name), "%s", name);
        *out = a;
    }
    zero_mem(ak, sizeof(ak));
    zero_mem(admin_key, sizeof(admin_key));
    zero_mem(user_key, sizeof(user_key));
    return SAR_OK;

fail:
    zero_mem(ak, sizeof(ak));
    zero_mem(admin_key, sizeof(admin_key));
    zero_mem(user_key, sizeof(user_key));
    return SAR_FAIL;
}

ULONG SKF_CreateApplication(DEVHANDLE hDev, LPSTR szAppName,
                            LPSTR szAdminPin, DWORD dwAdminPinRetryCount,
                            LPSTR szUserPin, DWORD dwUserPinRetryCount,
                            DWORD dwCreateFileRights,
                            HAPPLICATION *phApplication)
{
    SOFT_DEV *d = (SOFT_DEV *)hDev;
    if (!d || d->type != SOFT_HANDLE_DEV)
        return SAR_INVALIDHANDLEERR;
    if (!d->authed)
        return SAR_USER_NOT_LOGGED_IN;
    if (!szAppName || !szAdminPin || !szUserPin || !phApplication)
        return SAR_INVALIDPARAMERR;
    return app_create_internal(d, szAppName, szAdminPin,
                               (int)dwAdminPinRetryCount, szUserPin,
                               (int)dwUserPinRetryCount,
                               dwCreateFileRights, (SOFT_APP **)phApplication);
}

ULONG SKF_DeleteApplication(DEVHANDLE hDev, LPSTR szAppName)
{
    SOFT_DEV *d = (SOFT_DEV *)hDev;
    if (!d || d->type != SOFT_HANDLE_DEV)
        return SAR_INVALIDHANDLEERR;
    if (!d->authed)
        return SAR_USER_NOT_LOGGED_IN;
    if (!szAppName)
        return SAR_INVALIDPARAMERR;
    if (!app_exists(d, szAppName))
        return SAR_APPLICATION_NOT_EXISTS;

    if (db_begin(d->db) != 0)
        return SAR_FAIL;
    sqlite3_stmt *st = NULL;
    if (db_prepare(d->db, "DELETE FROM app WHERE name=?", &st) != 0 ||
        db_bind_text(st, 1, szAppName) != 0 ||
        sqlite3_step(st) != SQLITE_DONE) {
        sqlite3_finalize(st);
        db_rollback(d->db);
        return SAR_FAIL;
    }
    sqlite3_finalize(st);
    return db_commit(d->db) == 0 ? SAR_OK : SAR_FAIL;
}

ULONG SKF_EnumApplication(DEVHANDLE hDev, LPSTR szAppName, ULONG *pulSize)
{
    SOFT_DEV *d = (SOFT_DEV *)hDev;
    if (!d || d->type != SOFT_HANDLE_DEV || !pulSize)
        return SAR_INVALIDPARAMERR;

    sqlite3_stmt *st = NULL;
    if (db_prepare(d->db, "SELECT name FROM app ORDER BY id", &st) != 0)
        return SAR_FAIL;
    int need = 1;
    while (sqlite3_step(st) == SQLITE_ROW) {
        const unsigned char *p = sqlite3_column_text(st, 0);
        if (p)
            need += (int)strlen((const char *)p) + 1;
    }
    sqlite3_finalize(st);

    if (!szAppName) {
        *pulSize = (ULONG)need;
        return SAR_OK;
    }
    if (*pulSize < (ULONG)need) {
        *pulSize = (ULONG)need;
        return SAR_BUFFER_TOO_SMALL;
    }
    if (db_prepare(d->db, "SELECT name FROM app ORDER BY id", &st) != 0)
        return SAR_FAIL;
    char *p = szAppName;
    while (sqlite3_step(st) == SQLITE_ROW) {
        const unsigned char *name = sqlite3_column_text(st, 0);
        if (!name)
            continue;
        size_t n = strlen((const char *)name) + 1;
        memcpy(p, name, n);
        p += n;
    }
    *p = '\0';
    sqlite3_finalize(st);
    *pulSize = (ULONG)need;
    return SAR_OK;
}

ULONG SKF_OpenApplication(DEVHANDLE hDev, LPSTR szAppName,
                          HAPPLICATION *phApplication)
{
    SOFT_DEV *d = (SOFT_DEV *)hDev;
    if (!d || d->type != SOFT_HANDLE_DEV || !szAppName || !phApplication)
        return SAR_INVALIDPARAMERR;

    sqlite3_stmt *st = NULL;
    if (db_prepare(d->db, "SELECT id FROM app WHERE name=?", &st) != 0)
        return SAR_FAIL;
    db_bind_text(st, 1, szAppName);
    if (sqlite3_step(st) != SQLITE_ROW) {
        sqlite3_finalize(st);
        return SAR_APPLICATION_NOT_EXISTS;
    }
    sqlite3_int64 id = sqlite3_column_int64(st, 0);
    sqlite3_finalize(st);

    SOFT_APP *a = calloc(1, sizeof(*a));
    if (!a)
        return SAR_MEMORYERR;
    a->type = SOFT_HANDLE_APP;
    a->dev = d;
    a->id = id;
    snprintf(a->name, sizeof(a->name), "%s", szAppName);
    *phApplication = (HAPPLICATION)a;
    return SAR_OK;
}

ULONG SKF_CloseApplication(HAPPLICATION hApplication)
{
    SOFT_APP *a = (SOFT_APP *)hApplication;
    if (!a || a->type != SOFT_HANDLE_APP)
        return SAR_INVALIDHANDLEERR;
    zero_mem(a->ak, sizeof(a->ak));
    free(a);
    return SAR_OK;
}

static int pin_columns(ULONG type, const char **salt_col,
                       const char **ver_col, const char **nonce_col,
                       const char **tag_col, const char **ak_col,
                       const char **retry_col, const char **max_col,
                       const char **locked_col, const char **default_col)
{
    if (type == ADMIN_TYPE) {
        *salt_col = "admin_salt"; *ver_col = "admin_verifier";
        *nonce_col = "admin_nonce"; *tag_col = "admin_tag";
        *ak_col = "admin_ak"; *retry_col = "admin_retry";
        *max_col = "admin_max_retry"; *locked_col = "admin_locked";
        *default_col = "default_admin";
        return 0;
    }
    if (type == USER_TYPE) {
        *salt_col = "user_salt"; *ver_col = "user_verifier";
        *nonce_col = "user_nonce"; *tag_col = "user_tag";
        *ak_col = "user_ak"; *retry_col = "user_retry";
        *max_col = "user_max_retry"; *locked_col = "user_locked";
        *default_col = "default_user";
        return 0;
    }
    return -1;
}

static int app_max_retry(SOFT_APP *a, ULONG type, int *maxretry)
{
    const char *salt_col, *ver_col, *nonce_col, *tag_col, *ak_col;
    const char *retry_col, *max_col, *locked_col, *default_col;
    if (!a || !maxretry ||
        pin_columns(type, &salt_col, &ver_col, &nonce_col, &tag_col,
                    &ak_col, &retry_col, &max_col, &locked_col,
                    &default_col) != 0)
        return -1;
    char sql[128];
    snprintf(sql, sizeof(sql), "SELECT %s FROM app WHERE id=?", max_col);
    sqlite3_stmt *st = NULL;
    if (db_prepare(a->dev->db, sql, &st) != 0)
        return -1;
    db_bind_int(st, 1, a->id);
    int ok = sqlite3_step(st) == SQLITE_ROW;
    if (ok)
        *maxretry = sqlite3_column_int(st, 0);
    sqlite3_finalize(st);
    if (ok && *maxretry <= 0)
        *maxretry = 6;
    return ok ? 0 : -1;
}

static ULONG app_pin_check(SOFT_APP *a, ULONG type, const char *pin,
                           int update_retry, int *remaining)
{
    if (remaining)
        *remaining = 0;
    if (!a || a->type != SOFT_HANDLE_APP || !a->dev)
        return SAR_INVALIDHANDLEERR;
    if (!pin)
        return SAR_INVALIDPARAMERR;

    const char *salt_col, *ver_col, *nonce_col, *tag_col, *ak_col;
    const char *retry_col, *max_col, *locked_col, *default_col;
    if (pin_columns(type, &salt_col, &ver_col, &nonce_col, &tag_col, &ak_col,
                    &retry_col, &max_col, &locked_col, &default_col) != 0)
        return SAR_USER_TYPE_INVALID;

    char sql[512];
    snprintf(sql, sizeof(sql),
             "SELECT %s,%s,%s,%s,%s,%s,%s,%s FROM app WHERE id=?",
             salt_col, ver_col, nonce_col, tag_col, ak_col,
             retry_col, max_col, locked_col);
    sqlite3_stmt *st = NULL;
    if (db_prepare(a->dev->db, sql, &st) != 0)
        return SAR_FAIL;
    db_bind_int(st, 1, a->id);
    if (sqlite3_step(st) != SQLITE_ROW) {
        sqlite3_finalize(st);
        return SAR_APPLICATION_NOT_EXISTS;
    }

    unsigned char *salt = NULL, *ver = NULL, *nonce = NULL, *wrapped = NULL;
    unsigned char *tag = NULL;
    int saltlen = 0, verlen = 0, noncelen = 0, wrappedlen = 0, taglen = 0;
    db_column_blob_dup(st, 0, &salt, &saltlen);
    db_column_blob_dup(st, 1, &ver, &verlen);
    db_column_blob_dup(st, 2, &nonce, &noncelen);
    db_column_blob_dup(st, 3, &tag, &taglen);
    db_column_blob_dup(st, 4, &wrapped, &wrappedlen);
    int retry = sqlite3_column_int(st, 5);
    int maxretry = sqlite3_column_int(st, 6);
    int locked = sqlite3_column_int(st, 7);
    sqlite3_finalize(st);

    if (maxretry <= 0)
        maxretry = 6;
    if (remaining)
        *remaining = maxretry - retry > 0 ? maxretry - retry : 0;
    if (locked) {
        free(salt); free(ver); free(nonce); free(tag); free(wrapped);
        return SAR_PIN_LOCKED;
    }
    if (!salt || saltlen <= 0 || !ver || verlen != 32 || !nonce ||
        noncelen != SOFTSKF_GCM_NONCE_LEN || !tag ||
        taglen != SOFTSKF_GCM_TAG_LEN || !wrapped || wrappedlen != 32) {
        free(salt); free(ver); free(nonce); free(tag); free(wrapped);
        return SAR_PIN_INVALID;
    }

    unsigned char key[32], calc[32], ak[32];
    int ok = derive_pin_key(pin, salt, saltlen, key) == 0 &&
             pin_verifier(key, calc) == 0 &&
             CRYPTO_memcmp(calc, ver, 32) == 0;
    char aad[96];
    if (ok) {
        snprintf(aad, sizeof(aad), "app:%s:%s", a->name,
                 type == ADMIN_TYPE ? "admin" : "user");
        ok = unwrap_with_key(key, aad, nonce, wrapped, (size_t)wrappedlen,
                             tag, ak) == 0;
    }
    zero_mem(key, sizeof(key));
    zero_mem(calc, sizeof(calc));

    if (ok) {
        memcpy(a->ak, ak, 32);
        if (type == ADMIN_TYPE)
            a->admin_logged = 1;
        else
            a->user_logged = 1;
        zero_mem(ak, sizeof(ak));

        char usql[256];
        snprintf(usql, sizeof(usql),
                 "UPDATE app SET %s=0,%s=0 WHERE id=?", retry_col, locked_col);
        if (db_prepare(a->dev->db, usql, &st) == 0) {
            db_bind_int(st, 1, a->id);
            sqlite3_step(st);
            sqlite3_finalize(st);
        }
        if (remaining)
            *remaining = maxretry;
        free(salt); free(ver); free(nonce); free(tag); free(wrapped);
        return SAR_OK;
    }

    zero_mem(ak, sizeof(ak));
    if (update_retry) {
        retry++;
        if (retry >= maxretry) {
            locked = 1;
            retry = maxretry;
        }
        char usql[256];
        snprintf(usql, sizeof(usql),
                 "UPDATE app SET %s=?,%s=? WHERE id=?", retry_col, locked_col);
        if (db_prepare(a->dev->db, usql, &st) == 0) {
            db_bind_int(st, 1, retry);
            db_bind_int(st, 2, locked);
            db_bind_int(st, 3, a->id);
            sqlite3_step(st);
            sqlite3_finalize(st);
        }
    }
    if (remaining)
        *remaining = maxretry - retry > 0 ? maxretry - retry : 0;
    free(salt); free(ver); free(nonce); free(tag); free(wrapped);
    return locked ? SAR_PIN_LOCKED : SAR_PIN_INCORRECT;
}

ULONG SKF_VerifyPIN(HAPPLICATION hApplication, ULONG ulPINType,
                    LPSTR szPIN, ULONG *pulRetryCount)
{
    SOFT_APP *a = (SOFT_APP *)hApplication;
    if (!a || a->type != SOFT_HANDLE_APP)
        return SAR_INVALIDHANDLEERR;
    int remaining = 0;
    ULONG rc = app_pin_check(a, ulPINType, szPIN, 1, &remaining);
    if (pulRetryCount)
        *pulRetryCount = (ULONG)remaining;
    return rc;
}

ULONG SKF_ChangePIN(HAPPLICATION hApplication, ULONG ulPINType,
                    LPSTR szOldPin, LPSTR szNewPin, ULONG *pulRetryCount)
{
    SOFT_APP *a = (SOFT_APP *)hApplication;
    if (!a || a->type != SOFT_HANDLE_APP)
        return SAR_INVALIDHANDLEERR;
    if (!szOldPin || !szNewPin)
        return SAR_INVALIDPARAMERR;
    if (strlen(szNewPin) == 0 || strlen(szNewPin) >= 128)
        return SAR_PIN_LEN_RANGE;

    int remaining = 0;
    ULONG rc = app_pin_check(a, ulPINType, szOldPin, 1, &remaining);
    if (pulRetryCount)
        *pulRetryCount = (ULONG)remaining;
    if (rc != SAR_OK)
        return rc;

    const char *salt_col, *ver_col, *nonce_col, *tag_col, *ak_col;
    const char *retry_col, *max_col, *locked_col, *default_col;
    if (pin_columns(ulPINType, &salt_col, &ver_col, &nonce_col, &tag_col,
                    &ak_col, &retry_col, &max_col, &locked_col,
                    &default_col) != 0)
        return SAR_USER_TYPE_INVALID;

    unsigned char salt[SOFTSKF_SALT_LEN], key[32], ver[32];
    unsigned char nonce[SOFTSKF_GCM_NONCE_LEN], wrapped[32], tag[16];
    if (rand_bytes(salt, sizeof(salt)) != 0)
        return SAR_GENRANDERR;
    if (derive_pin_key(szNewPin, salt, sizeof(salt), key) != 0 ||
        pin_verifier(key, ver) != 0)
        return SAR_FAIL;
    char aad[96];
    snprintf(aad, sizeof(aad), "app:%s:%s", a->name,
             ulPINType == ADMIN_TYPE ? "admin" : "user");
    if (wrap_with_key(key, aad, a->ak, 32, nonce, wrapped, tag) != 0)
        return SAR_FAIL;

    char sql[512];
    snprintf(sql, sizeof(sql),
             "UPDATE app SET %s=?,%s=?,%s=?,%s=?,%s=?,"
             "%s=0,%s=0,%s=0 WHERE id=?",
             salt_col, ver_col, nonce_col, tag_col, ak_col,
             retry_col, locked_col, default_col);
    sqlite3_stmt *st = NULL;
    if (db_prepare(a->dev->db, sql, &st) != 0)
        return SAR_FAIL;
    db_bind_blob(st, 1, salt, sizeof(salt));
    db_bind_blob(st, 2, ver, sizeof(ver));
    db_bind_blob(st, 3, nonce, sizeof(nonce));
    db_bind_blob(st, 4, tag, sizeof(tag));
    db_bind_blob(st, 5, wrapped, sizeof(wrapped));
    db_bind_int(st, 6, a->id);
    int rc2 = sqlite3_step(st);
    sqlite3_finalize(st);
    zero_mem(key, sizeof(key));
    if (pulRetryCount) {
        int maxretry = 6;
        app_max_retry(a, ulPINType, &maxretry);
        *pulRetryCount = (ULONG)maxretry;
    }
    return rc2 == SQLITE_DONE ? SAR_OK : SAR_FAIL;
}

ULONG SKF_UnblockPIN(HAPPLICATION hApplication, LPSTR szAdminPIN,
                     LPSTR szNewUserPIN, ULONG *pulRetryCount)
{
    SOFT_APP *a = (SOFT_APP *)hApplication;
    if (!a || a->type != SOFT_HANDLE_APP)
        return SAR_INVALIDHANDLEERR;
    if (!szAdminPIN || !szNewUserPIN)
        return SAR_INVALIDPARAMERR;
    if (!*szNewUserPIN)
        return SAR_PIN_LEN_RANGE;
    int remaining = 0;
    ULONG rc = app_pin_check(a, ADMIN_TYPE, szAdminPIN, 1, &remaining);
    if (pulRetryCount)
        *pulRetryCount = (ULONG)remaining;
    if (rc != SAR_OK)
        return rc;

    unsigned char salt[SOFTSKF_SALT_LEN], key[32], ver[32];
    unsigned char nonce[SOFTSKF_GCM_NONCE_LEN], wrapped[32], tag[16];
    if (rand_bytes(salt, sizeof(salt)) != 0)
        return SAR_GENRANDERR;
    if (derive_pin_key(szNewUserPIN, salt, sizeof(salt), key) != 0 ||
        pin_verifier(key, ver) != 0)
        return SAR_FAIL;
    char aad[96];
    snprintf(aad, sizeof(aad), "app:%s:user", a->name);
    if (wrap_with_key(key, aad, a->ak, 32, nonce, wrapped, tag) != 0)
        return SAR_FAIL;

    sqlite3_stmt *st = NULL;
    if (db_prepare(a->dev->db,
        "UPDATE app SET user_salt=?,user_verifier=?,user_nonce=?,user_tag=?,"
        "user_ak=?,user_retry=0,user_locked=0,default_user=0 WHERE id=?",
        &st) != 0)
        return SAR_FAIL;
    db_bind_blob(st, 1, salt, sizeof(salt));
    db_bind_blob(st, 2, ver, sizeof(ver));
    db_bind_blob(st, 3, nonce, sizeof(nonce));
    db_bind_blob(st, 4, tag, sizeof(tag));
    db_bind_blob(st, 5, wrapped, sizeof(wrapped));
    db_bind_int(st, 6, a->id);
    int rc2 = sqlite3_step(st);
    sqlite3_finalize(st);
    zero_mem(key, sizeof(key));
    if (pulRetryCount) {
        int maxretry = 6;
        app_max_retry(a, ADMIN_TYPE, &maxretry);
        *pulRetryCount = (ULONG)maxretry;
    }
    return rc2 == SQLITE_DONE ? SAR_OK : SAR_FAIL;
}

LONG SKF_GetPINInfo(HAPPLICATION hApplication, ULONG ulPINType,
                    ULONG *pulMaxRetryCount, ULONG *pulRemainRetryCount,
                    BOOL *pbDefaultPin)
{
    SOFT_APP *a = (SOFT_APP *)hApplication;
    if (!a || a->type != SOFT_HANDLE_APP)
        return SAR_INVALIDHANDLEERR;
    if (!pulMaxRetryCount || !pulRemainRetryCount || !pbDefaultPin)
        return SAR_INVALIDPARAMERR;

    const char *salt_col, *ver_col, *nonce_col, *tag_col, *ak_col;
    const char *retry_col, *max_col, *locked_col, *default_col;
    if (pin_columns(ulPINType, &salt_col, &ver_col, &nonce_col, &tag_col,
                    &ak_col, &retry_col, &max_col, &locked_col,
                    &default_col) != 0)
        return SAR_USER_TYPE_INVALID;

    char sql[256];
    snprintf(sql, sizeof(sql), "SELECT %s,%s,%s FROM app WHERE id=?",
             max_col, retry_col, default_col);
    sqlite3_stmt *st = NULL;
    if (db_prepare(a->dev->db, sql, &st) != 0)
        return SAR_FAIL;
    db_bind_int(st, 1, a->id);
    if (sqlite3_step(st) != SQLITE_ROW) {
        sqlite3_finalize(st);
        return SAR_APPLICATION_NOT_EXISTS;
    }
    int maxretry = sqlite3_column_int(st, 0);
    int retry = sqlite3_column_int(st, 1);
    int def = sqlite3_column_int(st, 2);
    sqlite3_finalize(st);
    if (maxretry <= 0)
        maxretry = 6;
    *pulMaxRetryCount = (ULONG)maxretry;
    *pulRemainRetryCount = (ULONG)(maxretry - retry > 0 ? maxretry - retry : 0);
    *pbDefaultPin = def ? TRUE : FALSE;
    return SAR_OK;
}

ULONG SKF_ClearSecureState(HAPPLICATION hApplication)
{
    SOFT_APP *a = (SOFT_APP *)hApplication;
    if (!a || a->type != SOFT_HANDLE_APP)
        return SAR_INVALIDHANDLEERR;
    zero_mem(a->ak, sizeof(a->ak));
    a->user_logged = 0;
    a->admin_logged = 0;
    return SAR_OK;
}

/* ------------------------------------------------------------------ */
/* Application files                                                   */
/* ------------------------------------------------------------------ */

static int app_logged(SOFT_APP *a)
{
    return a && (a->user_logged || a->admin_logged) &&
           a->type == SOFT_HANDLE_APP;
}

static int file_key(SOFT_APP *a, sqlite3_int64 id, unsigned char key[32])
{
    return object_key(a->ak, "file", id, key);
}

static int file_seal(SOFT_APP *a, sqlite3_int64 id,
                     const unsigned char *plain, size_t len,
                     unsigned char nonce[SOFTSKF_GCM_NONCE_LEN],
                     unsigned char *cipher, unsigned char tag[16])
{
    unsigned char key[32];
    if (file_key(a, id, key) != 0)
        return -1;
    if (rand_bytes(nonce, SOFTSKF_GCM_NONCE_LEN) != 0) {
        zero_mem(key, sizeof(key));
        return -1;
    }
    char aad[64];
    int n = snprintf(aad, sizeof(aad), "file:%lld", (long long)id);
    int rc = aes_gcm_seal(key, nonce, (const unsigned char *)aad,
                          (size_t)n, plain, len, cipher, tag);
    zero_mem(key, sizeof(key));
    return rc;
}

static int file_open(SOFT_APP *a, sqlite3_int64 id,
                     const unsigned char nonce[SOFTSKF_GCM_NONCE_LEN],
                     const unsigned char *cipher, size_t len,
                     const unsigned char tag[16], unsigned char *plain)
{
    unsigned char key[32];
    if (file_key(a, id, key) != 0)
        return -1;
    char aad[64];
    int n = snprintf(aad, sizeof(aad), "file:%lld", (long long)id);
    int rc = aes_gcm_open(key, nonce, (const unsigned char *)aad,
                          (size_t)n, cipher, len, tag, plain);
    zero_mem(key, sizeof(key));
    return rc;
}

static int file_lookup(SOFT_APP *a, const char *name,
                       sqlite3_int64 *id, sqlite3_int64 *size,
                       sqlite3_int64 *read_rights, sqlite3_int64 *write_rights,
                       unsigned char **nonce, int *noncelen,
                       unsigned char **cipher, int *cipherlen,
                       unsigned char **tag, int *taglen)
{
    if (id) *id = 0;
    if (size) *size = 0;
    if (read_rights) *read_rights = 0;
    if (write_rights) *write_rights = 0;
    if (nonce) { *nonce = NULL; *noncelen = 0; }
    if (cipher) { *cipher = NULL; *cipherlen = 0; }
    if (tag) { *tag = NULL; *taglen = 0; }

    sqlite3_stmt *st = NULL;
    if (db_prepare(a->dev->db,
        "SELECT id,size,read_rights,write_rights,nonce,tag,content "
        "FROM file WHERE app_id=? AND name=?", &st) != 0)
        return -1;
    db_bind_int(st, 1, a->id);
    db_bind_text(st, 2, name);
    if (sqlite3_step(st) != SQLITE_ROW) {
        sqlite3_finalize(st);
        return -1;
    }
    if (id) *id = sqlite3_column_int64(st, 0);
    if (size) *size = sqlite3_column_int64(st, 1);
    if (read_rights) *read_rights = sqlite3_column_int64(st, 2);
    if (write_rights) *write_rights = sqlite3_column_int64(st, 3);
    if (nonce) db_column_blob_dup(st, 4, nonce, noncelen);
    if (tag) db_column_blob_dup(st, 5, tag, taglen);
    if (cipher) db_column_blob_dup(st, 6, cipher, cipherlen);
    sqlite3_finalize(st);
    return 0;
}

ULONG SKF_CreateFile(HAPPLICATION hApplication, LPSTR szFileName,
                     ULONG ulFileSize, ULONG ulReadRights,
                     ULONG ulWriteRights)
{
    SOFT_APP *a = (SOFT_APP *)hApplication;
    if (!a || a->type != SOFT_HANDLE_APP)
        return SAR_INVALIDHANDLEERR;
    if (!app_logged(a))
        return SAR_USER_NOT_LOGGED_IN;
    if (!szFileName)
        return SAR_INVALIDPARAMERR;
    size_t nlen = strlen(szFileName);
    if (nlen == 0 || nlen >= MAX_FILE_NAME_SIZE)
        return SAR_NAMELENERR;
    if (ulFileSize > SOFTSKF_MAX_FILE_SIZE)
        return SAR_NO_ROOM;

    sqlite3_int64 oldid, oldsize;
    if (file_lookup(a, szFileName, &oldid, &oldsize, NULL, NULL,
                    NULL, NULL, NULL, NULL, NULL, NULL) == 0)
        return SAR_FILE_ALREADY_EXIST;

    unsigned char *plain = calloc(1, ulFileSize ? ulFileSize : 1);
    unsigned char *cipher = malloc(ulFileSize ? ulFileSize : 1);
    unsigned char nonce[SOFTSKF_GCM_NONCE_LEN], tag[16];
    if (!plain || !cipher || !ulFileSize) {
        free(plain); free(cipher);
        if (ulFileSize)
            return SAR_MEMORYERR;
    }
    if (ulFileSize > 0 &&
        file_seal(a, 0, plain, ulFileSize, nonce, cipher, tag) != 0) {
        free(plain); free(cipher);
        return SAR_FAIL;
    }
    /* The AAD uses the row id, which is not known until after insert.
     * Use a two-step transaction: insert with a zero content, then update. */
    free(plain); free(cipher);

    if (db_begin(a->dev->db) != 0)
        return SAR_FAIL;
    sqlite3_stmt *st = NULL;
    if (db_prepare(a->dev->db,
        "INSERT INTO file(app_id,name,size,read_rights,write_rights,"
        "nonce,tag,content,created_at) VALUES(?,?,?,?,?,?,?,?,?)",
        &st) != 0)
        goto fail;
    unsigned char znonce[SOFTSKF_GCM_NONCE_LEN] = {0};
    unsigned char ztag[16] = {0};
    unsigned char dummy = 0;
    db_bind_int(st, 1, a->id);
    db_bind_text(st, 2, szFileName);
    db_bind_int(st, 3, ulFileSize);
    db_bind_int(st, 4, ulReadRights);
    db_bind_int(st, 5, ulWriteRights);
    db_bind_blob(st, 6, znonce, sizeof(znonce));
    db_bind_blob(st, 7, ztag, sizeof(ztag));
    db_bind_blob(st, 8, &dummy, 0);
    db_bind_int(st, 9, (sqlite3_int64)time(NULL));
    if (sqlite3_step(st) != SQLITE_DONE) {
        sqlite3_finalize(st);
        goto fail;
    }
    sqlite3_finalize(st);

    sqlite3_int64 id = sqlite3_last_insert_rowid(a->dev->db);
    if (ulFileSize > 0) {
        plain = calloc(1, ulFileSize);
        cipher = malloc(ulFileSize);
        if (!plain || !cipher || file_seal(a, id, plain, ulFileSize,
                                           nonce, cipher, tag) != 0) {
            free(plain); free(cipher);
            goto fail;
        }
        if (db_prepare(a->dev->db,
            "UPDATE file SET nonce=?,tag=?,content=? WHERE id=?", &st) != 0) {
            free(plain); free(cipher);
            goto fail;
        }
        db_bind_blob(st, 1, nonce, sizeof(nonce));
        db_bind_blob(st, 2, tag, sizeof(tag));
        db_bind_blob(st, 3, cipher, (int)ulFileSize);
        db_bind_int(st, 4, id);
        int rc = sqlite3_step(st);
        sqlite3_finalize(st);
        free(plain); free(cipher);
        if (rc != SQLITE_DONE)
            goto fail;
    }
    if (db_commit(a->dev->db) != 0)
        return SAR_FAIL;
    return SAR_OK;

fail:
    db_rollback(a->dev->db);
    return SAR_FAIL;
}

ULONG SKF_DeleteFile(HAPPLICATION hApplication, LPSTR szFileName)
{
    SOFT_APP *a = (SOFT_APP *)hApplication;
    if (!a || a->type != SOFT_HANDLE_APP)
        return SAR_INVALIDHANDLEERR;
    if (!app_logged(a))
        return SAR_USER_NOT_LOGGED_IN;
    if (!szFileName)
        return SAR_INVALIDPARAMERR;
    sqlite3_int64 id;
    if (file_lookup(a, szFileName, &id, NULL, NULL, NULL, NULL, NULL,
                    NULL, NULL, NULL, NULL) != 0)
        return SAR_FILE_NOT_EXIST;
    sqlite3_stmt *st = NULL;
    if (db_prepare(a->dev->db, "DELETE FROM file WHERE id=?", &st) != 0)
        return SAR_FAIL;
    db_bind_int(st, 1, id);
    int rc = sqlite3_step(st);
    sqlite3_finalize(st);
    return rc == SQLITE_DONE ? SAR_OK : SAR_FAIL;
}

ULONG SKF_EnumFiles(HAPPLICATION hApplication, LPSTR szFileList,
                    ULONG *pulSize)
{
    SOFT_APP *a = (SOFT_APP *)hApplication;
    if (!a || a->type != SOFT_HANDLE_APP || !pulSize)
        return SAR_INVALIDPARAMERR;
    sqlite3_stmt *st = NULL;
    if (db_prepare(a->dev->db,
        "SELECT name FROM file WHERE app_id=? ORDER BY id", &st) != 0)
        return SAR_FAIL;
    db_bind_int(st, 1, a->id);
    int need = 1;
    while (sqlite3_step(st) == SQLITE_ROW) {
        const unsigned char *p = sqlite3_column_text(st, 0);
        if (p)
            need += (int)strlen((const char *)p) + 1;
    }
    sqlite3_finalize(st);
    if (!szFileList) {
        *pulSize = (ULONG)need;
        return SAR_OK;
    }
    if (*pulSize < (ULONG)need) {
        *pulSize = (ULONG)need;
        return SAR_BUFFER_TOO_SMALL;
    }
    if (db_prepare(a->dev->db,
        "SELECT name FROM file WHERE app_id=? ORDER BY id", &st) != 0)
        return SAR_FAIL;
    db_bind_int(st, 1, a->id);
    char *p = szFileList;
    while (sqlite3_step(st) == SQLITE_ROW) {
        const unsigned char *name = sqlite3_column_text(st, 0);
        if (!name)
            continue;
        size_t n = strlen((const char *)name) + 1;
        memcpy(p, name, n);
        p += n;
    }
    *p = '\0';
    sqlite3_finalize(st);
    *pulSize = (ULONG)need;
    return SAR_OK;
}

ULONG SKF_GetFileInfo(HAPPLICATION hApplication, LPSTR szFileName,
                      FILEATTRIBUTE *pFileInfo)
{
    SOFT_APP *a = (SOFT_APP *)hApplication;
    if (!a || a->type != SOFT_HANDLE_APP || !szFileName || !pFileInfo)
        return SAR_INVALIDPARAMERR;
    sqlite3_int64 id, size, rr, wr;
    if (file_lookup(a, szFileName, &id, &size, &rr, &wr, NULL, NULL,
                    NULL, NULL, NULL, NULL) != 0)
        return SAR_FILE_NOT_EXIST;
    memset(pFileInfo, 0, sizeof(*pFileInfo));
    snprintf(pFileInfo->FileName, sizeof(pFileInfo->FileName), "%s",
             szFileName);
    pFileInfo->FileSize = (ULONG)size;
    pFileInfo->ReadRights = (ULONG)rr;
    pFileInfo->WriteRights = (ULONG)wr;
    return SAR_OK;
}

ULONG SKF_ReadFile(HAPPLICATION hApplication, LPSTR szFileName,
                   ULONG ulOffset, ULONG ulSize, BYTE *pbOutData,
                   ULONG *pulOutLen)
{
    SOFT_APP *a = (SOFT_APP *)hApplication;
    if (!a || a->type != SOFT_HANDLE_APP)
        return SAR_INVALIDHANDLEERR;
    if (!app_logged(a))
        return SAR_USER_NOT_LOGGED_IN;
    if (!szFileName || !pulOutLen || (!pbOutData && ulSize))
        return SAR_INVALIDPARAMERR;

    sqlite3_int64 id, size;
    unsigned char *nonce = NULL, *cipher = NULL, *tag = NULL;
    int noncelen = 0, cipherlen = 0, taglen = 0;
    if (file_lookup(a, szFileName, &id, &size, NULL, NULL,
                    &nonce, &noncelen, &cipher, &cipherlen,
                    &tag, &taglen) != 0)
        return SAR_FILE_NOT_EXIST;
    if (ulOffset > (ULONG)size || noncelen != SOFTSKF_GCM_NONCE_LEN ||
        taglen != SOFTSKF_GCM_TAG_LEN || cipherlen != (int)size) {
        free(nonce); free(cipher); free(tag);
        return SAR_READFILEERR;
    }
    unsigned char *plain = malloc(size ? (size_t)size : 1);
    if (!plain) {
        free(nonce); free(cipher); free(tag);
        return SAR_MEMORYERR;
    }
    if (size > 0 &&
        file_open(a, id, nonce, cipher, (size_t)size, tag, plain) != 0) {
        free(plain); free(nonce); free(cipher); free(tag);
        return SAR_READFILEERR;
    }
    ULONG avail = (ULONG)size - ulOffset;
    ULONG n = ulSize < avail ? ulSize : avail;
    if (*pulOutLen < n) {
        *pulOutLen = n;
        free(plain); free(nonce); free(cipher); free(tag);
        return SAR_BUFFER_TOO_SMALL;
    }
    if (n)
        memcpy(pbOutData, plain + ulOffset, n);
    *pulOutLen = n;
    free(plain); free(nonce); free(cipher); free(tag);
    return SAR_OK;
}

ULONG SKF_WriteFile(HAPPLICATION hApplication, LPSTR szFileName,
                    ULONG ulOffset, BYTE *pbData, ULONG ulSize)
{
    SOFT_APP *a = (SOFT_APP *)hApplication;
    if (!a || a->type != SOFT_HANDLE_APP)
        return SAR_INVALIDHANDLEERR;
    if (!app_logged(a))
        return SAR_USER_NOT_LOGGED_IN;
    if (!szFileName || (!pbData && ulSize))
        return SAR_INVALIDPARAMERR;

    sqlite3_int64 id, size;
    unsigned char *nonce = NULL, *cipher = NULL, *tag = NULL;
    int noncelen = 0, cipherlen = 0, taglen = 0;
    if (file_lookup(a, szFileName, &id, &size, NULL, NULL,
                    &nonce, &noncelen, &cipher, &cipherlen,
                    &tag, &taglen) != 0)
        return SAR_FILE_NOT_EXIST;
    if ((sqlite3_int64)ulOffset + ulSize > size ||
        noncelen != SOFTSKF_GCM_NONCE_LEN ||
        taglen != SOFTSKF_GCM_TAG_LEN || cipherlen != (int)size) {
        free(nonce); free(cipher); free(tag);
        return SAR_WRITEFILEERR;
    }
    unsigned char *plain = calloc(1, size ? (size_t)size : 1);
    if (!plain) {
        free(nonce); free(cipher); free(tag);
        return SAR_MEMORYERR;
    }
    if (size > 0 &&
        file_open(a, id, nonce, cipher, (size_t)size, tag, plain) != 0) {
        free(plain); free(nonce); free(cipher); free(tag);
        return SAR_WRITEFILEERR;
    }
    if (ulSize)
        memcpy(plain + ulOffset, pbData, ulSize);
    if (size > 0) {
        unsigned char nnonce[SOFTSKF_GCM_NONCE_LEN], ntag[16];
        unsigned char *ncipher = malloc((size_t)size);
        if (!ncipher || file_seal(a, id, plain, (size_t)size, nnonce,
                                  ncipher, ntag) != 0) {
            free(ncipher); free(plain); free(nonce); free(cipher); free(tag);
            return SAR_FAIL;
        }
        sqlite3_stmt *st = NULL;
        if (db_prepare(a->dev->db,
            "UPDATE file SET nonce=?,tag=?,content=? WHERE id=?", &st) != 0) {
            free(ncipher); free(plain); free(nonce); free(cipher); free(tag);
            return SAR_FAIL;
        }
        db_bind_blob(st, 1, nnonce, sizeof(nnonce));
        db_bind_blob(st, 2, ntag, sizeof(ntag));
        db_bind_blob(st, 3, ncipher, (int)size);
        db_bind_int(st, 4, id);
        int rc = sqlite3_step(st);
        sqlite3_finalize(st);
        free(ncipher);
        if (rc != SQLITE_DONE) {
            free(plain); free(nonce); free(cipher); free(tag);
            return SAR_WRITEFILEERR;
        }
    }
    free(plain); free(nonce); free(cipher); free(tag);
    return SAR_OK;
}

/* ------------------------------------------------------------------ */
/* Containers                                                          */
/* ------------------------------------------------------------------ */

static int ctn_lookup(SOFT_APP *a, const char *name, sqlite3_int64 *id,
                      int *ctype, int *bits, unsigned char **pub, int *publen)
{
    *id = 0; *ctype = 0; *bits = 0;
    if (pub) { *pub = NULL; *publen = 0; }
    sqlite3_stmt *st = NULL;
    if (db_prepare(a->dev->db,
        "SELECT id,ctype,bits,pub_blob FROM container WHERE app_id=? AND name=?",
        &st) != 0)
        return -1;
    db_bind_int(st, 1, a->id);
    db_bind_text(st, 2, name);
    if (sqlite3_step(st) != SQLITE_ROW) {
        sqlite3_finalize(st);
        return -1;
    }
    *id = sqlite3_column_int64(st, 0);
    *ctype = sqlite3_column_int(st, 1);
    *bits = sqlite3_column_int(st, 2);
    if (pub)
        db_column_blob_dup(st, 3, pub, publen);
    sqlite3_finalize(st);
    return 0;
}

ULONG SKF_CreateContainer(HAPPLICATION hApplication, LPSTR szContainerName,
                          HCONTAINER *phContainer)
{
    SOFT_APP *a = (SOFT_APP *)hApplication;
    if (!a || a->type != SOFT_HANDLE_APP)
        return SAR_INVALIDHANDLEERR;
    if (!app_logged(a))
        return SAR_USER_NOT_LOGGED_IN;
    if (!szContainerName || !phContainer)
        return SAR_INVALIDPARAMERR;
    size_t nlen = strlen(szContainerName);
    if (nlen == 0 || nlen >= MAX_FILE_CONTAINER_NAME_SIZE)
        return SAR_NAMELENERR;

    sqlite3_int64 id; int ctype, bits;
    if (ctn_lookup(a, szContainerName, &id, &ctype, &bits, NULL, NULL) == 0)
        return SAR_FILE_ALREADY_EXIST;

    sqlite3_stmt *cnt = NULL;
    if (db_prepare(a->dev->db,
        "SELECT COUNT(*) FROM container WHERE app_id=?", &cnt) == 0 &&
        sqlite3_step(cnt) == SQLITE_ROW &&
        sqlite3_column_int64(cnt, 0) >= SOFTSKF_MAX_CONTAINERS) {
        sqlite3_finalize(cnt);
        return SAR_REACH_MAX_CONTAINER_COUNT;
    }
    sqlite3_finalize(cnt);

    sqlite3_stmt *st = NULL;
    if (db_prepare(a->dev->db,
        "INSERT INTO container(app_id,name,ctype,bits,created_at)"
        " VALUES(?,?,0,0,?)", &st) != 0)
        return SAR_FAIL;
    db_bind_int(st, 1, a->id);
    db_bind_text(st, 2, szContainerName);
    db_bind_int(st, 3, (sqlite3_int64)time(NULL));
    int rc = sqlite3_step(st);
    sqlite3_finalize(st);
    if (rc != SQLITE_DONE)
        return SAR_FAIL;

    SOFT_CTN *c = calloc(1, sizeof(*c));
    if (!c)
        return SAR_MEMORYERR;
    c->type = SOFT_HANDLE_CTN;
    c->app = a;
    c->id = sqlite3_last_insert_rowid(a->dev->db);
    c->ctype = 0;
    snprintf(c->name, sizeof(c->name), "%s", szContainerName);
    *phContainer = (HCONTAINER)c;
    return SAR_OK;
}

ULONG SKF_DeleteContainer(HAPPLICATION hApplication, LPSTR szContainerName)
{
    SOFT_APP *a = (SOFT_APP *)hApplication;
    if (!a || a->type != SOFT_HANDLE_APP)
        return SAR_INVALIDHANDLEERR;
    if (!app_logged(a))
        return SAR_USER_NOT_LOGGED_IN;
    if (!szContainerName)
        return SAR_INVALIDPARAMERR;
    sqlite3_int64 id; int ctype, bits;
    if (ctn_lookup(a, szContainerName, &id, &ctype, &bits, NULL, NULL) != 0)
        return SAR_FILE_NOT_EXIST;
    sqlite3_stmt *st = NULL;
    if (db_prepare(a->dev->db, "DELETE FROM container WHERE id=?", &st) != 0)
        return SAR_FAIL;
    db_bind_int(st, 1, id);
    int rc = sqlite3_step(st);
    sqlite3_finalize(st);
    return rc == SQLITE_DONE ? SAR_OK : SAR_FAIL;
}

ULONG SKF_OpenContainer(HAPPLICATION hApplication, LPSTR szContainerName,
                        HCONTAINER *phContainer)
{
    SOFT_APP *a = (SOFT_APP *)hApplication;
    if (!a || a->type != SOFT_HANDLE_APP || !szContainerName || !phContainer)
        return SAR_INVALIDPARAMERR;

    sqlite3_int64 id; int ctype, bits, publen = 0;
    unsigned char *pub = NULL;
    if (ctn_lookup(a, szContainerName, &id, &ctype, &bits, &pub, &publen) != 0)
        return SAR_FILE_NOT_EXIST;

    SOFT_CTN *c = calloc(1, sizeof(*c));
    if (!c) {
        free(pub);
        return SAR_MEMORYERR;
    }
    c->type = SOFT_HANDLE_CTN;
    c->app = a;
    c->id = id;
    c->ctype = ctype;
    c->bits = bits;
    snprintf(c->name, sizeof(c->name), "%s", szContainerName);
    if (pub && publen > 0 && publen <= (int)sizeof(c->pub_blob)) {
        memcpy(c->pub_blob, pub, (size_t)publen);
        c->pub_len = publen;
    }
    free(pub);
    *phContainer = (HCONTAINER)c;
    return SAR_OK;
}

ULONG SKF_CloseContainer(HCONTAINER hContainer)
{
    SOFT_CTN *c = (SOFT_CTN *)hContainer;
    if (!c || c->type != SOFT_HANDLE_CTN)
        return SAR_INVALIDHANDLEERR;
    free(c);
    return SAR_OK;
}

ULONG SKF_EnumContainer(HAPPLICATION hApplication, LPSTR szContainerName,
                        ULONG *pulSize)
{
    SOFT_APP *a = (SOFT_APP *)hApplication;
    if (!a || a->type != SOFT_HANDLE_APP || !pulSize)
        return SAR_INVALIDPARAMERR;
    sqlite3_stmt *st = NULL;
    if (db_prepare(a->dev->db,
        "SELECT name FROM container WHERE app_id=? ORDER BY id", &st) != 0)
        return SAR_FAIL;
    db_bind_int(st, 1, a->id);
    int need = 1;
    while (sqlite3_step(st) == SQLITE_ROW) {
        const unsigned char *p = sqlite3_column_text(st, 0);
        if (p)
            need += (int)strlen((const char *)p) + 1;
    }
    sqlite3_finalize(st);
    if (!szContainerName) {
        *pulSize = (ULONG)need;
        return SAR_OK;
    }
    if (*pulSize < (ULONG)need) {
        *pulSize = (ULONG)need;
        return SAR_BUFFER_TOO_SMALL;
    }
    if (db_prepare(a->dev->db,
        "SELECT name FROM container WHERE app_id=? ORDER BY id", &st) != 0)
        return SAR_FAIL;
    db_bind_int(st, 1, a->id);
    char *p = szContainerName;
    while (sqlite3_step(st) == SQLITE_ROW) {
        const unsigned char *name = sqlite3_column_text(st, 0);
        if (!name)
            continue;
        size_t n = strlen((const char *)name) + 1;
        memcpy(p, name, n);
        p += n;
    }
    *p = '\0';
    sqlite3_finalize(st);
    *pulSize = (ULONG)need;
    return SAR_OK;
}

ULONG SKF_GetContainerType(HCONTAINER hContainer, ULONG *pulContainerType)
{
    SOFT_CTN *c = (SOFT_CTN *)hContainer;
    if (!c || c->type != SOFT_HANDLE_CTN || !pulContainerType)
        return SAR_INVALIDPARAMERR;
    *pulContainerType = (ULONG)c->ctype;
    return SAR_OK;
}

static int ctn_store_blob(SOFT_CTN *c, const char *column,
                          const unsigned char *data, size_t len)
{
    char sql[256];
    snprintf(sql, sizeof(sql), "UPDATE container SET %s=? WHERE id=?", column);
    sqlite3_stmt *st = NULL;
    if (db_prepare(c->app->dev->db, sql, &st) != 0)
        return -1;
    db_bind_blob(st, 1, data, (int)len);
    db_bind_int(st, 2, c->id);
    int rc = sqlite3_step(st);
    sqlite3_finalize(st);
    return rc == SQLITE_DONE ? 0 : -1;
}

static int ctn_store_private(SOFT_CTN *c, const unsigned char *data,
                             size_t len)
{
    if (!c || !c->app || !c->app->ak[0])
        return -1;
    unsigned char key[32];
    if (object_key(c->app->ak, "container-priv", c->id, key) != 0)
        return -1;
    unsigned char nonce[SOFTSKF_GCM_NONCE_LEN], tag[16];
    unsigned char *cipher = malloc(len ? len : 1);
    if (!cipher) {
        zero_mem(key, sizeof(key));
        return -1;
    }
    char aad[64];
    int n = snprintf(aad, sizeof(aad), "container:%lld", (long long)c->id);
    int rc = -1;
    if (rand_bytes(nonce, sizeof(nonce)) == 0 &&
        aes_gcm_seal(key, nonce, (const unsigned char *)aad, (size_t)n,
                     data, len, cipher, tag) == 0) {
        sqlite3_stmt *st = NULL;
        if (db_prepare(c->app->dev->db,
            "UPDATE container SET priv_nonce=?,priv_tag=?,priv_blob=? WHERE id=?",
            &st) == 0) {
            db_bind_blob(st, 1, nonce, sizeof(nonce));
            db_bind_blob(st, 2, tag, sizeof(tag));
            db_bind_blob(st, 3, cipher, (int)len);
            db_bind_int(st, 4, c->id);
            rc = sqlite3_step(st) == SQLITE_DONE ? 0 : -1;
            sqlite3_finalize(st);
        }
    }
    zero_mem(key, sizeof(key));
    free(cipher);
    return rc;
}

static int ctn_load_private(SOFT_CTN *c, unsigned char **out, int *outlen)
{
    *out = NULL;
    *outlen = 0;
    if (!c || !c->app || !c->app->ak[0])
        return -1;
    sqlite3_stmt *st = NULL;
    if (db_prepare(c->app->dev->db,
        "SELECT priv_nonce,priv_tag,priv_blob FROM container WHERE id=?",
        &st) != 0)
        return -1;
    db_bind_int(st, 1, c->id);
    if (sqlite3_step(st) != SQLITE_ROW) {
        sqlite3_finalize(st);
        return -1;
    }
    unsigned char *nonce = NULL, *tag = NULL, *cipher = NULL;
    int noncelen = 0, taglen = 0, cipherlen = 0;
    db_column_blob_dup(st, 0, &nonce, &noncelen);
    db_column_blob_dup(st, 1, &tag, &taglen);
    db_column_blob_dup(st, 2, &cipher, &cipherlen);
    sqlite3_finalize(st);
    if (noncelen != SOFTSKF_GCM_NONCE_LEN || taglen != 16 || cipherlen <= 0) {
        free(nonce); free(tag); free(cipher);
        return -1;
    }
    unsigned char *plain = malloc((size_t)cipherlen);
    unsigned char key[32];
    if (!plain || object_key(c->app->ak, "container-priv", c->id, key) != 0) {
        free(plain); free(nonce); free(tag); free(cipher);
        return -1;
    }
    char aad[64];
    int n = snprintf(aad, sizeof(aad), "container:%lld", (long long)c->id);
    int rc = aes_gcm_open(key, nonce, (const unsigned char *)aad, (size_t)n,
                          cipher, (size_t)cipherlen, tag, plain);
    zero_mem(key, sizeof(key));
    free(nonce); free(tag); free(cipher);
    if (rc != 0) {
        free(plain);
        return -1;
    }
    *out = plain;
    *outlen = cipherlen;
    return 0;
}

/* ------------------------------------------------------------------ */
/* Symmetric ciphers                                                   */
/* ------------------------------------------------------------------ */

static int sym_valid_alg(ULONG alg)
{
    switch (alg) {
    case SGD_SM4_ECB:
    case SGD_SM4_CBC:
    case SGD_SM4_CFB:
    case SGD_SM4_OFB:
    case SGD_SM4_MAC:
        return 1;
    default:
        return 0;
    }
}

static ULONG sym_init_ctx(SOFT_SYM *s, int enc)
{
    if (!s || s->type != SOFT_HANDLE_SYM)
        return SAR_INVALIDHANDLEERR;
    if (s->is_mac)
        return SAR_INVALIDPARAMERR;
    if (s->ctx) {
        EVP_CIPHER_CTX_free(s->ctx);
        s->ctx = NULL;
    }
    const EVP_CIPHER *cipher = cipher_for_alg(s->alg);
    if (!cipher)
        return SAR_NOTSUPPORTYETERR;
    s->ctx = EVP_CIPHER_CTX_new();
    if (!s->ctx)
        return SAR_MEMORYERR;
    int padding = s->param.PaddingType ? 1 : 0;
    if (s->alg == SGD_SM4_CFB || s->alg == SGD_SM4_OFB)
        padding = s->param.PaddingType ? 1 : 0;
    int ok;
    if (enc)
        ok = EVP_EncryptInit_ex(s->ctx, cipher, NULL, s->key,
                                (s->alg == SGD_SM4_ECB) ? NULL : s->param.IV);
    else
        ok = EVP_DecryptInit_ex(s->ctx, cipher, NULL, s->key,
                                (s->alg == SGD_SM4_ECB) ? NULL : s->param.IV);
    if (ok != 1 || EVP_CIPHER_CTX_set_padding(s->ctx, padding) != 1) {
        EVP_CIPHER_CTX_free(s->ctx);
        s->ctx = NULL;
        return SAR_FAIL;
    }
    s->initialized = 1;
    s->enc = enc;
    return SAR_OK;
}

ULONG SKF_SetSymmKey(DEVHANDLE hDev, BYTE *pbKey, ULONG ulAlgID,
                     HANDLE *phKey)
{
    SOFT_DEV *d = (SOFT_DEV *)hDev;
    if (!d || d->type != SOFT_HANDLE_DEV || !pbKey || !phKey)
        return SAR_INVALIDPARAMERR;
    if (!sym_valid_alg(ulAlgID))
        return SAR_NOTSUPPORTYETERR;

    SOFT_SYM *s = calloc(1, sizeof(*s));
    if (!s)
        return SAR_MEMORYERR;
    s->type = SOFT_HANDLE_SYM;
    s->dev = d;
    s->alg = ulAlgID;
    s->keylen = 16;
    s->is_mac = (ulAlgID == SGD_SM4_MAC);
    memcpy(s->key, pbKey, 16);
    *phKey = (HANDLE)s;
    return SAR_OK;
}

ULONG SKF_ImportSessionKey(HCONTAINER hContainer, ULONG ulAlgId,
                           BYTE *pbWrapedData, ULONG ulWrapedLen,
                           HANDLE *phKey)
{
    SOFT_CTN *c = (SOFT_CTN *)hContainer;
    if (!c || c->type != SOFT_HANDLE_CTN || !phKey)
        return SAR_INVALIDHANDLEERR;
    if (!c->app || !c->app->user_logged)
        return SAR_USER_NOT_LOGGED_IN;
    if (!pbWrapedData || !ulWrapedLen)
        return SAR_INVALIDPARAMERR;
    if (!sym_valid_alg(ulAlgId))
        return SAR_NOTSUPPORTYETERR;
    if (ulWrapedLen != 16)
        return SAR_INVALIDPARAMERR;
    SOFT_SYM *s = calloc(1, sizeof(*s));
    if (!s)
        return SAR_MEMORYERR;
    s->type = SOFT_HANDLE_SYM;
    s->dev = c->app->dev;
    s->alg = ulAlgId;
    s->keylen = 16;
    s->is_mac = (ulAlgId == SGD_SM4_MAC);
    memcpy(s->key, pbWrapedData, 16);
    *phKey = (HANDLE)s;
    return SAR_OK;
}

ULONG SKF_EncryptInit(HANDLE hKey, BLOCKCIPHERPARAM EncryptParam)
{
    SOFT_SYM *s = (SOFT_SYM *)hKey;
    if (!s || s->type != SOFT_HANDLE_SYM || s->is_mac)
        return SAR_INVALIDHANDLEERR;
    if (EncryptParam.IVLen > MAX_IV_LEN)
        return SAR_INVALIDPARAMERR;
    if (s->alg == SGD_SM4_CFB && EncryptParam.FeedBitLen != 0 &&
        EncryptParam.FeedBitLen != 128)
        return SAR_NOTSUPPORTYETERR;
    s->param = EncryptParam;
    s->enc = 1;
    s->initialized = 1;
    free(s->buf);
    s->buf = NULL;
    s->buflen = 0;
    return SAR_OK;
}

ULONG SKF_DecryptInit(HANDLE hKey, BLOCKCIPHERPARAM DecryptParam)
{
    SOFT_SYM *s = (SOFT_SYM *)hKey;
    if (!s || s->type != SOFT_HANDLE_SYM || s->is_mac)
        return SAR_INVALIDHANDLEERR;
    if (DecryptParam.IVLen > MAX_IV_LEN)
        return SAR_INVALIDPARAMERR;
    if (s->alg == SGD_SM4_CFB && DecryptParam.FeedBitLen != 0 &&
        DecryptParam.FeedBitLen != 128)
        return SAR_NOTSUPPORTYETERR;
    s->param = DecryptParam;
    s->enc = 0;
    s->initialized = 1;
    free(s->buf);
    s->buf = NULL;
    s->buflen = 0;
    return SAR_OK;
}

static ULONG sym_one_shot(SOFT_SYM *s, int enc, BYTE *in, ULONG inlen,
                          BYTE *out, ULONG *outlen)
{
    if (!s || !outlen)
        return SAR_INVALIDPARAMERR;
    unsigned char *tmp = NULL;
    ULONG result;
    if (enc && !s->param.PaddingType && (inlen % 16) != 0) {
        size_t plen = ((size_t)inlen + 15) & ~(size_t)15;
        tmp = calloc(1, plen);
        if (!tmp)
            return SAR_MEMORYERR;
        if (inlen)
            memcpy(tmp, in, inlen);
        in = tmp;
        inlen = (ULONG)plen;
    }
    result = sym_init_ctx(s, enc);
    if (result != SAR_OK)
        goto out;
    int n = 0, total = 0;
    int ok;
    if (inlen > 0x7fffffff) {
        result = SAR_INDATALENERR;
        goto out;
    }
    if (enc)
        ok = EVP_EncryptUpdate(s->ctx, out, &n, in, (int)inlen);
    else
        ok = EVP_DecryptUpdate(s->ctx, out, &n, in, (int)inlen);
    if (ok != 1) {
        result = SAR_FAIL;
        goto out;
    }
    total = n;
    if (enc)
        ok = EVP_EncryptFinal_ex(s->ctx, out + total, &n);
    else
        ok = EVP_DecryptFinal_ex(s->ctx, out + total, &n);
    if (ok != 1) {
        result = enc ? SAR_FAIL : SAR_DECRYPTPADERR;
        goto out;
    }
    total += n;
    *outlen = (ULONG)total;
    result = SAR_OK;
out:
    if (s->ctx) {
        EVP_CIPHER_CTX_free(s->ctx);
        s->ctx = NULL;
    }
    s->initialized = 0;
    free(tmp);
    return result;
}

ULONG SKF_Encrypt(HANDLE hKey, BYTE *pbData, ULONG ulDataLen,
                  BYTE *pbEncryptedData, ULONG *pulEncryptedLen)
{
    SOFT_SYM *s = (SOFT_SYM *)hKey;
    if (!s || s->type != SOFT_HANDLE_SYM || s->is_mac)
        return SAR_INVALIDHANDLEERR;
    if (!pbData || !pbEncryptedData || !pulEncryptedLen)
        return SAR_INVALIDPARAMERR;
    return sym_one_shot(s, 1, pbData, ulDataLen, pbEncryptedData,
                        pulEncryptedLen);
}

ULONG SKF_Decrypt(HANDLE hKey, BYTE *pbEncryptedData, ULONG ulEncryptedLen,
                  BYTE *pbData, ULONG *pulDataLen)
{
    SOFT_SYM *s = (SOFT_SYM *)hKey;
    if (!s || s->type != SOFT_HANDLE_SYM || s->is_mac)
        return SAR_INVALIDHANDLEERR;
    if (!pbEncryptedData || !pbData || !pulDataLen)
        return SAR_INVALIDPARAMERR;
    return sym_one_shot(s, 0, pbEncryptedData, ulEncryptedLen, pbData,
                        pulDataLen);
}

ULONG SKF_EncryptUpdate(HANDLE hKey, BYTE *pbData, ULONG ulDataLen,
                        BYTE *pbEncryptedData, ULONG *pulEncryptedLen)
{
    SOFT_SYM *s = (SOFT_SYM *)hKey;
    if (!s || s->type != SOFT_HANDLE_SYM || s->is_mac)
        return SAR_INVALIDHANDLEERR;
    if (!pbData && ulDataLen)
        return SAR_INVALIDPARAMERR;
    if (!s->initialized) {
        s->param.PaddingType = 0;
        s->enc = 1;
        s->initialized = 1;
    }
    if (ulDataLen) {
        unsigned char *nb = realloc(s->buf, s->buflen + ulDataLen);
        if (!nb)
            return SAR_MEMORYERR;
        s->buf = nb;
        memcpy(s->buf + s->buflen, pbData, ulDataLen);
        s->buflen += ulDataLen;
    }
    (void)pbEncryptedData;
    if (pulEncryptedLen)
        *pulEncryptedLen = 0;
    return SAR_OK;
}

ULONG SKF_EncryptFinal(HANDLE hKey, BYTE *pbEncryptedData,
                       ULONG *pulEncryptedDataLen)
{
    SOFT_SYM *s = (SOFT_SYM *)hKey;
    if (!s || s->type != SOFT_HANDLE_SYM || s->is_mac)
        return SAR_INVALIDHANDLEERR;
    if (!pulEncryptedDataLen)
        return SAR_INVALIDPARAMERR;
    if (!s->initialized) {
        s->param.PaddingType = 0;
        s->enc = 1;
        s->initialized = 1;
    }
    ULONG rc = SAR_OK;
    if (s->buflen > 0) {
        rc = sym_one_shot(s, 1, s->buf, (ULONG)s->buflen,
                          pbEncryptedData, pulEncryptedDataLen);
    } else {
        *pulEncryptedDataLen = 0;
    }
    free(s->buf);
    s->buf = NULL;
    s->buflen = 0;
    return rc;
}

ULONG SKF_DecryptUpdate(HANDLE hKey, BYTE *pbEncryptedData,
                        ULONG ulEncryptedLen, BYTE *pbData,
                        ULONG *pulDataLen)
{
    SOFT_SYM *s = (SOFT_SYM *)hKey;
    if (!s || s->type != SOFT_HANDLE_SYM || s->is_mac)
        return SAR_INVALIDHANDLEERR;
    if (!pbEncryptedData && ulEncryptedLen)
        return SAR_INVALIDPARAMERR;
    if (!s->initialized) {
        s->param.PaddingType = 0;
        s->enc = 0;
        s->initialized = 1;
    }
    if (ulEncryptedLen) {
        unsigned char *nb = realloc(s->buf, s->buflen + ulEncryptedLen);
        if (!nb)
            return SAR_MEMORYERR;
        s->buf = nb;
        memcpy(s->buf + s->buflen, pbEncryptedData, ulEncryptedLen);
        s->buflen += ulEncryptedLen;
    }
    (void)pbData;
    if (pulDataLen)
        *pulDataLen = 0;
    return SAR_OK;
}

ULONG SKF_DecryptFinal(HANDLE hKey, BYTE *pbDecryptedData,
                       ULONG *pulDecryptedDataLen)
{
    SOFT_SYM *s = (SOFT_SYM *)hKey;
    if (!s || s->type != SOFT_HANDLE_SYM || s->is_mac)
        return SAR_INVALIDHANDLEERR;
    if (!pulDecryptedDataLen)
        return SAR_INVALIDPARAMERR;
    if (!s->initialized) {
        s->param.PaddingType = 0;
        s->enc = 0;
        s->initialized = 1;
    }
    ULONG rc = SAR_OK;
    if (s->buflen > 0) {
        rc = sym_one_shot(s, 0, s->buf, (ULONG)s->buflen,
                          pbDecryptedData, pulDecryptedDataLen);
    } else {
        *pulDecryptedDataLen = 0;
    }
    free(s->buf);
    s->buf = NULL;
    s->buflen = 0;
    return rc;
}

/* ------------------------------------------------------------------ */
/* Hash                                                                */
/* ------------------------------------------------------------------ */

static const EVP_MD *digest_md(ULONG alg)
{
    ULONG base = alg & SGD_HASH_TO;
    if (base == SGD_SM3)
        return EVP_sm3();
    if (base == SGD_SHA1)
        return EVP_sha1();
    if (base == SGD_SHA256)
        return EVP_sha256();
    return NULL;
}

ULONG SKF_DigestInit(DEVHANDLE hDev, ULONG ulAlgID,
                     ECCPUBLICKEYBLOB *pPubKey, BYTE *pbID, ULONG ulIDLen,
                     HANDLE *phHash)
{
    SOFT_DEV *d = (SOFT_DEV *)hDev;
    (void)pPubKey; (void)pbID; (void)ulIDLen;
    if (!d || d->type != SOFT_HANDLE_DEV || !phHash)
        return SAR_INVALIDPARAMERR;
    const EVP_MD *md = digest_md(ulAlgID);
    if (!md)
        return SAR_NOTSUPPORTYETERR;
    SOFT_HASH *h = calloc(1, sizeof(*h));
    if (!h)
        return SAR_MEMORYERR;
    h->type = SOFT_HANDLE_HASH;
    h->md = md;
    h->ctx = EVP_MD_CTX_new();
    if (!h->ctx || EVP_DigestInit_ex(h->ctx, md, NULL) != 1) {
        EVP_MD_CTX_free(h->ctx);
        free(h);
        return SAR_FAIL;
    }
    *phHash = (HANDLE)h;
    return SAR_OK;
}

ULONG SKF_Digest(HANDLE hHash, BYTE *pbData, ULONG ulDataLen,
                 BYTE *pbHashData, ULONG *pulHashLen)
{
    SOFT_HASH *h = (SOFT_HASH *)hHash;
    if (!h || h->type != SOFT_HANDLE_HASH || !pbData || !pbHashData ||
        !pulHashLen)
        return SAR_INVALIDPARAMERR;
    unsigned char out[EVP_MAX_MD_SIZE];
    unsigned int outlen = 0;
    if (EVP_Digest(pbData, ulDataLen, out, &outlen, h->md, NULL) != 1)
        return SAR_HASHERR;
    if (*pulHashLen < outlen) {
        *pulHashLen = outlen;
        return SAR_BUFFER_TOO_SMALL;
    }
    memcpy(pbHashData, out, outlen);
    *pulHashLen = outlen;
    return SAR_OK;
}

ULONG SKF_DigestUpdate(HANDLE hHash, BYTE *pbData, ULONG ulDataLen)
{
    SOFT_HASH *h = (SOFT_HASH *)hHash;
    if (!h || h->type != SOFT_HANDLE_HASH || !h->ctx)
        return SAR_INVALIDHANDLEERR;
    if (!pbData && ulDataLen)
        return SAR_INVALIDPARAMERR;
    return EVP_DigestUpdate(h->ctx, pbData, ulDataLen) == 1
               ? SAR_OK : SAR_HASHERR;
}

ULONG SKF_DigestFinal(HANDLE hHash, BYTE *pHashData, ULONG *pulHashLen)
{
    SOFT_HASH *h = (SOFT_HASH *)hHash;
    if (!h || h->type != SOFT_HANDLE_HASH || !h->ctx || !pulHashLen)
        return SAR_INVALIDHANDLEERR;
    unsigned char out[EVP_MAX_MD_SIZE];
    unsigned int outlen = 0;
    if (EVP_DigestFinal_ex(h->ctx, out, &outlen) != 1)
        return SAR_HASHERR;
    if (*pulHashLen < outlen) {
        *pulHashLen = outlen;
        return SAR_BUFFER_TOO_SMALL;
    }
    memcpy(pHashData, out, outlen);
    *pulHashLen = outlen;
    return SAR_OK;
}

/* ------------------------------------------------------------------ */
/* CBC-MAC                                                             */
/* ------------------------------------------------------------------ */

ULONG SKF_MacInit(HANDLE hKey, BLOCKCIPHERPARAM *pMacParam, HANDLE *phMac)
{
    SOFT_SYM *s = (SOFT_SYM *)hKey;
    if (!s || s->type != SOFT_HANDLE_SYM || !pMacParam || !phMac)
        return SAR_INVALIDPARAMERR;
    if (!s->is_mac)
        return SAR_INVALIDPARAMERR;
    SOFT_MAC *m = calloc(1, sizeof(*m));
    if (!m)
        return SAR_MEMORYERR;
    m->type = SOFT_HANDLE_MAC;
    m->dev = s->dev;
    memcpy(m->key, s->key, 16);
    if (pMacParam->IVLen >= 16)
        memcpy(m->iv, pMacParam->IV, 16);
    memset(m->state, 0, 16);
    m->buflen = 0;
    m->finalized = 0;
    m->padding = pMacParam->PaddingType ? 1 : 0;
    *phMac = (HANDLE)m;
    return SAR_OK;
}

static int mac_update_block(SOFT_MAC *m, const unsigned char *block)
{
    unsigned char x[16], y[16];
    for (int i = 0; i < 16; i++)
        x[i] = (unsigned char)(block[i] ^ m->state[i]);
    if (sm4_ecb_block(m->key, x, y, 1) != 0)
        return -1;
    memcpy(m->state, y, 16);
    return 0;
}

static int mac_update_data(SOFT_MAC *m, const unsigned char *data, size_t len)
{
    while (len > 0) {
        size_t need = 16 - (size_t)m->buflen;
        size_t n = len < need ? len : need;
        memcpy(m->buf + m->buflen, data, n);
        m->buflen += (int)n;
        data += n;
        len -= n;
        if (m->buflen == 16) {
            if (mac_update_block(m, m->buf) != 0)
                return -1;
            m->buflen = 0;
        }
    }
    return 0;
}

static int mac_finalize(SOFT_MAC *m, unsigned char out[16])
{
    if (m->finalized) {
        memcpy(out, m->state, 16);
        return 0;
    }
    if (m->padding) {
        unsigned char last[16];
        int pad = 16 - m->buflen;
        memcpy(last, m->buf, (size_t)m->buflen);
        memset(last + m->buflen, pad, (size_t)pad);
        if (mac_update_block(m, last) != 0)
            return -1;
        m->buflen = 0;
    } else if (m->buflen > 0) {
        unsigned char last[16] = {0};
        memcpy(last, m->buf, (size_t)m->buflen);
        if (mac_update_block(m, last) != 0)
            return -1;
        m->buflen = 0;
    }
    memcpy(out, m->state, 16);
    m->finalized = 1;
    return 0;
}

ULONG SKF_Mac(HANDLE hMac, BYTE *pbData, ULONG ulDataLen,
              BYTE *pbMacData, ULONG *pulMacLen)
{
    SOFT_MAC *m = (SOFT_MAC *)hMac;
    if (!m || m->type != SOFT_HANDLE_MAC || !pulMacLen)
        return SAR_INVALIDHANDLEERR;
    if (!pbData && ulDataLen)
        return SAR_INVALIDPARAMERR;
    if (mac_update_data(m, pbData, ulDataLen) != 0)
        return SAR_FAIL;
    unsigned char out[16];
    if (mac_finalize(m, out) != 0)
        return SAR_FAIL;
    if (*pulMacLen < 16) {
        *pulMacLen = 16;
        return SAR_MACLENERR;
    }
    memcpy(pbMacData, out, 16);
    *pulMacLen = 16;
    return SAR_OK;
}

ULONG SKF_MacUpdate(HANDLE hMac, BYTE *pbData, ULONG ulDataLen)
{
    SOFT_MAC *m = (SOFT_MAC *)hMac;
    if (!m || m->type != SOFT_HANDLE_MAC)
        return SAR_INVALIDHANDLEERR;
    if (!pbData && ulDataLen)
        return SAR_INVALIDPARAMERR;
    return mac_update_data(m, pbData, ulDataLen) == 0 ? SAR_OK : SAR_FAIL;
}

ULONG SKF_MacFinal(HANDLE hMac, BYTE *pbMacData, ULONG *pulMacDataLen)
{
    SOFT_MAC *m = (SOFT_MAC *)hMac;
    if (!m || m->type != SOFT_HANDLE_MAC || !pulMacDataLen)
        return SAR_INVALIDHANDLEERR;
    unsigned char out[16];
    if (mac_finalize(m, out) != 0)
        return SAR_FAIL;
    if (*pulMacDataLen < 16) {
        *pulMacDataLen = 16;
        return SAR_MACLENERR;
    }
    memcpy(pbMacData, out, 16);
    *pulMacDataLen = 16;
    return SAR_OK;
}

/* ------------------------------------------------------------------ */
/* Random and device authentication                                    */
/* ------------------------------------------------------------------ */

ULONG SKF_GenRandom(DEVHANDLE hDev, BYTE *pbRandom, ULONG ulRandomLen)
{
    SOFT_DEV *d = (SOFT_DEV *)hDev;
    if (!d || d->type != SOFT_HANDLE_DEV || (!pbRandom && ulRandomLen))
        return SAR_INVALIDPARAMERR;
    if (rand_bytes(pbRandom, ulRandomLen) != 0)
        return SAR_GENRANDERR;
    if (ulRandomLen > 0) {
        size_t n = ulRandomLen < sizeof(d->challenge)
                       ? ulRandomLen : sizeof(d->challenge);
        memcpy(d->challenge, pbRandom, n);
        d->challenge_len = (int)n;
    }
    return SAR_OK;
}

static int dev_save_auth_state(SOFT_DEV *d)
{
    sqlite3_stmt *st = NULL;
    if (db_prepare(d->db,
        "UPDATE token SET auth_retry=?,auth_locked=? WHERE id=1", &st) != 0)
        return -1;
    db_bind_int(st, 1, d->auth_retry);
    db_bind_int(st, 2, d->auth_locked);
    int rc = sqlite3_step(st);
    sqlite3_finalize(st);
    return rc == SQLITE_DONE ? 0 : -1;
}

ULONG SKF_DevAuth(DEVHANDLE hDev, BYTE *pbAuthData, ULONG ulLen)
{
    SOFT_DEV *d = (SOFT_DEV *)hDev;
    if (!d || d->type != SOFT_HANDLE_DEV || !pbAuthData)
        return SAR_INVALIDPARAMERR;
    if (d->authed)
        return SAR_OK;
    if (d->auth_locked)
        return SAR_PIN_LOCKED;
    if (ulLen != 16 || d->challenge_len <= 0)
        return SAR_INVALIDPARAMERR;

    unsigned char plain[16];
    if (sm4_ecb_block(d->dak, pbAuthData, plain, 0) != 0)
        return SAR_FAIL;
    int ok = memcmp(plain, d->challenge, (size_t)d->challenge_len) == 0;
    zero_mem(plain, sizeof(plain));
    if (ok) {
        d->authed = 1;
        d->auth_retry = 0;
        d->challenge_len = 0;
        dev_save_auth_state(d);
        return SAR_OK;
    }
    d->auth_retry++;
    if (d->auth_retry >= d->auth_max_retry) {
        d->auth_retry = d->auth_max_retry;
        d->auth_locked = 1;
    }
    dev_save_auth_state(d);
    return d->auth_locked ? SAR_PIN_LOCKED : SAR_PIN_INCORRECT;
}

ULONG SKF_ChangeDevAuthKey(DEVHANDLE hDev, BYTE *pbKeyValue, ULONG ulKeyLen)
{
    SOFT_DEV *d = (SOFT_DEV *)hDev;
    if (!d || d->type != SOFT_HANDLE_DEV || !pbKeyValue)
        return SAR_INVALIDPARAMERR;
    if (!d->authed)
        return SAR_USER_NOT_LOGGED_IN;
    if (ulKeyLen == 0 || ulKeyLen > 16)
        return SAR_INVALIDPARAMERR;

    unsigned char key[16] = {0};
    memcpy(key, pbKeyValue, ulKeyLen);
    unsigned char nonce[SOFTSKF_GCM_NONCE_LEN], tag[16], enc[16];
    if (wrap_with_key(d->store_key, "token-auth-key", key, sizeof(key),
                      nonce, enc, tag) != 0) {
        zero_mem(key, sizeof(key));
        return SAR_FAIL;
    }
    sqlite3_stmt *st = NULL;
    if (db_prepare(d->db,
        "UPDATE token SET auth_enc=?,auth_nonce=?,auth_tag=?,"
        "auth_retry=0,auth_locked=0 WHERE id=1", &st) != 0) {
        zero_mem(key, sizeof(key));
        return SAR_FAIL;
    }
    db_bind_blob(st, 1, enc, sizeof(enc));
    db_bind_blob(st, 2, nonce, sizeof(nonce));
    db_bind_blob(st, 3, tag, sizeof(tag));
    int rc = sqlite3_step(st);
    sqlite3_finalize(st);
    if (rc != SQLITE_DONE) {
        zero_mem(key, sizeof(key));
        return SAR_FAIL;
    }
    memcpy(d->dak, key, sizeof(d->dak));
    zero_mem(key, sizeof(key));
    d->auth_retry = 0;
    d->auth_locked = 0;
    return SAR_OK;
}

/* ------------------------------------------------------------------ */
/* Handle cleanup                                                      */
/* ------------------------------------------------------------------ */

ULONG SKF_CloseHandle(HANDLE hHandle)
{
    SOFT_HDR *h = (SOFT_HDR *)hHandle;
    if (!h)
        return SAR_INVALIDHANDLEERR;
    switch (h->type) {
    case SOFT_HANDLE_SYM: {
        SOFT_SYM *s = (SOFT_SYM *)h;
        if (s->ctx)
            EVP_CIPHER_CTX_free(s->ctx);
        free(s->buf);
        zero_mem(s->key, sizeof(s->key));
        free(s);
        return SAR_OK;
    }
    case SOFT_HANDLE_HASH: {
        SOFT_HASH *x = (SOFT_HASH *)h;
        if (x->ctx)
            EVP_MD_CTX_free(x->ctx);
        free(x);
        return SAR_OK;
    }
    case SOFT_HANDLE_MAC: {
        SOFT_MAC *m = (SOFT_MAC *)h;
        zero_mem(m->key, sizeof(m->key));
        zero_mem(m->state, sizeof(m->state));
        free(m);
        return SAR_OK;
    }
    case SOFT_HANDLE_AGREE: {
        SOFT_AGREE *a = (SOFT_AGREE *)h;
        zero_mem(a->static_priv, sizeof(a->static_priv));
        zero_mem(a->eph_priv, sizeof(a->eph_priv));
        free(a);
        return SAR_OK;
    }
    case SOFT_HANDLE_APP:
        return SKF_CloseApplication((HAPPLICATION)h);
    case SOFT_HANDLE_CTN:
        return SKF_CloseContainer((HCONTAINER)h);
    case SOFT_HANDLE_DEV:
        return SKF_DisConnectDev((DEVHANDLE)h);
    default:
        return SAR_INVALIDHANDLEERR;
    }
}

/* ------------------------------------------------------------------ */
/* ECC / SM2                                                           */
/* ------------------------------------------------------------------ */

static int ec_curve_nid(void)
{
    return NID_sm2;
}

static void ecc_coord32(const unsigned char *coord, unsigned char out[32])
{
    int leading_zero = 1;
    for (int i = 0; i < 32; i++) {
        if (coord[i]) {
            leading_zero = 0;
            break;
        }
    }
    memcpy(out, coord + (leading_zero ? 32 : 0), 32);
}

static EC_KEY *ec_key_from_pub(const ECCPUBLICKEYBLOB *pub)
{
    if (!pub || pub->BitLen != 256)
        return NULL;
    int nid = ec_curve_nid();
    EC_KEY *k = EC_KEY_new_by_curve_name(nid);
    if (!k)
        return NULL;
    const EC_GROUP *g = EC_KEY_get0_group(k);
    unsigned char xbuf[32], ybuf[32];
    ecc_coord32(pub->XCoordinate, xbuf);
    ecc_coord32(pub->YCoordinate, ybuf);
    BIGNUM *x = BN_bin2bn(xbuf, 32, NULL);
    BIGNUM *y = BN_bin2bn(ybuf, 32, NULL);
    EC_POINT *p = EC_POINT_new(g);
    int ok = x && y && p &&
             EC_POINT_set_affine_coordinates(g, p, x, y, NULL) == 1 &&
             EC_KEY_set_public_key(k, p) == 1;
    BN_free(x); BN_free(y); EC_POINT_free(p);
    if (!ok) {
        EC_KEY_free(k);
        return NULL;
    }
    return k;
}

static void ec_pub_from_key(EC_KEY *k, ECCPUBLICKEYBLOB *pub)
{
    const EC_GROUP *g = EC_KEY_get0_group(k);
    const EC_POINT *p = EC_KEY_get0_public_key(k);
    BIGNUM *x = BN_new(), *y = BN_new();
    memset(pub, 0, sizeof(*pub));
    pub->BitLen = 256;
    if (x && y && p &&
        EC_POINT_get_affine_coordinates(g, p, x, y, NULL) == 1) {
        BN_bn2binpad(x, pub->XCoordinate + 32, 32);
        BN_bn2binpad(y, pub->YCoordinate + 32, 32);
    }
    BN_free(x); BN_free(y);
}

static int ec_pub_from_priv(const unsigned char priv[32], ECCPUBLICKEYBLOB *pub)
{
    int nid = ec_curve_nid();
    EC_KEY *k = EC_KEY_new_by_curve_name(nid);
    if (!k)
        return -1;
    const EC_GROUP *g = EC_KEY_get0_group(k);
    BIGNUM *d = BN_bin2bn(priv, 32, NULL);
    EC_POINT *p = EC_POINT_new(g);
    int ok = d && p && EC_POINT_mul(g, p, d, NULL, NULL, NULL) == 1 &&
             EC_KEY_set_public_key(k, p) == 1;
    if (ok)
        ec_pub_from_key(k, pub);
    BN_free(d); EC_POINT_free(p); EC_KEY_free(k);
    return ok ? 0 : -1;
}

static int ecc_pub_equal(const ECCPUBLICKEYBLOB *a, const ECCPUBLICKEYBLOB *b)
{
    unsigned char ax[32], ay[32], bx[32], by[32];
    if (!a || !b || a->BitLen != b->BitLen)
        return 0;
    ecc_coord32(a->XCoordinate, ax);
    ecc_coord32(a->YCoordinate, ay);
    ecc_coord32(b->XCoordinate, bx);
    ecc_coord32(b->YCoordinate, by);
    return memcmp(ax, bx, 32) == 0 && memcmp(ay, by, 32) == 0;
}

static int ecc_priv_matches(const unsigned char priv[32],
                            const ECCPUBLICKEYBLOB *pub)
{
    ECCPUBLICKEYBLOB calc;
    if (ec_pub_from_priv(priv, &calc) != 0)
        return 0;
    calc.BitLen = pub->BitLen;
    return ecc_pub_equal(&calc, pub);
}

static void sm2_kdf(const unsigned char *z, size_t zlen,
                    unsigned char *out, size_t outlen)
{
    unsigned int ct = 1;
    size_t done = 0;
    while (done < outlen) {
        unsigned char md[32], ctr[4];
        unsigned int mdlen = 0;
        ctr[0] = (unsigned char)(ct >> 24);
        ctr[1] = (unsigned char)(ct >> 16);
        ctr[2] = (unsigned char)(ct >> 8);
        ctr[3] = (unsigned char)ct;
        EVP_MD_CTX *ctx = EVP_MD_CTX_new();
        if (ctx && EVP_DigestInit_ex(ctx, EVP_sm3(), NULL) == 1 &&
            EVP_DigestUpdate(ctx, z, zlen) == 1 &&
            EVP_DigestUpdate(ctx, ctr, 4) == 1 &&
            EVP_DigestFinal_ex(ctx, md, &mdlen) == 1) {
            size_t n = outlen - done;
            if (n > 32)
                n = 32;
            memcpy(out + done, md, n);
            done += n;
        } else {
            memset(out + done, 0, outlen - done);
            done = outlen;
        }
        EVP_MD_CTX_free(ctx);
        ct++;
    }
}

static int sm2_sign_digest(const unsigned char priv[32],
                           const unsigned char digest[32],
                           unsigned char r_out[32], unsigned char s_out[32])
{
    int nid = ec_curve_nid();
    EC_GROUP *g = nid ? EC_GROUP_new_by_curve_name(nid) : NULL;
    BN_CTX *ctx = BN_CTX_new();
    BIGNUM *n = BN_new(), *d = BN_bin2bn(priv, 32, NULL);
    BIGNUM *e = BN_bin2bn(digest, 32, NULL);
    int ok = 0;
    if (!g || !ctx || !n || !d || !e ||
        EC_GROUP_get_order(g, n, ctx) != 1)
        goto out;
    for (int tries = 0; tries < 64 && !ok; tries++) {
        BIGNUM *k = BN_new(), *r = BN_new(), *s = BN_new();
        BIGNUM *one = BN_new(), *d1 = BN_new(), *inv = BN_new();
        BIGNUM *rd = BN_new(), *kr = BN_new(), *t = BN_new();
        EC_POINT *p = EC_POINT_new(g);
        BIGNUM *x = BN_new();
        int good = k && r && s && one && d1 && inv && rd && kr && t && p && x &&
                   BN_rand_range(k, n) == 1 && !BN_is_zero(k) &&
                   EC_POINT_mul(g, p, k, NULL, NULL, ctx) == 1 &&
                   EC_POINT_get_affine_coordinates(g, p, x, NULL, ctx) == 1 &&
                   BN_mod_add(r, e, x, n, ctx) == 1 && !BN_is_zero(r) &&
                   BN_mod_add(t, r, k, n, ctx) == 1 && !BN_is_zero(t) &&
                   BN_one(one) == 1 &&
                   BN_mod_add(d1, one, d, n, ctx) == 1 &&
                   BN_mod_inverse(inv, d1, n, ctx) != NULL &&
                   BN_mod_mul(rd, r, d, n, ctx) == 1 &&
                   BN_mod_sub(kr, k, rd, n, ctx) == 1 &&
                   BN_mod_mul(s, inv, kr, n, ctx) == 1 && !BN_is_zero(s);
        if (good &&
            BN_bn2binpad(r, r_out, 32) == 32 &&
            BN_bn2binpad(s, s_out, 32) == 32)
            ok = 1;
        BN_free(k); BN_free(r); BN_free(s); BN_free(one); BN_free(d1);
        BN_free(inv); BN_free(rd); BN_free(kr); BN_free(t); BN_free(x);
        EC_POINT_free(p);
    }
out:
    BN_free(n); BN_free(d); BN_free(e);
    BN_CTX_free(ctx);
    EC_GROUP_free(g);
    return ok ? 0 : -1;
}

static int sm2_verify_digest(const ECCPUBLICKEYBLOB *pub,
                             const unsigned char digest[32],
                             const unsigned char r_in[32],
                             const unsigned char s_in[32])
{
    int nid = ec_curve_nid();
    EC_GROUP *g = nid ? EC_GROUP_new_by_curve_name(nid) : NULL;
    BN_CTX *ctx = BN_CTX_new();
    BIGNUM *n = BN_new(), *e = BN_bin2bn(digest, 32, NULL);
    BIGNUM *r = BN_bin2bn(r_in, 32, NULL), *s = BN_bin2bn(s_in, 32, NULL);
    BIGNUM *t = BN_new(), *rx = BN_new();
    EC_POINT *P = NULL, *X = NULL, *sG = NULL, *tP = NULL;
    EC_KEY *key = ec_key_from_pub(pub);
    int ok = 0;
    if (!g || !ctx || !n || !e || !r || !s || !t || !rx || !key ||
        EC_GROUP_get_order(g, n, ctx) != 1)
        goto out;
    if (BN_is_zero(r) || BN_is_zero(s) || BN_cmp(r, n) >= 0 ||
        BN_cmp(s, n) >= 0)
        goto out;
    P = EC_POINT_dup(EC_KEY_get0_public_key(key), g);
    X = EC_POINT_new(g);
    sG = EC_POINT_new(g);
    tP = EC_POINT_new(g);
    if (!P || !X || !sG || !tP ||
        BN_mod_add(t, r, s, n, ctx) != 1 || BN_is_zero(t) ||
        EC_POINT_mul(g, sG, s, NULL, NULL, ctx) != 1 ||
        EC_POINT_mul(g, tP, NULL, P, t, ctx) != 1 ||
        EC_POINT_add(g, X, sG, tP, ctx) != 1 ||
        EC_POINT_get_affine_coordinates(g, X, rx, NULL, ctx) != 1)
        goto out;
    if (BN_mod_add(rx, e, rx, n, ctx) == 1 && BN_cmp(rx, r) == 0)
        ok = 1;
out:
    EC_POINT_free(P); EC_POINT_free(X); EC_POINT_free(sG); EC_POINT_free(tP);
    EC_KEY_free(key);
    BN_free(n); BN_free(e); BN_free(r); BN_free(s); BN_free(t); BN_free(rx);
    BN_CTX_free(ctx);
    EC_GROUP_free(g);
    return ok ? 0 : -1;
}

static int sm2_encrypt_std(const ECCPUBLICKEYBLOB *pub,
                           const unsigned char *in, size_t inlen,
                           ECCCIPHERBLOB *out)
{
    if (!pub || pub->BitLen != 256 || !in || !out || inlen == 0 ||
        inlen > 4096)
        return -1;
    int nid = ec_curve_nid();
    EC_GROUP *g = EC_GROUP_new_by_curve_name(nid);
    EC_KEY *key = ec_key_from_pub(pub);
    BN_CTX *ctx = BN_CTX_new();
    BIGNUM *n = BN_new(), *k = BN_new();
    EC_POINT *C1 = NULL, *shared = NULL;
    BIGNUM *x1 = BN_new(), *y1 = BN_new();
    BIGNUM *x2 = BN_new(), *y2 = BN_new();
    unsigned char x1b[32], y1b[32], x2b[32], y2b[32], z[64];
    unsigned char *t = malloc(inlen);
    unsigned char c3[32];
    unsigned int c3len = 0;
    int ok = 0;

    if (!g || !key || !ctx || !n || !k || !x1 || !y1 || !x2 || !y2 || !t)
        goto out;
    C1 = EC_POINT_new(g);
    shared = EC_POINT_new(g);
    if (!C1 || !shared ||
        EC_GROUP_get_order(g, n, ctx) != 1 ||
        BN_rand_range(k, n) != 1 || BN_is_zero(k) ||
        EC_POINT_mul(g, C1, k, NULL, NULL, ctx) != 1 ||
        EC_POINT_mul(g, shared, NULL,
                     EC_KEY_get0_public_key(key), k, ctx) != 1 ||
        EC_POINT_get_affine_coordinates(g, C1, x1, y1, ctx) != 1 ||
        EC_POINT_get_affine_coordinates(g, shared, x2, y2, ctx) != 1)
        goto out;
    BN_bn2binpad(x1, x1b, 32);
    BN_bn2binpad(y1, y1b, 32);
    BN_bn2binpad(x2, x2b, 32);
    BN_bn2binpad(y2, y2b, 32);
    memcpy(z, x2b, 32);
    memcpy(z + 32, y2b, 32);
    sm2_kdf(z, sizeof(z), t, inlen);

    memset(out, 0, sizeof(*out));
    memcpy(out->XCoordinate + 32, x1b, 32);
    memcpy(out->YCoordinate + 32, y1b, 32);
    for (size_t i = 0; i < inlen; i++)
        out->Cipher[i] = (unsigned char)(in[i] ^ t[i]);
    out->CipherLen = (ULONG)inlen;

    EVP_MD_CTX *md = EVP_MD_CTX_new();
    if (md && EVP_DigestInit_ex(md, EVP_sm3(), NULL) == 1 &&
        EVP_DigestUpdate(md, x2b, 32) == 1 &&
        EVP_DigestUpdate(md, in, inlen) == 1 &&
        EVP_DigestUpdate(md, y2b, 32) == 1 &&
        EVP_DigestFinal_ex(md, c3, &c3len) == 1 && c3len == 32)
        memcpy(out->HASH, c3, 32);
    else
        memset(out->HASH, 0, 32);
    EVP_MD_CTX_free(md);
    ok = 1;
out:
    if (t) {
        zero_mem(t, inlen);
        free(t);
    }
    BN_free(n); BN_free(k); BN_free(x1); BN_free(y1); BN_free(x2); BN_free(y2);
    EC_POINT_free(C1); EC_POINT_free(shared);
    EC_KEY_free(key); EC_GROUP_free(g); BN_CTX_free(ctx);
    return ok ? 0 : -1;
}

static int sm2_decrypt_std(const unsigned char priv[32],
                           const ECCCIPHERBLOB *c,
                           unsigned char *out, ULONG *outlen)
{
    if (!c || c->CipherLen == 0 || c->CipherLen > 4096)
        return -1;
    int nid = ec_curve_nid();
    EC_GROUP *g = EC_GROUP_new_by_curve_name(nid);
    EC_POINT *c1 = EC_POINT_new(g);
    BN_CTX *bnctx = BN_CTX_new();
    unsigned char x1b[32], y1b[32];
    ecc_coord32(c->XCoordinate, x1b);
    ecc_coord32(c->YCoordinate, y1b);
    BIGNUM *x = BN_bin2bn(x1b, 32, NULL);
    BIGNUM *y = BN_bin2bn(y1b, 32, NULL);
    BIGNUM *d = BN_bin2bn(priv, 32, NULL);
    EC_POINT *shared = EC_POINT_new(g);
    int ok = g && c1 && bnctx && x && y && d && shared &&
             EC_POINT_set_affine_coordinates(g, c1, x, y, bnctx) == 1 &&
             EC_POINT_mul(g, shared, NULL, c1, d, bnctx) == 1;
    unsigned char x2b[32], y2b[32], z[64], c3[32];
    unsigned char *kdf = malloc(c->CipherLen);
    unsigned int c3len = 0;
    if (!kdf)
        ok = 0;
    if (ok) {
        BIGNUM *sx = BN_new(), *sy = BN_new();
        ok = sx && sy &&
             EC_POINT_get_affine_coordinates(g, shared, sx, sy, bnctx) == 1;
        if (ok) {
            BN_bn2binpad(sx, x2b, 32);
            BN_bn2binpad(sy, y2b, 32);
        }
        BN_free(sx); BN_free(sy);
    }
    if (ok) {
        memcpy(z, x2b, 32);
        memcpy(z + 32, y2b, 32);
        sm2_kdf(z, sizeof(z), kdf, c->CipherLen);
        for (ULONG i = 0; i < c->CipherLen; i++)
            out[i] = (unsigned char)(c->Cipher[i] ^ kdf[i]);
        int hash_nonzero = 0;
        for (int i = 0; i < 32; i++)
            if (c->HASH[i])
                hash_nonzero = 1;
        if (hash_nonzero) {
            EVP_MD_CTX *md = EVP_MD_CTX_new();
            if (md && EVP_DigestInit_ex(md, EVP_sm3(), NULL) == 1 &&
                EVP_DigestUpdate(md, x2b, 32) == 1 &&
                EVP_DigestUpdate(md, out, c->CipherLen) == 1 &&
                EVP_DigestUpdate(md, y2b, 32) == 1 &&
                EVP_DigestFinal_ex(md, c3, &c3len) == 1) {
                if (c3len != 32 || memcmp(c3, c->HASH, 32) != 0)
                    ok = 0;
            }
            EVP_MD_CTX_free(md);
        }
    }
    if (kdf)
        free(kdf);
    BN_free(x); BN_free(y); BN_free(d);
    EC_POINT_free(c1); EC_POINT_free(shared);
    BN_CTX_free(bnctx); EC_GROUP_free(g);
    if (!ok)
        return -1;
    *outlen = c->CipherLen;
    return 0;
}

static EC_KEY *ec_generate(ECCPUBLICKEYBLOB *pub, unsigned char priv[32])
{
    int nid = ec_curve_nid();
    EC_KEY *k = EC_KEY_new_by_curve_name(nid);
    if (!k || EC_KEY_generate_key(k) != 1) {
        EC_KEY_free(k);
        return NULL;
    }
    ec_pub_from_key(k, pub);
    BN_bn2binpad(EC_KEY_get0_private_key(k), priv, 32);
    return k;
}

static int ecdh_raw(const unsigned char priv[32], const ECCPUBLICKEYBLOB *pub,
                    unsigned char out[32])
{
    EC_KEY *k = ec_key_from_pub(pub);
    if (!k)
        return -1;
    BIGNUM *d = BN_bin2bn(priv, 32, NULL);
    if (!d || EC_KEY_set_private_key(k, d) != 1) {
        BN_free(d); EC_KEY_free(k);
        return -1;
    }
    const EC_POINT *p = EC_KEY_get0_public_key(k);
    int n = ECDH_compute_key(out, 32, p, k, NULL);
    BN_free(d);
    EC_KEY_free(k);
    return n == 32 ? 0 : -1;
}

static void agreement_kdf(const unsigned char shared[32],
                          const unsigned char *id1, ULONG id1len,
                          const unsigned char *id2, ULONG id2len,
                          unsigned char key[16])
{
    const unsigned char *a = id1, *b = id2;
    ULONG alen = id1len, blen = id2len;
    if (alen > blen || (alen == blen && memcmp(a, b, alen) > 0)) {
        a = id2; b = id1; alen = id2len; blen = id1len;
    }
    unsigned char md[32];
    unsigned int mdlen = 0;
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (ctx && EVP_DigestInit_ex(ctx, EVP_sm3(), NULL) == 1 &&
        EVP_DigestUpdate(ctx, shared, 32) == 1 &&
        EVP_DigestUpdate(ctx, a, alen) == 1 &&
        EVP_DigestUpdate(ctx, b, blen) == 1 &&
        EVP_DigestFinal_ex(ctx, md, &mdlen) == 1)
        memcpy(key, md, 16);
    else
        memcpy(key, shared, 16);
    EVP_MD_CTX_free(ctx);
}

static ULONG agreement_make_key(SOFT_DEV *d, ULONG alg,
                                const unsigned char key[16], HANDLE *phKey)
{
    SOFT_SYM *s = calloc(1, sizeof(*s));
    if (!s)
        return SAR_MEMORYERR;
    s->type = SOFT_HANDLE_SYM;
    s->dev = d;
    s->alg = alg;
    s->keylen = 16;
    s->is_mac = (alg == SGD_SM4_MAC);
    memcpy(s->key, key, 16);
    *phKey = (HANDLE)s;
    return SAR_OK;
}

static int ctn_set_type_pub(SOFT_CTN *c, int ctype, int bits,
                            const void *pub, int publen)
{
    sqlite3_stmt *st = NULL;
    if (db_prepare(c->app->dev->db,
        "UPDATE container SET ctype=?,bits=?,pub_blob=? WHERE id=?",
        &st) != 0)
        return -1;
    db_bind_int(st, 1, ctype);
    db_bind_int(st, 2, bits);
    db_bind_blob(st, 3, pub, publen);
    db_bind_int(st, 4, c->id);
    int rc = sqlite3_step(st);
    sqlite3_finalize(st);
    return rc == SQLITE_DONE ? 0 : -1;
}

static int ctn_store_keypair(SOFT_CTN *c, int ctype, int bits,
                             const void *pub, int publen,
                             const unsigned char *priv, size_t privlen)
{
    if (db_begin(c->app->dev->db) != 0)
        return -1;
    if (ctn_set_type_pub(c, ctype, bits, pub, publen) != 0 ||
        ctn_store_private(c, priv, privlen) != 0) {
        db_rollback(c->app->dev->db);
        return -1;
    }
    if (db_commit(c->app->dev->db) != 0) {
        db_rollback(c->app->dev->db);
        return -1;
    }
    return 0;
}

static int ctn_load_ecc(SOFT_CTN *c, unsigned char priv[32],
                        ECCPUBLICKEYBLOB *pub)
{
    if (!c || c->ctype != 1 || !c->app || !c->app->ak[0])
        return -1;
    unsigned char *p = NULL;
    int plen = 0;
    if (ctn_load_private(c, &p, &plen) != 0 || plen != 32)
        return -1;
    memcpy(priv, p, 32);
    zero_mem(p, (size_t)plen);
    free(p);
    if (c->pub_len != (int)sizeof(ECCPUBLICKEYBLOB))
        return -1;
    memcpy(pub, c->pub_blob, sizeof(*pub));
    return 0;
}

static int ctn_load_rsa(SOFT_CTN *c, RSA **rsa)
{
    *rsa = NULL;
    if (!c || c->ctype != 2 || !c->app || !c->app->ak[0])
        return -1;
    unsigned char *p = NULL;
    int plen = 0;
    if (ctn_load_private(c, &p, &plen) != 0)
        return -1;
    const unsigned char *pp = p;
    RSA *r = d2i_RSAPrivateKey(NULL, &pp, plen);
    zero_mem(p, (size_t)plen);
    free(p);
    if (!r)
        return -1;
    *rsa = r;
    return 0;
}

ULONG SKF_GenECCKeyPair(HCONTAINER hContainer, ULONG ulAlgId,
                        ECCPUBLICKEYBLOB *pBlob)
{
    SOFT_CTN *c = (SOFT_CTN *)hContainer;
    if (!c || c->type != SOFT_HANDLE_CTN || !pBlob)
        return SAR_INVALIDPARAMERR;
    if (!c->app || !c->app->user_logged)
        return SAR_USER_NOT_LOGGED_IN;
    if (ulAlgId != SGD_SM2 && ulAlgId != SGD_SM2_1 &&
        ulAlgId != SGD_SM2_2 && ulAlgId != SGD_SM2_3)
        return SAR_INVALIDPARAMERR;

    ECCPUBLICKEYBLOB pub;
    unsigned char priv[32];
    EC_KEY *k = ec_generate(&pub, priv);
    if (!k)
        return SAR_FAIL;
    EC_KEY_free(k);

    if (ctn_store_keypair(c, 1, 256, &pub, sizeof(pub),
                          priv, sizeof(priv)) != 0) {
        zero_mem(priv, sizeof(priv));
        return SAR_FAIL;
    }
    zero_mem(priv, sizeof(priv));
    c->ctype = 1;
    c->bits = 256;
    memcpy(c->pub_blob, &pub, sizeof(pub));
    c->pub_len = sizeof(pub);
    *pBlob = pub;
    return SAR_OK;
}

ULONG SKF_ExportPublicKey(HCONTAINER hContainer, BOOL bSignFlag,
                          BYTE *pbBlob, ULONG *pulBlobLen)
{
    SOFT_CTN *c = (SOFT_CTN *)hContainer;
    (void)bSignFlag;
    if (!c || c->type != SOFT_HANDLE_CTN || !pulBlobLen)
        return SAR_INVALIDPARAMERR;
    if (c->pub_len <= 0 || c->ctype == 0)
        return SAR_KEYNOTFOUNTERR;
    if (!pbBlob || *pulBlobLen < (ULONG)c->pub_len) {
        *pulBlobLen = (ULONG)c->pub_len;
        return SAR_BUFFER_TOO_SMALL;
    }
    memcpy(pbBlob, c->pub_blob, (size_t)c->pub_len);
    *pulBlobLen = (ULONG)c->pub_len;
    return SAR_OK;
}

ULONG SKF_ECCSignData(HCONTAINER hContainer, BYTE *pbDigest,
                      ULONG ulDigestLen, ECCSIGNATUREBLOB *pSignature)
{
    SOFT_CTN *c = (SOFT_CTN *)hContainer;
    if (!c || c->type != SOFT_HANDLE_CTN || !pbDigest || !pSignature)
        return SAR_INVALIDPARAMERR;
    if (!c->app || !c->app->user_logged)
        return SAR_USER_NOT_LOGGED_IN;
    if (ulDigestLen != 32)
        return SAR_INVALIDPARAMERR;
    unsigned char priv[32];
    ECCPUBLICKEYBLOB pub;
    if (ctn_load_ecc(c, priv, &pub) != 0)
        return SAR_KEYNOTFOUNTERR;
    memset(pSignature, 0, sizeof(*pSignature));
    int rc = sm2_sign_digest(priv, pbDigest, pSignature->r + 32,
                             pSignature->s + 32);
    zero_mem(priv, sizeof(priv));
    return rc == 0 ? SAR_OK : SAR_FAIL;
}

ULONG SKF_ECCVerify(DEVHANDLE hDev, ECCPUBLICKEYBLOB *pECCPubKeyBlob,
                    BYTE *pbData, ULONG ulDataLen,
                    ECCSIGNATUREBLOB *pSignature)
{
    if (!hDev || !pECCPubKeyBlob || !pbData || !pSignature)
        return SAR_INVALIDPARAMERR;
    if (pECCPubKeyBlob->BitLen != 256 || ulDataLen != 32)
        return SAR_NOTSUPPORTYETERR;
    return sm2_verify_digest(pECCPubKeyBlob, pbData,
                             pSignature->r + 32, pSignature->s + 32) == 0
               ? SAR_OK : SAR_HASHNOTEQUALERR;
}

ULONG SKF_ExtECCEncrypt(DEVHANDLE hDev, ECCPUBLICKEYBLOB *pECCPubKeyBlob,
                        BYTE *pbPlainText, ULONG ulPlainTextLen,
                        ECCCIPHERBLOB *pCipherText)
{
    (void)hDev;
    if (!pECCPubKeyBlob || !pbPlainText || !pCipherText ||
        ulPlainTextLen == 0)
        return SAR_INVALIDPARAMERR;
    if (pECCPubKeyBlob->BitLen != 256)
        return SAR_NOTSUPPORTYETERR;
    return sm2_encrypt_std(pECCPubKeyBlob, pbPlainText, ulPlainTextLen,
                           pCipherText) == 0 ? SAR_OK : SAR_FAIL;
}

ULONG SKF_ExtECCDecrypt(DEVHANDLE hDev, ECCPRIVATEKEYBLOB *pECCPriKeyBlob,
                        ECCCIPHERBLOB *pCipherText, BYTE *pbPlainText,
                        ULONG *pulPlainTextLen)
{
    (void)hDev;
    if (!pECCPriKeyBlob || !pCipherText || !pbPlainText || !pulPlainTextLen)
        return SAR_INVALIDPARAMERR;
    if (pECCPriKeyBlob->BitLen != 256)
        return SAR_NOTSUPPORTYETERR;
    if (*pulPlainTextLen < pCipherText->CipherLen)
        return SAR_INVALIDPARAMERR;
    unsigned char priv[32];
    memcpy(priv, pECCPriKeyBlob->PrivateKey + 32, 32);
    ULONG got = *pulPlainTextLen;
    int rc = sm2_decrypt_std(priv, pCipherText, pbPlainText, &got);
    zero_mem(priv, sizeof(priv));
    if (rc != 0)
        return SAR_DECRYPTPADERR;
    *pulPlainTextLen = got;
    return SAR_OK;
}

ULONG SKF_ExtECCSign(DEVHANDLE hDev, ECCPRIVATEKEYBLOB *pECCPriKeyBlob,
                     BYTE *pbData, ULONG ulDataLen,
                     ECCSIGNATUREBLOB *pSignature)
{
    (void)hDev;
    if (!pECCPriKeyBlob || !pbData || !pSignature)
        return SAR_INVALIDPARAMERR;
    if (pECCPriKeyBlob->BitLen != 256 || ulDataLen != 32)
        return SAR_NOTSUPPORTYETERR;
    unsigned char priv[32];
    memcpy(priv, pECCPriKeyBlob->PrivateKey + 32, 32);
    memset(pSignature, 0, sizeof(*pSignature));
    int rc = sm2_sign_digest(priv, pbData, pSignature->r + 32,
                             pSignature->s + 32);
    zero_mem(priv, sizeof(priv));
    return rc == 0 ? SAR_OK : SAR_FAIL;
}

ULONG SKF_ExtECCVerify(DEVHANDLE hDev, ECCPUBLICKEYBLOB *pECCPubKeyBlob,
                       BYTE *pbData, ULONG ulDataLen,
                       ECCSIGNATUREBLOB *pSignature)
{
    (void)hDev;
    if (!pECCPubKeyBlob || !pbData || !pSignature)
        return SAR_INVALIDPARAMERR;
    if (pECCPubKeyBlob->BitLen != 256 || ulDataLen != 32)
        return SAR_NOTSUPPORTYETERR;
    return sm2_verify_digest(pECCPubKeyBlob, pbData,
                             pSignature->r + 32, pSignature->s + 32) == 0
               ? SAR_OK : SAR_HASHNOTEQUALERR;
}

ULONG SKF_ECCExportSessionKey(HCONTAINER hContainer, ULONG ulAlgId,
                              ECCPUBLICKEYBLOB *pPubKey,
                              ECCCIPHERBLOB *pData, HANDLE *phSessionKey)
{
    SOFT_CTN *c = (SOFT_CTN *)hContainer;
    if (!c || c->type != SOFT_HANDLE_CTN || !pPubKey || !pData ||
        !phSessionKey)
        return SAR_INVALIDPARAMERR;
    unsigned char key[16];
    if (rand_bytes(key, sizeof(key)) != 0)
        return SAR_GENRANDERR;
    if (sm2_encrypt_std(pPubKey, key, sizeof(key), pData) != 0) {
        zero_mem(key, sizeof(key));
        return SAR_FAIL;
    }
    ULONG rc = agreement_make_key(c->app->dev, ulAlgId, key, phSessionKey);
    zero_mem(key, sizeof(key));
    return rc;
}

ULONG SKF_ECCDecrypt(HCONTAINER hContainer, ECCCIPHERBLOB *pCipherBlob,
                     BYTE *pbPlainText, ULONG *pulPlainTextLen)
{
    SOFT_CTN *c = (SOFT_CTN *)hContainer;
    if (!c || c->type != SOFT_HANDLE_CTN || !pCipherBlob || !pbPlainText ||
        !pulPlainTextLen)
        return SAR_INVALIDPARAMERR;
    if (!c->app || !c->app->user_logged)
        return SAR_USER_NOT_LOGGED_IN;
    unsigned char priv[32];
    ECCPUBLICKEYBLOB pub;
    if (ctn_load_ecc(c, priv, &pub) != 0)
        return SAR_KEYNOTFOUNTERR;
    if (*pulPlainTextLen < pCipherBlob->CipherLen) {
        zero_mem(priv, sizeof(priv));
        return SAR_INVALIDPARAMERR;
    }
    ULONG got = *pulPlainTextLen;
    int rc = sm2_decrypt_std(priv, pCipherBlob, pbPlainText, &got);
    zero_mem(priv, sizeof(priv));
    if (rc != 0)
        return SAR_DECRYPTPADERR;
    *pulPlainTextLen = got;
    return SAR_OK;
}

ULONG SKF_ImportECCKeyPair(HCONTAINER hContainer,
                           ENVELOPEDKEYBLOB *pEnvelopedKeyBlob)
{
    SOFT_CTN *c = (SOFT_CTN *)hContainer;
    if (!c || c->type != SOFT_HANDLE_CTN || !pEnvelopedKeyBlob)
        return SAR_INVALIDPARAMERR;
    if (!c->app || !c->app->user_logged)
        return SAR_USER_NOT_LOGGED_IN;
    if (pEnvelopedKeyBlob->PubKey.BitLen != 256)
        return SAR_INVALIDPARAMERR;

    unsigned char priv[32];
    int found = 0;

    if (pEnvelopedKeyBlob->ECCCipherBlob.CipherLen == 0) {
        /* Native/soft extension: cbEncryptedPriKey[0..31] is the scalar. */
        memset(priv, 0, sizeof(priv));
        memcpy(priv, pEnvelopedKeyBlob->cbEncryptedPriKey, 32);
        if (ecc_priv_matches(priv, &pEnvelopedKeyBlob->PubKey))
            found = 1;
    } else {
        unsigned char oldpriv[32];
        ECCPUBLICKEYBLOB oldpub;
        if (ctn_load_ecc(c, oldpriv, &oldpub) != 0)
            return SAR_NOTSUPPORTYETERR;
        unsigned char sess[256];
        ULONG sesslen = sizeof(sess);
        if (pEnvelopedKeyBlob->ECCCipherBlob.CipherLen > sizeof(sess))
            return SAR_INVALIDPARAMERR;
        int sr = sm2_decrypt_std(oldpriv, &pEnvelopedKeyBlob->ECCCipherBlob,
                                 sess, &sesslen);
        zero_mem(oldpriv, sizeof(oldpriv));
        if (sr != 0 || sesslen < 16)
            return SAR_INVALIDPARAMERR;
        int bits = pEnvelopedKeyBlob->ulBits ? (int)pEnvelopedKeyBlob->ulBits : 256;
        int plen = bits / 8;
        if (plen <= 0 || plen > 32)
            plen = 32;
        for (int off = 32; off >= 0 && !found; off -= 32) {
            unsigned char tmp[64];
            const EVP_CIPHER *cipher = cipher_for_alg(pEnvelopedKeyBlob->ulSymmAlgID);
            if (!cipher)
                break;
            EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
            unsigned char iv[16] = {0};
            int n = 0, total = 0;
            int ok = ctx &&
                     EVP_DecryptInit_ex(ctx, cipher, NULL, sess, iv) == 1 &&
                     EVP_CIPHER_CTX_set_padding(ctx, 0) == 1 &&
                     EVP_DecryptUpdate(ctx, tmp, &n,
                                       pEnvelopedKeyBlob->cbEncryptedPriKey + off,
                                       plen) == 1;
            total = n;
            if (ok)
                ok = EVP_DecryptFinal_ex(ctx, tmp + total, &n) == 1;
            total += n;
            EVP_CIPHER_CTX_free(ctx);
            if (!ok || total < 32)
                continue;
            if (ecc_priv_matches(tmp, &pEnvelopedKeyBlob->PubKey)) {
                memcpy(priv, tmp, 32);
                found = 1;
            } else {
                unsigned char rev[32];
                for (int i = 0; i < 32; i++)
                    rev[i] = tmp[31 - i];
                if (ecc_priv_matches(rev, &pEnvelopedKeyBlob->PubKey)) {
                    memcpy(priv, rev, 32);
                    found = 1;
                }
            }
        }
    }
    if (!found) {
        zero_mem(priv, sizeof(priv));
        return SAR_INVALIDPARAMERR;
    }

    if (ctn_store_keypair(c, 1, 256, &pEnvelopedKeyBlob->PubKey,
                          sizeof(pEnvelopedKeyBlob->PubKey),
                          priv, sizeof(priv)) != 0) {
        zero_mem(priv, sizeof(priv));
        return SAR_FAIL;
    }
    zero_mem(priv, sizeof(priv));
    c->ctype = 1;
    c->bits = 256;
    memcpy(c->pub_blob, &pEnvelopedKeyBlob->PubKey,
           sizeof(pEnvelopedKeyBlob->PubKey));
    c->pub_len = sizeof(pEnvelopedKeyBlob->PubKey);
    return SAR_OK;
}

ULONG SKF_GenerateAgreementDataWithECC(HCONTAINER hContainer, ULONG ulAlgId,
                                       ECCPUBLICKEYBLOB *pTempECCPubKeyBlob,
                                       BYTE *pbID, ULONG ulIDLen,
                                       HANDLE *phAgreementHandle)
{
    SOFT_CTN *c = (SOFT_CTN *)hContainer;
    if (!c || c->type != SOFT_HANDLE_CTN || !pTempECCPubKeyBlob ||
        !phAgreementHandle || ulIDLen > 32 || (!pbID && ulIDLen))
        return SAR_INVALIDPARAMERR;
    if (!c->app || !c->app->user_logged)
        return SAR_USER_NOT_LOGGED_IN;
    unsigned char priv[32];
    ECCPUBLICKEYBLOB pub;
    if (ctn_load_ecc(c, priv, &pub) != 0)
        return SAR_NOTSUPPORTYETERR;

    SOFT_AGREE *a = calloc(1, sizeof(*a));
    if (!a) {
        zero_mem(priv, sizeof(priv));
        return SAR_MEMORYERR;
    }
    a->type = SOFT_HANDLE_AGREE;
    a->dev = c->app->dev;
    a->alg = ulAlgId;
    memcpy(a->static_priv, priv, 32);
    a->static_pub = pub;
    zero_mem(priv, sizeof(priv));
    EC_KEY *eph = ec_generate(&a->eph_pub, a->eph_priv);
    if (!eph) {
        zero_mem(a->static_priv, sizeof(a->static_priv));
        free(a);
        return SAR_FAIL;
    }
    EC_KEY_free(eph);
    if (ulIDLen)
        memcpy(a->id, pbID, ulIDLen);
    a->idlen = (int)ulIDLen;
    *pTempECCPubKeyBlob = a->eph_pub;
    *phAgreementHandle = (HANDLE)a;
    return SAR_OK;
}

ULONG SKF_GenerateAgreementDataAndKeyWithECC(
    HANDLE hContainer, ULONG ulAlgId,
    ECCPUBLICKEYBLOB *pSponsorECCPubKeyBlob,
    ECCPUBLICKEYBLOB *pSponsorTempECCPubKeyBlob,
    ECCPUBLICKEYBLOB *pTempECCPubKeyBlob,
    BYTE *pbID, ULONG ulIDLen, BYTE *pbSponsorID, ULONG ulSponsorIDLen,
    HANDLE *phKeyHandle)
{
    SOFT_CTN *c = (SOFT_CTN *)hContainer;
    if (!c || c->type != SOFT_HANDLE_CTN || !pSponsorECCPubKeyBlob ||
        !pSponsorTempECCPubKeyBlob || !pTempECCPubKeyBlob || !phKeyHandle ||
        ulIDLen > 32 || ulSponsorIDLen > 32 ||
        (!pbID && ulIDLen) || (!pbSponsorID && ulSponsorIDLen))
        return SAR_INVALIDPARAMERR;
    if (!c->app || !c->app->user_logged)
        return SAR_USER_NOT_LOGGED_IN;
    unsigned char static_priv[32];
    ECCPUBLICKEYBLOB static_pub;
    if (ctn_load_ecc(c, static_priv, &static_pub) != 0)
        return SAR_NOTSUPPORTYETERR;

    ECCPUBLICKEYBLOB respTemp;
    unsigned char respPriv[32];
    EC_KEY *eph = ec_generate(&respTemp, respPriv);
    if (!eph) {
        zero_mem(static_priv, sizeof(static_priv));
        return SAR_FAIL;
    }
    EC_KEY_free(eph);
    unsigned char s1[32], s2[32], shared[32], key[16];
    int ok = ecdh_raw(static_priv, pSponsorTempECCPubKeyBlob, s1) == 0 &&
             ecdh_raw(respPriv, pSponsorECCPubKeyBlob, s2) == 0;
    zero_mem(static_priv, sizeof(static_priv));
    zero_mem(respPriv, sizeof(respPriv));
    if (!ok)
        return SAR_FAIL;
    for (int i = 0; i < 32; i++)
        shared[i] = (unsigned char)(s1[i] ^ s2[i]);
    agreement_kdf(shared, pbID, ulIDLen, pbSponsorID, ulSponsorIDLen, key);
    *pTempECCPubKeyBlob = respTemp;
    ULONG rc = agreement_make_key(c->app->dev, ulAlgId, key, phKeyHandle);
    zero_mem(key, sizeof(key));
    return rc;
}

ULONG SKF_GenerateKeyWithECC(HANDLE hAgreementHandle,
                             ECCPUBLICKEYBLOB *pECCPubKeyBlob,
                             ECCPUBLICKEYBLOB *pTempECCPubKeyBlob,
                             BYTE *pbID, ULONG ulIDLen,
                             HANDLE *phKeyHandle)
{
    SOFT_AGREE *a = (SOFT_AGREE *)hAgreementHandle;
    if (!a || a->type != SOFT_HANDLE_AGREE || !pECCPubKeyBlob ||
        !pTempECCPubKeyBlob || !phKeyHandle || ulIDLen > 32 ||
        (!pbID && ulIDLen))
        return SAR_INVALIDPARAMERR;
    unsigned char s1[32], s2[32], shared[32], key[16];
    if (ecdh_raw(a->static_priv, pTempECCPubKeyBlob, s1) != 0 ||
        ecdh_raw(a->eph_priv, pECCPubKeyBlob, s2) != 0)
        return SAR_FAIL;
    for (int i = 0; i < 32; i++)
        shared[i] = (unsigned char)(s1[i] ^ s2[i]);
    agreement_kdf(shared, a->id, (ULONG)a->idlen, pbID, ulIDLen, key);
    ULONG rc = agreement_make_key(a->dev, a->alg, key, phKeyHandle);
    zero_mem(key, sizeof(key));
    return rc;
}

/* ------------------------------------------------------------------ */
/* RSA                                                                 */
/* ------------------------------------------------------------------ */

static RSA *rsa_from_private_blob(const RSAPRIVATEKEYBLOB *b)
{
    if (!b || b->BitLen == 0 || b->BitLen > MAX_RSA_MODULUS_LEN * 8)
        return NULL;
    RSA *r = RSA_new();
    if (!r)
        return NULL;
    BIGNUM *n = BN_bin2bn(b->Modulus, MAX_RSA_MODULUS_LEN, NULL);
    BIGNUM *e = BN_bin2bn(b->PublicExponent, MAX_RSA_EXPONENT_LEN, NULL);
    BIGNUM *d = BN_bin2bn(b->PrivateExponent, MAX_RSA_MODULUS_LEN, NULL);
    BIGNUM *p = BN_bin2bn(b->Prime1, MAX_RSA_MODULUS_LEN / 2, NULL);
    BIGNUM *q = BN_bin2bn(b->Prime2, MAX_RSA_MODULUS_LEN / 2, NULL);
    BIGNUM *dmp1 = BN_bin2bn(b->Prime1Exponent, MAX_RSA_MODULUS_LEN / 2, NULL);
    BIGNUM *dmq1 = BN_bin2bn(b->Prime2Exponent, MAX_RSA_MODULUS_LEN / 2, NULL);
    BIGNUM *iqmp = BN_bin2bn(b->Coefficient, MAX_RSA_MODULUS_LEN / 2, NULL);
    if (!n || !e || !d || RSA_set0_key(r, n, e, d) != 1) {
        BN_free(n); BN_free(e); BN_free(d);
        BN_free(p); BN_free(q); BN_free(dmp1); BN_free(dmq1); BN_free(iqmp);
        RSA_free(r);
        return NULL;
    }
    if (p && q && RSA_set0_factors(r, p, q) != 1) {
        BN_free(p); BN_free(q); p = q = NULL;
    }
    if (dmp1 && dmq1 && iqmp &&
        RSA_set0_crt_params(r, dmp1, dmq1, iqmp) != 1) {
        BN_free(dmp1); BN_free(dmq1); BN_free(iqmp);
    }
    return r;
}

static void rsa_to_private_blob(RSA *r, RSAPRIVATEKEYBLOB *b)
{
    memset(b, 0, sizeof(*b));
    b->AlgID = SGD_RSA;
    const BIGNUM *n, *e, *d, *p, *q, *dmp1, *dmq1, *iqmp;
    RSA_get0_key(r, &n, &e, &d);
    RSA_get0_factors(r, &p, &q);
    RSA_get0_crt_params(r, &dmp1, &dmq1, &iqmp);
    b->BitLen = (ULONG)BN_num_bits(n);
    if (e)
        BN_bn2binpad(e, b->PublicExponent, MAX_RSA_EXPONENT_LEN);
    if (n)
        BN_bn2binpad(n, b->Modulus + MAX_RSA_MODULUS_LEN - BN_num_bytes(n),
                     BN_num_bytes(n));
    if (d)
        BN_bn2binpad(d, b->PrivateExponent, MAX_RSA_MODULUS_LEN);
    if (p) BN_bn2binpad(p, b->Prime1, MAX_RSA_MODULUS_LEN / 2);
    if (q) BN_bn2binpad(q, b->Prime2, MAX_RSA_MODULUS_LEN / 2);
    if (dmp1) BN_bn2binpad(dmp1, b->Prime1Exponent, MAX_RSA_MODULUS_LEN / 2);
    if (dmq1) BN_bn2binpad(dmq1, b->Prime2Exponent, MAX_RSA_MODULUS_LEN / 2);
    if (iqmp) BN_bn2binpad(iqmp, b->Coefficient, MAX_RSA_MODULUS_LEN / 2);
}

static void rsa_to_public_blob(RSA *r, RSAPUBLICKEYBLOB *b)
{
    memset(b, 0, sizeof(*b));
    b->AlgID = SGD_RSA;
    const BIGNUM *n, *e;
    RSA_get0_key(r, &n, &e, NULL);
    b->BitLen = (ULONG)BN_num_bits(n);
    if (n)
        BN_bn2binpad(n, b->Modulus + MAX_RSA_MODULUS_LEN - BN_num_bytes(n),
                     BN_num_bytes(n));
    if (e)
        BN_bn2binpad(e, b->PublicExponent, MAX_RSA_EXPONENT_LEN);
}

static RSA *rsa_from_public_blob(const RSAPUBLICKEYBLOB *b)
{
    if (!b || b->BitLen == 0 || b->BitLen > MAX_RSA_MODULUS_LEN * 8)
        return NULL;
    RSA *r = RSA_new();
    if (!r)
        return NULL;
    BIGNUM *n = BN_bin2bn(b->Modulus, MAX_RSA_MODULUS_LEN, NULL);
    BIGNUM *e = BN_bin2bn(b->PublicExponent, MAX_RSA_EXPONENT_LEN, NULL);
    if (!n || !e || RSA_set0_key(r, n, e, NULL) != 1) {
        BN_free(n); BN_free(e);
        RSA_free(r);
        return NULL;
    }
    return r;
}

ULONG SKF_GenRSAKeyPair(HCONTAINER hContainer, ULONG ulBitsLen,
                        RSAPUBLICKEYBLOB *pBlob)
{
    SOFT_CTN *c = (SOFT_CTN *)hContainer;
    if (!c || c->type != SOFT_HANDLE_CTN || !pBlob)
        return SAR_INVALIDPARAMERR;
    if (!c->app || !c->app->user_logged)
        return SAR_USER_NOT_LOGGED_IN;
    if (ulBitsLen < 1024 || ulBitsLen > 4096 || (ulBitsLen % 8) != 0)
        return SAR_INVALIDPARAMERR;

    RSA *r = RSA_new();
    BIGNUM *e = BN_new();
    if (!r || !e || BN_set_word(e, RSA_F4) != 1 ||
        RSA_generate_key_ex(r, (int)ulBitsLen, e, NULL) != 1) {
        BN_free(e);
        RSA_free(r);
        return SAR_GENRSAKEYERR;
    }
    BN_free(e);

    RSAPUBLICKEYBLOB pub;
    rsa_to_public_blob(r, &pub);
    int derlen = i2d_RSAPrivateKey(r, NULL);
    unsigned char *der = malloc((size_t)derlen);
    if (!der || derlen <= 0) {
        free(der);
        RSA_free(r);
        return SAR_MEMORYERR;
    }
    unsigned char *dp = der;
    i2d_RSAPrivateKey(r, &dp);
    RSA_free(r);

    int rc = 0;
    if (ctn_store_keypair(c, 2, (int)ulBitsLen, &pub, sizeof(pub),
                          der, (size_t)derlen) != 0)
        rc = -1;
    zero_mem(der, (size_t)derlen);
    free(der);
    if (rc != 0)
        return SAR_FAIL;

    c->ctype = 2;
    c->bits = (int)ulBitsLen;
    memcpy(c->pub_blob, &pub, sizeof(pub));
    c->pub_len = sizeof(pub);
    *pBlob = pub;
    return SAR_OK;
}

ULONG SKF_ImportRSAKeyPair(HCONTAINER hContainer, ULONG ulSymAlgId,
                           BYTE *pbWrappedKey, ULONG ulWrappedKeyLen,
                           BYTE *pbEncryptedData, ULONG ulEncryptedDataLen)
{
    SOFT_CTN *c = (SOFT_CTN *)hContainer;
    (void)ulSymAlgId;
    (void)pbEncryptedData;
    (void)ulEncryptedDataLen;
    if (!c || c->type != SOFT_HANDLE_CTN || !pbWrappedKey ||
        !ulWrappedKeyLen)
        return SAR_INVALIDPARAMERR;
    if (!c->app || !c->app->user_logged)
        return SAR_USER_NOT_LOGGED_IN;

    RSA *r = NULL;
    RSAPRIVATEKEYBLOB blob;
    if (pbEncryptedData && ulEncryptedDataLen && c->ctype == 2) {
        RSA *old = NULL;
        if (ctn_load_rsa(c, &old) != 0)
            return SAR_NOTSUPPORTYETERR;
        unsigned char sess[512];
        int slen = RSA_private_decrypt((int)ulEncryptedDataLen,
                                       pbEncryptedData, sess, old,
                                       RSA_PKCS1_PADDING);
        if (slen <= 0)
            slen = RSA_private_decrypt((int)ulEncryptedDataLen,
                                       pbEncryptedData, sess, old,
                                       RSA_NO_PADDING);
        RSA_free(old);
        if (slen <= 0)
            return SAR_INVALIDPARAMERR;
        const unsigned char *sk = sess;
        if (slen > 16)
            sk = sess + slen - 16;
        const EVP_CIPHER *cipher = cipher_for_alg(ulSymAlgId);
        if (!cipher)
            return SAR_NOTSUPPORTYETERR;
        unsigned char *dec = malloc(ulWrappedKeyLen + 64);
        if (!dec)
            return SAR_MEMORYERR;
        EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
        unsigned char iv[16] = {0};
        int n = 0, total = 0;
        int ok = ctx &&
                 EVP_DecryptInit_ex(ctx, cipher, NULL, sk, iv) == 1 &&
                 EVP_CIPHER_CTX_set_padding(ctx, 0) == 1 &&
                 EVP_DecryptUpdate(ctx, dec, &n, pbWrappedKey,
                                   (int)ulWrappedKeyLen) == 1;
        total = n;
        if (ok)
            ok = EVP_DecryptFinal_ex(ctx, dec + total, &n) == 1;
        total += n;
        EVP_CIPHER_CTX_free(ctx);
        zero_mem(sess, sizeof(sess));
        if (ok && total >= (int)sizeof(RSAPRIVATEKEYBLOB)) {
            memcpy(&blob, dec, sizeof(blob));
            if (blob.AlgID == SGD_RSA && blob.BitLen >= 512 &&
                blob.BitLen <= MAX_RSA_MODULUS_LEN * 8)
                r = rsa_from_private_blob(&blob);
        }
        if (!r) {
            const unsigned char *pp = dec;
            r = d2i_RSAPrivateKey(NULL, &pp, total);
        }
        zero_mem(dec, ulWrappedKeyLen + 64);
        free(dec);
    }
    if (!r && ulWrappedKeyLen >= sizeof(RSAPRIVATEKEYBLOB)) {
        memcpy(&blob, pbWrappedKey, sizeof(blob));
        if (blob.AlgID == SGD_RSA && blob.BitLen >= 512 &&
            blob.BitLen <= MAX_RSA_MODULUS_LEN * 8)
            r = rsa_from_private_blob(&blob);
    }
    if (!r) {
        const unsigned char *p = pbWrappedKey;
        r = d2i_RSAPrivateKey(NULL, &p, (long)ulWrappedKeyLen);
    }
    if (!r)
        return SAR_INVALIDPARAMERR;

    RSAPUBLICKEYBLOB pub;
    rsa_to_public_blob(r, &pub);
    int derlen = i2d_RSAPrivateKey(r, NULL);
    unsigned char *der = malloc((size_t)derlen);
    if (!der || derlen <= 0) {
        free(der);
        RSA_free(r);
        return SAR_MEMORYERR;
    }
    unsigned char *dp = der;
    i2d_RSAPrivateKey(r, &dp);
    RSA_free(r);

    int rc = 0;
    if (ctn_store_keypair(c, 2, (int)pub.BitLen, &pub, sizeof(pub),
                          der, (size_t)derlen) != 0)
        rc = -1;
    zero_mem(der, (size_t)derlen);
    free(der);
    if (rc != 0)
        return SAR_FAIL;

    c->ctype = 2;
    c->bits = (int)pub.BitLen;
    memcpy(c->pub_blob, &pub, sizeof(pub));
    c->pub_len = sizeof(pub);
    return SAR_OK;
}

ULONG SKF_RSASignData(HCONTAINER hContainer, BYTE *pbData, ULONG ulDataLen,
                      BYTE *pbSignature, ULONG *pulSignLen)
{
    SOFT_CTN *c = (SOFT_CTN *)hContainer;
    if (!c || c->type != SOFT_HANDLE_CTN || !pbData || !pbSignature ||
        !pulSignLen)
        return SAR_INVALIDPARAMERR;
    if (!c->app || !c->app->user_logged)
        return SAR_USER_NOT_LOGGED_IN;
    if (ulDataLen != 32)
        return SAR_INVALIDPARAMERR;
    RSA *r = NULL;
    if (ctn_load_rsa(c, &r) != 0)
        return SAR_KEYNOTFOUNTERR;
    int need = RSA_size(r);
    if (*pulSignLen < (ULONG)need) {
        *pulSignLen = (ULONG)need;
        RSA_free(r);
        return SAR_INVALIDPARAMERR;
    }
    int n = RSA_private_encrypt((int)ulDataLen, pbData, pbSignature, r,
                                 RSA_PKCS1_PADDING);
    RSA_free(r);
    if (n <= 0)
        return SAR_FAIL;
    *pulSignLen = (ULONG)n;
    return SAR_OK;
}

ULONG SKF_RSAVerify(DEVHANDLE hDev, RSAPUBLICKEYBLOB *pRSAPubKeyBlob,
                    BYTE *pbData, ULONG ulDataLen, BYTE *pbSignature,
                    ULONG ulSignLen)
{
    (void)hDev;
    if (!pRSAPubKeyBlob || !pbData || !pbSignature)
        return SAR_INVALIDPARAMERR;
    if (ulDataLen != 32)
        return SAR_INVALIDPARAMERR;
    RSA *r = rsa_from_public_blob(pRSAPubKeyBlob);
    if (!r)
        return SAR_INVALIDPARAMERR;
    unsigned char out[512];
    int n = RSA_public_decrypt((int)ulSignLen, pbSignature, out, r,
                               RSA_PKCS1_PADDING);
    RSA_free(r);
    if (n != (int)ulDataLen || memcmp(out, pbData, ulDataLen) != 0)
        return SAR_HASHNOTEQUALERR;
    return SAR_OK;
}

ULONG SKF_RSAExportSessionKey(HCONTAINER hContainer, ULONG ulAlgId,
                              RSAPUBLICKEYBLOB *pPubKey, BYTE *pbData,
                              ULONG *pulDataLen, HANDLE *phSessionKey)
{
    SOFT_CTN *c = (SOFT_CTN *)hContainer;
    if (!c || c->type != SOFT_HANDLE_CTN || !pPubKey || !pbData ||
        !pulDataLen || !phSessionKey)
        return SAR_INVALIDPARAMERR;
    RSA *r = rsa_from_public_blob(pPubKey);
    if (!r)
        return SAR_INVALIDPARAMERR;
    unsigned char key[16];
    if (rand_bytes(key, sizeof(key)) != 0) {
        RSA_free(r);
        return SAR_GENRANDERR;
    }
    int need = RSA_size(r);
    if (*pulDataLen < (ULONG)need) {
        *pulDataLen = (ULONG)need;
        RSA_free(r);
        zero_mem(key, sizeof(key));
        return SAR_INVALIDPARAMERR;
    }
    int n = RSA_public_encrypt(16, key, pbData, r, RSA_PKCS1_PADDING);
    RSA_free(r);
    if (n <= 0) {
        zero_mem(key, sizeof(key));
        return SAR_RSAENCERR;
    }
    *pulDataLen = (ULONG)n;
    ULONG rc = agreement_make_key(c->app->dev, ulAlgId, key, phSessionKey);
    zero_mem(key, sizeof(key));
    return rc;
}

ULONG SKF_GenExtRSAKey(DEVHANDLE hDev, ULONG ulBitsLen,
                       RSAPRIVATEKEYBLOB *pBlob)
{
    (void)hDev;
    if (!pBlob || ulBitsLen < 1024 || ulBitsLen > 4096 ||
        (ulBitsLen % 8) != 0)
        return SAR_INVALIDPARAMERR;
    RSA *r = RSA_new();
    BIGNUM *e = BN_new();
    if (!r || !e || BN_set_word(e, RSA_F4) != 1 ||
        RSA_generate_key_ex(r, (int)ulBitsLen, e, NULL) != 1) {
        BN_free(e);
        RSA_free(r);
        return SAR_GENRSAKEYERR;
    }
    BN_free(e);
    rsa_to_private_blob(r, pBlob);
    RSA_free(r);
    return SAR_OK;
}

ULONG SKF_ExtRSAPubKeyOperation(DEVHANDLE hDev,
                                RSAPUBLICKEYBLOB *pRSAPubKeyBlob,
                                BYTE *pbInput, ULONG ulInputLen,
                                BYTE *pbOutput, ULONG *pulOutputLen)
{
    (void)hDev;
    if (!pRSAPubKeyBlob || !pbInput || !pbOutput || !pulOutputLen)
        return SAR_INVALIDPARAMERR;
    RSA *r = rsa_from_public_blob(pRSAPubKeyBlob);
    if (!r)
        return SAR_INVALIDPARAMERR;
    int need = RSA_size(r);
    if (*pulOutputLen < (ULONG)need) {
        *pulOutputLen = (ULONG)need;
        RSA_free(r);
        return SAR_INVALIDPARAMERR;
    }
    int n = RSA_public_encrypt((int)ulInputLen, pbInput, pbOutput, r,
                               RSA_NO_PADDING);
    RSA_free(r);
    if (n <= 0)
        return SAR_RSAENCERR;
    *pulOutputLen = (ULONG)n;
    return SAR_OK;
}

ULONG SKF_ExtRSAPriKeyOperation(DEVHANDLE hDev,
                                RSAPRIVATEKEYBLOB *pRSAPriKeyBlob,
                                BYTE *pbInput, ULONG ulInputLen,
                                BYTE *pbOutput, ULONG *pulOutputLen)
{
    (void)hDev;
    if (!pRSAPriKeyBlob || !pbInput || !pbOutput || !pulOutputLen)
        return SAR_INVALIDPARAMERR;
    RSA *r = rsa_from_private_blob(pRSAPriKeyBlob);
    if (!r)
        return SAR_INVALIDPARAMERR;
    int need = RSA_size(r);
    if (*pulOutputLen < (ULONG)need) {
        *pulOutputLen = (ULONG)need;
        RSA_free(r);
        return SAR_INVALIDPARAMERR;
    }
    int n = RSA_private_decrypt((int)ulInputLen, pbInput, pbOutput, r,
                                RSA_NO_PADDING);
    RSA_free(r);
    if (n <= 0)
        return SAR_RSADECERR;
    *pulOutputLen = (ULONG)n;
    return SAR_OK;
}

/* ------------------------------------------------------------------ */
/* Certificates                                                        */
/* ------------------------------------------------------------------ */

static int cert_sm2_raw_matches(SOFT_CTN *c, X509 *x)
{
    X509_PUBKEY *xp = X509_get_X509_PUBKEY(x);
    ASN1_OBJECT *alg = NULL;
    const unsigned char *pk = NULL;
    int pklen = 0;
    X509_ALGOR *pa = NULL;
    if (!xp || X509_PUBKEY_get0_param(&alg, &pk, &pklen, &pa, xp) != 1)
        return 0;
    (void)pa;
    if (alg) {
        int nid = OBJ_obj2nid(alg);
        if (nid != NID_sm2 && nid != NID_X9_62_id_ecPublicKey)
            return 0;
    }
    if (!pk || pklen < 65)
        return 0;
    const unsigned char *px = pk, *py = pk + 32;
    if (pk[0] == 0x00 && pklen >= 66) {
        px = pk + 1;
        py = pk + 33;
    }
    if (*px != 0x04)
        return 0;
    px++;
    py = px + 32;
    if (py + 32 > pk + pklen)
        return 0;
    ECCPUBLICKEYBLOB *want = (ECCPUBLICKEYBLOB *)c->pub_blob;
    unsigned char wx[32], wy[32];
    ecc_coord32(want->XCoordinate, wx);
    ecc_coord32(want->YCoordinate, wy);
    return memcmp(px, wx, 32) == 0 && memcmp(py, wy, 32) == 0;
}

static int cert_pub_matches(SOFT_CTN *c, X509 *x)
{
    if (!c || !x || c->ctype == 0 || c->pub_len <= 0)
        return 0;
    EVP_PKEY *pk = X509_get_pubkey(x);
    if (!pk)
        return 0;
    int ok = 0;
    if (c->ctype == 1 && c->pub_len == (int)sizeof(ECCPUBLICKEYBLOB)) {
        EC_KEY *k = EVP_PKEY_get1_EC_KEY(pk);
        if (k) {
            ECCPUBLICKEYBLOB calc;
            ec_pub_from_key(k, &calc);
            ok = ecc_pub_equal(&calc, (ECCPUBLICKEYBLOB *)c->pub_blob);
            EC_KEY_free(k);
        }
        if (!ok)
            ok = cert_sm2_raw_matches(c, x);
    } else if (c->ctype == 2 && c->pub_len == (int)sizeof(RSAPUBLICKEYBLOB)) {
        RSA *r = EVP_PKEY_get1_RSA(pk);
        if (r) {
            RSAPUBLICKEYBLOB calc;
            rsa_to_public_blob(r, &calc);
            RSAPUBLICKEYBLOB *want = (RSAPUBLICKEYBLOB *)c->pub_blob;
            ok = calc.BitLen == want->BitLen &&
                 memcmp(calc.Modulus, want->Modulus,
                        sizeof(calc.Modulus)) == 0 &&
                 memcmp(calc.PublicExponent, want->PublicExponent,
                        sizeof(calc.PublicExponent)) == 0;
            RSA_free(r);
        }
    }
    EVP_PKEY_free(pk);
    return ok;
}

ULONG SKF_ImportCertificate(HCONTAINER hContainer, BOOL bExportSignKey,
                            BYTE *pbCert, ULONG ulCertLen)
{
    SOFT_CTN *c = (SOFT_CTN *)hContainer;
    if (!c || c->type != SOFT_HANDLE_CTN || !pbCert || !ulCertLen)
        return SAR_INVALIDPARAMERR;
    if (!c->app || (!c->app->user_logged && !c->app->admin_logged))
        return SAR_USER_NOT_LOGGED_IN;
    const unsigned char *p = pbCert;
    X509 *x = d2i_X509(NULL, &p, (long)ulCertLen);
    if (!x)
        return SAR_OBJERR;
    int ok = cert_pub_matches(c, x);
    X509_free(x);
    if (!ok)
        return SAR_OBJERR;
    return ctn_store_blob(c, bExportSignKey ? "sign_cert" : "enc_cert",
                          pbCert, ulCertLen) == 0 ? SAR_OK : SAR_FAIL;
}

ULONG SKF_ExportCertificate(HCONTAINER hContainer, BOOL bSignFlag,
                            BYTE *pbCert, ULONG *pulCertLen)
{
    SOFT_CTN *c = (SOFT_CTN *)hContainer;
    if (!c || c->type != SOFT_HANDLE_CTN || !pulCertLen)
        return SAR_INVALIDPARAMERR;
    const char *col = bSignFlag ? "sign_cert" : "enc_cert";
    char sql[128];
    snprintf(sql, sizeof(sql), "SELECT %s FROM container WHERE id=?", col);
    sqlite3_stmt *st = NULL;
    if (db_prepare(c->app->dev->db, sql, &st) != 0)
        return SAR_FAIL;
    db_bind_int(st, 1, c->id);
    if (sqlite3_step(st) != SQLITE_ROW) {
        sqlite3_finalize(st);
        return SAR_CERTNOTFOUNTERR;
    }
    unsigned char *cert = NULL;
    int certlen = 0;
    db_column_blob_dup(st, 0, &cert, &certlen);
    sqlite3_finalize(st);
    if (!cert || certlen <= 0) {
        free(cert);
        return SAR_CERTNOTFOUNTERR;
    }
    if (!pbCert || *pulCertLen < (ULONG)certlen) {
        *pulCertLen = (ULONG)certlen;
        free(cert);
        return SAR_BUFFER_TOO_SMALL;
    }
    memcpy(pbCert, cert, (size_t)certlen);
    *pulCertLen = (ULONG)certlen;
    free(cert);
    return SAR_OK;
}

/* ------------------------------------------------------------------ */
/* Token initialization                                                */
/* ------------------------------------------------------------------ */

int softskf_init_token(const char *home, const char *name,
                       const unsigned char *auth_key, int auth_key_len,
                       const char *label, const char *app,
                       const char *admin_pin, const char *user_pin,
                       int force);
int softskf_init_token(const char *home, const char *name,
                       const unsigned char *auth_key, int auth_key_len,
                       const char *label, const char *app,
                       const char *admin_pin, const char *user_pin,
                       int force)
{
    if (!home || !name || !*name || !auth_key || auth_key_len <= 0 ||
        auth_key_len > 16)
        return -1;
    if (strlen(name) >= 64)
        return -1;

    char dir[PATH_MAX];
    if (path_join(dir, sizeof(dir), home, name) != 0)
        return -1;
    if (ensure_dir_mode(home, 0700) != 0 ||
        ensure_dir_mode(dir, 0700) != 0)
        return -1;

    char dbpath[PATH_MAX], keypath[PATH_MAX];
    if (path_join(dbpath, sizeof(dbpath), dir, "token.db") != 0 ||
        path_join(keypath, sizeof(keypath), dir, "token.key") != 0)
        return -1;

    struct stat st;
    if (!force && stat(dbpath, &st) == 0)
        return -2;
    if (force) {
        char wal[PATH_MAX + 8], shm[PATH_MAX + 8];
        unlink(dbpath);
        snprintf(wal, sizeof(wal), "%s-wal", dbpath);
        snprintf(shm, sizeof(shm), "%s-shm", dbpath);
        unlink(wal);
        unlink(shm);
    }

    unsigned char store_key[32];
    if (rand_bytes(store_key, sizeof(store_key)) != 0)
        return -1;
    if (write_file_atomic(keypath, store_key, sizeof(store_key), 0600) != 0) {
        zero_mem(store_key, sizeof(store_key));
        return -1;
    }

    sqlite3 *db = NULL;
    if (db_open(dbpath, &db) != 0) {
        zero_mem(store_key, sizeof(store_key));
        return -1;
    }
    chmod(dbpath, 0600);
    if (db_exec(db, schema_sql) != 0) {
        sqlite3_close(db);
        zero_mem(store_key, sizeof(store_key));
        return -1;
    }

    unsigned char dak[16] = {0};
    memcpy(dak, auth_key, (size_t)auth_key_len);
    unsigned char auth_nonce[SOFTSKF_GCM_NONCE_LEN], auth_tag[16], auth_enc[16];
    if (wrap_with_key(store_key, "token-auth-key", dak, sizeof(dak),
                      auth_nonce, auth_enc, auth_tag) != 0) {
        sqlite3_close(db);
        zero_mem(store_key, sizeof(store_key));
        return -1;
    }

    unsigned char serial_raw[8];
    char serial[17];
    if (rand_bytes(serial_raw, sizeof(serial_raw)) != 0) {
        sqlite3_close(db);
        zero_mem(store_key, sizeof(store_key));
        return -1;
    }
    hex_encode(serial_raw, sizeof(serial_raw), serial);

    sqlite3_stmt *ts = NULL;
    if (db_prepare(db,
        "INSERT OR REPLACE INTO token(id,format_version,name,serial,label,"
        "created_at,total_space,auth_enc,auth_nonce,auth_tag,"
        "auth_retry,auth_max_retry,auth_locked) "
        "VALUES(1,?,?,?,?,?,?,?,?,?,0,15,0)", &ts) != 0) {
        sqlite3_close(db);
        zero_mem(store_key, sizeof(store_key));
        return -1;
    }
    db_bind_int(ts, 1, SOFTSKF_FORMAT_VERSION);
    db_bind_text(ts, 2, name);
    db_bind_text(ts, 3, serial);
    db_bind_text(ts, 4, label ? label : "SoftSKF");
    db_bind_int(ts, 5, (sqlite3_int64)time(NULL));
    db_bind_int(ts, 6, SOFTSKF_TOTAL_SPACE);
    db_bind_blob(ts, 7, auth_enc, sizeof(auth_enc));
    db_bind_blob(ts, 8, auth_nonce, sizeof(auth_nonce));
    db_bind_blob(ts, 9, auth_tag, sizeof(auth_tag));
    int rc = sqlite3_step(ts);
    sqlite3_finalize(ts);
    zero_mem(dak, sizeof(dak));
    zero_mem(auth_enc, sizeof(auth_enc));

    if (rc != SQLITE_DONE) {
        sqlite3_close(db);
        zero_mem(store_key, sizeof(store_key));
        return -1;
    }

    if (app && *app) {
        if (!admin_pin || !*admin_pin || !user_pin || !*user_pin) {
            sqlite3_close(db);
            zero_mem(store_key, sizeof(store_key));
            return -1;
        }
        SOFT_DEV d;
        memset(&d, 0, sizeof(d));
        d.type = SOFT_HANDLE_DEV;
        d.db = db;
        snprintf(d.name, sizeof(d.name), "%s", name);
        memcpy(d.store_key, store_key, sizeof(d.store_key));
        ULONG ar = app_create_internal(&d, app, admin_pin, 6,
                                       user_pin, 6,
                                       SECURE_ANYONE_ACCOUNT, NULL);
        if (ar != SAR_OK) {
            sqlite3_close(db);
            zero_mem(store_key, sizeof(store_key));
            return -1;
        }
    }

    sqlite3_close(db);
    zero_mem(store_key, sizeof(store_key));
    return 0;
}
