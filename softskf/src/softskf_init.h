#ifndef SOFTSKF_INIT_H
#define SOFTSKF_INIT_H

#ifdef __cplusplus
extern "C" {
#endif

int softskf_init_token(const char *home, const char *name,
                       const unsigned char *auth_key, int auth_key_len,
                       const char *label, const char *app,
                       const char *admin_pin, const char *user_pin,
                       int force);

#ifdef __cplusplus
}
#endif
#endif
