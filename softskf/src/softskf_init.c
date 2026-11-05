#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "softskf_init.h"

static void usage(const char *prog)
{
    fprintf(stderr,
        "Usage: %s [options]\n"
        "  --home DIR          token root (default: $SOFTSKF_HOME or ~/.softskf)\n"
        "  --name NAME         token name (default: softskf0)\n"
        "  --auth-key KEY      device auth key, 1..16 bytes (required)\n"
        "  --label LABEL       token label\n"
        "  --app NAME          create an application with this name\n"
        "  --admin-pin PIN     administrator PIN (required with --app)\n"
        "  --user-pin PIN      user PIN (required with --app)\n"
        "  --force             overwrite an existing token\n"
        "  --help              show this help\n", prog);
}

int main(int argc, char **argv)
{
    const char *home = getenv("SOFTSKF_HOME");
    char homebuf[4096];
    if (!home || !*home) {
        const char *h = getenv("HOME");
        if (!h || !*h)
            h = ".";
        snprintf(homebuf, sizeof(homebuf), "%s/.softskf", h);
        home = homebuf;
    }

    const char *name = "softskf0";
    const char *auth = getenv("SOFTSKF_DEVAUTH_KEY");
    const char *label = "SoftSKF";
    const char *app = NULL;
    const char *admin_pin = NULL;
    const char *user_pin = NULL;
    int force = 0;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--home") == 0 && i + 1 < argc)
            home = argv[++i];
        else if (strcmp(argv[i], "--name") == 0 && i + 1 < argc)
            name = argv[++i];
        else if (strcmp(argv[i], "--auth-key") == 0 && i + 1 < argc)
            auth = argv[++i];
        else if (strcmp(argv[i], "--label") == 0 && i + 1 < argc)
            label = argv[++i];
        else if (strcmp(argv[i], "--app") == 0 && i + 1 < argc)
            app = argv[++i];
        else if (strcmp(argv[i], "--admin-pin") == 0 && i + 1 < argc)
            admin_pin = argv[++i];
        else if (strcmp(argv[i], "--user-pin") == 0 && i + 1 < argc)
            user_pin = argv[++i];
        else if (strcmp(argv[i], "--force") == 0)
            force = 1;
        else if (strcmp(argv[i], "--help") == 0) {
            usage(argv[0]);
            return 0;
        } else {
            fprintf(stderr, "unknown option: %s\n", argv[i]);
            usage(argv[0]);
            return 2;
        }
    }

    if (!auth || !*auth) {
        fprintf(stderr,
            "error: --auth-key or SOFTSKF_DEVAUTH_KEY is required\n");
        return 2;
    }
    size_t alen = strlen(auth);
    if (alen == 0 || alen > 16) {
        fprintf(stderr, "error: device auth key must be 1..16 bytes\n");
        return 2;
    }
    if (app && (!admin_pin || !admin_pin[0] || !user_pin || !user_pin[0])) {
        fprintf(stderr,
            "error: --admin-pin and --user-pin are required with --app\n");
        return 2;
    }

    int rc = softskf_init_token(home, name, (const unsigned char *)auth,
                                (int)alen, label, app, admin_pin, user_pin,
                                force);
    if (rc == -2) {
        fprintf(stderr, "error: token already exists (use --force)\n");
        return 1;
    }
    if (rc != 0) {
        fprintf(stderr, "error: failed to initialize token\n");
        return 1;
    }
    printf("token initialized: %s/%s\n", home, name);
    if (app)
        printf("application: %s (admin/user PIN initialized)\n", app);
    return 0;
}
