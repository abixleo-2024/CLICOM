/*
 * server/src/main.c — CLICOM Server Entry Point
 *
 * CLICOM - CLI Communication System
 * Software version : 2.0.0
 * Protocol         : CLIPv1.0 (separate versioning)
 *
 * Phase 0: Scaffold only.
 * Networking, node registry, channels, sessions, PTT arbitration,
 * speech analysis, admin, and storage are NOT implemented yet.
 *
 * Supported flags:
 *   --version, -v   Print version information and exit
 *   --help,    -h   Print usage and exit
 *   --test          Run Phase 0 self-test and exit (used by ctest)
 *
 * Eventually:
 *   --config <path>   Path to server.conf
 *   --bind <addr>     Override bind address
 *   --port <port>     Override port (default 8765)
 *   --admin-port <p>  Override admin port (default 8766)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <stdbool.h>

#include "clip_version.h"
#include "clip_types.h"
#include "clip_protocol.h"
#include "clip_errors.h"
#include "clip_log.h"
#include "server.h"
#include "clip_admin.h"
#include "clip_admin_db.h"
#include "clip_crypto.h"
#include <openssl/crypto.h>

#ifdef _WIN32
#include <conio.h>
#else
#include <termios.h>
#include <unistd.h>
#endif

/* ── Signal handling ────────────────────────────────────────────────────── */
static volatile bool g_stop_flag = false;

static void handle_signal(int sig)
{
    (void)sig;
    g_stop_flag = true;
}

/* ── Forward declarations ───────────────────────────────────────────────── */
static void print_banner(void);
static void print_version(void);
static void print_help(const char* argv0);
static int  run_self_test(void);

static int read_password_no_echo(const char* prompt, char* out_buf, size_t buf_len)
{
    printf("%s", prompt);
    fflush(stdout);

#ifdef _WIN32
    size_t idx = 0;
    while (1) {
        int c = _getch();
        if (c == '\r' || c == '\n') {
            printf("\n");
            break;
        } else if (c == '\b' || c == 127) {
            if (idx > 0) {
                idx--;
            }
        } else if (c == 3) { /* Ctrl+C */
            printf("\n");
            return -1;
        } else if (c >= 32 && c <= 126) {
            if (idx + 1 < buf_len) {
                out_buf[idx++] = (char)c;
            }
        }
    }
    out_buf[idx] = '\0';
    return (int)idx;
#else
    struct termios old_t, new_t;
    if (tcgetattr(STDIN_FILENO, &old_t) != 0) return -1;
    new_t = old_t;
    new_t.c_lflag &= ~(ECHO);
    if (tcsetattr(STDIN_FILENO, TCSAFLUSH, &new_t) != 0) return -1;

    if (!fgets(out_buf, (int)buf_len, stdin)) {
        tcsetattr(STDIN_FILENO, TCSAFLUSH, &old_t);
        printf("\n");
        return -1;
    }
    tcsetattr(STDIN_FILENO, TCSAFLUSH, &old_t);
    printf("\n");

    size_t len = strlen(out_buf);
    while (len > 0 && (out_buf[len - 1] == '\r' || out_buf[len - 1] == '\n')) {
        out_buf[--len] = '\0';
    }
    return (int)len;
#endif
}

static int do_create_admin(const char* db_path, const char* username)
{
    if (!username || username[0] == '\0') {
        fprintf(stderr, "Error: --create-admin requires a non-empty username.\n");
        return 1;
    }

    ClipIdentityDb* id_db = NULL;
    ClipError err = clip_identity_db_open(&id_db, db_path);
    if (err != CLIP_OK) {
        fprintf(stderr, "Error: Failed to open database '%s': %s\n", db_path, clip_error_string(err));
        return 1;
    }

    sqlite3* db = clip_identity_get_sqlite(id_db);
    size_t admin_count = 0;
    clip_admin_db_count_admins(db, &admin_count);
    if (admin_count > 0) {
        fprintf(stderr, "Error: Initial SUPER_ADMIN already provisioned. Additional administrators must be created by an authenticated SUPER_ADMIN via client protocol.\n");
        clip_identity_db_close(id_db);
        return 1;
    }

    char pass1[128] = {0};
    char pass2[128] = {0};

    const char* env_pass = getenv("CLICOM_BOOTSTRAP_ADMIN_PASSWORD");
    if (env_pass && env_pass[0] != '\0') {
        strncpy(pass1, env_pass, sizeof(pass1) - 1);
    } else {
        char prompt[128];
        snprintf(prompt, sizeof(prompt), "Enter password for SUPER_ADMIN '%s' (min 10 chars): ", username);
        if (read_password_no_echo(prompt, pass1, sizeof(pass1)) < 0) {
            clip_identity_db_close(id_db);
            return 1;
        }
        if (read_password_no_echo("Confirm password: ", pass2, sizeof(pass2)) < 0) {
            OPENSSL_cleanse(pass1, sizeof(pass1));
            clip_identity_db_close(id_db);
            return 1;
        }
        if (strcmp(pass1, pass2) != 0) {
            fprintf(stderr, "Error: Passwords do not match.\n");
            OPENSSL_cleanse(pass1, sizeof(pass1));
            OPENSSL_cleanse(pass2, sizeof(pass2));
            clip_identity_db_close(id_db);
            return 1;
        }
        OPENSSL_cleanse(pass2, sizeof(pass2));
    }

    if (strlen(pass1) < CLIP_ADMIN_PASSWORD_MIN_LEN) {
        fprintf(stderr, "Error: Password must be at least %u characters.\n", (unsigned int)CLIP_ADMIN_PASSWORD_MIN_LEN);
        OPENSSL_cleanse(pass1, sizeof(pass1));
        clip_identity_db_close(id_db);
        return 1;
    }

    ClipAdminUser user;
    memset(&user, 0, sizeof(user));
    clip_crypto_uuid_generate((ClipUuid*)user.admin_uuid);
    strncpy(user.username, username, sizeof(user.username) - 1);
    user.role = CLIP_ADMIN_PERM_SUPER_ADMIN;
    user.iterations = CLIP_ADMIN_DEFAULT_ITERATIONS;
    clip_crypto_random_bytes(user.salt, CLIP_ADMIN_SALT_BYTES);

    err = clip_admin_hash_password(pass1, user.salt, user.iterations, user.verifier);
    OPENSSL_cleanse(pass1, sizeof(pass1));

    if (err != CLIP_OK) {
        fprintf(stderr, "Error: Failed to compute password verifier: %s\n", clip_error_string(err));
        clip_identity_db_close(id_db);
        return 1;
    }

    err = clip_admin_db_create_admin(db, &user);
    clip_identity_db_close(id_db);

    if (err != CLIP_OK) {
        fprintf(stderr, "Error: Failed to store administrator in database: %s\n", clip_error_string(err));
        return 1;
    }

    printf("Successfully created first administrator '%s' as SUPER_ADMIN.\n", username);
    return 0;
}

/* ── Entry point ────────────────────────────────────────────────────────── */

int main(int argc, char* argv[])
{
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);

    const char* bind_host   = CLIP_DEFAULT_HOST;
    const char* db_path     = CLIP_DEFAULT_IDENTITY_DB;
    int         port        = CLIP_DEFAULT_PORT;
    size_t      max_clients = CLIP_MAX_CLIENTS_DEFAULT;
    int         do_test     = 0;
    bool        use_tls     = true;
    const char* cert_file   = "certs/server.crt";
    const char* key_file    = "certs/server.key";
    const char* create_admin_user = NULL;
    int         i;

    /* ── Argument parsing ─────────────────────────────────────────────── */
    for (i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--version") == 0 || strcmp(argv[i], "-v") == 0) {
            print_version();
            return 0;
        } else if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0) {
            print_help(argv[0]);
            return 0;
        } else if (strcmp(argv[i], "--test") == 0) {
            do_test = 1;
        } else if (strcmp(argv[i], "--create-admin") == 0) {
            if (i + 1 >= argc) {
                fprintf(stderr, "Error: --create-admin requires a username argument.\n");
                print_help(argv[0]);
                return 1;
            }
            create_admin_user = argv[++i];
        } else if (strcmp(argv[i], "--cert") == 0) {
            if (i + 1 >= argc) {
                fprintf(stderr, "Error: --cert requires an argument.\n");
                print_help(argv[0]);
                return 1;
            }
            cert_file = argv[++i];
        } else if (strcmp(argv[i], "--key") == 0) {
            if (i + 1 >= argc) {
                fprintf(stderr, "Error: --key requires an argument.\n");
                print_help(argv[0]);
                return 1;
            }
            key_file = argv[++i];
        } else if (strcmp(argv[i], "--insecure-plaintext") == 0 || strcmp(argv[i], "--no-tls") == 0) {
            use_tls = false;
        } else if (strcmp(argv[i], "--tls") == 0) {
            use_tls = true;
        } else if (strcmp(argv[i], "--bind") == 0) {
            if (i + 1 >= argc) {
                fprintf(stderr, "Error: --bind requires an argument.\n");
                print_help(argv[0]);
                return 1;
            }
            bind_host = argv[++i];
        } else if (strcmp(argv[i], "--db") == 0) {
            if (i + 1 >= argc) {
                fprintf(stderr, "Error: --db requires an argument.\n");
                print_help(argv[0]);
                return 1;
            }
            db_path = argv[++i];
        } else if (strcmp(argv[i], "--port") == 0) {
            if (i + 1 >= argc) {
                fprintf(stderr, "Error: --port requires an argument.\n");
                print_help(argv[0]);
                return 1;
            }
            port = atoi(argv[++i]);
        } else if (strcmp(argv[i], "--max-clients") == 0) {
            if (i + 1 >= argc) {
                fprintf(stderr, "Error: --max-clients requires an argument.\n");
                print_help(argv[0]);
                return 1;
            }
            max_clients = (size_t)atoi(argv[++i]);
        } else {
            fprintf(stderr, "Error: Unknown option: %s\n", argv[i]);
            print_help(argv[0]);
            return 1;
        }
    }

    /* ── Bootstrap administrator if requested ────────────────────────── */
    if (create_admin_user) {
        return do_create_admin(db_path, create_admin_user);
    }

    /* ── Logging init ─────────────────────────────────────────────────── */
    clip_log_init(CLIP_LOG_INFO, NULL);

    /* ── Self-test mode (invoked by ctest) ───────────────────────────── */
    if (do_test) {
        int result = run_self_test();
        clip_log_close();
        return result;
    }

    /* ── Validate TLS certificate files if TLS is enabled (default) ──── */
    if (use_tls) {
        FILE* fc = fopen(cert_file, "r");
        if (!fc) {
            fprintf(stderr, "Error: TLS server certificate '%s' not found.\n"
                            "CLICOM requires TLS 1.3 by default.\n"
                            "To run in unencrypted mode for testing, pass --insecure-plaintext.\n",
                    cert_file);
            clip_log_close();
            return 1;
        }
        fclose(fc);

        FILE* fk = fopen(key_file, "r");
        if (!fk) {
            fprintf(stderr, "Error: TLS server private key '%s' not found.\n"
                            "CLICOM requires TLS 1.3 by default.\n"
                            "To run in unencrypted mode for testing, pass --insecure-plaintext.\n",
                    key_file);
            clip_log_close();
            return 1;
        }
        fclose(fk);
    }

    /* ── Normal startup & networking ─────────────────────────────────── */
    print_banner();

    ClipServerConfig srv_cfg;
    clip_server_config_init_default(&srv_cfg);
    strncpy(srv_cfg.bind_host, bind_host, sizeof(srv_cfg.bind_host) - 1);
    strncpy(srv_cfg.db_path, db_path, sizeof(srv_cfg.db_path) - 1);
    srv_cfg.port = (uint16_t)port;
    srv_cfg.max_clients = max_clients;
    srv_cfg.use_tls = use_tls;
    if (use_tls) {
        strncpy(srv_cfg.cert_file, cert_file, sizeof(srv_cfg.cert_file) - 1);
        strncpy(srv_cfg.key_file, key_file, sizeof(srv_cfg.key_file) - 1);
    }

    ClipServer server;
    ClipError init_err = clip_server_init(&server, &srv_cfg);
    if (init_err != CLIP_OK) {
        CLIP_LOGE("Failed to initialize server: %s", clip_error_string(init_err));
        clip_log_close();
        return 1;
    }

    ClipError start_err = clip_server_start(&server);
    if (start_err != CLIP_OK) {
        CLIP_LOGE("Failed to start server: %s", clip_error_string(start_err));
        clip_server_cleanup(&server);
        clip_log_close();
        return 1;
    }

    signal(SIGINT, handle_signal);
#ifdef SIGTERM
    signal(SIGTERM, handle_signal);
#endif

    CLIP_LOGI("Server event loop started (press Ctrl+C to stop)...");
    ClipError run_err = clip_server_run(&server, &g_stop_flag);
    if (run_err != CLIP_OK) {
        CLIP_LOGE("Server event loop error: %s", clip_error_string(run_err));
    }

    CLIP_LOGI("Server shutting down cleanly...");
    clip_server_cleanup(&server);
    clip_log_close();
    return (run_err == CLIP_OK) ? 0 : 1;
}

/* ── Banner ─────────────────────────────────────────────────────────────── */

static void print_banner(void)
{
    printf("\n");
    printf("============================================================\n");
    printf("                   C L I C O M  SERVER\n");
    printf("                   CLI COMMUNICATION\n");
    printf("                       v%s\n", CLICOM_VERSION_STRING);
    printf("============================================================\n");
    printf("  Protocol  : CLIPv%s\n", CLIP_PROTOCOL_VERSION_STRING);
    printf("  Platform  : %s\n",      CLICOM_TARGET_PLATFORM);
    printf("  Built     : %s\n",      CLICOM_BUILD_TIMESTAMP);
    printf("============================================================\n");
    printf("  Authority : node presence | channels | PTT | admin actions\n");
    printf("  Speech    : server-mediated (disclosed in SESSION_START)\n");
    printf("  Security  : advisory events only — admin review required\n");
    printf("============================================================\n");
    printf("\n");
}

static void print_version(void)
{
    printf("clicom-server %s (protocol CLIPv%s, platform %s)\n",
           CLICOM_VERSION_STRING,
           CLIP_PROTOCOL_VERSION_STRING,
           CLICOM_TARGET_PLATFORM);
}

static void print_help(const char* argv0)
{
    printf("Usage: %s [OPTIONS]\n\n", argv0);
    printf("Options:\n");
    printf("  --version, -v        Print version and exit\n");
    printf("  --help,    -h        Print this help and exit\n");
    printf("  --test               Run Phase 0 self-test and exit\n");
    printf("  --create-admin <usr> Create the initial SUPER_ADMIN and exit\n");
    printf("  --bind <addr>        Bind address (default %s)\n", CLIP_DEFAULT_HOST);
    printf("  --port <port>        Port (default %d)\n", CLIP_DEFAULT_PORT);
    printf("  --max-clients <num>  Maximum concurrent clients (default %d)\n", CLIP_MAX_CLIENTS_DEFAULT);
    printf("  --cert <path>        Path to TLS server certificate (default certs/server.crt)\n");
    printf("  --key <path>         Path to TLS server private key (default certs/server.key)\n");
    printf("  --insecure-plaintext Run without TLS (development/test mode only)\n");
    printf("  --no-tls             Alias for --insecure-plaintext\n");
    printf("\nFuture options (Phase 3+):\n");
    printf("  --config <path>      Path to server.conf\n");
    printf("  --admin-port <port>  Admin port (default 8766)\n");
    printf("\n");
}

/* ── Self-test (Phase 0) ────────────────────────────────────────────────── */

static int run_self_test(void)
{
    int pass_count = 0;
    int fail_count = 0;

#define CHECK(label, condition) do { \
    if (condition) { \
        printf("  PASS  %s\n", label); \
        pass_count++; \
    } else { \
        printf("  FAIL  %s\n", label); \
        fail_count++; \
    } \
} while (0)

    printf("CLICOM Server — Phase 0 Self-Test\n");
    printf("==================================\n");

    CHECK("Software version major == 2",  CLICOM_VERSION_MAJOR == 2);
    CHECK("Software version minor == 0",  CLICOM_VERSION_MINOR == 0);
    CHECK("Software version patch == 0",  CLICOM_VERSION_PATCH == 0);
    CHECK("Protocol version major == 1",  CLIP_PROTOCOL_VERSION_MAJOR == 1);
    CHECK("Protocol version minor == 0",  CLIP_PROTOCOL_VERSION_MINOR == 0);
    CHECK("Protocol magic == 0x434C4950", CLIP_PROTOCOL_MAGIC == 0x434C4950u);
    CHECK("Header size == 36 bytes",      CLIP_HEADER_SIZE == 36u);
    CHECK("Session UUID size == 16",      CLIP_SESSION_UUID_SIZE == 16u);
    CHECK("Software version != protocol version string",
          strcmp(CLICOM_VERSION_STRING, CLIP_PROTOCOL_VERSION_STRING) != 0);
    CHECK("Error string for CLIP_OK not empty",
          clip_error_string(CLIP_OK) != NULL &&
          clip_error_string(CLIP_OK)[0] != '\0');

    printf("==================================\n");
    printf("Result : %d passed", pass_count);
    if (fail_count > 0) {
        printf(", %d FAILED", fail_count);
    }
    printf("\n\n");

#undef CHECK
    return (fail_count == 0) ? 0 : 1;
}
