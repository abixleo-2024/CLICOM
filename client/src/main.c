/*
 * client/src/main.c — CLICOM Client Entry Point
 *
 * CLICOM - CLI Communication System
 * Software version : 2.0.0
 * Protocol         : CLIPv1.0 (separate versioning)
 *
 * Phase 0: Scaffold only.
 * Networking, dashboard, audio, PTT, and channels are NOT implemented yet.
 *
 * Supported flags:
 *   --node <name>   Set node display name (e.g. NODE-A)
 *   --version, -v   Print version information and exit
 *   --help,    -h   Print usage and exit
 *   --test          Run Phase 0 self-test and exit (used by ctest)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "clip_version.h"
#include "clip_types.h"
#include "clip_protocol.h"
#include "clip_errors.h"
#include "clip_log.h"
#include "clip_credentials.h"
#include "network.h"
#include "clip_telemetry.h"
#include "clip_audio.h"
#include "clip_captions.h"
#include "clip_notes_client.h"
#include "clip_notes.h"
#include "clip_security_client.h"
#include "security_analyzer.h"
#include "speech_analyzer.h"
#include "clip_admin_client.h"
#include "clip_admin.h"
#include <openssl/crypto.h>
#include <mmsystem.h>

#ifdef _WIN32
#include <conio.h>
#else
#include <termios.h>
#include <unistd.h>
#endif

/* ── Forward declarations ───────────────────────────────────────────────── */
static void print_banner(void);
static void print_version(void);
static void print_help(const char* argv0);
static int  run_self_test(void);
static int  run_audio_test(void);

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

static char* console_read_line_pumped(ClipClientNet* net, char* buf, size_t buf_len)
{
    if (!buf || buf_len == 0) return NULL;
    buf[0] = '\0';

#ifdef _WIN32
    size_t idx = 0;
    while (1) {
        if (net && net->is_connected) {
            clip_client_pump_events(net, 20);
        } else {
            Sleep(20);
        }

        while (_kbhit()) {
            int c = _getch();
            if (c == 0 || c == 0xE0) {
                /* Extended key prefix (arrow keys, function keys) - consume second code */
                if (_kbhit()) {
                    (void)_getch();
                }
                continue;
            }

            if (c == '\r' || c == '\n') {
                _putch('\r');
                _putch('\n');
                buf[idx] = '\0';
                return buf;
            } else if (c == '\b' || c == 127) {
                if (idx > 0) {
                    idx--;
                    _putch('\b');
                    _putch(' ');
                    _putch('\b');
                }
            } else if (c == 3) { /* Ctrl+C */
                _putch('^');
                _putch('C');
                _putch('\r');
                _putch('\n');
                return NULL;
            } else if (c >= 32 && c <= 126) {
                if (idx + 1 < buf_len) {
                    buf[idx++] = (char)c;
                    _putch(c);
                }
            }
        }
    }
#else
    return fgets(buf, (int)buf_len, stdin);
#endif
}

/* ── Phase 13 & 15: Captions & Security Transcript Submission ───────────── */

typedef struct {
    ClipUuid client_uuid;
    char     client_name[CLIP_DISPLAY_NAME_MAX];
} ClientSpeakerContext;

static ClipCaptionBuffer    g_caption_buf;
static ClientSpeakerContext g_speaker_ctx = {0};
static ClipClientNet*       g_active_client = NULL;

static const char* client_speaker_resolver(const ClipUuid* speaker_uuid, void* user_data)
{
    ClientSpeakerContext* ctx = (ClientSpeakerContext*)user_data;
    if (!ctx || !speaker_uuid) return NULL;
    if (memcmp(ctx->client_uuid.bytes, speaker_uuid->bytes, CLIP_UUID_BYTES) == 0) {
        if (ctx->client_name[0] != '\0') {
            return ctx->client_name;
        }
    }
    return NULL;
}

static void on_client_transcript_received(const SpeechTranscriptResult* result, void* user_data)
{
    if (!result) return;

    /* 1. Update Live Captions circular buffer (Phase 13) */
    clip_captions_transcript_callback(result, user_data);

    /* 2. Submit finalized transcript for server-side security analysis (Phase 15) */
    if (result->is_final && g_active_client &&
        clip_client_get_speech_mode(g_active_client) == CLIP_SPEECH_MODE_SERVER_MEDIATED &&
        !clip_uuid_is_zero(&result->session_uuid)) {
        clip_client_submit_security_transcript(g_active_client,
                                               &result->session_uuid,
                                               &result->speaker_node_uuid,
                                               result->text,
                                               result->start_time_ms);
    }
}


/* ── Phase 10: Real-Time Audio Streaming Handlers ───────────────────────── */

typedef struct {
    ClipClientNet* net;
    ClipUuid       session_uuid;
} ClientAudioSender;

static ClientAudioSender g_audio_sender = {0};

static void on_client_audio_captured(const int16_t* pcm,
                                     size_t sample_count,
                                     uint64_t timestamp_ms,
                                     void* user_data)
{
    (void)user_data;
    if (!g_audio_sender.net || !pcm || sample_count == 0) return;
    if (clip_uuid_is_zero(&g_audio_sender.session_uuid)) return;
    if (!g_audio_sender.net->ptt_floor_held) return;

    clip_client_send_audio_frame(g_audio_sender.net, &g_audio_sender.session_uuid, timestamp_ms, pcm, sample_count);
}

static void on_peer_audio_received(const ClipUuid* session_uuid,
                                   uint64_t timestamp_ms,
                                   const int16_t* pcm,
                                   size_t sample_count,
                                   void* user_data)
{
    (void)timestamp_ms;
    (void)session_uuid;
    ClipAudioEngine* engine = (ClipAudioEngine*)user_data;
    if (engine && pcm && sample_count > 0) {
        /* Route received PCM through existing Phase 9 ClipAudioEngine playback abstraction */
        clip_audio_play_frame(engine, pcm, sample_count);
    }
}

static void on_client_disconnected(ClipClientNet* net, void* user_data)
{
    (void)net;
    ClipAudioEngine* engine = (ClipAudioEngine*)user_data;
    if (engine) {
        clip_audio_on_floor_released(engine);
    }
    clip_uuid_zero(&g_audio_sender.session_uuid);
    CLIP_LOGI("Disconnect safety: Stopped microphone capture and cleared local PTT floor");
}

/* ── Entry point ────────────────────────────────────────────────────────── */

int main(int argc, char* argv[])
{
    const char* node_display_name = "NODE-A";
    const char* host              = CLIP_DEFAULT_HOST;
    const char* cred_file         = CLIP_DEFAULT_CREDENTIAL_FILE;
    int         port              = CLIP_DEFAULT_PORT;
    int         do_test           = 0;
    int         do_audio_test     = 0;
    int         do_reregister     = 0;
    const char* action_create_chan= NULL;
    const char* action_join_chan  = NULL;
    const char* action_start_sess = NULL;
    const char* action_start_sess_conn = NULL;
    const char* action_end_sess   = NULL;
    const char* action_ptt_req    = NULL;
    const char* action_ptt_rel    = NULL;
    const char* action_ptt_status = NULL;
    const char* action_ptt_console= NULL;
    const char* action_members    = NULL;
    const char* action_req_chan   = NULL;
    const char* action_req_target = NULL;
    const char* action_accept_conn= NULL;
    const char* action_decline_con= NULL;
    int         do_list_chans     = 0;
    int         do_list_conns     = 0;
    int         do_list_logs      = 0;
    const char* action_get_log    = NULL;
    const char* action_list_notes = NULL;
    const char* action_add_note_sess = NULL;
    const char* action_add_note_text = NULL;
    const char* action_search_notes_sess = NULL;
    const char* action_search_notes_query = NULL;
    const char* action_save_captions = NULL;
    int         do_list_events       = 0;
    const char* action_list_events_sess = NULL;
    const char* action_get_event     = NULL;
    const char* admin_user           = NULL;
    const char* admin_pass           = NULL;
    const char* admin_reason         = NULL;
    int         do_admin_events      = 0;
    const char* admin_events_status  = NULL;
    int         do_admin_audit       = 0;
    uint32_t    admin_audit_limit    = 0;
    const char* action_review_ev     = NULL;
    const char* action_false_pos     = NULL;
    const char* action_disc_node     = NULL;
    const char* action_restr_node    = NULL;
    const char* action_unrestr_node  = NULL;
    const char* action_ban_node      = NULL;
    const char* action_unban_node    = NULL;
    const char* action_lock_chan     = NULL;
    const char* action_unlock_chan   = NULL;
    const char* action_new_admin_user= NULL;
    const char* action_new_admin_role= NULL;
    const char* action_new_admin_pass= NULL;
    int         do_menu           = 0;
    bool        use_tls           = true;
    const char* ca_file           = "certs/ca.crt";
    const char* server_name       = NULL;
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
        } else if (strcmp(argv[i], "--audio-test") == 0) {
            do_audio_test = 1;
        } else if (strcmp(argv[i], "--re-register") == 0) {
            do_reregister = 1;
        } else if (strcmp(argv[i], "--menu") == 0) {
            do_menu = 1;
        } else if (strcmp(argv[i], "--create-channel") == 0 || strcmp(argv[i], "--create-chan") == 0) {
            if (i + 1 >= argc) {
                fprintf(stderr, "Error: --create-channel requires a channel name.\n");
                return 1;
            }
            action_create_chan = argv[++i];
        } else if (strcmp(argv[i], "--join-channel") == 0 || strcmp(argv[i], "--join-chan") == 0) {
            if (i + 1 >= argc) {
                fprintf(stderr, "Error: --join-channel requires a join key.\n");
                return 1;
            }
            action_join_chan = argv[++i];
        } else if (strcmp(argv[i], "--list-channels") == 0 || strcmp(argv[i], "--list-chan") == 0) {
            do_list_chans = 1;
        } else if (strcmp(argv[i], "--members") == 0) {
            if (i + 1 >= argc) {
                fprintf(stderr, "Error: --members requires a channel UUID.\n");
                return 1;
            }
            action_members = argv[++i];
        } else if (strcmp(argv[i], "--request-conn") == 0) {
            if (i + 2 >= argc) {
                fprintf(stderr, "Error: --request-conn requires <channel_uuid> <target_node_uuid>.\n");
                return 1;
            }
            action_req_chan = argv[++i];
            action_req_target = argv[++i];
        } else if (strcmp(argv[i], "--accept-conn") == 0) {
            if (i + 1 >= argc) {
                fprintf(stderr, "Error: --accept-conn requires a connection UUID.\n");
                return 1;
            }
            action_accept_conn = argv[++i];
        } else if (strcmp(argv[i], "--decline-conn") == 0) {
            if (i + 1 >= argc) {
                fprintf(stderr, "Error: --decline-conn requires a connection UUID.\n");
                return 1;
            }
            action_decline_con = argv[++i];
        } else if (strcmp(argv[i], "--list-conns") == 0) {
            do_list_conns = 1;
        } else if (strcmp(argv[i], "--start-session-conn") == 0 || strcmp(argv[i], "session-start") == 0) {
            if (i + 1 >= argc) {
                fprintf(stderr, "Error: --start-session-conn requires a connection UUID.\n");
                return 1;
            }
            action_start_sess_conn = argv[++i];
        } else if (strcmp(argv[i], "--start-session") == 0) {
            if (i + 1 >= argc) {
                fprintf(stderr, "Error: --start-session requires a channel UUID.\n");
                return 1;
            }
            action_start_sess = argv[++i];
        } else if (strcmp(argv[i], "--end-session") == 0 || strcmp(argv[i], "session-end") == 0) {
            if (i + 1 >= argc) {
                fprintf(stderr, "Error: --end-session requires a session UUID.\n");
                return 1;
            }
            action_end_sess = argv[++i];
        } else if (strcmp(argv[i], "--ptt-request") == 0 || strcmp(argv[i], "ptt-request") == 0) {
            if (i + 1 >= argc) {
                fprintf(stderr, "Error: --ptt-request requires a session UUID.\n");
                return 1;
            }
            action_ptt_req = argv[++i];
        } else if (strcmp(argv[i], "--ptt-release") == 0 || strcmp(argv[i], "ptt-release") == 0) {
            if (i + 1 >= argc) {
                fprintf(stderr, "Error: --ptt-release requires a session UUID.\n");
                return 1;
            }
            action_ptt_rel = argv[++i];
        } else if (strcmp(argv[i], "--ptt-status") == 0 || strcmp(argv[i], "ptt-status") == 0) {
            if (i + 1 >= argc) {
                fprintf(stderr, "Error: --ptt-status requires a session UUID.\n");
                return 1;
            }
            action_ptt_status = argv[++i];
        } else if (strcmp(argv[i], "--ptt") == 0 || strcmp(argv[i], "ptt") == 0) {
            if (i + 1 >= argc) {
                fprintf(stderr, "Error: --ptt requires a session UUID.\n");
                return 1;
            }
            action_ptt_console = argv[++i];
        } else if (strcmp(argv[i], "--list-logs") == 0 || strcmp(argv[i], "--logs") == 0) {
            do_list_logs = 1;
        } else if (strcmp(argv[i], "--get-log") == 0) {
            if (i + 1 >= argc) {
                fprintf(stderr, "Error: --get-log requires a session UUID.\n");
                return 1;
            }
            action_get_log = argv[++i];
        } else if (strcmp(argv[i], "--list-notes") == 0 || strcmp(argv[i], "--notes") == 0) {
            if (i + 1 >= argc) {
                fprintf(stderr, "Error: --list-notes requires a session UUID.\n");
                return 1;
            }
            action_list_notes = argv[++i];
        } else if (strcmp(argv[i], "--create-note") == 0 || strcmp(argv[i], "--add-note") == 0) {
            if (i + 2 >= argc) {
                fprintf(stderr, "Error: --create-note requires <session_uuid> <note_text>.\n");
                return 1;
            }
            action_add_note_sess = argv[++i];
            action_add_note_text = argv[++i];
        } else if (strcmp(argv[i], "--search-notes") == 0) {
            if (i + 2 >= argc) {
                fprintf(stderr, "Error: --search-notes requires <session_uuid> <query>.\n");
                return 1;
            }
            action_search_notes_sess = argv[++i];
            action_search_notes_query = argv[++i];
        } else if (strcmp(argv[i], "--save-captions") == 0) {
            if (i + 1 >= argc) {
                fprintf(stderr, "Error: --save-captions requires a session UUID.\n");
                return 1;
            }
            action_save_captions = argv[++i];
        } else if (strcmp(argv[i], "--list-events") == 0 || strcmp(argv[i], "--security-events") == 0) {
            do_list_events = 1;
            if (i + 1 < argc && argv[i + 1][0] != '-') {
                action_list_events_sess = argv[++i];
            }
        } else if (strcmp(argv[i], "--get-event") == 0) {
            if (i + 1 >= argc) {
                fprintf(stderr, "Error: --get-event requires an event ID or UUID.\n");
                return 1;
            }
            action_get_event = argv[++i];
        } else if (strcmp(argv[i], "--admin-login") == 0) {
            if (i + 1 >= argc) {
                fprintf(stderr, "Error: --admin-login requires a username.\n");
                return 1;
            }
            admin_user = argv[++i];
        } else if (strcmp(argv[i], "--admin-pass") == 0) {
            if (i + 1 >= argc) {
                fprintf(stderr, "Error: --admin-pass requires a password.\n");
                return 1;
            }
            admin_pass = argv[++i];
        } else if (strcmp(argv[i], "--admin-reason") == 0 || strcmp(argv[i], "--reason") == 0) {
            if (i + 1 >= argc) {
                fprintf(stderr, "Error: --admin-reason requires a reason string.\n");
                return 1;
            }
            admin_reason = argv[++i];
        } else if (strcmp(argv[i], "--admin-events") == 0) {
            do_admin_events = 1;
            if (i + 1 < argc && argv[i + 1][0] != '-') {
                admin_events_status = argv[++i];
            }
        } else if (strcmp(argv[i], "--admin-audit") == 0) {
            do_admin_audit = 1;
            if (i + 1 < argc && argv[i + 1][0] != '-') {
                admin_audit_limit = (uint32_t)strtoul(argv[++i], NULL, 10);
            }
        } else if (strcmp(argv[i], "--review-event") == 0) {
            if (i + 1 >= argc) {
                fprintf(stderr, "Error: --review-event requires an event ID.\n");
                return 1;
            }
            action_review_ev = argv[++i];
        } else if (strcmp(argv[i], "--mark-false-pos") == 0) {
            if (i + 1 >= argc) {
                fprintf(stderr, "Error: --mark-false-pos requires an event ID.\n");
                return 1;
            }
            action_false_pos = argv[++i];
        } else if (strcmp(argv[i], "--disconnect-node") == 0) {
            if (i + 1 >= argc) {
                fprintf(stderr, "Error: --disconnect-node requires a node UUID.\n");
                return 1;
            }
            action_disc_node = argv[++i];
        } else if (strcmp(argv[i], "--restrict-node") == 0) {
            if (i + 1 >= argc) {
                fprintf(stderr, "Error: --restrict-node requires a node UUID.\n");
                return 1;
            }
            action_restr_node = argv[++i];
        } else if (strcmp(argv[i], "--unrestrict-node") == 0) {
            if (i + 1 >= argc) {
                fprintf(stderr, "Error: --unrestrict-node requires a node UUID.\n");
                return 1;
            }
            action_unrestr_node = argv[++i];
        } else if (strcmp(argv[i], "--ban-node") == 0) {
            if (i + 1 >= argc) {
                fprintf(stderr, "Error: --ban-node requires a node UUID.\n");
                return 1;
            }
            action_ban_node = argv[++i];
        } else if (strcmp(argv[i], "--unban-node") == 0) {
            if (i + 1 >= argc) {
                fprintf(stderr, "Error: --unban-node requires a node UUID.\n");
                return 1;
            }
            action_unban_node = argv[++i];
        } else if (strcmp(argv[i], "--lock-channel") == 0) {
            if (i + 1 >= argc) {
                fprintf(stderr, "Error: --lock-channel requires a channel UUID.\n");
                return 1;
            }
            action_lock_chan = argv[++i];
        } else if (strcmp(argv[i], "--unlock-channel") == 0) {
            if (i + 1 >= argc) {
                fprintf(stderr, "Error: --unlock-channel requires a channel UUID.\n");
                return 1;
            }
            action_unlock_chan = argv[++i];
        } else if (strcmp(argv[i], "--create-admin-account") == 0) {
            if (i + 3 >= argc) {
                fprintf(stderr, "Error: --create-admin-account requires <username> <role> <password>.\n");
                return 1;
            }
            action_new_admin_user = argv[++i];
            action_new_admin_role = argv[++i];
            action_new_admin_pass = argv[++i];
        } else if (strcmp(argv[i], "--node") == 0) {
            if (i + 1 >= argc) {
                fprintf(stderr, "Error: --node requires an argument.\n");
                print_help(argv[0]);
                return 1;
            }
            node_display_name = argv[++i];
        } else if (strcmp(argv[i], "--cred-file") == 0) {
            if (i + 1 >= argc) {
                fprintf(stderr, "Error: --cred-file requires an argument.\n");
                print_help(argv[0]);
                return 1;
            }
            cred_file = argv[++i];
        } else if (strcmp(argv[i], "--host") == 0) {
            if (i + 1 >= argc) {
                fprintf(stderr, "Error: --host requires an argument.\n");
                print_help(argv[0]);
                return 1;
            }
            host = argv[++i];
        } else if (strcmp(argv[i], "--port") == 0) {
            if (i + 1 >= argc) {
                fprintf(stderr, "Error: --port requires an argument.\n");
                print_help(argv[0]);
                return 1;
            }
            port = atoi(argv[++i]);
        } else if (strcmp(argv[i], "--ca") == 0 || strcmp(argv[i], "--ca-cert") == 0) {
            if (i + 1 >= argc) {
                fprintf(stderr, "Error: %s requires a path.\n", argv[i]);
                return 1;
            }
            ca_file = argv[++i];
        } else if (strcmp(argv[i], "--server-name") == 0 || strcmp(argv[i], "--expected-host") == 0) {
            if (i + 1 >= argc) {
                fprintf(stderr, "Error: %s requires a hostname.\n", argv[i]);
                return 1;
            }
            server_name = argv[++i];
        } else if (strcmp(argv[i], "--insecure-plaintext") == 0 || strcmp(argv[i], "--no-tls") == 0) {
            use_tls = false;
        } else {
            fprintf(stderr, "Error: Unknown option: %s\n", argv[i]);
            print_help(argv[0]);
            return 1;
        }
    }

    /* ── Logging init ─────────────────────────────────────────────────── */
    clip_log_init(CLIP_LOG_INFO, NULL);

    /* ── Self-test mode (invoked by ctest) ───────────────────────────── */
    if (do_test) {
        int result = run_self_test();
        clip_log_close();
        return result;
    }

    if (do_audio_test) {
        int result = run_audio_test();
        clip_log_close();
        return result;
    }

    /* ── Validate TLS CA certificate if TLS is enabled (default) ─────── */
    if (use_tls) {
        FILE* fca = fopen(ca_file, "r");
        if (!fca) {
            fprintf(stderr, "Error: Trusted CA file '%s' not found.\n"
                            "CLICOM requires TLS 1.3 by default.\n"
                            "To run in unencrypted mode for testing, pass --insecure-plaintext.\n",
                    ca_file);
            clip_log_close();
            return 1;
        }
        fclose(fca);
    }

    /* ── Normal startup & network connection ─────────────────────────── */
    print_banner();
    printf("CLICOM CLIENT\n");
    printf("Connecting to %s:%d (%s)...\n\n", host, port, use_tls ? "TLS 1.3" : "PLAINTEXT");

    /* ── Phase 9 Audio Subsystem Initialization ───────────────────────── */
    ClipAudioEngine audio_engine;
    ClipAudioConfig audio_cfg;
    clip_audio_config_init_default(&audio_cfg);
    UINT num_wave_in = waveInGetNumDevs();
    if (num_wave_in > 0) {
        audio_cfg.backend = CLIP_AUDIO_BACKEND_WINMM;
    } else {
        audio_cfg.backend = CLIP_AUDIO_BACKEND_MOCK;
    }
    ClipError a_init_err = clip_audio_engine_init(&audio_engine, &audio_cfg);
    if (a_init_err != CLIP_OK && audio_cfg.backend != CLIP_AUDIO_BACKEND_MOCK) {
        audio_cfg.backend = CLIP_AUDIO_BACKEND_MOCK;
        clip_audio_engine_init(&audio_engine, &audio_cfg);
    }

    ClipClientNet client;
    clip_client_net_init(&client);
    g_active_client = &client;
    clip_client_set_disconnect_callback(&client, on_client_disconnected, &audio_engine);
    clip_client_set_audio_recv_callback(&client, on_peer_audio_received, &audio_engine);
    clip_audio_set_capture_callback(&audio_engine, on_client_audio_captured, &g_audio_sender);
    clip_audio_start_playback(&audio_engine);

    clip_captions_init(&g_caption_buf, CLIP_CAPTION_HISTORY_DEFAULT);
    clip_captions_set_speaker_resolver(&g_caption_buf, client_speaker_resolver, &g_speaker_ctx);

    SpeechAnalyzer* speech_analyzer = speech_analyzer_create("mock", NULL);
    if (speech_analyzer) {
        speech_analyzer_set_callback(speech_analyzer, on_client_transcript_received, &g_caption_buf);
        clip_client_set_speech_analyzer(&client, speech_analyzer);
    }

    if (use_tls) {
        clip_tls_client_config_t tls_cfg = {
            .ca_file = ca_file,
            .expected_host = server_name ? server_name : ((strcmp(host, "127.0.0.1") == 0) ? "localhost" : host),
            .insecure_skip_verify = true
        };
        clip_client_net_set_tls_config(&client, &tls_cfg);
    } else {
        clip_client_net_set_insecure_plaintext(&client);
    }

    ClipError conn_err = clip_client_connect(&client, host, (uint16_t)port);
    if (conn_err != CLIP_OK) {
        printf("Connection failed: %s\n", clip_error_string(conn_err));
        if (speech_analyzer) {
            speech_analyzer_destroy(speech_analyzer);
            speech_analyzer = NULL;
        }
        clip_captions_cleanup(&g_caption_buf);
        clip_client_net_cleanup(&client);
        clip_log_close();
        return 1;
    }

    printf("CONNECTED (%s)\n", use_tls ? "TLS 1.3 Encrypted" : "Plaintext");
    if (use_tls && client.transport) {
        printf("  TLS Protocol : %s\n", clip_transport_get_tls_version(client.transport));
        printf("  Cipher Suite : %s\n", clip_transport_get_cipher_name(client.transport));
    }
    printf("\n");

    /* Check for existing DPAPI-protected credentials */
    bool has_creds = (!do_reregister && clip_credentials_exists(cred_file));
    ClipClientCredentials creds;
    memset(&creds, 0, sizeof(creds));

    if (has_creds) {
        ClipError load_err = clip_credentials_load(cred_file, &creds);
        if (load_err != CLIP_OK) {
            has_creds = false;
        }
    }

    if (has_creds) {
        printf("Existing identity found.\n\n");
        printf("Authenticating...\n");

        char srv_name[CLIP_DISPLAY_NAME_MAX];
        ClipError auth_err = clip_client_authenticate(&client,
                                                      &creds.node_uuid,
                                                      creds.credential,
                                                      srv_name,
                                                      sizeof(srv_name));

#ifdef _WIN32
        SecureZeroMemory(creds.credential, sizeof(creds.credential));
#else
        memset(creds.credential, 0, sizeof(creds.credential));
#endif

        if (auth_err != CLIP_OK) {
            printf("Authentication FAILED: %s\n", clip_error_string(auth_err));
            clip_client_disconnect(&client);
            if (speech_analyzer) {
                speech_analyzer_destroy(speech_analyzer);
                speech_analyzer = NULL;
            }
            clip_captions_cleanup(&g_caption_buf);
            clip_client_net_cleanup(&client);
            clip_log_close();
            return 1;
        }

        printf("Authentication successful.\n\n");
        char uuid_str[CLIP_UUID_STR_SIZE];
        clip_uuid_to_string(&creds.node_uuid, uuid_str, sizeof(uuid_str));
        printf("Node UUID          : %s\n", uuid_str);
        printf("Node Display Name  : %s\n", srv_name);
        printf("Authenticated      : YES\n\n");

        memcpy(g_speaker_ctx.client_uuid.bytes, creds.node_uuid.bytes, CLIP_UUID_BYTES);
        strncpy(g_speaker_ctx.client_name, srv_name, sizeof(g_speaker_ctx.client_name) - 1);
    } else {
        printf("FIRST-TIME REGISTRATION\n\n");
        printf("Display name: %s\n\n", node_display_name);
        printf("Sending REGISTER...\n");

        ClipUuid new_uuid;
        uint8_t new_cred[CLIP_CREDENTIAL_BYTES];

        ClipError reg_err = clip_client_register(&client, node_display_name, &new_uuid, new_cred);
        if (reg_err != CLIP_OK) {
            printf("Registration failed: %s\n", clip_error_string(reg_err));
            clip_client_disconnect(&client);
            if (speech_analyzer) {
                speech_analyzer_destroy(speech_analyzer);
                speech_analyzer = NULL;
            }
            clip_captions_cleanup(&g_caption_buf);
            clip_client_net_cleanup(&client);
            clip_log_close();
            return 1;
        }

        printf("Registration successful.\n\n");
        char uuid_str[CLIP_UUID_STR_SIZE];
        clip_uuid_to_string(&new_uuid, uuid_str, sizeof(uuid_str));
        printf("Node UUID          : %s\n", uuid_str);

        memcpy(g_speaker_ctx.client_uuid.bytes, new_uuid.bytes, CLIP_UUID_BYTES);
        strncpy(g_speaker_ctx.client_name, node_display_name, sizeof(g_speaker_ctx.client_name) - 1);

        /* Save credentials via Windows DPAPI */
        memcpy(creds.node_uuid.bytes, new_uuid.bytes, CLIP_UUID_BYTES);
        memcpy(creds.credential, new_cred, CLIP_CREDENTIAL_BYTES);
        strncpy(creds.display_name, node_display_name, sizeof(creds.display_name) - 1);

        ClipError save_err = clip_credentials_save(cred_file, &creds);
        if (save_err == CLIP_OK) {
            printf("Credential stored securely.\n");
        } else {
            printf("Warning: Failed to save credential securely: %s\n", clip_error_string(save_err));
        }

#ifdef _WIN32
        SecureZeroMemory(new_cred, sizeof(new_cred));
        SecureZeroMemory(creds.credential, sizeof(creds.credential));
#else
        memset(new_cred, 0, sizeof(new_cred));
        memset(creds.credential, 0, sizeof(creds.credential));
#endif

        printf("Authenticated      : YES\n\n");
    }

    /* ── Phase 4 Actions / Interactive CLI ────────────────────────────── */
    if (action_create_chan) {
        printf("Create Channel\n\n");
        printf("Channel name:\n%s\n\n", action_create_chan);
        printf("Creating...\n\n");
        ClipUuid chan_uuid;
        char jkey[CLIP_JOIN_KEY_MAX];
        ClipError err = clip_client_channel_create(&client, action_create_chan, &chan_uuid, jkey, sizeof(jkey));
        if (err == CLIP_OK) {
            char u_str[CLIP_UUID_STR_SIZE];
            clip_uuid_to_string(&chan_uuid, u_str, sizeof(u_str));
            printf("CHANNEL CREATED\n\n");
            printf("Channel UUID:\n%s\n\n", u_str);
            printf("JOIN KEY:\n%s\n\n", jkey);
            printf("You are now a member.\n\n");
        } else {
            printf("Failed to create channel: %s\n\n", clip_error_string(err));
        }
    } else if (action_join_chan) {
        printf("Join Channel\n\n");
        printf("Enter join key:\n%s\n\n", action_join_chan);
        ClipUuid chan_uuid;
        char cname[CLIP_DISPLAY_NAME_MAX];
        ClipChannelMember* mems = NULL;
        size_t m_cnt = 0;
        ClipError err = clip_client_channel_join(&client, action_join_chan, &chan_uuid, cname, sizeof(cname), &mems, &m_cnt);
        if (err == CLIP_OK) {
            printf("JOIN SUCCESSFUL\n\n");
            printf("Channel:\n%s\n\n", cname);
            printf("Members:\n");
            for (size_t m = 0; m < m_cnt; m++) {
                printf("%s %s\n", mems[m].display_name, (mems[m].presence == CLIP_PRESENCE_ONLINE) ? "ONLINE" : "OFFLINE");
            }
            printf("\n");
            clip_client_free_members(mems);
        } else {
            printf("Failed to join channel: %s\n\n", clip_error_string(err));
        }
    } else if (do_list_chans) {
        ClipChannelInfo* chans = NULL;
        size_t c_cnt = 0;
        ClipError err = clip_client_channel_list(&client, &chans, &c_cnt);
        if (err == CLIP_OK) {
            printf("My Channels (%u):\n", (unsigned)c_cnt);
            for (size_t k = 0; k < c_cnt; k++) {
                printf("  [%u] %s (Join Key: %s, UUID: %s)\n", (unsigned)(k + 1), chans[k].name, chans[k].join_key, chans[k].channel_uuid_str);
            }
            printf("\n");
            clip_client_free_channels(chans);
        } else {
            printf("Failed to list channels: %s\n\n", clip_error_string(err));
        }
    } else if (action_members) {
        printf("Channel Members\n\n");
        ClipUuid chan_uuid;
        if (clip_uuid_from_string(&chan_uuid, action_members) == 0) {
            ClipChannelMember* mems = NULL;
            size_t m_cnt = 0;
            ClipError err = clip_client_get_channel_members(&client, &chan_uuid, &mems, &m_cnt);
            if (err == CLIP_OK) {
                printf("Channel Members (%u):\n", (unsigned)m_cnt);
                for (size_t m = 0; m < m_cnt; m++) {
                    char nu_str[CLIP_UUID_STR_SIZE];
                    clip_uuid_to_string(&mems[m].node_uuid, nu_str, sizeof(nu_str));
                    printf("  - %s [%s] (%s)\n", mems[m].display_name, nu_str,
                           (mems[m].presence == CLIP_PRESENCE_ONLINE) ? "ONLINE" : "OFFLINE");
                }
                printf("\n");
                clip_client_free_members(mems);
            } else {
                printf("Failed to get channel members: %s\n\n", clip_error_string(err));
            }
        } else {
            printf("Invalid channel UUID: %s\n\n", action_members);
        }
    } else if (action_req_chan && action_req_target) {
        printf("Connection Request\n\n");
        ClipUuid chan_uuid, target_node_uuid;
        if (clip_uuid_from_string(&chan_uuid, action_req_chan) == 0 &&
            clip_uuid_from_string(&target_node_uuid, action_req_target) == 0) {
            ClipUuid conn_uuid;
            ClipConnectionState state;
            ClipError err = clip_client_send_conn_request(&client, &chan_uuid, &target_node_uuid, &conn_uuid, &state);
            if (err == CLIP_OK) {
                char cu_str[CLIP_UUID_STR_SIZE];
                clip_uuid_to_string(&conn_uuid, cu_str, sizeof(cu_str));
                printf("CONNECTION REQUESTED\n\n");
                printf("Connection UUID:\n%s\n\n", cu_str);
                printf("Status: %s\n\n", (state == CLIP_CONN_STATE_REQUESTED) ? "REQUESTED" :
                                         (state == CLIP_CONN_STATE_ACCEPTED) ? "ACCEPTED" : "PENDING");
            } else {
                printf("Failed to request connection: %s\n\n", clip_error_string(err));
            }
        } else {
            printf("Invalid UUID(s) provided.\n\n");
        }
    } else if (action_accept_conn) {
        printf("Accept Connection\n\n");
        ClipUuid conn_uuid;
        if (clip_uuid_from_string(&conn_uuid, action_accept_conn) == 0) {
            ClipError err = clip_client_respond_conn(&client, &conn_uuid, true);
            if (err == CLIP_OK) {
                printf("CONNECTION ACCEPTED\n\n");
                printf("Status: ACCEPTED\n\n");
            } else {
                printf("Failed to accept connection: %s\n\n", clip_error_string(err));
            }
        } else {
            printf("Invalid connection UUID.\n\n");
        }
    } else if (action_decline_con) {
        printf("Decline Connection\n\n");
        ClipUuid conn_uuid;
        if (clip_uuid_from_string(&conn_uuid, action_decline_con) == 0) {
            ClipError err = clip_client_respond_conn(&client, &conn_uuid, false);
            if (err == CLIP_OK) {
                printf("CONNECTION DECLINED\n\n");
                printf("Status: DECLINED\n\n");
            } else {
                printf("Failed to decline connection: %s\n\n", clip_error_string(err));
            }
        } else {
            printf("Invalid connection UUID.\n\n");
        }
    } else if (do_list_conns) {
        printf("My Connections\n\n");
        ClipConnectionRecord* conns = NULL;
        size_t c_cnt = 0;
        ClipError err = clip_client_list_connections(&client, &conns, &c_cnt);
        if (err == CLIP_OK) {
            printf("Connections (%u):\n", (unsigned)c_cnt);
            for (size_t k = 0; k < c_cnt; k++) {
                char cu_str[CLIP_UUID_STR_SIZE], ch_str[CLIP_UUID_STR_SIZE], req_str[CLIP_UUID_STR_SIZE], tgt_str[CLIP_UUID_STR_SIZE];
                clip_uuid_to_string(&conns[k].connection_uuid, cu_str, sizeof(cu_str));
                clip_uuid_to_string(&conns[k].channel_uuid, ch_str, sizeof(ch_str));
                clip_uuid_to_string(&conns[k].requester_node_uuid, req_str, sizeof(req_str));
                clip_uuid_to_string(&conns[k].target_node_uuid, tgt_str, sizeof(tgt_str));
                const char* st_name = (conns[k].state == CLIP_CONN_STATE_REQUESTED) ? "REQUESTED" :
                                      (conns[k].state == CLIP_CONN_STATE_ACCEPTED) ? "ACCEPTED" :
                                      (conns[k].state == CLIP_CONN_STATE_DECLINED) ? "DECLINED" :
                                      (conns[k].state == CLIP_CONN_STATE_CLOSED) ? "CLOSED" : "EXPIRED";
                printf("  [%u] Conn: %s | State: %s | Chan: %s | From: %s -> To: %s\n",
                       (unsigned)(k + 1), cu_str, st_name, ch_str, req_str, tgt_str);
            }
            printf("\n");
            clip_client_free_connections(conns);
        } else {
            printf("Failed to list connections: %s\n\n", clip_error_string(err));
        }
    } else if (action_start_sess_conn) {
        printf("Start Session by Connection\n\n");
        printf("Connection:\n%s\n\n", action_start_sess_conn);
        ClipUuid conn_uuid;
        if (clip_uuid_from_string(&conn_uuid, action_start_sess_conn) == 0) {
            ClipUuid sess_uuid;
            ClipError err = clip_client_session_start_by_conn(&client, &conn_uuid, &sess_uuid);
            if (err == CLIP_OK) {
                clip_captions_set_session(&g_caption_buf, &sess_uuid, clip_client_get_speech_mode(&client));
                char s_str[CLIP_UUID_STR_SIZE];
                clip_uuid_to_string(&sess_uuid, s_str, sizeof(s_str));
                printf("SESSION STARTED\n\n");
                printf("Session UUID:\n%s\n\n", s_str);
            } else {
                printf("Failed to start session: %s\n\n", clip_error_string(err));
            }
        } else {
            printf("Invalid connection UUID.\n\n");
        }
    } else if (action_start_sess) {
        printf("Start Session\n\n");
        printf("Channel:\n%s\n\n", action_start_sess);
        ClipUuid chan_uuid;
        if (clip_uuid_from_string(&chan_uuid, action_start_sess) == 0) {
            ClipUuid sess_uuid;
            ClipError err = clip_client_session_start(&client, &chan_uuid, &sess_uuid);
            if (err == CLIP_OK) {
                clip_captions_set_session(&g_caption_buf, &sess_uuid, clip_client_get_speech_mode(&client));
                char s_str[CLIP_UUID_STR_SIZE];
                clip_uuid_to_string(&sess_uuid, s_str, sizeof(s_str));
                printf("SESSION STARTED\n\n");
                printf("Session UUID:\n%s\n\n", s_str);
            } else {
                printf("Failed to start session: %s\n\n", clip_error_string(err));
            }
        } else {
            printf("Invalid channel UUID.\n\n");
        }
    } else if (action_end_sess) {
        printf("End Session\n\n");
        ClipUuid sess_uuid;
        if (clip_uuid_from_string(&sess_uuid, action_end_sess) == 0) {
            ClipError err = clip_client_session_end(&client, &sess_uuid);
            if (err == CLIP_OK) {
                clip_captions_set_session(&g_caption_buf, NULL, CLIP_SPEECH_MODE_NONE);
                printf("SESSION ENDED\n\n");
            } else {
                printf("Failed to end session: %s\n\n", clip_error_string(err));
            }
        } else {
            printf("Invalid session UUID.\n\n");
        }
    } else if (action_ptt_req) {
        printf("PTT Floor Request\n\n");
        ClipUuid sess_uuid;
        if (clip_uuid_from_string(&sess_uuid, action_ptt_req) == 0) {
            ClipPttFloor granted_floor;
            ClipError denial = CLIP_OK;
            ClipError err = clip_client_ptt_request(&client, &sess_uuid, 5000, &granted_floor, &denial);
            if (err == CLIP_OK) {
                client.ptt_floor_held = true;
                g_audio_sender.net = &client;
                g_audio_sender.session_uuid = sess_uuid;
                clip_audio_on_floor_granted(&audio_engine);
                printf("YOU HAVE THE FLOOR\n");
                printf("Audio Capture: ACTIVE (PTT floor held)\n");
                printf("Session: %s\n", action_ptt_req);
                printf("Status: GRANTED\n\n");
            } else if (err == CLIP_ERR_PTT_BUSY) {
                printf("FLOOR BUSY\n");
                printf("Current holder: %s\n", granted_floor.speaker_uuid_str);
                printf("Reason: FLOOR_BUSY\n\n");
            } else {
                printf("Failed: %s\n\n", clip_error_string(err));
            }
        } else {
            printf("Invalid session UUID.\n\n");
        }
    } else if (action_ptt_rel) {
        printf("PTT Floor Release\n\n");
        ClipUuid sess_uuid;
        if (clip_uuid_from_string(&sess_uuid, action_ptt_rel) == 0) {
            ClipError err = clip_client_ptt_release(&client, &sess_uuid);
            if (err == CLIP_OK) {
                clip_audio_on_floor_released(&audio_engine);
                clip_uuid_zero(&g_audio_sender.session_uuid);
                printf("FLOOR RELEASED\n");
                printf("Audio Capture: STOPPED (floor released)\n");
                printf("Floor is now FREE\n\n");
            } else {
                printf("Failed to release: %s\n\n", clip_error_string(err));
            }
        } else {
            printf("Invalid session UUID.\n\n");
        }
    } else if (action_ptt_status) {
        printf("PTT Floor Status\n\n");
        ClipUuid sess_uuid;
        if (clip_uuid_from_string(&sess_uuid, action_ptt_status) == 0) {
            ClipPttFloor floor;
            ClipError err = clip_client_ptt_status(&client, &sess_uuid, &floor);
            if (err == CLIP_OK) {
                printf("Session: %s\n", action_ptt_status);
                printf("Floor: %s\n", (floor.floor_state == CLIP_PTT_FLOOR_FREE) ? "FREE" : "HELD");
                if (floor.floor_state == CLIP_PTT_FLOOR_HELD) {
                    printf("Holder: %s\n", floor.speaker_uuid_str);
                    printf("Lease: ACTIVE (%u ms remaining)\n\n", (unsigned)floor.lease_timeout_ms);
                } else {
                    printf("\n");
                }
            } else {
                printf("Failed to get status: %s\n\n", clip_error_string(err));
            }
        } else {
            printf("Invalid session UUID.\n\n");
        }
    } else if (do_list_logs) {
        printf("Session Logs\n\n");
        ClipSessionLogEntry* logs = NULL;
        size_t l_cnt = 0;
        ClipError err = clip_client_list_session_logs(&client, &logs, &l_cnt);
        if (err == CLIP_OK) {
            printf("Authorized Sessions (%u):\n", (unsigned)l_cnt);
            for (size_t k = 0; k < l_cnt; k++) {
                char su_str[CLIP_UUID_STR_SIZE], ch_str[CLIP_UUID_STR_SIZE];
                clip_uuid_to_string(&logs[k].session_uuid, su_str, sizeof(su_str));
                clip_uuid_to_string(&logs[k].channel_uuid, ch_str, sizeof(ch_str));
                const char* st_name = (logs[k].state == 1) ? "ACTIVE" : "ENDED";
                printf("  [%u] Session: %s | State: %s | Chan: %s | Duration: %llu ms | Notes: %u\n",
                       (unsigned)(k + 1), su_str, st_name, ch_str, (unsigned long long)logs[k].duration_ms, (unsigned)logs[k].note_count);
            }
            printf("\n");
            clip_client_free_session_logs(logs);
        } else {
            printf("Failed to list session logs: %s\n\n", clip_error_string(err));
        }
    } else if (action_get_log) {
        printf("Session Log Details\n\n");
        ClipUuid su;
        if (clip_uuid_from_string(&su, action_get_log) == 0) {
            ClipSessionLogEntry log;
            ClipError err = clip_client_get_session_log(&client, &su, &log);
            if (err == CLIP_OK) {
                char su_str[CLIP_UUID_STR_SIZE], ch_str[CLIP_UUID_STR_SIZE], init_str[CLIP_UUID_STR_SIZE], peer_str[CLIP_UUID_STR_SIZE];
                clip_uuid_to_string(&log.session_uuid, su_str, sizeof(su_str));
                clip_uuid_to_string(&log.channel_uuid, ch_str, sizeof(ch_str));
                clip_uuid_to_string(&log.initiator_node_uuid, init_str, sizeof(init_str));
                clip_uuid_to_string(&log.peer_node_uuid, peer_str, sizeof(peer_str));
                printf("Session UUID : %s\n", su_str);
                printf("Channel UUID : %s\n", ch_str);
                printf("Initiator    : %s\n", init_str);
                printf("Peer         : %s\n", peer_str);
                printf("State        : %s\n", (log.state == 1) ? "ACTIVE" : "ENDED");
                printf("Created At   : %llu\n", (unsigned long long)log.created_at);
                printf("Duration     : %llu ms\n", (unsigned long long)log.duration_ms);
                printf("Notes Count  : %u\n\n", (unsigned)log.note_count);
            } else {
                printf("Failed to get session log: %s\n\n", clip_error_string(err));
            }
        } else {
            printf("Invalid session UUID.\n\n");
        }
    } else if (action_list_notes) {
        printf("Session Notes\n\n");
        ClipUuid su;
        if (clip_uuid_from_string(&su, action_list_notes) == 0) {
            ClipSessionNoteEntry* notes = NULL;
            size_t n_cnt = 0;
            ClipError err = clip_client_list_notes(&client, &su, NULL, &notes, &n_cnt);
            if (err == CLIP_OK) {
                printf("Notes (%u):\n", (unsigned)n_cnt);
                for (size_t k = 0; k < n_cnt; k++) {
                    char a_str[CLIP_UUID_STR_SIZE];
                    clip_uuid_to_string(&notes[k].author_node_uuid, a_str, sizeof(a_str));
                    const char* t_name = (notes[k].note_type == CLIP_NOTE_TYPE_TRANSCRIPT) ? "TRANSCRIPT" : "MANUAL";
                    printf("  [%u] Note #%u (%s) by %s:\n      %s\n",
                           (unsigned)(k + 1), notes[k].note_id, t_name, a_str, notes[k].note_text);
                }
                printf("\n");
                clip_client_free_notes(notes);
            } else {
                printf("Failed to list notes: %s\n\n", clip_error_string(err));
            }
        } else {
            printf("Invalid session UUID.\n\n");
        }
    } else if (action_add_note_sess && action_add_note_text) {
        printf("Add Session Note\n\n");
        ClipUuid su;
        if (clip_uuid_from_string(&su, action_add_note_sess) == 0) {
            uint32_t note_id = 0;
            ClipError err = clip_client_create_note(&client, &su, CLIP_NOTE_TYPE_MANUAL, action_add_note_text, &note_id);
            if (err == CLIP_OK) {
                printf("NOTE CREATED\nNote ID: %u\n\n", note_id);
            } else {
                printf("Failed to create note: %s\n\n", clip_error_string(err));
            }
        } else {
            printf("Invalid session UUID.\n\n");
        }
    } else if (action_search_notes_sess && action_search_notes_query) {
        printf("Search Session Notes\n\n");
        ClipUuid su;
        if (clip_uuid_from_string(&su, action_search_notes_sess) == 0) {
            ClipSessionNoteEntry* notes = NULL;
            size_t n_cnt = 0;
            ClipError err = clip_client_list_notes(&client, &su, action_search_notes_query, &notes, &n_cnt);
            if (err == CLIP_OK) {
                printf("Matching Notes (%u):\n", (unsigned)n_cnt);
                for (size_t k = 0; k < n_cnt; k++) {
                    char a_str[CLIP_UUID_STR_SIZE];
                    clip_uuid_to_string(&notes[k].author_node_uuid, a_str, sizeof(a_str));
                    const char* t_name = (notes[k].note_type == CLIP_NOTE_TYPE_TRANSCRIPT) ? "TRANSCRIPT" : "MANUAL";
                    printf("  [%u] Note #%u (%s) by %s:\n      %s\n",
                           (unsigned)(k + 1), notes[k].note_id, t_name, a_str, notes[k].note_text);
                }
                printf("\n");
                clip_client_free_notes(notes);
            } else {
                printf("Failed to search notes: %s\n\n", clip_error_string(err));
            }
        } else {
            printf("Invalid session UUID.\n\n");
        }
    } else if (action_save_captions) {
        printf("Save Captions as Session Note\n\n");
        ClipUuid su;
        if (clip_uuid_from_string(&su, action_save_captions) == 0) {
            char summary_buf[CLIP_NOTE_TEXT_MAX_LEN + 1];
            size_t written = 0;
            clip_captions_export_summary(&g_caption_buf, summary_buf, sizeof(summary_buf), &written);
            if (written == 0) {
                printf("No finalized captions available to export.\n\n");
            } else {
                uint32_t note_id = 0;
                ClipError err = clip_client_create_note(&client, &su, CLIP_NOTE_TYPE_TRANSCRIPT, summary_buf, &note_id);
                if (err == CLIP_OK) {
                    printf("CAPTIONS SAVED\nNote ID: %u\nLength: %zu bytes\n\n", note_id, written);
                } else {
                    printf("Failed to save captions note: %s\n\n", clip_error_string(err));
                }
            }
        } else {
            printf("Invalid session UUID.\n\n");
        }
    } else if (do_list_events) {
        printf("Security Advisory Events\n\n");
        ClipUuid su;
        ClipUuid* p_su = NULL;
        if (action_list_events_sess) {
            if (clip_uuid_from_string(&su, action_list_events_sess) == 0) {
                p_su = &su;
            } else {
                printf("Invalid session UUID: %s\n\n", action_list_events_sess);
                p_su = NULL;
            }
        }
        ClipSecurityEvent* events = NULL;
        size_t e_cnt = 0;
        ClipError err = clip_client_list_security_events(&client, p_su, &events, &e_cnt);
        if (err == CLIP_OK) {
            printf("Advisory Events (%u):\n", (unsigned)e_cnt);
            for (size_t k = 0; k < e_cnt; k++) {
                const char* st_name = (events[k].status == CLIP_EVENT_STATUS_REVIEWED) ? "REVIEWED" :
                                      (events[k].status == CLIP_EVENT_STATUS_FALSE_POS) ? "FALSE_POS" : "PENDING";
                const char* cat_name = (events[k].category == CLIP_SECURITY_CAT_THREAT) ? "THREAT" :
                                       (events[k].category == CLIP_SECURITY_CAT_SUSPICIOUS) ? "SUSPICIOUS" : "CUSTOM";
                const char* sev_name = (events[k].severity == CLIP_SECURITY_SEV_CRITICAL) ? "CRITICAL" :
                                       (events[k].severity == CLIP_SECURITY_SEV_HIGH) ? "HIGH" :
                                       (events[k].severity == CLIP_SECURITY_SEV_MEDIUM) ? "MEDIUM" : "LOW";
                printf("  [%u] Event #%u [%s/%s] Status: %s | Term: \"%s\" | Rule: %s\n",
                       (unsigned)(k + 1), events[k].event_id, cat_name, sev_name, st_name,
                       events[k].matched_term, events[k].matched_rule);
                if (events[k].context_text[0] != '\0') {
                    printf("      Context: \"%s\"\n", events[k].context_text);
                }
            }
            printf("\n");
            clip_client_free_security_events(events, e_cnt);
        } else {
            printf("Failed to list security events: %s\n\n", clip_error_string(err));
        }
    } else if (action_get_event) {
        printf("Security Advisory Event Details\n\n");
        uint32_t eid = (uint32_t)strtoul(action_get_event, NULL, 10);
        ClipUuid eu;
        ClipUuid* p_eu = NULL;
        if (clip_uuid_from_string(&eu, action_get_event) == 0) {
            p_eu = &eu;
        }
        ClipSecurityEvent ev;
        ClipError err = clip_client_get_security_event(&client, eid, p_eu, &ev);
        if (err == CLIP_OK) {
            char su_str[CLIP_UUID_STR_SIZE];
            clip_uuid_to_string((const ClipUuid*)ev.session_uuid, su_str, sizeof(su_str));
            const char* st_name = (ev.status == CLIP_EVENT_STATUS_REVIEWED) ? "REVIEWED" :
                                  (ev.status == CLIP_EVENT_STATUS_FALSE_POS) ? "FALSE_POS" : "PENDING (Advisory / Requires Review)";
            const char* cat_name = (ev.category == CLIP_SECURITY_CAT_THREAT) ? "THREAT" :
                                   (ev.category == CLIP_SECURITY_CAT_SUSPICIOUS) ? "SUSPICIOUS" : "CUSTOM";
            const char* sev_name = (ev.severity == CLIP_SECURITY_SEV_CRITICAL) ? "CRITICAL" :
                                   (ev.severity == CLIP_SECURITY_SEV_HIGH) ? "HIGH" :
                                   (ev.severity == CLIP_SECURITY_SEV_MEDIUM) ? "MEDIUM" : "LOW";
            printf("Event ID     : %u\n", ev.event_id);
            printf("Event UUID   : %s\n", ev.event_uuid_str);
            printf("Session UUID : %s\n", su_str);
            printf("Channel UUID : %s\n", ev.channel_uuid_str);
            printf("Speaker Node : %s\n", ev.node_uuid_str);
            printf("Timestamp    : %llu\n", (unsigned long long)ev.timestamp_ms);
            printf("Category     : %s\n", cat_name);
            printf("Severity     : %s\n", sev_name);
            printf("Matched Rule : %s\n", ev.matched_rule);
            printf("Matched Term : \"%s\"\n", ev.matched_term);
            printf("Context Text : \"%s\"\n", ev.context_text);
            printf("Review Status: %s\n\n", st_name);
        } else {
            printf("Failed to get security event: %s\n\n", clip_error_string(err));
        }
    } else if (admin_user || do_admin_events || do_admin_audit || action_review_ev || action_false_pos ||
               action_disc_node || action_restr_node || action_unrestr_node || action_ban_node ||
               action_unban_node || action_lock_chan || action_unlock_chan || action_new_admin_user) {
        if (!admin_user) {
            fprintf(stderr, "Error: Administrative actions require --admin-login <username>.\n\n");
        } else {
            char pass_buf[128] = {0};
            bool has_pass = false;
            if (admin_pass) {
                strncpy(pass_buf, admin_pass, sizeof(pass_buf) - 1);
                has_pass = true;
            } else {
                if (read_password_no_echo("Admin Password: ", pass_buf, sizeof(pass_buf)) > 0) {
                    has_pass = true;
                }
            }

            if (!has_pass) {
                fprintf(stderr, "Error: Admin password required.\n\n");
            } else {
                ClipAdminPermission admin_role = CLIP_ADMIN_PERM_NONE;
                ClipUuid admin_uuid;
                ClipError auth_err = clip_admin_client_login(&client, admin_user, pass_buf, &admin_role, &admin_uuid);
                OPENSSL_cleanse(pass_buf, sizeof(pass_buf));

                if (auth_err != CLIP_OK) {
                    printf("Administrator authentication FAILED: %s\n\n", clip_error_string(auth_err));
                } else {
                    printf("Administrator authenticated as '%s' (%s).\n\n", admin_user, clip_admin_role_name(admin_role));
                    const char* reason = admin_reason ? admin_reason : "Administrative action";

                    if (do_admin_events) {
                        printf("Security Advisory Events (Admin View)\n\n");
                        int filter = -1;
                        if (admin_events_status) {
                            if (strcmp(admin_events_status, "PENDING") == 0) filter = CLIP_EVENT_STATUS_PENDING;
                            else if (strcmp(admin_events_status, "REVIEWED") == 0) filter = CLIP_EVENT_STATUS_REVIEWED;
                            else if (strcmp(admin_events_status, "FALSE_POS") == 0) filter = CLIP_EVENT_STATUS_FALSE_POS;
                        }
                        ClipSecurityEvent* events = NULL;
                        size_t e_cnt = 0;
                        ClipError g_err = clip_admin_client_list_events(&client, filter, &events, &e_cnt);
                        if (g_err == CLIP_OK) {
                            printf("Advisories (%u):\n", (unsigned)e_cnt);
                            for (size_t k = 0; k < e_cnt; k++) {
                                const char* st_name = (events[k].status == CLIP_EVENT_STATUS_REVIEWED) ? "REVIEWED" :
                                                      (events[k].status == CLIP_EVENT_STATUS_FALSE_POS) ? "FALSE_POS" : "PENDING";
                                const char* cat_name = (events[k].category == CLIP_SECURITY_CAT_THREAT) ? "THREAT" :
                                                       (events[k].category == CLIP_SECURITY_CAT_SUSPICIOUS) ? "SUSPICIOUS" : "CUSTOM";
                                const char* sev_name = (events[k].severity == CLIP_SECURITY_SEV_CRITICAL) ? "CRITICAL" :
                                                       (events[k].severity == CLIP_SECURITY_SEV_HIGH) ? "HIGH" :
                                                       (events[k].severity == CLIP_SECURITY_SEV_MEDIUM) ? "MEDIUM" : "LOW";
                                printf("  [%u] Event #%u [%s/%s] Status: %s | Term: \"%s\" | Rule: %s\n",
                                       (unsigned)(k + 1), events[k].event_id, cat_name, sev_name, st_name,
                                       events[k].matched_term, events[k].matched_rule);
                                if (events[k].context_text[0] != '\0') {
                                    printf("      Context: \"%s\"\n", events[k].context_text);
                                }
                            }
                            printf("\n");
                            clip_admin_client_free_events(events, e_cnt);
                        } else {
                            printf("Failed to list events: %s\n\n", clip_error_string(g_err));
                        }
                    } else if (do_admin_audit) {
                        printf("Administrative Audit Log\n\n");
                        ClipAdminAuditRecord* recs = NULL;
                        size_t r_cnt = 0;
                        ClipError a_err = clip_admin_client_list_audit(&client, admin_audit_limit, &recs, &r_cnt);
                        if (a_err == CLIP_OK) {
                            printf("Audit Records (%u):\n", (unsigned)r_cnt);
                            for (size_t k = 0; k < r_cnt; k++) {
                                char tu_str[CLIP_UUID_STR_SIZE] = "N/A";
                                if (recs[k].has_target_uuid) {
                                    clip_uuid_to_string((const ClipUuid*)recs[k].target_uuid, tu_str, sizeof(tu_str));
                                }
                                const char* st_str = (recs[k].status == CLIP_AUDIT_STATUS_SUCCESS) ? "SUCCESS" :
                                                     (recs[k].status == CLIP_AUDIT_STATUS_DENIED) ? "DENIED" : "FAILED";
                                printf("  [%u] Audit #%u | Action: %s | Target: %s | Status: %s\n      Reason: \"%s\"\n",
                                       (unsigned)(k + 1), recs[k].audit_id, clip_admin_action_name(recs[k].action_type),
                                       tu_str, st_str, recs[k].reason);
                            }
                            printf("\n");
                            clip_admin_client_free_audit(recs, r_cnt);
                        } else {
                            printf("Failed to list audit log: %s\n\n", clip_error_string(a_err));
                        }
                    } else if (action_review_ev) {
                        uint32_t eid = (uint32_t)strtoul(action_review_ev, NULL, 10);
                        uint32_t audit_id = 0;
                        ClipError act_err = clip_admin_client_send_action(&client, CLIP_ADMIN_REVIEW_EVENT, NULL,
                                                                         reason, eid, NULL, NULL, &audit_id);
                        if (act_err == CLIP_OK) {
                            printf("ACTION SUCCESSFUL: Event #%u marked REVIEWED (audit_id=%u)\n\n", eid, audit_id);
                        } else {
                            printf("Action failed: %s\n\n", clip_error_string(act_err));
                        }
                    } else if (action_false_pos) {
                        uint32_t eid = (uint32_t)strtoul(action_false_pos, NULL, 10);
                        uint32_t audit_id = 0;
                        ClipError act_err = clip_admin_client_send_action(&client, CLIP_ADMIN_MARK_FALSE_POS, NULL,
                                                                         reason, eid, NULL, NULL, &audit_id);
                        if (act_err == CLIP_OK) {
                            printf("ACTION SUCCESSFUL: Event #%u marked FALSE_POS (audit_id=%u)\n\n", eid, audit_id);
                        } else {
                            printf("Action failed: %s\n\n", clip_error_string(act_err));
                        }
                    } else if (action_disc_node) {
                        ClipUuid tgt;
                        if (clip_uuid_from_string(&tgt, action_disc_node) != 0) {
                            printf("Invalid node UUID: %s\n\n", action_disc_node);
                        } else {
                            uint32_t audit_id = 0;
                            ClipError act_err = clip_admin_client_send_action(&client, CLIP_ADMIN_DISCONNECT_NODE, &tgt,
                                                                             reason, 0, NULL, NULL, &audit_id);
                            if (act_err == CLIP_OK) {
                                printf("ACTION SUCCESSFUL: Node %s disconnected (audit_id=%u)\n\n", action_disc_node, audit_id);
                            } else {
                                printf("Action failed: %s\n\n", clip_error_string(act_err));
                            }
                        }
                    } else if (action_restr_node) {
                        ClipUuid tgt;
                        if (clip_uuid_from_string(&tgt, action_restr_node) != 0) {
                            printf("Invalid node UUID: %s\n\n", action_restr_node);
                        } else {
                            uint32_t audit_id = 0;
                            ClipError act_err = clip_admin_client_send_action(&client, CLIP_ADMIN_RESTRICT_NODE, &tgt,
                                                                             reason, 0, NULL, NULL, &audit_id);
                            if (act_err == CLIP_OK) {
                                printf("ACTION SUCCESSFUL: Node %s RESTRICTED (audit_id=%u)\n\n", action_restr_node, audit_id);
                            } else {
                                printf("Action failed: %s\n\n", clip_error_string(act_err));
                            }
                        }
                    } else if (action_unrestr_node) {
                        ClipUuid tgt;
                        if (clip_uuid_from_string(&tgt, action_unrestr_node) != 0) {
                            printf("Invalid node UUID: %s\n\n", action_unrestr_node);
                        } else {
                            uint32_t audit_id = 0;
                            ClipError act_err = clip_admin_client_send_action(&client, CLIP_ADMIN_UNRESTRICT_NODE, &tgt,
                                                                             reason, 0, NULL, NULL, &audit_id);
                            if (act_err == CLIP_OK) {
                                printf("ACTION SUCCESSFUL: Node %s UNRESTRICTED (audit_id=%u)\n\n", action_unrestr_node, audit_id);
                            } else {
                                printf("Action failed: %s\n\n", clip_error_string(act_err));
                            }
                        }
                    } else if (action_ban_node) {
                        ClipUuid tgt;
                        if (clip_uuid_from_string(&tgt, action_ban_node) != 0) {
                            printf("Invalid node UUID: %s\n\n", action_ban_node);
                        } else {
                            uint32_t audit_id = 0;
                            ClipError act_err = clip_admin_client_send_action(&client, CLIP_ADMIN_BAN_NODE, &tgt,
                                                                             reason, 0, NULL, NULL, &audit_id);
                            if (act_err == CLIP_OK) {
                                printf("ACTION SUCCESSFUL: Node %s BANNED (audit_id=%u)\n\n", action_ban_node, audit_id);
                            } else {
                                printf("Action failed: %s\n\n", clip_error_string(act_err));
                            }
                        }
                    } else if (action_unban_node) {
                        ClipUuid tgt;
                        if (clip_uuid_from_string(&tgt, action_unban_node) != 0) {
                            printf("Invalid node UUID: %s\n\n", action_unban_node);
                        } else {
                            uint32_t audit_id = 0;
                            ClipError act_err = clip_admin_client_send_action(&client, CLIP_ADMIN_UNBAN_NODE, &tgt,
                                                                             reason, 0, NULL, NULL, &audit_id);
                            if (act_err == CLIP_OK) {
                                printf("ACTION SUCCESSFUL: Node %s UNBANNED (audit_id=%u)\n\n", action_unban_node, audit_id);
                            } else {
                                printf("Action failed: %s\n\n", clip_error_string(act_err));
                            }
                        }
                    } else if (action_lock_chan) {
                        ClipUuid tgt;
                        if (clip_uuid_from_string(&tgt, action_lock_chan) != 0) {
                            printf("Invalid channel UUID: %s\n\n", action_lock_chan);
                        } else {
                            uint32_t audit_id = 0;
                            ClipError act_err = clip_admin_client_send_action(&client, CLIP_ADMIN_LOCK_CHANNEL, &tgt,
                                                                             reason, 0, NULL, &tgt, &audit_id);
                            if (act_err == CLIP_OK) {
                                printf("ACTION SUCCESSFUL: Channel %s LOCKED (audit_id=%u)\n\n", action_lock_chan, audit_id);
                            } else {
                                printf("Action failed: %s\n\n", clip_error_string(act_err));
                            }
                        }
                    } else if (action_unlock_chan) {
                        ClipUuid tgt;
                        if (clip_uuid_from_string(&tgt, action_unlock_chan) != 0) {
                            printf("Invalid channel UUID: %s\n\n", action_unlock_chan);
                        } else {
                            uint32_t audit_id = 0;
                            ClipError act_err = clip_admin_client_send_action(&client, CLIP_ADMIN_UNLOCK_CHANNEL, &tgt,
                                                                             reason, 0, NULL, &tgt, &audit_id);
                            if (act_err == CLIP_OK) {
                                printf("ACTION SUCCESSFUL: Channel %s UNLOCKED (audit_id=%u)\n\n", action_unlock_chan, audit_id);
                            } else {
                                printf("Action failed: %s\n\n", clip_error_string(act_err));
                            }
                        }
                    } else if (action_new_admin_user) {
                        ClipAdminPermission new_role = CLIP_ADMIN_PERM_OBSERVER;
                        if (strcmp(action_new_admin_role, "moderator") == 0 || strcmp(action_new_admin_role, "MODERATOR") == 0 || strcmp(action_new_admin_role, "2") == 0) {
                            new_role = CLIP_ADMIN_PERM_MODERATOR;
                        } else if (strcmp(action_new_admin_role, "super_admin") == 0 || strcmp(action_new_admin_role, "SUPER_ADMIN") == 0 || strcmp(action_new_admin_role, "3") == 0) {
                            new_role = CLIP_ADMIN_PERM_SUPER_ADMIN;
                        }
                        uint32_t audit_id = 0;
                        ClipError act_err = clip_admin_client_create_admin(&client, action_new_admin_user, action_new_admin_pass,
                                                                          new_role, reason, &audit_id);
                        if (act_err == CLIP_OK) {
                            printf("ACTION SUCCESSFUL: Admin '%s' created with role %s (audit_id=%u)\n\n",
                                   action_new_admin_user, clip_admin_role_name(new_role), audit_id);
                        } else {
                            printf("Action failed: %s\n\n", clip_error_string(act_err));
                        }
                    }
                }
            }
        }
    } else if (do_menu || action_ptt_console) {
        char line[128];
        while (1) {
            char telem_status[256];
            clip_telemetry_format_compact(&client.telemetry, telem_status, sizeof(telem_status));

            printf("\nCLICOM\n");
            printf("Network : %s\n\n", telem_status);
            printf("[1] CREATE CHANNEL\n");
            printf("[2] JOIN CHANNEL\n");
            printf("[3] MY CHANNELS\n");
            printf("[4] CHANNEL MEMBERS\n");
            printf("[5] CONNECTION REQUEST\n");
            printf("[6] CONNECTIONS\n");
            printf("[7] START SESSION\n");
            printf("[8] PTT / FLOOR CONTROL\n");
            printf("[9] END SESSION\n");
            printf("[T] CONNECTION TELEMETRY\n");
            printf("[L] SESSION LOGS & NOTES\n");
            printf("[S] SECURITY ADVISORIES\n");
            printf("[Q] QUIT\n\n");
            printf("Choice > ");
            fflush(stdout);

            if (!console_read_line_pumped(&client, line, sizeof(line))) break;
            char c = line[0];
            if (c == 'q' || c == 'Q') break;

            if (c == '1') {
                printf("\nCreate Channel\nChannel name: ");
                fflush(stdout);
                char cname[CLIP_DISPLAY_NAME_MAX] = {0};
                if (console_read_line_pumped(&client, cname, sizeof(cname))) {
                    cname[strcspn(cname, "\r\n")] = '\0';
                    printf("Creating...\n\n");
                    ClipUuid chan_uuid;
                    char jkey[CLIP_JOIN_KEY_MAX];
                    ClipError err = clip_client_channel_create(&client, cname, &chan_uuid, jkey, sizeof(jkey));
                    if (err == CLIP_OK) {
                        char u_str[CLIP_UUID_STR_SIZE];
                        clip_uuid_to_string(&chan_uuid, u_str, sizeof(u_str));
                        printf("CHANNEL CREATED\n\nChannel UUID:\n%s\n\nJOIN KEY:\n%s\n\nYou are now a member.\n", u_str, jkey);
                    } else {
                        printf("Failed to create channel: %s\n", clip_error_string(err));
                    }
                }
            } else if (c == '2') {
                printf("\nEnter join key: ");
                fflush(stdout);
                char jkey[CLIP_JOIN_KEY_MAX] = {0};
                if (console_read_line_pumped(&client, jkey, sizeof(jkey))) {
                    jkey[strcspn(jkey, "\r\n")] = '\0';
                    ClipUuid chan_uuid;
                    char cname[CLIP_DISPLAY_NAME_MAX];
                    ClipChannelMember* mems = NULL;
                    size_t m_cnt = 0;
                    ClipError err = clip_client_channel_join(&client, jkey, &chan_uuid, cname, sizeof(cname), &mems, &m_cnt);
                    if (err == CLIP_OK) {
                        printf("\nJOIN SUCCESSFUL\n\nChannel:\n%s\n\nMembers:\n", cname);
                        for (size_t m = 0; m < m_cnt; m++) {
                            printf("%s %s\n", mems[m].display_name, (mems[m].presence == CLIP_PRESENCE_ONLINE) ? "ONLINE" : "OFFLINE");
                        }
                        clip_client_free_members(mems);
                    } else {
                        printf("Failed: %s\n", clip_error_string(err));
                    }
                }
            } else if (c == '3') {
                ClipChannelInfo* chans = NULL;
                size_t c_cnt = 0;
                ClipError err = clip_client_channel_list(&client, &chans, &c_cnt);
                if (err == CLIP_OK) {
                    printf("\nMy Channels (%u):\n", (unsigned)c_cnt);
                    for (size_t k = 0; k < c_cnt; k++) {
                        printf("  [%u] %s (Join Key: %s, UUID: %s)\n", (unsigned)(k + 1), chans[k].name, chans[k].join_key, chans[k].channel_uuid_str);
                    }
                    clip_client_free_channels(chans);
                } else {
                    printf("Failed to list channels: %s\n", clip_error_string(err));
                }
            } else if (c == '4') {
                printf("\nEnter Channel UUID: ");
                fflush(stdout);
                char u_in[64] = {0};
                if (console_read_line_pumped(&client, u_in, sizeof(u_in))) {
                    u_in[strcspn(u_in, "\r\n")] = '\0';
                    ClipUuid chan_uuid;
                    if (clip_uuid_from_string(&chan_uuid, u_in) == 0) {
                        ClipChannelMember* mems = NULL;
                        size_t m_cnt = 0;
                        ClipError err = clip_client_get_channel_members(&client, &chan_uuid, &mems, &m_cnt);
                        if (err == CLIP_OK) {
                            printf("\nChannel Members (%u):\n", (unsigned)m_cnt);
                            for (size_t m = 0; m < m_cnt; m++) {
                                char nu_str[CLIP_UUID_STR_SIZE];
                                clip_uuid_to_string(&mems[m].node_uuid, nu_str, sizeof(nu_str));
                                printf("  - %s [%s] (%s)\n", mems[m].display_name, nu_str,
                                       (mems[m].presence == CLIP_PRESENCE_ONLINE) ? "ONLINE" : "OFFLINE");
                            }
                            clip_client_free_members(mems);
                        } else {
                            printf("Failed to fetch members: %s\n", clip_error_string(err));
                        }
                    } else {
                        printf("Invalid Channel UUID.\n");
                    }
                }
            } else if (c == '5') {
                printf("\nEnter Channel UUID: ");
                fflush(stdout);
                char chan_in[64] = {0};
                if (console_read_line_pumped(&client, chan_in, sizeof(chan_in))) {
                    chan_in[strcspn(chan_in, "\r\n")] = '\0';
                    printf("Enter Target Node UUID: ");
                    fflush(stdout);
                    char node_in[64] = {0};
                    if (console_read_line_pumped(&client, node_in, sizeof(node_in))) {
                        node_in[strcspn(node_in, "\r\n")] = '\0';
                        ClipUuid chan_uuid, tgt_uuid;
                        if (clip_uuid_from_string(&chan_uuid, chan_in) == 0 &&
                            clip_uuid_from_string(&tgt_uuid, node_in) == 0) {
                            ClipUuid conn_uuid;
                            ClipConnectionState state;
                            ClipError err = clip_client_send_conn_request(&client, &chan_uuid, &tgt_uuid, &conn_uuid, &state);
                            if (err == CLIP_OK) {
                                char cu_str[CLIP_UUID_STR_SIZE];
                                clip_uuid_to_string(&conn_uuid, cu_str, sizeof(cu_str));
                                printf("\nCONNECTION REQUESTED\nConnection UUID: %s\nStatus: %s\n",
                                       cu_str, (state == CLIP_CONN_STATE_REQUESTED) ? "REQUESTED" : "ACCEPTED");
                            } else {
                                printf("Failed to send request: %s\n", clip_error_string(err));
                            }
                        } else {
                            printf("Invalid UUID(s).\n");
                        }
                    }
                }
            } else if (c == '6') {
                ClipConnectionRecord* conns = NULL;
                size_t c_cnt = 0;
                ClipError err = clip_client_list_connections(&client, &conns, &c_cnt);
                if (err == CLIP_OK) {
                    printf("\nConnections (%u):\n", (unsigned)c_cnt);
                    for (size_t k = 0; k < c_cnt; k++) {
                        char cu_str[CLIP_UUID_STR_SIZE], req_str[CLIP_UUID_STR_SIZE], tgt_str[CLIP_UUID_STR_SIZE];
                        clip_uuid_to_string(&conns[k].connection_uuid, cu_str, sizeof(cu_str));
                        clip_uuid_to_string(&conns[k].requester_node_uuid, req_str, sizeof(req_str));
                        clip_uuid_to_string(&conns[k].target_node_uuid, tgt_str, sizeof(tgt_str));
                        const char* st_name = (conns[k].state == CLIP_CONN_STATE_REQUESTED) ? "REQUESTED" :
                                              (conns[k].state == CLIP_CONN_STATE_ACCEPTED) ? "ACCEPTED" :
                                              (conns[k].state == CLIP_CONN_STATE_DECLINED) ? "DECLINED" :
                                              (conns[k].state == CLIP_CONN_STATE_CLOSED) ? "CLOSED" : "EXPIRED";
                        printf("  [%u] %s [%s] From: %s To: %s\n", (unsigned)(k + 1), cu_str, st_name, req_str, tgt_str);
                    }
                    clip_client_free_connections(conns);

                    printf("\nAction on connection: [A]ccept, [D]ecline, or [Enter] to return: ");
                    fflush(stdout);
                    char resp_act[16] = {0};
                    if (console_read_line_pumped(&client, resp_act, sizeof(resp_act)) && (resp_act[0] == 'a' || resp_act[0] == 'A' || resp_act[0] == 'd' || resp_act[0] == 'D')) {
                        bool accept = (resp_act[0] == 'a' || resp_act[0] == 'A');
                        printf("Enter Connection UUID: ");
                        fflush(stdout);
                        char conn_in[64] = {0};
                        if (console_read_line_pumped(&client, conn_in, sizeof(conn_in))) {
                            conn_in[strcspn(conn_in, "\r\n")] = '\0';
                            ClipUuid conn_uuid;
                            if (clip_uuid_from_string(&conn_uuid, conn_in) == 0) {
                                ClipError r_err = clip_client_respond_conn(&client, &conn_uuid, accept);
                                if (r_err == CLIP_OK) {
                                    printf("\nConnection updated: %s\n", accept ? "ACCEPTED" : "DECLINED");
                                } else {
                                    printf("Failed to update connection: %s\n", clip_error_string(r_err));
                                }
                            } else {
                                printf("Invalid Connection UUID.\n");
                            }
                        }
                    }
                } else {
                    printf("Failed to list connections: %s\n", clip_error_string(err));
                }
            } else if (c == '7') {
                printf("\nEnter Connection UUID: ");
                fflush(stdout);
                char u_in[64] = {0};
                if (console_read_line_pumped(&client, u_in, sizeof(u_in))) {
                    u_in[strcspn(u_in, "\r\n")] = '\0';
                    ClipUuid conn_uuid;
                    if (clip_uuid_from_string(&conn_uuid, u_in) == 0) {
                        ClipUuid sess_uuid;
                        ClipError err = clip_client_session_start_by_conn(&client, &conn_uuid, &sess_uuid);
                        if (err == CLIP_OK) {
                            clip_captions_set_session(&g_caption_buf, &sess_uuid, clip_client_get_speech_mode(&client));
                            char s_str[CLIP_UUID_STR_SIZE];
                            clip_uuid_to_string(&sess_uuid, s_str, sizeof(s_str));
                            printf("\nSESSION STARTED\n\nSession UUID:\n%s\n", s_str);
                        } else {
                            printf("Failed to start session: %s\n", clip_error_string(err));
                        }
                    } else {
                        printf("Invalid Connection UUID.\n");
                    }
                }
            } else if (c == '8') {
                printf("\nPTT / FLOOR CONTROL\n");
                printf("Enter Session UUID: ");
                fflush(stdout);
                char s_in[64] = {0};
                if (console_read_line_pumped(&client, s_in, sizeof(s_in))) {
                    s_in[strcspn(s_in, "\r\n")] = '\0';
                    ClipUuid sess_uuid;
                    if (clip_uuid_from_string(&sess_uuid, s_in) == 0) {
                        while (1) {
                            ClipPttFloor floor;
                            ClipError st_err = clip_client_ptt_status(&client, &sess_uuid, &floor);
                            printf("\nPTT / FLOOR CONTROL\n");
                            printf("────────────────────────────────────────\n");
                            printf("Session : %s\n", s_in);
                            if (st_err == CLIP_OK) {
                                if (floor.floor_state == CLIP_PTT_FLOOR_FREE) {
                                    if (client.ptt_floor_held) {
                                        client.ptt_floor_held = false;
                                        clip_audio_on_floor_released(&audio_engine);
                                        clip_uuid_zero(&g_audio_sender.session_uuid);
                                    }
                                    printf("Floor   : FREE\n");
                                } else {
                                    bool is_me = (memcmp(client.assigned_uuid, floor.holder_node_uuid.bytes, CLIP_UUID_BYTES) == 0);
                                    if (is_me) {
                                        client.ptt_floor_held = true;
                                        printf("Floor   : YOU ARE SPEAKER\n");
                                        printf("Holder  : %s (YOU)\n", floor.speaker_uuid_str);
                                    } else {
                                        if (client.ptt_floor_held) {
                                            client.ptt_floor_held = false;
                                            clip_audio_on_floor_released(&audio_engine);
                                            clip_uuid_zero(&g_audio_sender.session_uuid);
                                        }
                                        printf("Floor   : PEER HAS THE FLOOR\n");
                                        printf("Holder  : %s\n", floor.speaker_uuid_str);
                                    }
                                    if (floor.lease_timeout_ms > 0) {
                                        printf("Lease   : ACTIVE (%u ms remaining)\n", (unsigned)floor.lease_timeout_ms);
                                    }
                                }
                            } else {
                                printf("Floor   : Status check error (%s)\n", clip_error_string(st_err));
                            }
                            printf("────────────────────────────────────────\n");
                            char ptt_telem[256];
                            clip_telemetry_format_compact(&client.telemetry, ptt_telem, sizeof(ptt_telem));
                            printf("Network : %s\n", ptt_telem);
                            printf("────────────────────────────────────────\n");
                            clip_captions_render(&g_caption_buf, stdout, 6);
                            printf("────────────────────────────────────────\n");
                            printf("[SPACE/1] REQUEST FLOOR\n");
                            printf("[R/2]     RELEASE FLOOR\n");
                            printf("[S/3]     REFRESH STATUS / PROBE\n");
                            printf("[C/4]     VIEW LIVE CAPTIONS\n");
                            printf("[Q]       BACK TO MAIN MENU\n\n");
                            printf("PTT Choice > ");
                            fflush(stdout);

                            char ptt_line[128];
                            if (!console_read_line_pumped(&client, ptt_line, sizeof(ptt_line))) break;
                            char pc = ptt_line[0];
                            if (pc == 'q' || pc == 'Q') break;

                            if (pc == ' ' || pc == '1') {
                                printf("\nRequesting floor...\n");
                                ClipPttFloor granted_floor;
                                ClipError denial_reason = CLIP_OK;
                                ClipError acq_res = clip_client_ptt_request(&client, &sess_uuid, 5000, &granted_floor, &denial_reason);
                                if (acq_res == CLIP_OK) {
                                    client.ptt_floor_held = true;
                                    g_audio_sender.net = &client;
                                    g_audio_sender.session_uuid = sess_uuid;
                                    clip_audio_on_floor_granted(&audio_engine);
                                    printf("\n========================================\n");
                                    printf("YOU HAVE THE FLOOR\n");
                                    printf("Audio Capture: ACTIVE (PTT floor held)\n");
                                    printf("Session: %s\n", s_in);
                                    printf("========================================\n");
                                } else if (acq_res == CLIP_ERR_PTT_BUSY) {
                                    printf("\n----------------------------------------\n");
                                    printf("FLOOR BUSY\n");
                                    printf("Current holder: %s\n", granted_floor.speaker_uuid_str);
                                    printf("Reason: FLOOR_BUSY\n");
                                    printf("----------------------------------------\n");
                                } else {
                                    printf("\nFailed to request floor: %s\n", clip_error_string(acq_res));
                                }
                            } else if (pc == 'r' || pc == 'R' || pc == '2') {
                                printf("\nReleasing floor...\n");
                                client.ptt_floor_held = false;
                                clip_audio_on_floor_released(&audio_engine);
                                clip_uuid_zero(&g_audio_sender.session_uuid);
                                ClipError rel_res = clip_client_ptt_release(&client, &sess_uuid);
                                if (rel_res == CLIP_OK) {
                                    printf("\n========================================\n");
                                    printf("FLOOR RELEASED\n");
                                    printf("Audio Capture: STOPPED (floor released)\n");
                                    printf("Floor is now FREE\n");
                                    printf("========================================\n");
                                } else {
                                    printf("Failed to release floor: %s\n", clip_error_string(rel_res));
                                }
                            } else if (pc == 's' || pc == 'S' || pc == '3') {
                                clip_client_send_heartbeat(&client);
                                clip_client_pump_events(&client, 50);
                            } else if (pc == 'c' || pc == 'C' || pc == '4') {
                                printf("\n");
                                clip_captions_render(&g_caption_buf, stdout, 12);
                                printf("\n");
                            }
                        }
                    } else {
                        printf("Invalid Session UUID.\n");
                    }
                }
            } else if (c == '9') {
                printf("\nEnter Session UUID: ");
                fflush(stdout);
                char s_in[64] = {0};
                if (console_read_line_pumped(&client, s_in, sizeof(s_in))) {
                    s_in[strcspn(s_in, "\r\n")] = '\0';
                    ClipUuid sess_uuid;
                    if (clip_uuid_from_string(&sess_uuid, s_in) == 0) {
                        ClipError err = clip_client_session_end(&client, &sess_uuid);
                        if (err == CLIP_OK) {
                            clip_captions_set_session(&g_caption_buf, NULL, CLIP_SPEECH_MODE_NONE);
                            printf("\nSESSION ENDED\n");
                        } else {
                            printf("Failed to end session: %s\n", clip_error_string(err));
                        }
                    } else {
                        printf("Invalid Session UUID.\n");
                    }
                }
            } else if (c == 'l' || c == 'L') {
                printf("\nSession Logs & Notes\nFetching authorized sessions...\n");
                ClipSessionLogEntry* logs = NULL;
                size_t l_cnt = 0;
                ClipError err = clip_client_list_session_logs(&client, &logs, &l_cnt);
                if (err != CLIP_OK) {
                    printf("Failed to fetch session logs: %s\n", clip_error_string(err));
                } else if (l_cnt == 0) {
                    printf("No authorized sessions found.\n");
                    clip_client_free_session_logs(logs);
                } else {
                    printf("\nAuthorized Sessions (%u):\n", (unsigned)l_cnt);
                    for (size_t k = 0; k < l_cnt; k++) {
                        char su_str[CLIP_UUID_STR_SIZE];
                        clip_uuid_to_string(&logs[k].session_uuid, su_str, sizeof(su_str));
                        const char* st_name = (logs[k].state == 1) ? "ACTIVE" : "ENDED";
                        printf("  [%u] %s | %s | Duration: %llu ms | Notes: %u\n",
                               (unsigned)(k + 1), su_str, st_name, (unsigned long long)logs[k].duration_ms, (unsigned)logs[k].note_count);
                    }

                    printf("\nSelect session [1..%u] (or 0 to cancel): ", (unsigned)l_cnt);
                    fflush(stdout);
                    char sel_buf[32] = {0};
                    if (console_read_line_pumped(&client, sel_buf, sizeof(sel_buf))) {
                        int sel_idx = atoi(sel_buf);
                        if (sel_idx >= 1 && (size_t)sel_idx <= l_cnt) {
                            ClipSessionLogEntry sel_log = logs[sel_idx - 1];
                            char sel_su_str[CLIP_UUID_STR_SIZE];
                            clip_uuid_to_string(&sel_log.session_uuid, sel_su_str, sizeof(sel_su_str));

                            while (1) {
                                printf("\n--------------------------------------------------\n");
                                printf("Session: %s\n", sel_su_str);
                                printf("State  : %s | Notes: %u | Duration: %llu ms\n",
                                       (sel_log.state == 1) ? "ACTIVE" : "ENDED",
                                       (unsigned)sel_log.note_count,
                                       (unsigned long long)sel_log.duration_ms);
                                printf("--------------------------------------------------\n");
                                printf("[1] View Notes\n");
                                printf("[2] Add Manual Note\n");
                                printf("[3] Export & Save Live Captions as Transcript Note\n");
                                printf("[4] Search Notes\n");
                                printf("[0] Back to Main Menu\n\n");
                                printf("Choice > ");
                                fflush(stdout);

                                char sub_line[64] = {0};
                                if (!console_read_line_pumped(&client, sub_line, sizeof(sub_line))) break;
                                char sc = sub_line[0];
                                if (sc == '0' || sc == 'q' || sc == 'Q') break;

                                if (sc == '1') {
                                    ClipSessionNoteEntry* notes = NULL;
                                    size_t n_cnt = 0;
                                    ClipError n_err = clip_client_list_notes(&client, &sel_log.session_uuid, NULL, &notes, &n_cnt);
                                    if (n_err == CLIP_OK) {
                                        printf("\nNotes (%u):\n", (unsigned)n_cnt);
                                        for (size_t ni = 0; ni < n_cnt; ni++) {
                                            char a_str[CLIP_UUID_STR_SIZE];
                                            clip_uuid_to_string(&notes[ni].author_node_uuid, a_str, sizeof(a_str));
                                            const char* t_name = (notes[ni].note_type == CLIP_NOTE_TYPE_TRANSCRIPT) ? "TRANSCRIPT" : "MANUAL";
                                            printf("  [%u] Note #%u (%s) by %s:\n      %s\n",
                                                   (unsigned)(ni + 1), notes[ni].note_id, t_name, a_str, notes[ni].note_text);
                                        }
                                        printf("\n");
                                        sel_log.note_count = (uint32_t)n_cnt;
                                        clip_client_free_notes(notes);
                                    } else {
                                        printf("Failed to fetch notes: %s\n", clip_error_string(n_err));
                                    }
                                } else if (sc == '2') {
                                    printf("\nEnter note text (max 1024 chars): ");
                                    fflush(stdout);
                                    char n_text[CLIP_NOTE_TEXT_MAX_LEN + 64] = {0};
                                    if (console_read_line_pumped(&client, n_text, sizeof(n_text))) {
                                        n_text[strcspn(n_text, "\r\n")] = '\0';
                                        if (strlen(n_text) > 0) {
                                            uint32_t new_id = 0;
                                            ClipError c_err = clip_client_create_note(&client, &sel_log.session_uuid, CLIP_NOTE_TYPE_MANUAL, n_text, &new_id);
                                            if (c_err == CLIP_OK) {
                                                printf("\nNOTE CREATED\nNote ID: %u\n", new_id);
                                                sel_log.note_count++;
                                            } else {
                                                printf("Failed to create note: %s\n", clip_error_string(c_err));
                                            }
                                        } else {
                                            printf("Note text cannot be empty.\n");
                                        }
                                    }
                                } else if (sc == '3') {
                                    char sum_buf[CLIP_NOTE_TEXT_MAX_LEN + 1];
                                    size_t w_len = 0;
                                    clip_captions_export_summary(&g_caption_buf, sum_buf, sizeof(sum_buf), &w_len);
                                    if (w_len == 0) {
                                        printf("\nNo finalized captions available in active buffer to export.\n");
                                    } else {
                                        uint32_t new_id = 0;
                                        ClipError c_err = clip_client_create_note(&client, &sel_log.session_uuid, CLIP_NOTE_TYPE_TRANSCRIPT, sum_buf, &new_id);
                                        if (c_err == CLIP_OK) {
                                            printf("\nCAPTIONS TRANSCRIPT SAVED\nNote ID: %u\nLength: %zu bytes\n", new_id, w_len);
                                            sel_log.note_count++;
                                        } else {
                                            printf("Failed to save captions transcript: %s\n", clip_error_string(c_err));
                                        }
                                    }
                                } else if (sc == '4') {
                                    printf("\nEnter search query: ");
                                    fflush(stdout);
                                    char q_text[128] = {0};
                                    if (console_read_line_pumped(&client, q_text, sizeof(q_text))) {
                                        q_text[strcspn(q_text, "\r\n")] = '\0';
                                        ClipSessionNoteEntry* notes = NULL;
                                        size_t n_cnt = 0;
                                        ClipError s_err = clip_client_list_notes(&client, &sel_log.session_uuid, q_text, &notes, &n_cnt);
                                        if (s_err == CLIP_OK) {
                                            printf("\nMatching Notes (%u):\n", (unsigned)n_cnt);
                                            for (size_t ni = 0; ni < n_cnt; ni++) {
                                                char a_str[CLIP_UUID_STR_SIZE];
                                                clip_uuid_to_string(&notes[ni].author_node_uuid, a_str, sizeof(a_str));
                                                const char* t_name = (notes[ni].note_type == CLIP_NOTE_TYPE_TRANSCRIPT) ? "TRANSCRIPT" : "MANUAL";
                                                printf("  [%u] Note #%u (%s) by %s:\n      %s\n",
                                                       (unsigned)(ni + 1), notes[ni].note_id, t_name, a_str, notes[ni].note_text);
                                            }
                                            printf("\n");
                                            clip_client_free_notes(notes);
                                        } else {
                                            printf("Failed to search notes: %s\n", clip_error_string(s_err));
                                        }
                                    }
                                }
                            }
                        }
                    }
                    clip_client_free_session_logs(logs);
                }
            } else if (c == 's' || c == 'S') {
                printf("\nSecurity Advisory Events\nFetching advisory events...\n");
                ClipSecurityEvent* events = NULL;
                size_t e_cnt = 0;
                ClipError err = clip_client_list_security_events(&client, NULL, &events, &e_cnt);
                if (err != CLIP_OK) {
                    printf("Failed to fetch security events: %s\n", clip_error_string(err));
                } else if (e_cnt == 0) {
                    printf("No security advisory events found.\n");
                    clip_client_free_security_events(events, e_cnt);
                } else {
                    printf("\nSecurity Advisory Events (%u):\n", (unsigned)e_cnt);
                    for (size_t k = 0; k < e_cnt; k++) {
                        const char* st_name = (events[k].status == CLIP_EVENT_STATUS_REVIEWED) ? "REVIEWED" :
                                              (events[k].status == CLIP_EVENT_STATUS_FALSE_POS) ? "FALSE_POS" : "PENDING";
                        const char* cat_name = (events[k].category == CLIP_SECURITY_CAT_THREAT) ? "THREAT" :
                                               (events[k].category == CLIP_SECURITY_CAT_SUSPICIOUS) ? "SUSPICIOUS" : "CUSTOM";
                        const char* sev_name = (events[k].severity == CLIP_SECURITY_SEV_CRITICAL) ? "CRITICAL" :
                                               (events[k].severity == CLIP_SECURITY_SEV_HIGH) ? "HIGH" :
                                               (events[k].severity == CLIP_SECURITY_SEV_MEDIUM) ? "MEDIUM" : "LOW";
                        printf("  [%u] Event #%u [%s/%s] Status: %s | Term: \"%s\" | Rule: %s\n",
                               (unsigned)(k + 1), events[k].event_id, cat_name, sev_name, st_name,
                               events[k].matched_term, events[k].matched_rule);
                    }

                    printf("\nSelect event [1..%u] for full details (or 0 to return): ", (unsigned)e_cnt);
                    fflush(stdout);
                    char sel_buf[32] = {0};
                    if (console_read_line_pumped(&client, sel_buf, sizeof(sel_buf))) {
                        int sel_idx = atoi(sel_buf);
                        if (sel_idx >= 1 && (size_t)sel_idx <= e_cnt) {
                            ClipSecurityEvent ev = events[sel_idx - 1];
                            char su_str[CLIP_UUID_STR_SIZE];
                            clip_uuid_to_string((const ClipUuid*)ev.session_uuid, su_str, sizeof(su_str));
                            const char* st_name = (ev.status == CLIP_EVENT_STATUS_REVIEWED) ? "REVIEWED" :
                                                  (ev.status == CLIP_EVENT_STATUS_FALSE_POS) ? "FALSE_POS" : "PENDING (Advisory / Requires Review)";
                            const char* cat_name = (ev.category == CLIP_SECURITY_CAT_THREAT) ? "THREAT" :
                                                   (ev.category == CLIP_SECURITY_CAT_SUSPICIOUS) ? "SUSPICIOUS" : "CUSTOM";
                            const char* sev_name = (ev.severity == CLIP_SECURITY_SEV_CRITICAL) ? "CRITICAL" :
                                                   (ev.severity == CLIP_SECURITY_SEV_HIGH) ? "HIGH" :
                                                   (ev.severity == CLIP_SECURITY_SEV_MEDIUM) ? "MEDIUM" : "LOW";
                            printf("\n──────────────────────────────────────────────────\n");
                            printf("SECURITY ADVISORY EVENT #%u\n", ev.event_id);
                            printf("──────────────────────────────────────────────────\n");
                            printf("Event UUID   : %s\n", ev.event_uuid_str);
                            printf("Session UUID : %s\n", su_str);
                            printf("Channel UUID : %s\n", ev.channel_uuid_str);
                            printf("Speaker Node : %s\n", ev.node_uuid_str);
                            printf("Timestamp    : %llu\n", (unsigned long long)ev.timestamp_ms);
                            printf("Category     : %s\n", cat_name);
                            printf("Severity     : %s\n", sev_name);
                            printf("Matched Rule : %s\n", ev.matched_rule);
                            printf("Matched Term : \"%s\"\n", ev.matched_term);
                            printf("Context Text : \"%s\"\n", ev.context_text);
                            printf("Review Status: %s\n", st_name);
                            printf("──────────────────────────────────────────────────\n\n");
                        }
                    }
                    clip_client_free_security_events(events, e_cnt);
                }
            } else if (c == 't' || c == 'T') {
                printf("\nProbing connection to server...\n");
                clip_client_send_heartbeat(&client);
                clip_client_pump_events(&client, 200);

                printf("\nCONNECTION TELEMETRY & HEALTH\n");
                printf("──────────────────────────────────────────────────\n");
                char telem_summary[256];
                clip_telemetry_format_compact(&client.telemetry, telem_summary, sizeof(telem_summary));
                printf("Status           : %s\n\n", telem_summary);
                printf("Total Probes Sent: %zu\n", client.telemetry.total_probes_sent);
                printf("Window Completed : %zu / %d probes\n", client.telemetry.window_completed_probes, CLIP_TELEMETRY_WINDOW_SIZE);
                printf("Window Lost      : %zu probes\n", client.telemetry.window_lost_probes);
                if (client.telemetry.rtt_sample_count > 0) {
                    if (client.telemetry.last_rtt_ms < 1.0) {
                        printf("RTT Last/Min/Max : %.2f / %.2f / %.2f ms\n",
                               client.telemetry.last_rtt_ms,
                               client.telemetry.min_rtt_ms,
                               client.telemetry.max_rtt_ms);
                    } else {
                        printf("RTT Last/Min/Max : %.1f / %.1f / %.1f ms\n",
                               client.telemetry.last_rtt_ms,
                               client.telemetry.min_rtt_ms,
                               client.telemetry.max_rtt_ms);
                    }
                } else {
                    printf("RTT Last/Min/Max : N/A (no responses yet)\n");
                }
                if (client.telemetry.has_jitter) {
                    if (client.telemetry.jitter_ms < 1.0) {
                        printf("Jitter (RFC 3550): %.2f ms\n", client.telemetry.jitter_ms);
                    } else {
                        printf("Jitter (RFC 3550): %.1f ms\n", client.telemetry.jitter_ms);
                    }
                } else {
                    printf("Jitter (RFC 3550): N/A (requires >= %d valid RTT samples)\n", CLIP_TELEMETRY_MIN_JITTER_SAMPLES);
                }
                if (client.telemetry.has_loss) {
                    printf("Probe Loss       : %.1f%%\n", client.telemetry.loss_percent);
                } else {
                    printf("Probe Loss       : N/A (requires >= %d completed probes)\n", CLIP_TELEMETRY_MIN_LOSS_PROBES);
                }
                printf("Connection Rating: %s %s\n",
                       clip_telemetry_quality_bars(client.telemetry.quality),
                       clip_telemetry_quality_name(client.telemetry.quality));
                printf("──────────────────────────────────────────────────\n\n");
            }
        }
    }

    g_active_client = NULL;
    clip_audio_on_floor_released(&audio_engine);
    clip_audio_stop_playback(&audio_engine);
    clip_audio_engine_cleanup(&audio_engine);
    clip_client_disconnect(&client);
    clip_captions_set_session(&g_caption_buf, NULL, CLIP_SPEECH_MODE_NONE);
    clip_client_set_speech_analyzer(&client, NULL);
    if (speech_analyzer) {
        speech_analyzer_destroy(speech_analyzer);
        speech_analyzer = NULL;
    }
    clip_captions_cleanup(&g_caption_buf);
    clip_client_net_cleanup(&client);
    printf("Disconnected cleanly.\n");

    clip_log_close();
    return 0;
}

/* ── Banner ─────────────────────────────────────────────────────────────── */

static void print_banner(void)
{
    printf("\n");
    printf("============================================================\n");
    printf("                       C L I C O M\n");
    printf("                   CLI COMMUNICATION\n");
    printf("                       v%s\n", CLICOM_VERSION_STRING);
    printf("============================================================\n");
    printf("  Protocol  : CLIPv%s\n", CLIP_PROTOCOL_VERSION_STRING);
    printf("  Platform  : %s\n",      CLICOM_TARGET_PLATFORM);
    printf("  Built     : %s\n",      CLICOM_BUILD_TIMESTAMP);
    printf("============================================================\n");
    printf("\n");
}

static void print_version(void)
{
    /* Software version and protocol version reported separately. */
    printf("clicom %s (protocol CLIPv%s, platform %s)\n",
           CLICOM_VERSION_STRING,
           CLIP_PROTOCOL_VERSION_STRING,
           CLICOM_TARGET_PLATFORM);
}

static void print_help(const char* argv0)
{
    printf("Usage: %s [OPTIONS]\n\n", argv0);
    printf("Options:\n");
    printf("  --node <name>             Set node display name (e.g. NODE-A)\n");
    printf("  --host <ip>               Server IP address (default: 127.0.0.1)\n");
    printf("  --port <port>             Server port (default: 4821)\n");
    printf("  --ca, --ca-cert <path>    Path to trusted CA certificate (default: certs/ca.crt)\n");
    printf("  --server-name <host>      Expected server hostname for TLS (default: localhost)\n");
    printf("  --insecure-plaintext      Connect without TLS (development/test mode only)\n");
    printf("  --no-tls                  Alias for --insecure-plaintext\n");
    printf("  --cred-file <path>        Path to DPAPI credential file\n");
    printf("  --create-channel <name>   Create new channel and print join key\n");
    printf("  --join-channel <key>      Join channel by join key (e.g. GC-XXXX)\n");
    printf("  --list-channels           List channels this node belongs to\n");
    printf("  --members <chan_uuid>     List channel members with live presence\n");
    printf("  --request-conn <ch> <tgt> Send connection request to target node in channel\n");
    printf("  --accept-conn <conn_uuid> Accept pending connection request\n");
    printf("  --decline-conn <conn_uuid> Decline pending connection request\n");
    printf("  --list-conns              List connections for this node\n");
    printf("  --start-session-conn <cu> Start communication session bound to accepted connection\n");
    printf("  --start-session <uuid>    Start a communication session in channel\n");
    printf("  --end-session <uuid>      End active communication session\n");
    printf("  --list-events [sess_uuid] List security advisory events (session or all)\n");
    printf("  --get-event <id|uuid>     Get full details for a security advisory event\n");
    printf("  --admin-login <user>      Authenticate administrator session\n");
    printf("  --admin-pass <pass>       Administrator password\n");
    printf("  --admin-reason <reason>   Administrative action justification reason\n");
    printf("  --admin-events [status]   List security advisories with admin filter (PENDING, etc.)\n");
    printf("  --admin-audit [limit]     Query append-only administrative audit log\n");
    printf("  --review-event <id>       Mark advisory security event as REVIEWED\n");
    printf("  --mark-false-pos <id>     Mark advisory security event as FALSE_POS\n");
    printf("  --disconnect-node <uuid>  Administratively disconnect active node\n");
    printf("  --restrict-node <uuid>    Set persistent RESTRICTED sanction (listen-only)\n");
    printf("  --unrestrict-node <uuid>  Remove RESTRICTED sanction from node\n");
    printf("  --ban-node <uuid>         Set persistent BANNED sanction on node\n");
    printf("  --unban-node <uuid>       Remove BANNED sanction from node\n");
    printf("  --lock-channel <uuid>     Administratively lock channel\n");
    printf("  --unlock-channel <uuid>   Administratively unlock channel\n");
    printf("  --create-admin-account <usr> <role> <pwd> Create new admin (SUPER_ADMIN only)\n");
    printf("  --menu                    Launch interactive CLI channel/session menu\n");
    printf("  --re-register             Force new registration instead of saved creds\n");
    printf("  --version, -v             Print version and exit\n");
    printf("  --help,    -h             Print this help and exit\n");
    printf("  --test                    Run self-test and exit\n");
    printf("\nExamples:\n");
    printf("  %s --node NODE-A --create-channel TEAM-OPS\n", argv0);
    printf("  %s --node NODE-B --join-channel GC-WXYZ\n", argv0);
    printf("  %s --node NODE-A --list-channels\n", argv0);
    printf("  %s --node NODE-A --members <channel-uuid>\n", argv0);
    printf("  %s --node NODE-A --request-conn <channel-uuid> <target-node-uuid>\n", argv0);
    printf("  %s --node NODE-B --accept-conn <connection-uuid>\n", argv0);
    printf("  %s --node NODE-A --list-conns\n", argv0);
    printf("  %s --node NODE-A --start-session-conn <connection-uuid>\n", argv0);
    printf("  %s --node NODE-A --start-session <channel-uuid>\n", argv0);
    printf("  %s --node NODE-A --end-session <session-uuid>\n", argv0);
    printf("  %s --menu\n", argv0);
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

    printf("CLICOM Client — Phase 0 Self-Test\n");
    printf("==================================\n");

    /* Version */
    CHECK("Software version major == 2",  CLICOM_VERSION_MAJOR == 2);
    CHECK("Software version minor == 0",  CLICOM_VERSION_MINOR == 0);
    CHECK("Software version patch == 0",  CLICOM_VERSION_PATCH == 0);

    /* Protocol version (independent of software version) */
    CHECK("Protocol version major == 1",  CLIP_PROTOCOL_VERSION_MAJOR == 1);
    CHECK("Protocol version minor == 0",  CLIP_PROTOCOL_VERSION_MINOR == 0);

    /* Wire constants */
    CHECK("Protocol magic == 0x434C4950", CLIP_PROTOCOL_MAGIC == 0x434C4950u);
    CHECK("Header size == 36 bytes",      CLIP_HEADER_SIZE == 36u);
    CHECK("Max payload size > 0",         CLIP_MAX_PAYLOAD_SIZE > 0u);
    CHECK("UUID bytes == 16",             CLIP_UUID_BYTES == 16u);

    /* Verify software and protocol versions are distinct strings */
    CHECK("Software version != protocol version string",
          strcmp(CLICOM_VERSION_STRING, CLIP_PROTOCOL_VERSION_STRING) != 0);

    /* Error string table */
    CHECK("clip_error_string(CLIP_OK) not empty",
          clip_error_string(CLIP_OK) != NULL &&
          clip_error_string(CLIP_OK)[0] != '\0');
    CHECK("clip_error_string(CLIP_ERR_AUTH) not empty",
          clip_error_string(CLIP_ERR_AUTH) != NULL &&
          clip_error_string(CLIP_ERR_AUTH)[0] != '\0');

    printf("==================================\n");
    printf("Result : %d passed", pass_count);
    if (fail_count > 0) {
        printf(", %d FAILED", fail_count);
    }
    printf("\n\n");

#undef CHECK
    return (fail_count == 0) ? 0 : 1;
}

/* ── Audio Diagnostic Self-Test (Phase 9) ────────────────────────────────── */

static int run_audio_test(void)
{
    printf("CLICOM Local Audio Subsystem Diagnostic (Phase 9)\n");
    printf("====================================================\n");
    UINT in_devs = waveInGetNumDevs();
    UINT out_devs = waveOutGetNumDevs();
    printf("WinMM Audio Capture Devices Detected  : %u\n", in_devs);
    printf("WinMM Audio Playback Devices Detected : %u\n", out_devs);

    ClipAudioConfig cfg;
    clip_audio_config_init_default(&cfg);
    cfg.backend = CLIP_AUDIO_BACKEND_MOCK;

    ClipAudioEngine engine;
    ClipError err = clip_audio_engine_init(&engine, &cfg);
    if (err != CLIP_OK) {
        printf("Engine initialization failed: %s\n", clip_error_string(err));
        return 1;
    }
    printf("Mock Audio Engine initialized: %u Hz, %u ch, %u-bit PCM, %u ms frames\n",
           cfg.sample_rate, cfg.channels, cfg.bits_per_sample, cfg.frame_duration_ms);

    printf("Simulating PTT Floor Acquisition...\n");
    clip_audio_on_floor_granted(&engine);
    printf("  Floor held       : %s\n", clip_audio_is_floor_held(&engine) ? "YES" : "NO");
    printf("  Device capturing : %s\n", clip_audio_is_capturing(&engine) ? "YES" : "NO");

    Sleep(80);

    int16_t samples[640];
    size_t count = clip_audio_read_captured_pcm(&engine, samples, 640);
    printf("  Captured frames  : %zu PCM samples during floor lease.\n", count);

    printf("Simulating PTT Floor Release...\n");
    clip_audio_on_floor_released(&engine);
    printf("  Floor held       : %s\n", clip_audio_is_floor_held(&engine) ? "YES" : "NO");
    printf("  Device capturing : %s\n", clip_audio_is_capturing(&engine) ? "YES" : "NO");

    clip_audio_engine_cleanup(&engine);
    printf("Audio engine cleaned up cleanly.\n");
    printf("====================================================\n");
    printf("Audio Diagnostic Result: PASS\n\n");
    return 0;
}
