#include <EndpointSecurity/EndpointSecurity.h>
#include <bsm/libbsm.h>
#include <dispatch/dispatch.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <pthread.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#define MAX_PROTECTED_ROOTS 8
#define MAX_TRACKED_PROCESSES 1024
#define DEFAULT_MUTATION_THRESHOLD 80
#define WINDOW_SECONDS 10

typedef enum {
    GUARD_SHADOW,
    GUARD_ENFORCE,
} guard_mode_t;

typedef struct {
    pid_t pid;
    int pidversion;
    time_t window_start;
    unsigned int mutations;
    unsigned int suspicious_names;
    bool tripped;
} process_window_t;

typedef struct {
    bool protected_path;
    bool would_block;
    bool suspicious_name;
    bool canary;
    bool ransom_note;
    bool emit;
    unsigned int mutations;
    unsigned int suspicious_names;
    const char *reason;
} guard_decision_t;

static FILE *g_output = NULL;
static bool g_output_is_file = false;
static guard_mode_t g_mode = GUARD_SHADOW;
static char g_roots[MAX_PROTECTED_ROOTS][PATH_MAX];
static size_t g_root_count = 0;
static unsigned int g_mutation_threshold = DEFAULT_MUTATION_THRESHOLD;
static process_window_t g_windows[MAX_TRACKED_PROCESSES];
static size_t g_next_window = 0;
static pthread_mutex_t g_window_lock = PTHREAD_MUTEX_INITIALIZER;
static uint64_t g_last_global_sequence = 0;

static void json_string_bytes(FILE *output, const char *bytes, size_t length) {
    fputc('"', output);
    for (size_t index = 0; index < length; index++) {
        unsigned char value = (unsigned char)bytes[index];
        switch (value) {
            case '"': fputs("\\\"", output); break;
            case '\\': fputs("\\\\", output); break;
            case '\n': fputs("\\n", output); break;
            case '\r': fputs("\\r", output); break;
            case '\t': fputs("\\t", output); break;
            default:
                if (value < 0x20) fprintf(output, "\\u%04x", value);
                else fputc(value, output);
        }
    }
    fputc('"', output);
}

static void json_token(FILE *output, es_string_token_t token) {
    if (token.data == NULL) fputs("null", output);
    else json_string_bytes(output, token.data, token.length);
}

static bool token_equals(es_string_token_t token, const char *value) {
    size_t length = strlen(value);
    return token.data != NULL && token.length == length && strncasecmp(token.data, value, length) == 0;
}

static bool token_ends_with(es_string_token_t token, const char *suffix) {
    size_t length = strlen(suffix);
    return token.data != NULL && token.length >= length &&
        strncasecmp(token.data + token.length - length, suffix, length) == 0;
}

static bool token_under_root(es_string_token_t token, const char *root) {
    size_t length = strlen(root);
    if (token.data == NULL || token.length < length || memcmp(token.data, root, length) != 0) return false;
    return token.length == length || root[length - 1] == '/' || token.data[length] == '/';
}

static bool protected_token(es_string_token_t token) {
    for (size_t index = 0; index < g_root_count; index++) {
        if (token_under_root(token, g_roots[index])) return true;
    }
    return false;
}

static bool suspicious_suffix(es_string_token_t token) {
    static const char *suffixes[] = {
        ".crypted", ".crypto", ".crypt", ".encrypted", ".enc", ".locked",
        ".lockbit", ".ryk", ".ryuk", ".wannacry", ".wncry",
    };
    for (size_t index = 0; index < sizeof(suffixes) / sizeof(suffixes[0]); index++) {
        if (token_ends_with(token, suffixes[index])) return true;
    }
    return false;
}

static bool ransom_note_name(es_string_token_t token) {
    static const char *names[] = {
        "decrypt_instructions.txt", "how_to_decrypt.txt", "how_to_restore_files.txt",
        "readme_to_decrypt.txt", "recover_files.txt", "restore_files.txt",
    };
    for (size_t index = 0; index < sizeof(names) / sizeof(names[0]); index++) {
        if (token_equals(token, names[index])) return true;
    }
    return false;
}

static es_string_token_t primary_path(const es_message_t *message) {
    switch (message->event_type) {
        case ES_EVENT_TYPE_AUTH_OPEN: return message->event.open.file->path;
        case ES_EVENT_TYPE_AUTH_RENAME: return message->event.rename.source->path;
        case ES_EVENT_TYPE_AUTH_UNLINK: return message->event.unlink.target->path;
        case ES_EVENT_TYPE_AUTH_CREATE:
            if (message->event.create.destination_type == ES_DESTINATION_TYPE_EXISTING_FILE)
                return message->event.create.destination.existing_file->path;
            return message->event.create.destination.new_path.dir->path;
        default: {
            es_string_token_t empty = {0};
            return empty;
        }
    }
}

static es_string_token_t destination_name(const es_message_t *message) {
    es_string_token_t empty = {0};
    if (message->event_type == ES_EVENT_TYPE_AUTH_RENAME) {
        if (message->event.rename.destination_type == ES_DESTINATION_TYPE_NEW_PATH)
            return message->event.rename.destination.new_path.filename;
        return message->event.rename.destination.existing_file->path;
    }
    if (message->event_type == ES_EVENT_TYPE_AUTH_CREATE) {
        if (message->event.create.destination_type == ES_DESTINATION_TYPE_NEW_PATH)
            return message->event.create.destination.new_path.filename;
        return message->event.create.destination.existing_file->path;
    }
    return empty;
}

static bool destination_is_protected(const es_message_t *message) {
    if (message->event_type == ES_EVENT_TYPE_AUTH_RENAME) {
        if (message->event.rename.destination_type == ES_DESTINATION_TYPE_NEW_PATH)
            return protected_token(message->event.rename.destination.new_path.dir->path);
        return protected_token(message->event.rename.destination.existing_file->path);
    }
    if (message->event_type == ES_EVENT_TYPE_AUTH_CREATE) {
        if (message->event.create.destination_type == ES_DESTINATION_TYPE_NEW_PATH)
            return protected_token(message->event.create.destination.new_path.dir->path);
        return protected_token(message->event.create.destination.existing_file->path);
    }
    return false;
}

static bool is_mutation(const es_message_t *message) {
    if (message->event_type == ES_EVENT_TYPE_AUTH_OPEN)
        return (message->event.open.fflag & FWRITE) != 0;
    return message->event_type == ES_EVENT_TYPE_AUTH_RENAME ||
        message->event_type == ES_EVENT_TYPE_AUTH_UNLINK ||
        message->event_type == ES_EVENT_TYPE_AUTH_CREATE;
}

static process_window_t *process_window(pid_t pid, int pidversion, time_t now) {
    process_window_t *available = NULL;
    for (size_t index = 0; index < MAX_TRACKED_PROCESSES; index++) {
        process_window_t *candidate = &g_windows[index];
        if (candidate->pid == pid && candidate->pidversion == pidversion) {
            if (now - candidate->window_start > WINDOW_SECONDS || now < candidate->window_start) {
                candidate->window_start = now;
                candidate->mutations = 0;
                candidate->suspicious_names = 0;
                candidate->tripped = false;
            }
            return candidate;
        }
        if (candidate->pid == 0 && available == NULL) available = candidate;
    }
    if (available == NULL) {
        available = &g_windows[g_next_window++ % MAX_TRACKED_PROCESSES];
    }
    memset(available, 0, sizeof(*available));
    available->pid = pid;
    available->pidversion = pidversion;
    available->window_start = now;
    return available;
}

static guard_decision_t evaluate(const es_message_t *message) {
    guard_decision_t decision = {0};
    es_string_token_t path = primary_path(message);
    es_string_token_t name = destination_name(message);
    decision.protected_path = protected_token(path) || destination_is_protected(message);
    if (!decision.protected_path || !is_mutation(message) || message->process->is_platform_binary) {
        decision.reason = message->process->is_platform_binary ? "platform_binary_allowed" : "outside_policy";
        return decision;
    }
    decision.suspicious_name = suspicious_suffix(name);
    decision.ransom_note = ransom_note_name(name);
    decision.canary = token_ends_with(path, "/ransomware-canary.txt") ||
        token_equals(name, "ransomware-canary.txt");
    pid_t pid = audit_token_to_pid(message->process->audit_token);
    int pidversion = audit_token_to_pidversion(message->process->audit_token);
    pthread_mutex_lock(&g_window_lock);
    process_window_t *window = process_window(pid, pidversion, message->time.tv_sec);
    window->mutations++;
    if (decision.suspicious_name) window->suspicious_names++;
    if (decision.canary || window->suspicious_names >= 3 ||
        window->mutations >= g_mutation_threshold ||
        (decision.ransom_note && window->mutations >= 10)) {
        window->tripped = true;
    }
    decision.would_block = window->tripped;
    decision.mutations = window->mutations;
    decision.suspicious_names = window->suspicious_names;
    pthread_mutex_unlock(&g_window_lock);
    if (decision.canary) decision.reason = "canary_write";
    else if (decision.suspicious_names >= 3) decision.reason = "encryption_extension_burst";
    else if (decision.ransom_note && decision.mutations >= 10) decision.reason = "ransom_note_after_mutations";
    else if (decision.mutations >= g_mutation_threshold) decision.reason = "rapid_file_mutations";
    else decision.reason = "below_threshold";
    decision.emit = decision.would_block || decision.suspicious_name || decision.ransom_note ||
        decision.mutations % 25 == 0;
    return decision;
}

static const char *event_name(es_event_type_t type) {
    switch (type) {
        case ES_EVENT_TYPE_AUTH_OPEN: return "open";
        case ES_EVENT_TYPE_AUTH_RENAME: return "rename";
        case ES_EVENT_TYPE_AUTH_UNLINK: return "unlink";
        case ES_EVENT_TYPE_AUTH_CREATE: return "create";
        default: return "unknown";
    }
}

static void emit_decision(
    const es_message_t *message, guard_decision_t decision, bool blocked,
    es_respond_result_t response, uint64_t dropped
) {
    if (!decision.emit || g_output == NULL) return;
    flockfile(g_output);
    fputs("{\"schema\":1,\"sensor\":\"rattler-es\",", g_output);
    fprintf(g_output, "\"timestamp_ns\":%lld,",
            (long long)message->time.tv_sec * 1000000000LL + message->time.tv_nsec);
    fputs("\"event_type\":\"ransomware_guard\",", g_output);
    fprintf(g_output, "\"event_type_id\":%u,\"sequence\":%llu,\"global_sequence\":%llu,",
            (unsigned int)message->event_type,
            message->version >= 2 ? message->seq_num : 0,
            message->version >= 4 ? message->global_seq_num : 0);
    fprintf(g_output, "\"dropped_since_previous\":%llu,", dropped);
    fprintf(g_output, "\"pid\":%d,\"pidversion\":%d,\"path\":",
            audit_token_to_pid(message->process->audit_token),
            audit_token_to_pidversion(message->process->audit_token));
    json_token(g_output, message->process->executable->path);
    fputs(",\"file_path\":", g_output);
    json_token(g_output, primary_path(message));
    fputs(",\"destination_name\":", g_output);
    json_token(g_output, destination_name(message));
    fprintf(g_output,
            ",\"operation\":\"%s\",\"decision_mode\":\"%s\",\"would_block\":%s,"
            "\"blocked\":%s,\"mutation_count\":%u,\"suspicious_names\":%u,"
            "\"reason\":\"%s\",\"response_code\":%d}\n",
            event_name(message->event_type), g_mode == GUARD_ENFORCE ? "enforce" : "shadow",
            decision.would_block ? "true" : "false", blocked ? "true" : "false",
            decision.mutations, decision.suspicious_names, decision.reason, response);
    fflush(g_output);
    funlockfile(g_output);
}

static void handle_message(es_client_t *client, const es_message_t *message) {
    if (message->action_type != ES_ACTION_TYPE_AUTH) return;
    uint64_t dropped = 0;
    pthread_mutex_lock(&g_window_lock);
    if (message->version >= 4 && g_last_global_sequence != 0 &&
        message->global_seq_num > g_last_global_sequence + 1) {
        dropped = message->global_seq_num - g_last_global_sequence - 1;
    }
    if (message->version >= 4) g_last_global_sequence = message->global_seq_num;
    pthread_mutex_unlock(&g_window_lock);
    guard_decision_t decision = evaluate(message);
    bool blocked = g_mode == GUARD_ENFORCE && decision.would_block;
    es_respond_result_t response;
    if (message->event_type == ES_EVENT_TYPE_AUTH_OPEN) {
        response = es_respond_flags_result(client, message, blocked ? 0 : UINT32_MAX, false);
    } else {
        response = es_respond_auth_result(
            client, message, blocked ? ES_AUTH_RESULT_DENY : ES_AUTH_RESULT_ALLOW, false);
    }
    emit_decision(message, decision, blocked, response, dropped);
}

static void close_output(void) {
    if (g_output == NULL) return;
    fflush(g_output);
    if (g_output_is_file) fclose(g_output);
    g_output = NULL;
}

static void usage(FILE *output, const char *program) {
    fprintf(output,
            "usage: %s --protect USER_FOLDER [--protect USER_FOLDER ...] "
            "[--mode shadow|enforce] [--mutation-threshold N] [--output PATH] "
            "[--acknowledge-enforcement]\n", program);
}

static bool add_root(const char *value) {
    if (g_root_count >= MAX_PROTECTED_ROOTS) return false;
    char resolved[PATH_MAX];
    if (realpath(value, resolved) == NULL) return false;
    struct stat metadata;
    if (lstat(resolved, &metadata) != 0 || !S_ISDIR(metadata.st_mode) || S_ISLNK(metadata.st_mode)) return false;
    if (strncmp(resolved, "/Users/", 7) != 0 || strchr(resolved + 7, '/') == NULL) return false;
    size_t length = strlen(resolved);
    while (length > 1 && resolved[length - 1] == '/') resolved[--length] = '\0';
    memcpy(g_roots[g_root_count], resolved, length + 1);
    g_root_count++;
    return true;
}

static bool parse_positive(const char *value, unsigned int *result) {
    char *end = NULL;
    errno = 0;
    unsigned long parsed = strtoul(value, &end, 10);
    if (errno != 0 || end == value || *end != '\0' || parsed == 0 || parsed > 1000000) return false;
    *result = (unsigned int)parsed;
    return true;
}

int main(int argc, char **argv) {
    const char *output_path = NULL;
    bool acknowledged = false;
    for (int index = 1; index < argc; index++) {
        if (strcmp(argv[index], "--help") == 0) {
            usage(stdout, argv[0]);
            return 0;
        } else if (strcmp(argv[index], "--protect") == 0 && index + 1 < argc) {
            if (!add_root(argv[++index])) {
                fprintf(stderr, "guard roots must be existing user folders beneath /Users/<name>\n");
                return 2;
            }
        } else if (strcmp(argv[index], "--mode") == 0 && index + 1 < argc) {
            const char *mode = argv[++index];
            if (strcmp(mode, "shadow") == 0) g_mode = GUARD_SHADOW;
            else if (strcmp(mode, "enforce") == 0) g_mode = GUARD_ENFORCE;
            else { usage(stderr, argv[0]); return 2; }
        } else if (strcmp(argv[index], "--mutation-threshold") == 0 && index + 1 < argc) {
            if (!parse_positive(argv[++index], &g_mutation_threshold)) return 2;
        } else if (strcmp(argv[index], "--output") == 0 && index + 1 < argc) {
            output_path = argv[++index];
        } else if (strcmp(argv[index], "--acknowledge-enforcement") == 0) {
            acknowledged = true;
        } else {
            usage(stderr, argv[0]);
            return 2;
        }
    }
    if (g_root_count == 0) {
        fprintf(stderr, "at least one --protect user folder is required\n");
        return 2;
    }
    if (g_mode == GUARD_ENFORCE && !acknowledged) {
        fprintf(stderr, "enforce mode requires --acknowledge-enforcement\n");
        return 2;
    }
    if (output_path != NULL) {
        int descriptor = open(output_path, O_WRONLY | O_APPEND | O_CREAT | O_CLOEXEC | O_NOFOLLOW, 0600);
        if (descriptor < 0) { fprintf(stderr, "could not open output: %s\n", strerror(errno)); return 2; }
        struct stat metadata;
        if (fstat(descriptor, &metadata) != 0 || !S_ISREG(metadata.st_mode) || metadata.st_nlink != 1) {
            close(descriptor);
            fprintf(stderr, "output must be a single-link regular file\n");
            return 2;
        }
        (void)fchmod(descriptor, 0600);
        g_output = fdopen(descriptor, "a");
        if (g_output == NULL) { close(descriptor); return 2; }
        g_output_is_file = true;
    } else {
        g_output = stdout;
    }
    setvbuf(g_output, NULL, _IOLBF, 0);
    __block es_client_t *client = NULL;
    es_new_client_result_t created = es_new_client(&client, ^(es_client_t *callback_client, const es_message_t *message) {
        handle_message(callback_client, message);
    });
    if (created != ES_NEW_CLIENT_RESULT_SUCCESS) {
        fprintf(stderr, "rattler-es-guard: could not create Endpoint Security client (%d)\n", created);
        close_output();
        return 3;
    }
    es_event_type_t events[] = {
        ES_EVENT_TYPE_AUTH_OPEN,
        ES_EVENT_TYPE_AUTH_RENAME,
        ES_EVENT_TYPE_AUTH_UNLINK,
        ES_EVENT_TYPE_AUTH_CREATE,
    };
    if (es_subscribe(client, events, (uint32_t)(sizeof(events) / sizeof(events[0]))) != ES_RETURN_SUCCESS) {
        fprintf(stderr, "rattler-es-guard: event subscription failed\n");
        es_delete_client(client);
        close_output();
        return 4;
    }
    signal(SIGINT, SIG_IGN);
    signal(SIGTERM, SIG_IGN);
    dispatch_source_t interrupt = dispatch_source_create(DISPATCH_SOURCE_TYPE_SIGNAL, SIGINT, 0, dispatch_get_main_queue());
    dispatch_source_set_event_handler(interrupt, ^{ es_delete_client(client); client = NULL; close_output(); exit(0); });
    dispatch_resume(interrupt);
    dispatch_source_t termination = dispatch_source_create(DISPATCH_SOURCE_TYPE_SIGNAL, SIGTERM, 0, dispatch_get_main_queue());
    dispatch_source_set_event_handler(termination, ^{ es_delete_client(client); client = NULL; close_output(); exit(0); });
    dispatch_resume(termination);
    dispatch_main();
}
