#include <EndpointSecurity/EndpointSecurity.h>
#include <bsm/libbsm.h>
#include <dispatch/dispatch.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

static FILE *g_output = NULL;
static bool g_output_is_file = false;
static uint64_t g_last_global_sequence = 0;

static void flush_output(void) {
    if (g_output == NULL) {
        return;
    }
    flockfile(g_output);
    fflush(g_output);
    funlockfile(g_output);
}

static void close_output(void) {
    if (!g_output_is_file || g_output == NULL) {
        return;
    }
    flush_output();
    fclose(g_output);
    g_output = NULL;
}

static void json_string_bytes(FILE *output, const char *bytes, size_t length) {
    fputc('"', output);
    for (size_t index = 0; index < length; index++) {
        unsigned char value = (unsigned char)bytes[index];
        switch (value) {
            case '"': fputs("\\\"", output); break;
            case '\\': fputs("\\\\", output); break;
            case '\b': fputs("\\b", output); break;
            case '\f': fputs("\\f", output); break;
            case '\n': fputs("\\n", output); break;
            case '\r': fputs("\\r", output); break;
            case '\t': fputs("\\t", output); break;
            default:
                if (value < 0x20) {
                    fprintf(output, "\\u%04x", value);
                } else {
                    fputc(value, output);
                }
        }
    }
    fputc('"', output);
}

static void json_token(FILE *output, es_string_token_t token) {
    if (token.data == NULL) {
        fputs("null", output);
        return;
    }
    json_string_bytes(output, token.data, token.length);
}

static void json_process_fields(FILE *output, const es_process_t *process, const char *prefix) {
    fprintf(output, "\"%spid\":%d,", prefix, audit_token_to_pid(process->audit_token));
    fprintf(output, "\"%spidversion\":%d,", prefix, audit_token_to_pidversion(process->audit_token));
    fprintf(output, "\"%sppid\":%d,", prefix, process->ppid);
    fprintf(output, "\"%spath\":", prefix);
    json_token(output, process->executable->path);
    fprintf(output, ",\"%ssigning_id\":", prefix);
    json_token(output, process->signing_id);
    fprintf(output, ",\"%steam_id\":", prefix);
    json_token(output, process->team_id);
    fprintf(output, ",\"%scs_flags\":%u,", prefix, process->codesigning_flags);
    fprintf(output, "\"%splatform_binary\":%s", prefix, process->is_platform_binary ? "true" : "false");
}

static const char *event_name(es_event_type_t type) {
    switch (type) {
        case ES_EVENT_TYPE_NOTIFY_EXEC: return "exec";
        case ES_EVENT_TYPE_NOTIFY_FORK: return "fork";
        case ES_EVENT_TYPE_NOTIFY_EXIT: return "exit";
        case ES_EVENT_TYPE_NOTIFY_MMAP: return "mmap";
        case ES_EVENT_TYPE_NOTIFY_MPROTECT: return "mprotect";
        case ES_EVENT_TYPE_NOTIFY_GET_TASK: return "get_task";
        case ES_EVENT_TYPE_NOTIFY_GET_TASK_READ: return "get_task_read";
        case ES_EVENT_TYPE_NOTIFY_GET_TASK_INSPECT: return "get_task_inspect";
        case ES_EVENT_TYPE_NOTIFY_TRACE: return "trace";
        case ES_EVENT_TYPE_NOTIFY_REMOTE_THREAD_CREATE: return "remote_thread_create";
        case ES_EVENT_TYPE_NOTIFY_CS_INVALIDATED: return "cs_invalidated";
        default: return "unknown";
    }
}

static void emit_event(const es_message_t *message) {
    if (message->process->is_es_client) {
        return;
    }
    flockfile(g_output);
    uint64_t dropped = 0;
    if (message->version >= 4 && g_last_global_sequence != 0 &&
        message->global_seq_num > g_last_global_sequence + 1) {
        dropped = message->global_seq_num - g_last_global_sequence - 1;
    }
    if (message->version >= 4) {
        g_last_global_sequence = message->global_seq_num;
    }

    fputc('{', g_output);
    fputs("\"schema\":1,\"sensor\":\"rattler-es\",", g_output);
    fprintf(g_output, "\"timestamp_ns\":%lld,", (long long)message->time.tv_sec * 1000000000LL + message->time.tv_nsec);
    fprintf(g_output, "\"message_version\":%u,", message->version);
    fprintf(g_output, "\"event_type\":\"%s\",", event_name(message->event_type));
    fprintf(g_output, "\"event_type_id\":%u,", (unsigned int)message->event_type);
    fprintf(g_output, "\"sequence\":%llu,", message->version >= 2 ? message->seq_num : 0);
    fprintf(g_output, "\"global_sequence\":%llu,", message->version >= 4 ? message->global_seq_num : 0);
    fprintf(g_output, "\"dropped_since_previous\":%llu,", dropped);
    json_process_fields(g_output, message->process, "");

    switch (message->event_type) {
        case ES_EVENT_TYPE_NOTIFY_EXEC:
            fputc(',', g_output);
            json_process_fields(g_output, message->event.exec.target, "target_");
            break;
        case ES_EVENT_TYPE_NOTIFY_FORK:
            fputc(',', g_output);
            json_process_fields(g_output, message->event.fork.child, "target_");
            break;
        case ES_EVENT_TYPE_NOTIFY_EXIT:
            fprintf(g_output, ",\"exit_status_raw\":%d", message->event.exit.stat);
            break;
        case ES_EVENT_TYPE_NOTIFY_MMAP:
            fprintf(g_output, ",\"protection\":%d,\"max_protection\":%d,\"mapping_flags\":%d,\"file_offset\":%llu,\"source_path\":",
                    message->event.mmap.protection, message->event.mmap.max_protection,
                    message->event.mmap.flags, message->event.mmap.file_pos);
            json_token(g_output, message->event.mmap.source->path);
            break;
        case ES_EVENT_TYPE_NOTIFY_MPROTECT:
            fprintf(g_output, ",\"protection\":%d,\"address\":%llu,\"size\":%llu",
                    message->event.mprotect.protection,
                    (unsigned long long)message->event.mprotect.address,
                    (unsigned long long)message->event.mprotect.size);
            break;
        case ES_EVENT_TYPE_NOTIFY_GET_TASK:
            fputc(',', g_output);
            json_process_fields(g_output, message->event.get_task.target, "target_");
            if (message->version >= 5) {
                fprintf(g_output, ",\"task_type\":%u", (unsigned int)message->event.get_task.type);
            }
            break;
        case ES_EVENT_TYPE_NOTIFY_GET_TASK_READ:
            fputc(',', g_output);
            json_process_fields(g_output, message->event.get_task_read.target, "target_");
            break;
        case ES_EVENT_TYPE_NOTIFY_GET_TASK_INSPECT:
            fputc(',', g_output);
            json_process_fields(g_output, message->event.get_task_inspect.target, "target_");
            break;
        case ES_EVENT_TYPE_NOTIFY_TRACE:
            fputc(',', g_output);
            json_process_fields(g_output, message->event.trace.target, "target_");
            break;
        case ES_EVENT_TYPE_NOTIFY_REMOTE_THREAD_CREATE:
            fputc(',', g_output);
            json_process_fields(g_output, message->event.remote_thread_create.target, "target_");
            fprintf(g_output, ",\"has_thread_state\":%s",
                    message->event.remote_thread_create.thread_state == NULL ? "false" : "true");
            break;
        case ES_EVENT_TYPE_NOTIFY_CS_INVALIDATED:
            break;
        default:
            break;
    }
    fputs("}\n", g_output);
    funlockfile(g_output);
}

static void emit_heartbeat(void) {
    struct timespec timestamp;
    if (g_output == NULL || clock_gettime(CLOCK_REALTIME, &timestamp) != 0) {
        return;
    }
    flockfile(g_output);
    fputc('{', g_output);
    fputs("\"schema\":1,\"sensor\":\"rattler-es\",", g_output);
    fprintf(g_output, "\"timestamp_ns\":%lld,",
            (long long)timestamp.tv_sec * 1000000000LL + timestamp.tv_nsec);
    fputs("\"message_version\":0,\"event_type\":\"heartbeat\",\"event_type_id\":0,", g_output);
    fprintf(g_output, "\"sequence\":0,\"global_sequence\":%llu,", g_last_global_sequence);
    fprintf(g_output, "\"dropped_since_previous\":0,\"pid\":%d,", getpid());
    fputs("\"path\":\"rattler-es-sensor\"}\n", g_output);
    fflush(g_output);
    funlockfile(g_output);
}

static const char *client_error(es_new_client_result_t result) {
    switch (result) {
        case ES_NEW_CLIENT_RESULT_ERR_NOT_ENTITLED: return "missing Endpoint Security entitlement";
        case ES_NEW_CLIENT_RESULT_ERR_NOT_PERMITTED: return "Full Disk Access is not approved";
        case ES_NEW_CLIENT_RESULT_ERR_NOT_PRIVILEGED: return "sensor must run as root";
        case ES_NEW_CLIENT_RESULT_ERR_TOO_MANY_CLIENTS: return "too many Endpoint Security clients";
        case ES_NEW_CLIENT_RESULT_ERR_INVALID_ARGUMENT: return "invalid Endpoint Security client argument";
        case ES_NEW_CLIENT_RESULT_ERR_INTERNAL: return "Endpoint Security internal error";
        default: return "unknown Endpoint Security error";
    }
}

int main(int argc, char **argv) {
    if (argc > 3 || (argc == 2 && strcmp(argv[1], "--help") == 0)) {
        fprintf(argc > 3 ? stderr : stdout, "usage: %s [--output PATH]\n", argv[0]);
        return argc > 3 ? 2 : 0;
    }
    if (argc == 3) {
        if (strcmp(argv[1], "--output") != 0) {
            fprintf(stderr, "usage: %s [--output PATH]\n", argv[0]);
            return 2;
        }
        int descriptor = open(argv[2], O_WRONLY | O_APPEND | O_CREAT | O_CLOEXEC | O_NOFOLLOW, 0600);
        if (descriptor < 0) {
            fprintf(stderr, "could not open output: %s\n", strerror(errno));
            return 2;
        }
        struct stat output_stat;
        if (fstat(descriptor, &output_stat) != 0 || !S_ISREG(output_stat.st_mode)) {
            close(descriptor);
            fprintf(stderr, "output must be a regular file\n");
            return 2;
        }
        if (output_stat.st_nlink != 1) {
            close(descriptor);
            fprintf(stderr, "output must not have hard links\n");
            return 2;
        }
        (void)fchmod(descriptor, 0600);
        g_output = fdopen(descriptor, "a");
        if (g_output == NULL) {
            close(descriptor);
            fprintf(stderr, "could not create output stream\n");
            return 2;
        }
        g_output_is_file = true;
    } else {
        g_output = stdout;
    }
    setvbuf(g_output, NULL, g_output_is_file ? _IOFBF : _IOLBF,
            g_output_is_file ? 1024 * 1024 : 0);

    __block es_client_t *client = NULL;
    es_new_client_result_t created = es_new_client(&client, ^(es_client_t *callback_client, const es_message_t *message) {
        (void)callback_client;
        emit_event(message);
    });
    if (created != ES_NEW_CLIENT_RESULT_SUCCESS) {
        fprintf(stderr, "rattler-es-sensor: %s (%d)\n", client_error(created), created);
        close_output();
        return 3;
    }

    es_event_type_t events[] = {
        ES_EVENT_TYPE_NOTIFY_EXEC,
        ES_EVENT_TYPE_NOTIFY_FORK,
        ES_EVENT_TYPE_NOTIFY_EXIT,
        ES_EVENT_TYPE_NOTIFY_MMAP,
        ES_EVENT_TYPE_NOTIFY_MPROTECT,
        ES_EVENT_TYPE_NOTIFY_GET_TASK,
        ES_EVENT_TYPE_NOTIFY_GET_TASK_READ,
        ES_EVENT_TYPE_NOTIFY_GET_TASK_INSPECT,
        ES_EVENT_TYPE_NOTIFY_TRACE,
        ES_EVENT_TYPE_NOTIFY_REMOTE_THREAD_CREATE,
        ES_EVENT_TYPE_NOTIFY_CS_INVALIDATED,
    };
    if (es_subscribe(client, events, (uint32_t)(sizeof(events) / sizeof(events[0]))) != ES_RETURN_SUCCESS) {
        fprintf(stderr, "rattler-es-sensor: event subscription failed\n");
        es_delete_client(client);
        close_output();
        return 4;
    }

    if (g_output_is_file) {
        dispatch_source_t flush_timer = dispatch_source_create(
            DISPATCH_SOURCE_TYPE_TIMER, 0, 0, dispatch_get_main_queue());
        if (flush_timer == NULL) {
            fprintf(stderr, "rattler-es-sensor: could not create flush timer\n");
            es_delete_client(client);
            close_output();
            return 4;
        }
        dispatch_source_set_timer(
            flush_timer, dispatch_time(DISPATCH_TIME_NOW, NSEC_PER_SEC),
            NSEC_PER_SEC, 100 * NSEC_PER_MSEC);
        dispatch_source_set_event_handler(flush_timer, ^{
            flush_output();
        });
        dispatch_resume(flush_timer);

        dispatch_source_t heartbeat_timer = dispatch_source_create(
            DISPATCH_SOURCE_TYPE_TIMER, 0, 0, dispatch_get_main_queue());
        if (heartbeat_timer == NULL) {
            fprintf(stderr, "rattler-es-sensor: could not create heartbeat timer\n");
            es_delete_client(client);
            close_output();
            return 4;
        }
        dispatch_source_set_timer(
            heartbeat_timer, dispatch_time(DISPATCH_TIME_NOW, 0),
            15 * NSEC_PER_SEC, NSEC_PER_SEC);
        dispatch_source_set_event_handler(heartbeat_timer, ^{
            emit_heartbeat();
        });
        dispatch_resume(heartbeat_timer);
    }

    signal(SIGINT, SIG_IGN);
    signal(SIGTERM, SIG_IGN);
    dispatch_source_t signals = dispatch_source_create(DISPATCH_SOURCE_TYPE_SIGNAL, SIGINT, 0, dispatch_get_main_queue());
    dispatch_source_set_event_handler(signals, ^{
        es_delete_client(client);
        client = NULL;
        close_output();
        exit(0);
    });
    dispatch_resume(signals);
    dispatch_source_t termination = dispatch_source_create(DISPATCH_SOURCE_TYPE_SIGNAL, SIGTERM, 0, dispatch_get_main_queue());
    dispatch_source_set_event_handler(termination, ^{
        es_delete_client(client);
        client = NULL;
        close_output();
        exit(0);
    });
    dispatch_resume(termination);
    dispatch_main();
}
