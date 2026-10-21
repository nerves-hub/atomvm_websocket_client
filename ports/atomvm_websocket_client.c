/*
 * Copyright 2026 NervesHub contributors
 *
 * SPDX-License-Identifier: Apache-2.0 OR LGPL-2.1-or-later
 */

/*
 * An AtomVM port driver over ESP-IDF's esp_websocket_client.
 *
 * The IDF client owns the socket, the TLS session and WebSocket framing on its
 * own FreeRTOS task, and calls back into `event_handler` from that task. So
 * every message this driver sends to Erlang is built on a temporary heap and
 * delivered with port_send_message_from_task, which is the API for posting to
 * a process from a thread the VM does not own.
 *
 * That task can outlive the port. A port can end without the driver being
 * called at all — exit/2, or a linked process exiting, has the scheduler
 * destroy it directly — so the task never touches the port's Context. What it
 * uses lives in `struct connection`, which is freed only after the client has
 * been stopped.
 *
 * Note the pid conversions. `conn->owner` is a local process id, an int32,
 * while the port_send_message_* functions take a pid *term* and decode it
 * themselves. Passing the int32 straight through compiles — term is an
 * integer type — and then decodes to a process that does not exist, so every
 * message is dropped without an error. Convert with
 * term_from_local_process_id/1 at the call.
 */

#include <sdkconfig.h>

#ifdef CONFIG_AVM_WEBSOCKET_CLIENT_ENABLE

#include <string.h>
#include <strings.h>

#include <esp_log.h>
#include <esp_websocket_client.h>

#ifdef CONFIG_MBEDTLS_CERTIFICATE_BUNDLE
#include <esp_crt_bundle.h>
#endif

#include <atom.h>
#include <context.h>
#include <defaultatoms.h>
#include <erl_nif.h>
#include <erl_nif_priv.h>
#include <globalcontext.h>
#include <interop.h>
#include <mailbox.h>
#include <memory.h>
#include <port.h>
#include <scheduler.h>
#include <term.h>
#include <utils.h>

#include <esp32_sys.h>

#define TAG "atomvm_websocket_client"

/* Not exported by libAtomVM; the in-tree drivers each define it. */
#define PORT_REPLY_SIZE (TUPLE_SIZE(2) + REF_SIZE)

/* WebSocket opcodes, RFC 6455 section 5.2. */
#define WS_OPCODE_CONTINUATION 0x00
#define WS_OPCODE_TEXT 0x01
#define WS_OPCODE_BINARY 0x02
#define WS_OPCODE_CLOSE 0x08
#define WS_OPCODE_PING 0x09
#define WS_OPCODE_PONG 0x0A

static const char *const websocket_atom = ATOM_STR("\x9", "websocket");
static const char *const connected_atom = ATOM_STR("\x9", "connected");
static const char *const closed_atom = ATOM_STR("\x6", "closed");
static const char *const text_atom = ATOM_STR("\x4", "text");
static const char *const binary_atom = ATOM_STR("\x6", "binary");
static const char *const normal_atom = ATOM_STR("\x6", "normal");
static const char *const disconnected_atom = ATOM_STR("\xC", "disconnected");
static const char *const message_too_large_atom = ATOM_STR("\x11", "message_too_large");
static const char *const not_connected_atom = ATOM_STR("\xD", "not_connected");
static const char *const out_of_memory_atom = ATOM_STR("\xD", "out_of_memory");
static const char *const send_failed_atom = ATOM_STR("\xB", "send_failed");
static const char *const esp_tls_atom = ATOM_STR("\x7", "esp_tls");
static const char *const esp_websocket_client_atom = ATOM_STR("\x14", "esp_websocket_client");
/* The default ERROR_ATOM is a term; send_tagged wants the AtomString. */
static const char *const error_atom = ATOM_STR("\x5", "error");
/* Sent to the port by connection_down when its owner exits. */
static const char *const owner_down_atom = ATOM_STR("\xB", "$owner_down");

/* option keys */
static const char *const url_atom = ATOM_STR("\x3", "url");
static const char *const owner_atom = ATOM_STR("\x5", "owner");
static const char *const headers_atom = ATOM_STR("\x7", "headers");
static const char *const verify_atom = ATOM_STR("\x6", "verify");
static const char *const crt_bundle_atom = ATOM_STR("\xA", "crt_bundle");
static const char *const cacert_pem_atom = ATOM_STR("\xA", "cacert_pem");
static const char *const none_atom = ATOM_STR("\x4", "none");
static const char *const client_cert_atom = ATOM_STR("\xB", "client_cert");
static const char *const max_message_size_atom = ATOM_STR("\x10", "max_message_size");
static const char *const ping_interval_ms_atom = ATOM_STR("\x10", "ping_interval_ms");
static const char *const reconnect_timeout_ms_atom = ATOM_STR("\x14", "reconnect_timeout_ms");
static const char *const network_timeout_ms_atom = ATOM_STR("\x12", "network_timeout_ms");
static const char *const disable_auto_reconnect_atom = ATOM_STR("\x16", "disable_auto_reconnect");
static const char *const buffer_size_atom = ATOM_STR("\xB", "buffer_size");

enum websocket_cmd
{
    WebSocketInvalidCmd = 0,
    WebSocketSendTextCmd,
    WebSocketSendBinaryCmd,
    WebSocketCloseCmd
};

static const AtomStringIntPair cmd_table[] = {
    { ATOM_STR("\x9", "send_text"), WebSocketSendTextCmd },
    { ATOM_STR("\xB", "send_binary"), WebSocketSendBinaryCmd },
    { ATOM_STR("\x5", "close"), WebSocketCloseCmd },
    SELECT_INT_DEFAULT(WebSocketInvalidCmd)
};

/*
 * Everything the IDF task reads or writes. It is a NIF resource rather than
 * the port's platform_data because context_destroy frees platform_data on
 * every way a port ends, without calling the driver, while the IDF task may
 * still be running. A monitor this resource holds on the port runs
 * connection_down from context_destroy instead, and that stops the client
 * before anything here is freed.
 */
struct connection
{
    GlobalContext *global;
    int32_t port_id;
    int32_t owner;
    ErlNifMonitor owner_monitor;
    bool owner_monitored;
    esp_websocket_client_handle_t client;
    /* How long a send or close may hold the scheduler thread that runs it. */
    TickType_t timeout;

    /*
     * A message can arrive in several WEBSOCKET_EVENT_DATA callbacks, and can
     * span several frames. Accumulate here and deliver once, so that Erlang
     * never has to reassemble.
     */
    char *buf;
    size_t buf_len;
    size_t buf_cap;
    size_t max_message_size;
    uint8_t message_opcode;
    /* Why the message being received is being thrown away, or NULL. */
    AtomString discard_reason;

    /* Owned copies: the IDF client keeps the pointers it is given. */
    char *url;
    char *headers;
    char *cacert_pem;
    char *client_cert_pem;
    char *client_key_pem;
};

/* ctx->platform_data, which context_destroy frees with free(). */
struct platform_data
{
    struct connection *conn;
};

static void connection_down(ErlNifEnv *caller_env, void *obj, ErlNifPid *pid, ErlNifMonitor *mon);

static const ErlNifResourceTypeInit connection_resource_type_init = {
    .members = 3,
    .down = connection_down,
};

static ErlNifResourceType *connection_resource_type;

/*
 * A string or binary as a C string the caller owns, or NULL if it is neither
 * or memory ran out. interop_term_to_string can return NULL without setting
 * ok, so the pointer is what gets tested.
 */
static char *term_to_c_string(term t)
{
    if (!term_is_list(t) && !term_is_binary(t)) {
        return NULL;
    }

    int ok = 0;
    char *str = interop_term_to_string(t, &ok);
    if (UNLIKELY(!ok || IS_NULL_PTR(str))) {
        free(str);
        return NULL;
    }
    return str;
}

/* Caller owns the returned string. */
static char *maybe_get_string(term kv, AtomString key, GlobalContext *global)
{
    return term_to_c_string(interop_kv_get_value(kv, key, global));
}

/*
 * An optional positive integer option, or default_value when it is absent.
 * False, logging why, when it is anything else: a negative max_message_size
 * used to become SIZE_MAX, which is no limit at all.
 */
static bool get_pos_int(term kv, AtomString key, int default_value, int *out, GlobalContext *global)
{
    term value = interop_kv_get_value(kv, key, global);
    if (value == term_invalid_term()) {
        *out = default_value;
        return true;
    }
    if (!term_is_integer(value) || term_to_int(value) <= 0) {
        ESP_LOGE(TAG, "%.*s must be a positive integer", (int) atom_string_len(key),
            (const char *) atom_string_data(key));
        return false;
    }
    *out = term_to_int(value);
    return true;
}

static bool get_bool(term kv, AtomString key, bool default_value, bool *out, GlobalContext *global)
{
    term value = interop_kv_get_value(kv, key, global);
    if (value == term_invalid_term()) {
        *out = default_value;
    } else if (value == TRUE_ATOM) {
        *out = true;
    } else if (value == FALSE_ATOM) {
        *out = false;
    } else {
        ESP_LOGE(TAG, "%.*s must be true or false", (int) atom_string_len(key),
            (const char *) atom_string_data(key));
        return false;
    }
    return true;
}

/*
 * Writes a header name or value at *p and advances past it. False if it is not
 * a string or binary, or holds CR or LF, which would end the header early, or
 * NUL, which would cut the block short.
 */
static bool write_header_part(term part, char **p)
{
    size_t len;
    if (interop_iolist_size(part, &len) != InteropOk || interop_write_iolist(part, *p) != InteropOk
        || memchr(*p, '\r', len) || memchr(*p, '\n', len) || memchr(*p, '\0', len)) {
        return false;
    }
    *p += len;
    return true;
}

/*
 * esp_websocket_client takes extra headers as one CRLF-terminated block rather
 * than a list, so flatten [{K, V}] into "K: V\r\n...". Anything else is
 * refused: skipping a bad entry used to drop every header, Authorization
 * included, and connect anyway. *block stays NULL when there are none.
 */
static bool build_headers(term headers, char **block)
{
    *block = NULL;
    if (headers == term_invalid_term() || term_is_nil(headers)) {
        return true;
    }

    size_t total = 0;
    term cursor = headers;
    while (term_is_nonempty_list(cursor)) {
        term pair = term_get_list_head(cursor);
        size_t name_len;
        size_t value_len;
        if (!term_is_tuple(pair) || term_get_tuple_arity(pair) != 2
            || interop_iolist_size(term_get_tuple_element(pair, 0), &name_len) != InteropOk
            || interop_iolist_size(term_get_tuple_element(pair, 1), &value_len) != InteropOk
            || name_len == 0) {
            break;
        }
        total += name_len + value_len + 4; /* ": " and CRLF */
        cursor = term_get_list_tail(cursor);
    }
    if (!term_is_nil(cursor)) {
        ESP_LOGE(TAG, "headers must be a list of {Name, Value} strings or binaries");
        return false;
    }

    char *buf = malloc(total + 1);
    if (IS_NULL_PTR(buf)) {
        ESP_LOGE(TAG, "Could not allocate %u bytes for the headers", (unsigned) (total + 1));
        return false;
    }

    char *p = buf;
    for (cursor = headers; term_is_nonempty_list(cursor); cursor = term_get_list_tail(cursor)) {
        term pair = term_get_list_head(cursor);
        if (!write_header_part(term_get_tuple_element(pair, 0), &p)) {
            goto bad_text;
        }
        memcpy(p, ": ", 2);
        p += 2;
        if (!write_header_part(term_get_tuple_element(pair, 1), &p)) {
            goto bad_text;
        }
        memcpy(p, "\r\n", 2);
        p += 2;
    }
    *p = '\0';

    *block = buf;
    return true;

bad_text:
    ESP_LOGE(TAG, "A header name or value contains CR, LF or NUL");
    free(buf);
    return false;
}

static void send_simple(GlobalContext *global, int32_t owner, term port_term, term payload)
{
    BEGIN_WITH_STACK_HEAP(TUPLE_SIZE(3), heap);
    term msg = port_heap_create_tuple3(&heap, globalcontext_make_atom(global, websocket_atom), port_term, payload);
    port_send_message_from_task(global, term_from_local_process_id(owner), msg);
    END_WITH_STACK_HEAP(heap, global);
}

static void send_tagged(GlobalContext *global, int32_t owner, term port_term, AtomString tag, AtomString reason)
{
    BEGIN_WITH_STACK_HEAP(TUPLE_SIZE(3) + TUPLE_SIZE(2), heap);
    term inner = port_heap_create_tuple2(
        &heap, globalcontext_make_atom(global, tag), globalcontext_make_atom(global, reason));
    term msg = port_heap_create_tuple3(&heap, globalcontext_make_atom(global, websocket_atom), port_term, inner);
    port_send_message_from_task(global, term_from_local_process_id(owner), msg);
    END_WITH_STACK_HEAP(heap, global);
}

static void send_frame(GlobalContext *global, struct connection *conn, term port_term)
{
    AtomString kind = (conn->message_opcode == WS_OPCODE_BINARY) ? binary_atom : text_atom;

    size_t requested = TUPLE_SIZE(3) + TUPLE_SIZE(2) + term_binary_heap_size(conn->buf_len);

    Heap heap;
    if (UNLIKELY(memory_init_heap(&heap, requested) != MEMORY_GC_OK)) {
        ESP_LOGW(TAG, "Could not allocate %u bytes to deliver a message", (unsigned) requested);
        send_tagged(global, conn->owner, port_term, error_atom, out_of_memory_atom);
        return;
    }

    /* buf is NULL for an empty message. */
    term payload = term_from_literal_binary(conn->buf ? conn->buf : "", conn->buf_len, &heap, global);
    term inner = port_heap_create_tuple2(&heap, globalcontext_make_atom(global, kind), payload);
    term msg = port_heap_create_tuple3(&heap, globalcontext_make_atom(global, websocket_atom), port_term, inner);

    port_send_message_from_task(global, term_from_local_process_id(conn->owner), msg);
    memory_destroy_heap_from_task(&heap, global);
}

/*
 * The IDF fills the esp_tls fields of an ERROR event only when error_type is
 * TCP_TRANSPORT, and it records an error's type only after posting the event
 * for it, so most errors arrive with those fields uninitialised. They are sent
 * only when the IDF vouches for them. Otherwise the client's own description
 * of the failure is sent, which also names the TLS error and HTTP status.
 *
 *   {websocket, Port, {error, {esp_tls, LastEspErr, StackErr, CertFlags}}}
 *   {websocket, Port, {error, {esp_websocket_client, Description}}}
 */
static void send_error(GlobalContext *global, int32_t owner, term port_term, esp_websocket_event_data_t *event)
{
    if (event->error_handle.error_type == WEBSOCKET_ERROR_TYPE_TCP_TRANSPORT) {
        BEGIN_WITH_STACK_HEAP(TUPLE_SIZE(3) + TUPLE_SIZE(2) + TUPLE_SIZE(4), heap);
        term detail = term_alloc_tuple(4, &heap);
        term_put_tuple_element(detail, 0, globalcontext_make_atom(global, esp_tls_atom));
        term_put_tuple_element(detail, 1, term_from_int(event->error_handle.esp_tls_last_esp_err));
        term_put_tuple_element(detail, 2, term_from_int(event->error_handle.esp_tls_stack_err));
        term_put_tuple_element(detail, 3, term_from_int(event->error_handle.esp_tls_cert_verify_flags));
        term inner = port_heap_create_tuple2(&heap, ERROR_ATOM, detail);
        term msg = port_heap_create_tuple3(&heap, globalcontext_make_atom(global, websocket_atom), port_term, inner);
        port_send_message_from_task(global, term_from_local_process_id(owner), msg);
        END_WITH_STACK_HEAP(heap, global);
        return;
    }

    size_t len = (event->data_ptr != NULL && event->data_len > 0) ? (size_t) event->data_len : 0;
    size_t requested = TUPLE_SIZE(3) + TUPLE_SIZE(2) + TUPLE_SIZE(2) + term_binary_heap_size(len);

    Heap heap;
    if (UNLIKELY(memory_init_heap(&heap, requested) != MEMORY_GC_OK)) {
        send_tagged(global, owner, port_term, error_atom, out_of_memory_atom);
        return;
    }

    term description = term_from_literal_binary(len > 0 ? event->data_ptr : "", len, &heap, global);
    term detail = port_heap_create_tuple2(
        &heap, globalcontext_make_atom(global, esp_websocket_client_atom), description);
    term inner = port_heap_create_tuple2(&heap, ERROR_ATOM, detail);
    term msg = port_heap_create_tuple3(&heap, globalcontext_make_atom(global, websocket_atom), port_term, inner);

    port_send_message_from_task(global, term_from_local_process_id(owner), msg);
    memory_destroy_heap_from_task(&heap, global);
}

static void free_buffer(struct connection *conn)
{
    free(conn->buf);
    conn->buf = NULL;
    conn->buf_len = 0;
    conn->buf_cap = 0;
}

static void reset_buffer(struct connection *conn)
{
    free_buffer(conn);
    conn->discard_reason = NULL;
}

/* Drops what is buffered now; the rest of the message is skipped, then reported. */
static void discard_message(struct connection *conn, AtomString reason)
{
    free_buffer(conn);
    conn->discard_reason = reason;
}

/*
 * A device that reconnects by reopening the port would otherwise leak its
 * URL, headers and PEMs each time. Only once the client is destroyed: it keeps
 * pointers to the PEMs.
 */
static void free_connection_contents(struct connection *conn)
{
    free(conn->buf);
    free(conn->url);
    free(conn->headers);
    free(conn->cacert_pem);
    free(conn->client_cert_pem);
    free(conn->client_key_pem);
}

static void handle_data(
    GlobalContext *global, struct connection *conn, term port_term, esp_websocket_event_data_t *event)
{
    /* The IDF answers control frames itself. A CLOSE is reported once, by
     * WEBSOCKET_EVENT_CLOSED when the closing handshake is over. */
    if (event->op_code == WS_OPCODE_PING || event->op_code == WS_OPCODE_PONG || event->op_code == WS_OPCODE_CLOSE) {
        return;
    }

    /* A new message starts with a text or binary opcode; a continuation keeps the first one. */
    if (event->op_code == WS_OPCODE_TEXT || event->op_code == WS_OPCODE_BINARY) {
        if (event->payload_offset == 0) {
            reset_buffer(conn);
            conn->message_opcode = event->op_code;
        }
    }

    if (IS_NULL_PTR(conn->discard_reason)) {
        /*
         * payload_len and payload_offset describe the current frame, not the
         * message, so what this frame still brings is added to what earlier
         * frames left in buf. Knowing the rest of the frame refuses an
         * oversized one before any of it is buffered, and normally means one
         * allocation per frame.
         */
        size_t wanted = conn->buf_len + event->data_len;
        if (event->payload_len > event->payload_offset + event->data_len) {
            wanted += (size_t) (event->payload_len - event->payload_offset - event->data_len);
        }
        if (wanted > conn->max_message_size) {
            ESP_LOGW(TAG, "Message exceeds max_message_size (%u), discarding", (unsigned) conn->max_message_size);
            discard_message(conn, message_too_large_atom);
        } else if (wanted > conn->buf_cap) {
            char *grown = realloc(conn->buf, wanted);
            if (IS_NULL_PTR(grown)) {
                ESP_LOGW(TAG, "Could not allocate %u bytes for an incoming message", (unsigned) wanted);
                discard_message(conn, out_of_memory_atom);
            } else {
                conn->buf = grown;
                conn->buf_cap = wanted;
            }
        }
    }

    if (IS_NULL_PTR(conn->discard_reason) && event->data_len > 0) {
        memcpy(conn->buf + conn->buf_len, event->data_ptr, event->data_len);
        conn->buf_len += event->data_len;
    }

    /* Even when this chunk is the one that was refused, the message ends here: report it. */
    if (event->fin && event->payload_offset + event->data_len >= event->payload_len) {
        if (IS_NULL_PTR(conn->discard_reason)) {
            send_frame(global, conn, port_term);
        } else {
            send_tagged(global, conn->owner, port_term, error_atom, conn->discard_reason);
        }
        reset_buffer(conn);
    }
}

static void event_handler(void *handler_args, esp_event_base_t base, int32_t event_id, void *event_data)
{
    UNUSED(base);

    struct connection *conn = (struct connection *) handler_args;
    GlobalContext *global = conn->global;
    esp_websocket_event_data_t *event = (esp_websocket_event_data_t *) event_data;

    /* Port in {websocket, Port, _} has to be the term open_port returned: a
     * port from AtomVM 0.7 on, a pid before it. A pid never compares equal to
     * a port, so tagging with the wrong one makes every receive miss. */
#ifdef TERM_PORT_TAG
    term port_term = term_port_from_local_process_id(conn->port_id);
#else
    term port_term = term_from_local_process_id(conn->port_id);
#endif

#ifndef AVM_NO_SMP
    /*
     * Sending from a task to a process that has exited leaves the process
     * table read-locked (the from-task send only unlocks a process it found),
     * so send only while the owner is known to be alive. Without SMP that send
     * never walks the table, and walking it from here would race the scheduler.
     */
    Context *target = globalcontext_get_process_lock(global, conn->owner);
    if (IS_NULL_PTR(target)) {
        /* The owner is gone; nothing to deliver to. */
        return;
    }
#endif

    switch ((esp_websocket_event_id_t) event_id) {
        case WEBSOCKET_EVENT_CONNECTED:
            reset_buffer(conn);
            send_simple(global, conn->owner, port_term, globalcontext_make_atom(global, connected_atom));
            break;

        case WEBSOCKET_EVENT_DATA:
            handle_data(global, conn, port_term, event);
            break;

        /* A message cut off by either can never complete; do not hold its buffer through the outage. */
        case WEBSOCKET_EVENT_DISCONNECTED:
            reset_buffer(conn);
            send_tagged(global, conn->owner, port_term, closed_atom, disconnected_atom);
            break;

        case WEBSOCKET_EVENT_CLOSED:
            reset_buffer(conn);
            send_tagged(global, conn->owner, port_term, closed_atom, normal_atom);
            break;

        case WEBSOCKET_EVENT_ERROR:
            send_error(global, conn->owner, port_term, event);
            break;

        default:
            break;
    }

#ifndef AVM_NO_SMP
    globalcontext_get_process_unlock(global, target);
#endif
}

static struct connection *port_connection(Context *ctx)
{
    return ((struct platform_data *) ctx->platform_data)->conn;
}

static term do_send(Context *ctx, term payload, bool text)
{
    struct connection *conn = port_connection(ctx);

    if (!term_is_binary(payload)) {
        return BADARG_ATOM;
    }

    if (!esp_websocket_client_is_connected(conn->client)) {
        return globalcontext_make_atom(ctx->global, not_connected_atom);
    }

    const char *bytes = term_binary_data(payload);
    int len = term_binary_size(payload);

    int sent = text
        ? esp_websocket_client_send_text(conn->client, bytes, len, conn->timeout)
        : esp_websocket_client_send_bin(conn->client, bytes, len, conn->timeout);

    /* A write that times out returns 0, having aborted the connection. */
    if (sent != len) {
        return globalcontext_make_atom(ctx->global, send_failed_atom);
    }

    return OK_ATOM;
}

static NativeHandlerResult consume_mailbox(Context *ctx)
{
    GlobalContext *global = ctx->global;
    struct connection *conn = port_connection(ctx);

    Message *message = mailbox_first(&ctx->mailbox);
    term msg = message->message;

    if (msg == globalcontext_make_atom(global, owner_down_atom)) {
        /* The owner exited, and nothing else can close this port. */
        esp_websocket_client_close(conn->client, conn->timeout);
        mailbox_remove_message(&ctx->mailbox, &ctx->heap);
        return NativeTerminate;
    }

    /* A '$call' is {'$call', {Pid, Ref}, Req}; let the VM unpack it. */
    GenMessage gen_message;
    if (UNLIKELY(port_parse_gen_message(msg, &gen_message) != GenCallMessage)) {
        ESP_LOGW(TAG, "Received a message that is not a call");
        mailbox_remove_message(&ctx->mailbox, &ctx->heap);
        return NativeContinue;
    }

    term pid = gen_message.pid;
    term ref = gen_message.ref;
    term req = gen_message.req;

    /* Requests are close and {send_text | send_binary, Payload}. Only a
     * 2-tuple is taken apart, so any other shape gets badarg instead of being
     * read past its end. */
    term cmd_term = req;
    term payload = term_nil();
    if (term_is_tuple(req) && term_get_tuple_arity(req) == 2) {
        cmd_term = term_get_tuple_element(req, 0);
        payload = term_get_tuple_element(req, 1);
    }
    int cmd = interop_atom_term_select_int(cmd_table, cmd_term, global);

    NativeHandlerResult result = NativeContinue;
    term reply;
    /* A refused send is {error, Reason}, as send_text/2 and send_binary/2 document. */
    bool error = false;

    switch (cmd) {
        case WebSocketSendTextCmd:
            reply = do_send(ctx, payload, true);
            error = reply != OK_ATOM;
            break;

        case WebSocketSendBinaryCmd:
            reply = do_send(ctx, payload, false);
            error = reply != OK_ATOM;
            break;

        case WebSocketCloseCmd:
            /* connection_down destroys the client once the port terminates. */
            esp_websocket_client_close(conn->client, conn->timeout);
            reply = OK_ATOM;
            result = NativeTerminate;
            break;

        default:
            ESP_LOGW(TAG, "Unrecognised command");
            reply = BADARG_ATOM;
            break;
    }

    /* Room for {Ref, Reply}, and for {error, Reason} when a send was refused. */
    port_ensure_available(ctx, PORT_REPLY_SIZE + (error ? TUPLE_SIZE(2) : 0));
    if (error) {
        reply = port_create_error_tuple(ctx, reply);
    }
    port_send_reply(ctx, pid, ref, reply);

    mailbox_remove_message(&ctx->mailbox, &ctx->heap);

    return result;
}

/*
 * Runs from context_destroy, with the process table unlocked, when the port
 * or its owner exits.
 */
static void connection_down(ErlNifEnv *caller_env, void *obj, ErlNifPid *pid, ErlNifMonitor *mon)
{
    UNUSED(mon);

    struct connection *conn = (struct connection *) obj;
    GlobalContext *global = conn->global;

    if (*pid != conn->port_id) {
        /*
         * The owner exited, and nothing else can close this port, so ask it
         * to close; this runs again for the port itself once it has.
         */
        globalcontext_send_message(global, conn->port_id, globalcontext_make_atom(global, owner_down_atom));
        return;
    }

    if (conn->owner_monitored) {
        enif_demonitor_process(caller_env, conn, &conn->owner_monitor);
    }
    /* destroy() waits for the IDF task to exit, so no event can follow it. */
    esp_websocket_client_destroy(conn->client);
    free_connection_contents(conn);
    enif_release_resource(conn);
}

void atomvm_websocket_client_init(GlobalContext *global)
{
    ErlNifEnv env;
    erl_nif_env_partial_init_from_globalcontext(&env, global);
    connection_resource_type = enif_init_resource_type(
        &env, "websocket_client", &connection_resource_type_init, ERL_NIF_RT_CREATE, NULL);
}

Context *atomvm_websocket_client_create_port(GlobalContext *global, term opts)
{
    if (IS_NULL_PTR(connection_resource_type)) {
        ESP_LOGE(TAG, "The connection resource type was not created");
        return NULL;
    }

    /* A remote pid decodes to no local process, and every event would be dropped. */
    term owner = interop_kv_get_value(opts, owner_atom, global);
    if (UNLIKELY(!term_is_local_pid(owner))) {
        ESP_LOGE(TAG, "owner must be a local pid");
        return NULL;
    }

    char *url = maybe_get_string(opts, url_atom, global);
    if (IS_NULL_PTR(url)) {
        ESP_LOGE(TAG, "Missing url");
        return NULL;
    }

    struct connection *conn = enif_alloc_resource(connection_resource_type, sizeof(struct connection));
    if (IS_NULL_PTR(conn)) {
        free(url);
        return NULL;
    }
    memset(conn, 0, sizeof(struct connection));
    Context *ctx = NULL;

    conn->global = global;
    conn->owner = term_to_local_process_id(owner);
    conn->url = url;
    if (!build_headers(interop_kv_get_value(opts, headers_atom, global), &conn->headers)) {
        goto fail;
    }

    esp_websocket_client_config_t cfg = { 0 };
    cfg.uri = conn->url;
    cfg.headers = conn->headers;

    int max_message_size;
    int ping_interval_ms;
    if (!get_pos_int(opts, max_message_size_atom, CONFIG_AVM_WEBSOCKET_CLIENT_MAX_MESSAGE_SIZE,
            &max_message_size, global)
        || !get_pos_int(opts, buffer_size_atom, 1024, &cfg.buffer_size, global)
        || !get_pos_int(opts, reconnect_timeout_ms_atom, 10000, &cfg.reconnect_timeout_ms, global)
        || !get_pos_int(opts, network_timeout_ms_atom, 10000, &cfg.network_timeout_ms, global)
        || !get_pos_int(opts, ping_interval_ms_atom, 0, &ping_interval_ms, global)
        || !get_bool(opts, disable_auto_reconnect_atom, false, &cfg.disable_auto_reconnect, global)) {
        goto fail;
    }
    conn->max_message_size = (size_t) max_message_size;
    /* Sends and close run on a scheduler thread, so they get the bound the IDF
     * puts on its own writes instead of waiting on a stalled connection until
     * lwIP gives up. */
    conn->timeout = pdMS_TO_TICKS(cfg.network_timeout_ms);
    /* disable_auto_reconnect only covers drops. After a clean close by the
     * server the IDF stops for good unless this is set as well. */
    cfg.enable_close_reconnect = !cfg.disable_auto_reconnect;

    if (ping_interval_ms > 0) {
        /* Rounded up: 0 would mean the IDF's 10 s default. */
        cfg.ping_interval_sec = (ping_interval_ms + 999) / 1000;
    }

    /*
     * Server verification. `none` is deliberately noisy: it leaves the device
     * unable to tell the real server from anything else on the path, which for
     * a device that takes firmware over this connection is not a small thing.
     * A value this does not recognise is refused, never taken as `none`.
     */
    bool tls = strncasecmp(conn->url, "wss://", 6) == 0;
    term verify = interop_kv_get_value(opts, verify_atom, global);
    if (verify == globalcontext_make_atom(global, crt_bundle_atom)) {
#ifdef CONFIG_MBEDTLS_CERTIFICATE_BUNDLE
        cfg.crt_bundle_attach = esp_crt_bundle_attach;
#else
        ESP_LOGE(TAG, "verify => crt_bundle needs CONFIG_MBEDTLS_CERTIFICATE_BUNDLE");
        goto fail;
#endif
    } else if (term_is_tuple(verify) && term_get_tuple_arity(verify) == 2
        && term_get_tuple_element(verify, 0) == globalcontext_make_atom(global, cacert_pem_atom)) {
        conn->cacert_pem = term_to_c_string(term_get_tuple_element(verify, 1));
        if (IS_NULL_PTR(conn->cacert_pem)) {
            ESP_LOGE(TAG, "cacert_pem is not a string or binary");
            goto fail;
        }
        cfg.cert_pem = conn->cacert_pem;
    } else if (verify == globalcontext_make_atom(global, none_atom) || verify == term_invalid_term()) {
        if (tls) {
#ifdef CONFIG_ESP_TLS_SKIP_SERVER_CERT_VERIFY
            /* Without the query string, which may carry a token. */
            ESP_LOGW(TAG, "%sTLS server verification is DISABLED for %.*s",
                verify == term_invalid_term() ? "No verify option given; " : "",
                (int) strcspn(conn->url, "?"), conn->url);
#else
            /* With no CA, bundle or store configured, esp-tls refuses to connect. */
            ESP_LOGE(TAG, "verify => none on a wss:// URL needs CONFIG_ESP_TLS_SKIP_SERVER_CERT_VERIFY; "
                          "pass crt_bundle or {cacert_pem, Pem}");
            goto fail;
#endif
        }
    } else {
        ESP_LOGE(TAG, "verify must be crt_bundle, {cacert_pem, Pem} or none");
        goto fail;
    }

    /* Optional client certificate, for mutual TLS. */
    term client_cert = interop_kv_get_value(opts, client_cert_atom, global);
    if (client_cert != term_invalid_term()) {
        if (term_is_tuple(client_cert) && term_get_tuple_arity(client_cert) == 2) {
            conn->client_cert_pem = term_to_c_string(term_get_tuple_element(client_cert, 0));
            conn->client_key_pem = term_to_c_string(term_get_tuple_element(client_cert, 1));
        }
        if (IS_NULL_PTR(conn->client_cert_pem) || IS_NULL_PTR(conn->client_key_pem)) {
            ESP_LOGE(TAG, "client_cert must be {CertPem, KeyPem}");
            goto fail;
        }
        cfg.client_cert = conn->client_cert_pem;
        cfg.client_key = conn->client_key_pem;
    }

    conn->client = esp_websocket_client_init(&cfg);
    if (IS_NULL_PTR(conn->client)) {
        ESP_LOGE(TAG, "esp_websocket_client_init failed");
        goto fail;
    }

    ctx = context_new(global);
    if (IS_NULL_PTR(ctx)) {
        goto fail;
    }
    struct platform_data *data = malloc(sizeof(struct platform_data));
    if (IS_NULL_PTR(data)) {
        goto fail;
    }
    data->conn = conn;
    ctx->native_handler = consume_mailbox;
    ctx->platform_data = data;
    conn->port_id = ctx->process_id;

    if (UNLIKELY(esp_websocket_register_events(conn->client, WEBSOCKET_EVENT_ANY, event_handler, conn) != ESP_OK)) {
        ESP_LOGE(TAG, "esp_websocket_register_events failed");
        goto fail;
    }

    esp_err_t err = esp_websocket_client_start(conn->client);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "esp_websocket_client_start failed: %s", esp_err_to_name(err));
        goto fail;
    }

    /*
     * The monitors come last. Monitoring the port lets another scheduler run
     * it, and from then on only the port may end itself: connection_down,
     * which context_destroy runs however that happens, owns the teardown. The
     * extra reference keeps conn alive while this function still writes to it.
     */
    enif_keep_resource(conn);
    ErlNifEnv env;
    erl_nif_env_partial_init_from_globalcontext(&env, global);
    if (UNLIKELY(enif_monitor_process(&env, conn, &conn->port_id, NULL) != 0)) {
        enif_release_resource(conn);
        goto fail;
    }

    ErlNifMonitor owner_monitor;
    if (UNLIKELY(enif_monitor_process(&env, conn, &conn->owner, &owner_monitor) != 0)) {
        ESP_LOGE(TAG, "The owner has already exited");
        globalcontext_send_message(global, conn->port_id, globalcontext_make_atom(global, owner_down_atom));
        enif_release_resource(conn);
        return NULL;
    }
    conn->owner_monitor = owner_monitor;
    conn->owner_monitored = true;
    enif_release_resource(conn);

    return ctx;

fail:
    if (ctx) {
        /*
         * Not context_destroy: context_new put ctx on the scheduler's waiting
         * list, and only scheduler_terminate takes it off before freeing it.
         * It frees platform_data, the box around conn, itself.
         */
        scheduler_terminate(ctx);
    }
    if (conn->client) {
        esp_websocket_client_destroy(conn->client);
    }
    free_connection_contents(conn);
    enif_release_resource(conn);
    return NULL;
}

REGISTER_PORT_DRIVER(
    websocket_client, atomvm_websocket_client_init, NULL, atomvm_websocket_client_create_port)

#endif
