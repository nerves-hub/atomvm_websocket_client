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
 * Note the pid conversions. `data->owner` is a local process id, an int32,
 * while the port_send_message_* functions take a pid *term* and decode it
 * themselves. Passing the int32 straight through compiles — term is an
 * integer type — and then decodes to a process that does not exist, so every
 * message is dropped without an error. Convert with
 * term_from_local_process_id/1 at the call.
 */

#include <sdkconfig.h>

#ifdef CONFIG_AVM_WEBSOCKET_CLIENT_ENABLE

#include <string.h>

#include <esp_log.h>
#include <esp_websocket_client.h>

#ifdef CONFIG_MBEDTLS_CERTIFICATE_BUNDLE
#include <esp_crt_bundle.h>
#endif

#include <atom.h>
#include <context.h>
#include <defaultatoms.h>
#include <globalcontext.h>
#include <interop.h>
#include <mailbox.h>
#include <memory.h>
#include <port.h>
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

struct platform_data
{
    int32_t owner;
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
    bool overflowed;

    /* Owned copies: the IDF client keeps the pointers it is given. */
    char *url;
    char *headers;
    char *cacert_pem;
    char *client_cert_pem;
    char *client_key_pem;
};

/* Caller owns the returned string. */
static char *maybe_get_string(term kv, AtomString key, GlobalContext *global)
{
    term value = interop_kv_get_value(kv, key, global);
    if (!term_is_string(value) && !term_is_binary(value)) {
        return NULL;
    }

    int ok;
    char *str = interop_term_to_string(value, &ok);
    if (UNLIKELY(!ok)) {
        ESP_LOGE(TAG, "Option is not a proper string or binary");
        return NULL;
    }
    return str;
}

static int get_int_default(term kv, AtomString key, int default_value, GlobalContext *global)
{
    term value = interop_kv_get_value(kv, key, global);
    return term_is_integer(value) ? term_to_int(value) : default_value;
}

static bool get_bool_default(term kv, AtomString key, bool default_value, GlobalContext *global)
{
    term value = interop_kv_get_value(kv, key, global);
    if (value == TRUE_ATOM) {
        return true;
    }
    if (value == FALSE_ATOM) {
        return false;
    }
    return default_value;
}

/*
 * esp_websocket_client takes extra headers as one CRLF-terminated block rather
 * than a list, so flatten [{K, V}] into "K: V\r\n...".
 */
static char *build_headers(term headers, GlobalContext *global)
{
    if (!term_is_list(headers) || term_is_nil(headers)) {
        return NULL;
    }

    size_t total = 0;
    term cursor = headers;
    while (term_is_nonempty_list(cursor)) {
        term pair = term_get_list_head(cursor);
        if (!term_is_tuple(pair) || term_get_tuple_arity(pair) != 2) {
            ESP_LOGE(TAG, "A header must be a {Name, Value} tuple");
            return NULL;
        }

        int ok_name;
        int ok_value;
        char *name = interop_term_to_string(term_get_tuple_element(pair, 0), &ok_name);
        char *value = interop_term_to_string(term_get_tuple_element(pair, 1), &ok_value);
        if (UNLIKELY(!ok_name || !ok_value)) {
            free(name);
            free(value);
            ESP_LOGE(TAG, "A header name and value must be strings or binaries");
            return NULL;
        }

        total += strlen(name) + strlen(value) + 4; /* ": " and CRLF */
        free(name);
        free(value);

        cursor = term_get_list_tail(cursor);
    }

    char *block = malloc(total + 1);
    if (IS_NULL_PTR(block)) {
        return NULL;
    }
    block[0] = '\0';

    cursor = headers;
    while (term_is_nonempty_list(cursor)) {
        term pair = term_get_list_head(cursor);

        int ok;
        char *name = interop_term_to_string(term_get_tuple_element(pair, 0), &ok);
        char *value = interop_term_to_string(term_get_tuple_element(pair, 1), &ok);

        strcat(block, name);
        strcat(block, ": ");
        strcat(block, value);
        strcat(block, "\r\n");

        free(name);
        free(value);

        cursor = term_get_list_tail(cursor);
    }

    return block;
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

static void send_frame(GlobalContext *global, struct platform_data *data, term port_term)
{
    AtomString kind = (data->message_opcode == WS_OPCODE_BINARY) ? binary_atom : text_atom;

    size_t requested = TUPLE_SIZE(3) + TUPLE_SIZE(2) + term_binary_heap_size(data->buf_len);

    Heap heap;
    if (UNLIKELY(memory_init_heap(&heap, requested) != MEMORY_GC_OK)) {
        ESP_LOGW(TAG, "Could not allocate %u bytes to deliver a message", (unsigned) requested);
        send_tagged(global, data->owner, port_term, error_atom, out_of_memory_atom);
        return;
    }

    term payload = term_from_literal_binary(data->buf, data->buf_len, &heap, global);
    term inner = port_heap_create_tuple2(&heap, globalcontext_make_atom(global, kind), payload);
    term msg = port_heap_create_tuple3(&heap, globalcontext_make_atom(global, websocket_atom), port_term, inner);

    port_send_message_from_task(global, term_from_local_process_id(data->owner), msg);
    memory_destroy_heap(&heap, global);
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
    memory_destroy_heap(&heap, global);
}

static void reset_buffer(struct platform_data *data)
{
    free(data->buf);
    data->buf = NULL;
    data->buf_len = 0;
    data->buf_cap = 0;
    data->overflowed = false;
}

/*
 * The port driver registers no destroy callback, so anything malloc'd here is
 * freed on the way out of the close command. A device that reconnects by
 * reopening the port would otherwise leak its URL, headers and PEMs each time.
 */
static void free_platform_data(struct platform_data *data)
{
    free(data->buf);
    free(data->url);
    free(data->headers);
    free(data->cacert_pem);
    free(data->client_cert_pem);
    free(data->client_key_pem);
    free(data);
}

/*
 * For a port that fails to open. context_destroy() frees ctx->platform_data
 * itself, so the data has to be detached first or it is freed twice.
 */
static void destroy_port(Context *ctx)
{
    free_platform_data((struct platform_data *) ctx->platform_data);
    ctx->platform_data = NULL;
    context_destroy(ctx);
}

static void handle_data(
    GlobalContext *global, struct platform_data *data, term port_term, esp_websocket_event_data_t *event)
{
    /* The IDF answers control frames itself. A CLOSE is reported once, by
     * WEBSOCKET_EVENT_CLOSED when the closing handshake is over. */
    if (event->op_code == WS_OPCODE_PING || event->op_code == WS_OPCODE_PONG || event->op_code == WS_OPCODE_CLOSE) {
        return;
    }

    /* A new message starts with a text or binary opcode; a continuation keeps the first one. */
    if (event->op_code == WS_OPCODE_TEXT || event->op_code == WS_OPCODE_BINARY) {
        if (event->payload_offset == 0) {
            reset_buffer(data);
            data->message_opcode = event->op_code;
        }
    }

    if (data->overflowed) {
        /* Keep discarding until the message ends, then report once. */
        if (event->fin && (event->payload_offset + event->data_len >= event->payload_len)) {
            send_tagged(global, data->owner, port_term, error_atom, message_too_large_atom);
            reset_buffer(data);
        }
        return;
    }

    if (data->buf_len + event->data_len > data->max_message_size) {
        ESP_LOGW(TAG, "Message exceeds max_message_size (%u), discarding", (unsigned) data->max_message_size);
        data->overflowed = true;
        return;
    }

    if (data->buf_len + event->data_len > data->buf_cap) {
        /* payload_len is the whole frame, so this normally allocates once. */
        size_t wanted = event->payload_len > 0 ? (size_t) event->payload_len : data->buf_len + event->data_len;
        if (wanted > data->max_message_size) {
            wanted = data->max_message_size;
        }
        char *grown = realloc(data->buf, wanted);
        if (IS_NULL_PTR(grown)) {
            ESP_LOGW(TAG, "Could not allocate %u bytes for an incoming message", (unsigned) wanted);
            data->overflowed = true;
            return;
        }
        data->buf = grown;
        data->buf_cap = wanted;
    }

    memcpy(data->buf + data->buf_len, event->data_ptr, event->data_len);
    data->buf_len += event->data_len;

    bool frame_complete = (event->payload_offset + event->data_len) >= event->payload_len;
    if (frame_complete && event->fin) {
        send_frame(global, data, port_term);
        reset_buffer(data);
    }
}

static void event_handler(void *handler_args, esp_event_base_t base, int32_t event_id, void *event_data)
{
    UNUSED(base);

    Context *ctx = (Context *) handler_args;
    GlobalContext *global = ctx->global;
    struct platform_data *data = (struct platform_data *) ctx->platform_data;
    esp_websocket_event_data_t *event = (esp_websocket_event_data_t *) event_data;

    /* Port in {websocket, Port, _} has to be the term open_port returned: a
     * port from AtomVM 0.7 on, a pid before it. A pid never compares equal to
     * a port, so tagging with the wrong one makes every receive miss. */
#ifdef TERM_PORT_TAG
    term port_term = term_port_from_local_process_id(ctx->process_id);
#else
    term port_term = term_from_local_process_id(ctx->process_id);
#endif

    Context *target = globalcontext_get_process_lock(global, data->owner);
    if (IS_NULL_PTR(target)) {
        /* The owner is gone; nothing to deliver to. */
        return;
    }

    switch ((esp_websocket_event_id_t) event_id) {
        case WEBSOCKET_EVENT_CONNECTED:
            reset_buffer(data);
            send_simple(global, data->owner, port_term, globalcontext_make_atom(global, connected_atom));
            break;

        case WEBSOCKET_EVENT_DATA:
            handle_data(global, data, port_term, event);
            break;

        case WEBSOCKET_EVENT_DISCONNECTED:
            send_tagged(global, data->owner, port_term, closed_atom, disconnected_atom);
            break;

        case WEBSOCKET_EVENT_CLOSED:
            send_tagged(global, data->owner, port_term, closed_atom, normal_atom);
            break;

        case WEBSOCKET_EVENT_ERROR:
            send_error(global, data->owner, port_term, event);
            break;

        default:
            break;
    }

    globalcontext_get_process_unlock(global, target);
}

static term do_send(Context *ctx, term payload, bool text)
{
    struct platform_data *data = (struct platform_data *) ctx->platform_data;

    if (!term_is_binary(payload)) {
        return BADARG_ATOM;
    }

    if (!esp_websocket_client_is_connected(data->client)) {
        return globalcontext_make_atom(ctx->global, not_connected_atom);
    }

    const char *bytes = term_binary_data(payload);
    int len = term_binary_size(payload);

    int sent = text
        ? esp_websocket_client_send_text(data->client, bytes, len, data->timeout)
        : esp_websocket_client_send_bin(data->client, bytes, len, data->timeout);

    /* A write that times out returns 0, having aborted the connection. */
    if (sent != len) {
        return globalcontext_make_atom(ctx->global, send_failed_atom);
    }

    return OK_ATOM;
}

static NativeHandlerResult consume_mailbox(Context *ctx)
{
    GlobalContext *global = ctx->global;
    struct platform_data *data = (struct platform_data *) ctx->platform_data;

    Message *message = mailbox_first(&ctx->mailbox);
    term msg = message->message;

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

    term cmd_term = term_is_tuple(req) ? term_get_tuple_element(req, 0) : req;
    int cmd = interop_atom_term_select_int(cmd_table, cmd_term, global);

    NativeHandlerResult result = NativeContinue;
    term reply;
    /* A refused send is {error, Reason}, as send_text/2 and send_binary/2 document. */
    bool error = false;

    switch (cmd) {
        case WebSocketSendTextCmd:
            reply = do_send(ctx, term_get_tuple_element(req, 1), true);
            error = reply != OK_ATOM;
            break;

        case WebSocketSendBinaryCmd:
            reply = do_send(ctx, term_get_tuple_element(req, 1), false);
            error = reply != OK_ATOM;
            break;

        case WebSocketCloseCmd:
            /* destroy() also unregisters the event handler, so no callback can
             * arrive after this and find freed platform data. */
            esp_websocket_client_close(data->client, data->timeout);
            esp_websocket_client_destroy(data->client);
            free_platform_data(data);
            ctx->platform_data = NULL;
            reply = OK_ATOM;
            result = NativeTerminate;
            break;

        default:
            ESP_LOGW(TAG, "Unrecognised command");
            reply = BADARG_ATOM;
            break;
    }

    /* One allocation for the error tuple and the reply: a second one could
     * collect the tuple before it is sent. */
    port_ensure_available(ctx, PORT_REPLY_SIZE + (error ? TUPLE_SIZE(2) : 0));
    if (error) {
        reply = port_create_error_tuple(ctx, reply);
    }
    port_send_reply(ctx, pid, ref, reply);

    mailbox_remove_message(&ctx->mailbox, &ctx->heap);

    return result;
}

void atomvm_websocket_client_init(GlobalContext *global)
{
    UNUSED(global);
    /* Nothing global to set up; each port owns its own IDF client. */
}

Context *atomvm_websocket_client_create_port(GlobalContext *global, term opts)
{
    term owner = interop_kv_get_value(opts, owner_atom, global);
    if (UNLIKELY(!term_is_pid(owner))) {
        ESP_LOGE(TAG, "Missing owner pid");
        return NULL;
    }

    char *url = maybe_get_string(opts, url_atom, global);
    if (IS_NULL_PTR(url)) {
        ESP_LOGE(TAG, "Missing url");
        return NULL;
    }

    Context *ctx = context_new(global);
    ctx->native_handler = consume_mailbox;

    struct platform_data *data = calloc(1, sizeof(struct platform_data));
    if (IS_NULL_PTR(data)) {
        free(url);
        context_destroy(ctx);
        return NULL;
    }

    data->owner = term_to_local_process_id(owner);
    data->url = url;
    data->headers = build_headers(interop_kv_get_value(opts, headers_atom, global), global);
    data->max_message_size = get_int_default(
        opts, max_message_size_atom, CONFIG_AVM_WEBSOCKET_CLIENT_MAX_MESSAGE_SIZE, global);

    ctx->platform_data = data;

    esp_websocket_client_config_t cfg = { 0 };
    cfg.uri = data->url;
    cfg.headers = data->headers;
    cfg.buffer_size = get_int_default(opts, buffer_size_atom, 1024, global);
    cfg.reconnect_timeout_ms = get_int_default(opts, reconnect_timeout_ms_atom, 10000, global);
    cfg.network_timeout_ms = get_int_default(opts, network_timeout_ms_atom, 10000, global);
    /* Sends and close run on a scheduler thread, so they get the bound the IDF
     * puts on its own writes instead of waiting on a stalled connection until
     * lwIP gives up. The IDF also reads a non-positive value as 10 s. */
    data->timeout = pdMS_TO_TICKS(cfg.network_timeout_ms > 0 ? cfg.network_timeout_ms : 10000);
    cfg.disable_auto_reconnect = get_bool_default(opts, disable_auto_reconnect_atom, false, global);
    /* disable_auto_reconnect only covers drops. After a clean close by the
     * server the IDF stops for good unless this is set as well. */
    cfg.enable_close_reconnect = !cfg.disable_auto_reconnect;

    int ping_interval_ms = get_int_default(opts, ping_interval_ms_atom, 0, global);
    if (ping_interval_ms > 0) {
        cfg.ping_interval_sec = ping_interval_ms / 1000;
    }

    /*
     * Server verification. `none` is deliberately noisy: it leaves the device
     * unable to tell the real server from anything else on the path, which for
     * a device that takes firmware over this connection is not a small thing.
     */
    term verify = interop_kv_get_value(opts, verify_atom, global);
    if (verify == globalcontext_make_atom(global, crt_bundle_atom)) {
#ifdef CONFIG_MBEDTLS_CERTIFICATE_BUNDLE
        cfg.crt_bundle_attach = esp_crt_bundle_attach;
#else
        ESP_LOGE(TAG, "verify => crt_bundle needs CONFIG_MBEDTLS_CERTIFICATE_BUNDLE");
        destroy_port(ctx);
        return NULL;
#endif
    } else if (term_is_tuple(verify) && term_get_tuple_arity(verify) == 2
        && term_get_tuple_element(verify, 0) == globalcontext_make_atom(global, cacert_pem_atom)) {
        int ok;
        data->cacert_pem = interop_term_to_string(term_get_tuple_element(verify, 1), &ok);
        if (UNLIKELY(!ok)) {
            ESP_LOGE(TAG, "cacert_pem is not a string or binary");
            destroy_port(ctx);
            return NULL;
        }
        cfg.cert_pem = data->cacert_pem;
    } else if (verify == globalcontext_make_atom(global, none_atom)) {
        ESP_LOGW(TAG, "TLS server verification is DISABLED for %s", data->url);
    } else {
        ESP_LOGW(TAG, "No verify option given; TLS server verification is DISABLED for %s", data->url);
    }

    /* Optional client certificate, for mutual TLS. */
    term client_cert = interop_kv_get_value(opts, client_cert_atom, global);
    if (term_is_tuple(client_cert) && term_get_tuple_arity(client_cert) == 2) {
        int ok_cert;
        int ok_key;
        data->client_cert_pem = interop_term_to_string(term_get_tuple_element(client_cert, 0), &ok_cert);
        data->client_key_pem = interop_term_to_string(term_get_tuple_element(client_cert, 1), &ok_key);
        if (UNLIKELY(!ok_cert || !ok_key)) {
            ESP_LOGE(TAG, "client_cert must be {CertPem, KeyPem}");
            destroy_port(ctx);
            return NULL;
        }
        cfg.client_cert = data->client_cert_pem;
        cfg.client_key = data->client_key_pem;
    }

    data->client = esp_websocket_client_init(&cfg);
    if (IS_NULL_PTR(data->client)) {
        ESP_LOGE(TAG, "esp_websocket_client_init failed");
        destroy_port(ctx);
        return NULL;
    }

    esp_websocket_register_events(data->client, WEBSOCKET_EVENT_ANY, event_handler, (void *) ctx);

    esp_err_t err = esp_websocket_client_start(data->client);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "esp_websocket_client_start failed: %s", esp_err_to_name(err));
        esp_websocket_client_destroy(data->client);
        destroy_port(ctx);
        return NULL;
    }

    return ctx;
}

REGISTER_PORT_DRIVER(
    websocket_client, atomvm_websocket_client_init, NULL, atomvm_websocket_client_create_port)

#endif
