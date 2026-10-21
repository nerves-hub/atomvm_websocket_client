# AtomVM WebSocket Client

An AtomVM Port and Erlang library for connecting to WebSocket servers from an
ESP32, wrapping ESP-IDF's `esp_websocket_client`.

The IDF client owns the socket, the TLS session and WebSocket framing on its own
FreeRTOS task, so Erlang sees whole messages rather than bytes, and TLS is
handled by the same code Espressif ships for every other protocol client.

This Port is an add-on to the AtomVM base image. Using it means building the
AtomVM virtual machine yourself, which requires the ESP-IDF SDK and toolchain.

## Adding it to an AtomVM build

Point the build at this repo wherever it lives. Nothing in the AtomVM checkout
needs to change:

```bash
cd AtomVM/src/platforms/esp32
idf.py -DEXTRA_COMPONENT_DIRS=/path/to/atomvm_websocket_client build
```

It can also be cloned into `AtomVM/src/platforms/esp32/components/`, which some
AtomVM components document, but that edits the AtomVM tree for no gain.

`esp_websocket_client` is not part of ESP-IDF core — it lives in `esp-protocols`
and is pulled in by the component manager via this component's
`idf_component.yml`.

Two things that will otherwise cost you an afternoon:

* **Run `idf.py reconfigure` after adding the component.** CMake caches its
  component list, so a plain `idf.py build` reports success without ever
  compiling the new component or fetching its managed dependency.
* **ESP-IDF v5.2 to v5.5.** AtomVM does not build against v6: mbedTLS 4.x moved
  `mbedtls/ctr_drbg.h`, and GCC 15 rejects the gperf-generated tables. Verified
  against v5.5.4.

## Size

Adding this component to an `esp32` build of AtomVM costs about 119 KB:

| | Size |
| --- | --- |
| AtomVM, unmodified | 1,595,536 bytes |
| With this component | 1,717,136 bytes |

## Usage

```erlang
{ok, WS} = websocket_client:open(#{
    url    => "wss://example.com/socket/websocket",
    owner  => self(),
    verify => crt_bundle
}),

receive
    {websocket, WS, connected} ->
        ok = websocket_client:send_text(WS, <<"hello">>)
end,

receive
    {websocket, WS, {text, Reply}} ->
        io:format("~p~n", [Reply])
end.
```

See [`examples/websocket_client_example`](examples/websocket_client_example) for
a complete application that connects over TLS and echoes a message a second.

## Messages

| Message | Meaning |
| --- | --- |
| `{websocket, Port, connected}` | Connected, or reconnected |
| `{websocket, Port, {text, Binary}}` | A complete text message |
| `{websocket, Port, {binary, Binary}}` | A complete binary message |
| `{websocket, Port, {closed, Reason}}` | `normal` or `disconnected` |
| `{websocket, Port, {error, Reason}}` | `message_too_large`, `out_of_memory`, `{esp_tls, ...}`, or `{esp_websocket_client, Description}` |

A connection error carries `{esp_tls, LastEspErr, StackErr, CertFlags}` only
when ESP-IDF reports TLS codes for it. Otherwise it carries ESP-IDF's own
description of the failure as a binary, which includes the TLS error and the
HTTP status of a rejected upgrade.

The client reconnects on its own, so `connected` arrives again after every
disconnection. Any state the server holds for a session has to be rebuilt each
time — a subprotocol that keeps server-side state must re-establish it on every
`connected`, not only the first.

## TLS

`verify` decides how the server certificate is checked:

| Value | Behaviour |
| --- | --- |
| `crt_bundle` | ESP-IDF's bundled root certificates. Needs `CONFIG_MBEDTLS_CERTIFICATE_BUNDLE`. |
| `{cacert_pem, Pem}` | Verify against one CA, for a private one. |
| `none` | No verification. On a `wss://` URL it needs `CONFIG_ESP_TLS_INSECURE` and `CONFIG_ESP_TLS_SKIP_SERVER_CERT_VERIFY` in the AtomVM build; without them esp-tls refuses an unverified connection, so `open/1` fails. |

Omitting `verify` behaves as `none`, and both log a warning. Any other value
makes `open/1` fail rather than falling back to `none`. Without verification any
machine on the network path can present itself as the server, so it is for
development only.

`client_cert => {CertPem, KeyPem}` supplies a client certificate for mutual TLS.
It is independent of `verify`.

`open/1` returns `{error, badarg}` for a `verify`, `client_cert` or `headers`
value it cannot use, rather than connecting without it.

## Options

| Option | Default |
| --- | --- |
| `url` | required |
| `owner` | the calling process |
| `headers` | none — `[{Name, Value}]`, sent on the opening handshake |
| `verify` | none (with a warning) |
| `client_cert` | none |
| `max_message_size` | `CONFIG_AVM_WEBSOCKET_CLIENT_MAX_MESSAGE_SIZE` (4096) |
| `buffer_size` | 1024 |
| `ping_interval_ms` | the IDF default |
| `reconnect_timeout_ms` | 10000 |
| `network_timeout_ms` | 10000; also the longest a send or `close/1` waits |
| `disable_auto_reconnect` | `false` |

A message larger than `max_message_size` is discarded and reported as
`{error, message_too_large}` rather than delivered truncated.

## Status

Runs on hardware. Built against AtomVM on ESP-IDF v5.5.4 for the `esp32`
target, and used on an ESP32 to hold a Phoenix channel connection to a
NervesHub server over `ws://` — joining, heartbeating, streaming a firmware
image over the socket, and carrying a remote console session.

The TLS paths are implemented and none of them has been run on a device yet:
`crt_bundle`, `{cacert_pem, Pem}`, and `client_cert` for mutual TLS.

## License

Apache-2.0 OR LGPL-2.1-or-later, matching AtomVM.
