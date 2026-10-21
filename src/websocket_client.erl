%
% Copyright 2026 NervesHub contributors
%
% SPDX-License-Identifier: Apache-2.0 OR LGPL-2.1-or-later
%

%%-----------------------------------------------------------------------------
%% @doc A WebSocket client for AtomVM on the ESP32.
%%
%% This is a thin Erlang interface over ESP-IDF's `esp_websocket_client', which
%% owns the TCP connection, the TLS session and WebSocket framing on its own
%% FreeRTOS task. Erlang sees whole messages, never bytes.
%%
%% == Delivery ==
%%
%% Messages are delivered to the `owner' process:
%%
%% ```
%% {websocket, Port, connected}
%% {websocket, Port, {text, binary()}}
%% {websocket, Port, {binary, binary()}}
%% {websocket, Port, {closed, Reason :: term()}}
%% {websocket, Port, {error, Reason :: term()}}
%% '''
%%
%% The client reconnects on its own unless `disable_auto_reconnect' is set, so
%% `connected' can arrive more than once. Any session state above this layer has
%% to be rebuilt each time — a WebSocket subprotocol that keeps server-side state
%% (Phoenix channels, say) must re-join on every `connected', not only the first.
%%
%% == TLS ==
%%
%% `verify' picks how the server certificate is checked:
%%
%% <ul>
%%   <li>`crt_bundle' — ESP-IDF's bundled root certificates. The usual choice for
%%       a public host.</li>
%%   <li>`{cacert_pem, Pem}' — verify against one CA, for a private one.</li>
%%   <li>`none' — no verification at all. Development only: it makes any on-path
%%       machine able to impersonate the server, and it logs a warning when the
%%       port opens so it cannot be left on by accident. On a `wss://' URL it
%%       needs `CONFIG_ESP_TLS_INSECURE' and
%%       `CONFIG_ESP_TLS_SKIP_SERVER_CERT_VERIFY' in the AtomVM build, or the
%%       open fails.</li>
%% </ul>
%%
%% Any other `verify' value, or a `client_cert' or `headers' value the driver
%% cannot use, makes `open/1' return `{error, badarg}'.
%%
%% `client_cert' supplies a client certificate for mutual TLS. It is independent
%% of `verify' — a server can be verified with the certificate bundle while the
%% client authenticates with a certificate, headers, or nothing at all.
%% @end
%%-----------------------------------------------------------------------------
-module(websocket_client).

-export([
    open/1,
    send_text/2,
    send_binary/2,
    close/1
]).

-export_type([config/0, verify/0]).

-type verify() :: crt_bundle | {cacert_pem, binary()} | none.

-type config() :: #{
    url := string() | binary(),
    owner => pid(),
    headers => [{string() | binary(), string() | binary()}],
    verify => verify(),
    client_cert => {Cert :: binary(), Key :: binary()},
    max_message_size => pos_integer(),
    ping_interval_ms => pos_integer(),
    reconnect_timeout_ms => pos_integer(),
    network_timeout_ms => pos_integer(),
    disable_auto_reconnect => boolean(),
    buffer_size => pos_integer()
}.

%%-----------------------------------------------------------------------------
%% @doc Open a connection.
%%
%% Returns once the port exists, not once the connection is up: wait for
%% `{websocket, Port, connected}' before sending.
%% @end
%%-----------------------------------------------------------------------------
-spec open(config()) -> {ok, port()} | {error, term()}.
open(#{url := _} = Config) ->
    Owner = maps:get(owner, Config, self()),

    Opts = maps:to_list(Config#{owner => Owner}),

    try open_port({spawn, "websocket_client"}, Opts) of
        Port when is_port(Port) -> {ok, Port}
    catch
        _:Reason -> {error, Reason}
    end;
open(_Config) ->
    {error, missing_url}.

%%-----------------------------------------------------------------------------
%% @doc Send a text frame.
%%
%% Fails with `{error, not_connected}' rather than queueing while the connection
%% is down — a caller that cannot see the difference will silently lose messages
%% across a reconnect.
%% @end
%%-----------------------------------------------------------------------------
-spec send_text(port(), iodata()) -> ok | {error, term()}.
send_text(Port, Data) ->
    reply(port:call(Port, {send_text, iolist_to_binary(Data)})).

%%-----------------------------------------------------------------------------
%% @doc Send a binary frame.
%% @end
%%-----------------------------------------------------------------------------
-spec send_binary(port(), iodata()) -> ok | {error, term()}.
send_binary(Port, Data) ->
    reply(port:call(Port, {send_binary, iolist_to_binary(Data)})).

%%-----------------------------------------------------------------------------
%% @doc Close the connection and destroy the port.
%% @end
%%-----------------------------------------------------------------------------
-spec close(port()) -> ok.
close(Port) ->
    port:call(Port, close).

%% A driver built before refused sends were wrapped replies the bare reason
%% (`not_connected', `send_failed'). The driver is part of the VM image and this
%% module part of the application, so an application update can run over an
%% older driver; port:call/2 can also return a bare `out_of_memory'.
reply(ok) ->
    ok;
reply({error, _} = Error) ->
    Error;
reply(Reason) ->
    {error, Reason}.
