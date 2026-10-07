## HTTP/0.9 File Serving Example

The `server` and `client` examples demonstrate fetching files using a HTTP-like toy protocol.

1. Server (`server.rs`)

The server listens for any client requesting a file. 
If the file path is valid and allowed, it returns the contents. 

Open up a terminal and execute:

```text
$ cargo run --example server ./
```

2. Client (`client.rs`)

The client requests a file and prints it to the console. 
If the file is on the server, it will receive the response. 

In a new terminal execute:

```test
$ cargo run --example client https://localhost:4433/Cargo.toml
```

where `Cargo.toml` is any file in the directory passed to the server.

**Result:**

The output will be the contents of this README.

**Troubleshooting:**

If the client times out with no activity on the server, try forcing the server to run on IPv4 by
running it with `cargo run --example server -- ./ --listen 127.0.0.1:4433`. The server listens on
IPv6 by default, `localhost` tends to resolve to IPv4, and support for accepting IPv4 packets on
IPv6 sockets varies between platforms.

If the client prints `failed to process request: failed reading file`, the request was processed
successfully but the path segment of the URL did not correspond to a file in the directory being
served.

## Minimal Example
The `connection.rs` example intends to use the smallest amount of code to make a simple QUIC connection.
The server issues it's own certificate and passes it to the client to trust.

```text
$ cargo run --example connection
```

This example will make a QUIC connection on localhost, and you should see output like:

```text
[client] connected: addr=127.0.0.1:5000
[server] connection accepted: addr=127.0.0.1:53712
```

## Insecure Connection Example

The `insecure_connection.rs` example demonstrates how to make a QUIC connection that ignores the server certificate.

```text
$ cargo run --example insecure_connection --features="rustls/dangerous_configuration"
```

## Single Socket Example

You can have multiple QUIC connections over a single UDP socket. This is especially
useful, if you are building a peer-to-peer system where you potentially need to communicate with
thousands of peers or if you have a
[hole punched](https://en.wikipedia.org/wiki/UDP_hole_punching) UDP socket.
Additionally, QUIC servers and clients can both operate on the same UDP socket.
This example demonstrates how to make multiple outgoing connections on a single UDP socket.

```text 
$ cargo run --example single_socket
```

The expected output should be something like:

```text
[client] connected: addr=127.0.0.1:5000
[server] incoming connection: addr=127.0.0.1:48930
[client] connected: addr=127.0.0.1:5001
[client] connected: addr=127.0.0.1:5002
[server] incoming connection: addr=127.0.0.1:48930
[server] incoming connection: addr=127.0.0.1:48930
```

Notice how the server sees multiple incoming connections with different IDs coming from the same
endpoint.

## Initial Filter Example

The `initial_filter.rs` example shows how to rate limit inbound connection attempts with
`InitialFilter`, which runs before any per-connection state is allocated. Strangers within the
configured budget are answered with a Retry to confirm the source address, the rest are dropped.
Peers bearing a valid token proceed without consuming the budget.

```text
$ cargo run --example initial_filter
```

The expected output should be something like:

```text
New client connecting to a server admitting 1 handshake/s
[client] connected: 127.0.0.1:36999
[server] accepted 127.0.0.1:47383
[server] admitted=1 retried=1 ignored=0
Familiar client connecting again - no problem
[client] connected: 127.0.0.1:36999
[server] accepted 127.0.0.1:47383
[server] admitted=2 retried=1 ignored=0
Unfamiliar client connecting
[client] second attempt got no response within 500ms, as expected
[server] admitted=2 retried=1 ignored=1
```

The first connection is retried once and then admitted when it comes back bearing the token. The
familiar client reconnects with the NEW_TOKEN it received, so it is admitted without a Retry. A
different client arriving immediately after exceeds the budget, is dropped, and hears nothing.

`InitialFilter` has two hooks, both executed synchronously in the receive path; they must not block
or re-enter the endpoint. `allow_initial` runs first and can enforce a global budget before any
token authentication, replay-log access or Initial-key derivation. `decide` runs after token
validation, so an `Ignore` there has already paid the token cost. Fast Retry skips Initial-key
derivation with the built-in provider; custom crypto providers should override `supports_version`
to get the same benefit. Existing connections bypass the hooks.
