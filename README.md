# Ossuary (libossuary)

Ossuary is a library for establishing an encrypted and authenticated communication channel between a client and a server.

It establishes a 1-to-1 client/server communication channel that requires reliable, in-order packet delivery, such as provided by TCP sockets.

Authentication and verification of remote hosts is optional, and requires an out-of-band exchange of host public keys, or a Trust-On-First-Use policy.

It is a written in Rust with a C FFI.  It is built as a Rust library, a C dynamic library (*libossuary.so/.dylib*), and a C static library (*libossuary.a*).

# Purpose

Ossuary serves the same purpose as TLS (or SSL): two hosts establish an end-to-end encrypted communication channel with each other, optionally identifying themselves in the process if access controls are required.

It differs primarily in simplicity.  It is small, simple, and opinionated.  It's fast enough, and no faster.

Ossuary has a single use case: "I have a TCP socket, I want to talk securely over it, and I don't want to deal with TLS."  Reasonable uses are command-and-control services, logging, status or sensor reporting, and one-off file transfers.

It contains no particular optimizations for large quantities of simultaneous connections, nor frequent connections or rapid connection re-establishment.  For these things, have you considered TLS?

# Method

Ossuary is designed as a utility library for encrypting and decrypting buffers of data.  The encrypted format includes a variety of metadata, but all of this is opaque to the user.

Ossuary is not involved in the network connection at all.  The parent application is responsible for establishing a communication channel, be it TCP or UDP or UNIX domain sockets or D-Bus or RS-232 or smoke signals.  Ossuary sits in between network calls, as a filter.  In pseudocode, it might look approximately like this:

```
<Setup TCP socket and Ossuary>

while socket.connected():

    // Read encrypted data from the network layer
    data_from_network = socket.read();

    // Decrypt the data with Ossuary
    plaintext_data = ossuary.recv_data(data_from_network);

    // React to the received message and get a plaintext response
    response = application_parse_command(plaintext_data);

    // Encrypt the response with Ossuary
    data_to_network = ossuary.send_data(response);

    // Write encrypted data to the network layer
    socket.write(data_to_network);

<tear down TCP socket and Ossuary>
```

This design accepts the trade-off that data is copied frequently, reducing the maximum bandwidth in favor of simple integration.

When using Ossuary from Rust, however, you can pass any objects that implement the Read and Write traits.  This means, for convenience, you can pass TcpStream objects directly.  This won't help much with performance, but it reduces the code required for simple integrations.

Ossuary does not involve itself in persistent storage, either.  Storage of keys is left as an exercise to the calling application.

# Reason

There are shockingly few "secure channel" libraries in the wild.  TLS is the big player with dozens of implementations (OpenSSL, GnuTLS, LibreSSL, BoringSSL, mbed TLS, MatrixSSL, wolfSSL, s2n...).  libssh2 can be used similarly, but doing so is maybe not as common.  Another alternative is to step above the TCP layer to a 'distributed messaging' system like ZeroMQ with its CurveZMQ protocol.

Although size varies wildly across the implementations, and custom minimal builds are viable, the default builds that ship for desktop systems vary between "large" and "gigantic".  The complexity of the APIs vary between "moderate" and "absurd".  The ability to shoot yourself in the foot varies between "likely" and "absolutely certain".

Ossuary is small, though not tiny due to... Rust.  Ossuary's API is minimal and simple.  Configuration is nearly zero.  The least code is the most secure; it takes more code to lower the security.

# Security

Should be presumed to be: none.  Don't assume immature cryptographic libraries from random people on the internet will be safe.

# API Documentation

[Ossuary Rustdoc](https://mrmekon.github.io/ossuary/ossuary/)

# Versioning

This is an experimental pre-1.0 release.  The version numbers mean nothing, the API is unstable.

# Dependencies

The underlying cryptographic primitives are from third parties:
 * [x25519-dalek](https://github.com/dalek-cryptography/x25519-dalek)
 * [ed25519-dalek](https://github.com/isislovecruft/ed25519-dalek)
 * [chacha20-poly1305-aead](https://github.com/cesarb/chacha20-poly1305-aead)

The underlying randomness is from third parties:
 * [rand](https://github.com/rust-random/rand)
