# Kaiyu's note

Use the `622ca23d` branch of quic-go, commit at Jan 31, 2021

The `Changelog.md` of this version is not correct. This version is at newer than v0.19.3 version, support QUIC-29/QUIC-32.

This version suppoert `go` 1.14, 1.15, and 1.16

Compatible `Wireshark` version: 3.3.1 (v3.3.1-0-gd64aca7966e2)

## Usage

Server
```
go run main.go 

# using -v will increate the latency a lot
go run main.go -v 
```

Client
```
# kaiyhou_client_go
go run main.go -insecure -interval 5 -numRequest 5 -keylog=key1.key -v -p https://localhost:6121/demo/echo
go run main.go ... -body "echo body" https://localhost:6121/demo/echo
go run main.go ... https://localhost:6162/demo/tiles
go run main.go ... https://localhost:6121/demo/tile

# kaiyhou_client_tls
go run main.go -insecure -interval 5 -numRequest 5  https://www.google.com

# kaiyhou_client_tcp
go run main.go -interval 5 -numRequest 5  http://www.google.com
```

## Implement `roundTripper.CloseAfterHandshakeConfirmed()` 

Diff
- http3/client.go
- http3/roundtrip.go
- interface.go
- session.go


# A QUIC implementation in pure Go

<img src="docs/quic.png" width=303 height=124>

[![PkgGoDev](https://pkg.go.dev/badge/github.com/lucas-clemente/quic-go)](https://pkg.go.dev/github.com/lucas-clemente/quic-go)
[![Travis Build Status](https://img.shields.io/travis/lucas-clemente/quic-go/master.svg?style=flat-square&label=Travis+build)](https://travis-ci.org/lucas-clemente/quic-go)
[![CircleCI Build Status](https://img.shields.io/circleci/project/github/lucas-clemente/quic-go.svg?style=flat-square&label=CircleCI+build)](https://circleci.com/gh/lucas-clemente/quic-go)
[![Windows Build Status](https://img.shields.io/appveyor/ci/lucas-clemente/quic-go/master.svg?style=flat-square&label=windows+build)](https://ci.appveyor.com/project/lucas-clemente/quic-go/branch/master)
[![Code Coverage](https://img.shields.io/codecov/c/github/lucas-clemente/quic-go/master.svg?style=flat-square)](https://codecov.io/gh/lucas-clemente/quic-go/)

quic-go is an implementation of the [QUIC](https://en.wikipedia.org/wiki/QUIC) protocol in Go. It implements the [IETF QUIC draft-29](https://tools.ietf.org/html/draft-ietf-quic-transport-29) and [draft-32](https://tools.ietf.org/html/draft-ietf-quic-transport-32).

## Version compatibility

Since quic-go is under active development, there's no guarantee that two builds of different commits are interoperable. The QUIC version used in the *master* branch is just a placeholder, and should not be considered stable.

When using quic-go as a library, please always use a [tagged release](https://github.com/lucas-clemente/quic-go/releases). Only these releases use the official draft version numbers.

## Guides

*We currently support Go 1.14+, with [Go modules](https://github.com/golang/go/wiki/Modules) support enabled.*

Running tests:

    go test ./...

### QUIC without HTTP/3

Take a look at [this echo example](example/echo/echo.go).

## Usage

### As a server

See the [example server](example/main.go). Starting a QUIC server is very similar to the standard lib http in go:

```go
http.Handle("/", http.FileServer(http.Dir(wwwDir)))
http3.ListenAndServeQUIC("localhost:4242", "/path/to/cert/chain.pem", "/path/to/privkey.pem", nil)
```

### As a client

See the [example client](example/client/main.go). Use a `http3.RoundTripper` as a `Transport` in a `http.Client`.

```go
http.Client{
  Transport: &http3.RoundTripper{},
}
```

## Contributing

We are always happy to welcome new contributors! We have a number of self-contained issues that are suitable for first-time contributors, they are tagged with [help wanted](https://github.com/lucas-clemente/quic-go/issues?q=is%3Aissue+is%3Aopen+label%3A%22help+wanted%22). If you have any questions, please feel free to reach out by opening an issue or leaving a comment.
