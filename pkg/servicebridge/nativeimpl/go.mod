module github.com/tosnetwork/openfox/pkg/servicebridge/nativeimpl

go 1.26.6

require (
	github.com/tosnetwork/openfox v0.0.0
	github.com/tosnetwork/tos-messenger v0.0.0-20261108064913-050c66234942
	github.com/tosnetwork/tos-service-protocol v0.0.0-20261108063330-1e95a4a6a7e8
	github.com/tosnetwork/tosutils-go v1.18.2-0.20260820143526-4d1a10d94bef
	google.golang.org/protobuf v1.36.11
)

require (
	connectrpc.com/connect v1.19.1 // indirect
	filippo.io/edwards25519 v1.2.0 // indirect
	github.com/fxamacker/cbor/v2 v2.9.2 // indirect
	github.com/pierrec/lz4/v4 v4.1.27 // indirect
	github.com/x448/float16 v0.8.4 // indirect
	github.com/xssnick/raptorq v1.5.0 // indirect
	golang.org/x/sys v0.46.0 // indirect
)

replace github.com/tosnetwork/openfox => ../../..
