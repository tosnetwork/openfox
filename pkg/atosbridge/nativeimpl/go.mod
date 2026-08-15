module github.com/tosnetwork/openfox/pkg/atosbridge/nativeimpl

go 1.26.5

require (
	github.com/tosnetwork/openfox v0.0.0
	github.com/tosnetwork/tos-ai v0.0.0
	github.com/tosnetwork/tos-protocol v0.0.0
	github.com/xssnick/tonutils-go v1.16.0
)

require (
	github.com/fxamacker/cbor/v2 v2.9.2 // indirect
	github.com/x448/float16 v0.8.4 // indirect
	google.golang.org/protobuf v1.36.11 // indirect
)

replace github.com/tosnetwork/openfox => ../../..

replace github.com/tosnetwork/tos-ai => ../../../../tos-ai

replace github.com/tosnetwork/tos-protocol => ../../../../tos-protocol
