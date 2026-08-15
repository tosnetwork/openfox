module github.com/tosnetwork/openfox/pkg/atosbridge/nativeimpl

go 1.26.5

require (
	github.com/a2aproject/a2a-go/v2 v2.4.0
	github.com/tosnetwork/openfox v0.0.0
	github.com/tosnetwork/tos-ai v0.0.0
	github.com/tosnetwork/tos-protocol v0.0.0
	github.com/xssnick/tonutils-go v1.16.0
)

require (
	github.com/fxamacker/cbor/v2 v2.9.2 // indirect
	github.com/google/jsonschema-go v0.4.3 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/modelcontextprotocol/go-sdk v1.7.0 // indirect
	github.com/segmentio/asm v1.1.3 // indirect
	github.com/segmentio/encoding v0.5.4 // indirect
	github.com/x448/float16 v0.8.4 // indirect
	github.com/yosida95/uritemplate/v3 v3.0.2 // indirect
	golang.org/x/oauth2 v0.36.0 // indirect
	golang.org/x/sync v0.21.0 // indirect
	golang.org/x/sys v0.46.0 // indirect
	golang.org/x/time v0.15.0 // indirect
	google.golang.org/protobuf v1.36.11 // indirect
)

replace github.com/tosnetwork/openfox => ../../..

replace github.com/tosnetwork/tos-ai => ../../../../tos-ai

replace github.com/tosnetwork/tos-protocol => ../../../../tos-protocol
