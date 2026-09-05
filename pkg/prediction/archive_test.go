package prediction

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	protocol "github.com/tosnetwork/tos-service-protocol/pkg/predictionmarket"
)

type signingArchiveReplica struct {
	key    ed25519.PrivateKey
	stored ArchiveObjectV1
	err    error
}

func (replica *signingArchiveReplica) StorePredictionEvidence(
	_ context.Context,
	object ArchiveObjectV1,
) (ArchiveReceipt, error) {
	if replica.err != nil {
		return ArchiveReceipt{}, replica.err
	}
	replica.stored = object
	replica.stored.Content = append([]byte(nil), object.Content...)
	return SignArchiveReceipt(
		replica.key,
		object.ContentDigest,
		object.ArchiveLocator,
		10_950,
		object.RetainUntil,
	)
}

func TestOracleFetchesAndArchivesIdenticalEvidenceBeforePlanning(t *testing.T) {
	profile, keys := oracleFixture(t, protocol.RoundNormal)
	journal, err := OpenOracleJournal(filepath.Join(t.TempDir(), "oracle"), profile)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = journal.Close() }()
	content := []byte(`{"winner":"YES","precincts_reporting":100}`)
	source, err := newHTTPSOracleSource(
		sourceProfile(),
		fixedSourceResolver{ips: []net.IP{net.ParseIP("8.8.8.8")}},
		sourceClient(func(request *http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode:    http.StatusOK,
				Header:        http.Header{"Content-Type": []string{"application/json"}},
				Body:          io.NopCloser(bytes.NewReader(content)),
				ContentLength: int64(len(content)),
				Request:       request,
			}, nil
		}),
	)
	if err != nil {
		t.Fatal(err)
	}
	replicas := []*signingArchiveReplica{{key: keys[0]}, {key: keys[1]}}
	evidence, err := journal.FetchAndArchiveEvidence(
		t.Context(),
		source,
		EvidenceMetadataV1{
			PublicationTimeSeconds: 10_900,
			EventTimeSeconds:       10_800,
			ParserProfileVersion:   "election-json/v1",
		},
		[]EvidenceArchiveReplica{replicas[0], replicas[1]},
		11_000,
	)
	if err != nil || len(evidence.Receipts) != 2 || !bytes.Equal(evidence.Content, content) {
		t.Fatalf("evidence acquisition failed: %+v err=%v", evidence, err)
	}
	if replicas[0].stored.ArchiveLocator != replicas[1].stored.ArchiveLocator ||
		replicas[0].stored.ContentDigest != replicas[1].stored.ContentDigest ||
		!bytes.Equal(replicas[0].stored.Content, replicas[1].stored.Content) ||
		replicas[0].stored.RetainUntil != profile.ClaimDeadline+profile.AuditRetention {
		t.Fatal("archive replicas did not receive one exact content-addressed object")
	}
	evidence.Content[0] ^= 1
	if bytes.Equal(evidence.Content, replicas[0].stored.Content) {
		t.Fatal("returned evidence aliases an archive request")
	}
}

func TestOracleEvidenceAcquisitionFailsClosedOnReplicaOrReceiptFailure(t *testing.T) {
	profile, keys := oracleFixture(t, protocol.RoundNormal)
	journal, err := OpenOracleJournal(filepath.Join(t.TempDir(), "oracle"), profile)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = journal.Close() }()
	source, err := newHTTPSOracleSource(
		sourceProfile(),
		fixedSourceResolver{ips: []net.IP{net.ParseIP("8.8.8.8")}},
		sourceClient(func(request *http.Request) (*http.Response, error) {
			content := []byte(`{"winner":"YES"}`)
			return &http.Response{
				StatusCode:    http.StatusOK,
				Header:        http.Header{"Content-Type": []string{"application/json"}},
				Body:          io.NopCloser(bytes.NewReader(content)),
				ContentLength: int64(len(content)),
				Request:       request,
			}, nil
		}),
	)
	if err != nil {
		t.Fatal(err)
	}
	metadata := EvidenceMetadataV1{
		PublicationTimeSeconds: 10_900,
		EventTimeSeconds:       10_800,
		ParserProfileVersion:   "election-json/v1",
	}
	failed := &signingArchiveReplica{key: keys[1], err: errors.New("archive unavailable")}
	if _, err := journal.FetchAndArchiveEvidence(
		t.Context(), source, metadata,
		[]EvidenceArchiveReplica{&signingArchiveReplica{key: keys[0]}, failed}, 11_000,
	); err == nil {
		t.Fatal("one unavailable required replica was ignored")
	}
	forgedKey := ed25519.NewKeyFromSeed(bytesOf(0x7f, ed25519.SeedSize))
	if _, err := journal.FetchAndArchiveEvidence(
		t.Context(), source, metadata,
		[]EvidenceArchiveReplica{&signingArchiveReplica{key: keys[0]}, &signingArchiveReplica{key: forgedKey}},
		11_000,
	); err == nil {
		t.Fatal("receipt from an unadmitted archive key was accepted")
	}
}

func TestOracleEvidenceAcquisitionUsesTwoDurableFileReplicas(t *testing.T) {
	profile, keys := oracleFixture(t, protocol.RoundNormal)
	journal, err := OpenOracleJournal(filepath.Join(t.TempDir(), "oracle"), profile)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = journal.Close() }()
	content := []byte(`{"winner":"NO","certified":true}`)
	source, err := newHTTPSOracleSource(
		sourceProfile(),
		fixedSourceResolver{ips: []net.IP{net.ParseIP("8.8.8.8")}},
		sourceClient(func(request *http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusOK, Header: http.Header{"Content-Type": []string{"application/json"}},
				Body: io.NopCloser(bytes.NewReader(content)), ContentLength: int64(len(content)), Request: request,
			}, nil
		}),
	)
	if err != nil {
		t.Fatal(err)
	}
	directories := []string{t.TempDir(), t.TempDir()}
	replicas := make([]*FileEvidenceArchiveReplica, 0, len(directories))
	for index, directory := range directories {
		if err := os.Chmod(directory, 0o700); err != nil {
			t.Fatal(err)
		}
		replica, openErr := OpenFileEvidenceArchiveReplica(FileEvidenceArchiveConfig{
			Directory: directory, SigningKey: keys[index], MaximumObjects: 8,
			MaximumObjectBytes: 4096, MaximumContentBytes: 32 << 10,
			Now: func() time.Time { return time.Unix(10_950, 0).UTC() },
		})
		if openErr != nil {
			t.Fatal(openErr)
		}
		replicas = append(replicas, replica)
	}
	evidence, err := journal.FetchAndArchiveEvidence(
		t.Context(), source,
		EvidenceMetadataV1{
			PublicationTimeSeconds: 10_900, EventTimeSeconds: 10_800,
			ParserProfileVersion: "election-json/v1",
		},
		[]EvidenceArchiveReplica{replicas[0], replicas[1]}, 11_000,
	)
	if err != nil || len(evidence.Receipts) != 2 {
		t.Fatalf("durable evidence acquisition failed: %+v err=%v", evidence, err)
	}
	for index, replica := range replicas {
		if err := replica.Close(); err != nil {
			t.Fatal(err)
		}
		reopened, openErr := OpenFileEvidenceArchiveReplica(FileEvidenceArchiveConfig{
			Directory: directories[index], SigningKey: keys[index], MaximumObjects: 8,
			MaximumObjectBytes: 4096, MaximumContentBytes: 32 << 10,
		})
		if openErr != nil {
			t.Fatal(openErr)
		}
		loaded, loadErr := reopened.LoadPredictionEvidence(t.Context(), evidence.Entry.ArchiveLocator)
		closeErr := reopened.Close()
		if loadErr != nil || closeErr != nil || !bytes.Equal(loaded.Content, content) ||
			loaded.RetainUntil != profile.ClaimDeadline+profile.AuditRetention {
			t.Fatalf("file replica %d did not retain exact evidence: %+v load=%v close=%v", index, loaded, loadErr, closeErr)
		}
	}
}
