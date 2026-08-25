package earning

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	commerce "github.com/tosnetwork/tos-service-protocol/pkg/agentcommerce"
)

// DirectoryCarrier is the reference second Carrier. It reads a replicated
// content-addressed directory and shares no database, process, cursor or HTTP
// implementation with the Gateway Carrier. Operators can distribute the
// files with TOS Storage, DHT announcements, removable media, or any other
// transport without changing Intent semantics.
type DirectoryCarrier struct {
	CarrierID string
	Directory string
}

func (carrier DirectoryCarrier) ID() string { return carrier.CarrierID }

func (carrier DirectoryCarrier) Search(ctx context.Context, query IntentQuery) ([]CarrierResult, error) {
	if carrier.CarrierID == "" || !filepath.IsAbs(carrier.Directory) || filepath.Clean(carrier.Directory) != carrier.Directory ||
		query.MaximumResults == 0 || query.MaximumResults > 1000 {
		return nil, errors.New("directory Carrier configuration or query is invalid")
	}
	info, err := os.Lstat(carrier.Directory)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return nil, errors.New("directory Carrier root is unavailable")
	}
	entries, err := os.ReadDir(carrier.Directory)
	if err != nil {
		return nil, err
	}
	type indexedObject struct {
		sequence uint64
		digest   string
		kind     string
	}
	var after uint64
	if query.Cursor != "" {
		if !strings.HasPrefix(query.Cursor, "seq:") {
			return nil, errors.New("directory Carrier cursor is invalid")
		}
		after, err = strconv.ParseUint(strings.TrimPrefix(query.Cursor, "seq:"), 10, 64)
		if err != nil || after == 0 {
			return nil, errors.New("directory Carrier cursor is invalid")
		}
	}
	indexed := make([]indexedObject, 0, len(entries))
	for _, entry := range entries {
		name := entry.Name()
		prefix, kind := ".cursor-", "intent"
		if strings.HasPrefix(name, ".withdrawal-cursor-") {
			prefix, kind = ".withdrawal-cursor-", "withdrawal"
		}
		if !entry.Type().IsRegular() || len(name) != len(prefix)+20+1+64 || !strings.HasPrefix(name, prefix) || name[len(prefix)+20] != '-' ||
			!lowerHex(name[len(prefix)+21:]) {
			continue
		}
		sequence, parseErr := strconv.ParseUint(name[len(prefix):len(prefix)+20], 10, 64)
		if parseErr == nil && sequence > after {
			indexed = append(indexed, indexedObject{sequence: sequence, digest: name[len(prefix)+21:], kind: kind})
		}
	}
	indexedProfile := len(indexed) > 0
	if !indexedProfile && query.Cursor == "" {
		for _, entry := range entries {
			name := entry.Name()
			if entry.Type().IsRegular() && len(name) == 69 && strings.HasSuffix(name, ".json") && lowerHex(name[:64]) {
				indexed = append(indexed, indexedObject{digest: name[:64], kind: "intent"})
			}
		}
		sort.Slice(indexed, func(i, j int) bool { return indexed[i].digest < indexed[j].digest })
	}
	if indexedProfile {
		sort.Slice(indexed, func(i, j int) bool { return indexed[i].sequence < indexed[j].sequence })
	}
	results := make([]CarrierResult, 0, query.MaximumResults)
	for _, item := range indexed {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		name := item.digest + ".json"
		digest := "sha256:" + item.digest
		if item.kind == "withdrawal" {
			path := filepath.Join(carrier.Directory, ".withdrawal-"+name)
			info, statErr := os.Lstat(path)
			if statErr != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Size() <= 0 || info.Size() > 2<<20 {
				continue
			}
			raw, readErr := os.ReadFile(path)
			var withdrawal commerce.SignedAgentIntentWithdrawal
			decoder := json.NewDecoder(bytes.NewReader(raw))
			decoder.DisallowUnknownFields()
			if readErr != nil || decoder.Decode(&withdrawal) != nil || decoder.Decode(&struct{}{}) != io.EOF ||
				withdrawal.Body.IntentDigest != digest {
				continue
			}
			computed, digestErr := commerce.IntentWithdrawalDigest(withdrawal.Body)
			if digestErr != nil || computed == "" {
				continue
			}
			cursor := "seq:" + strconv.FormatUint(item.sequence, 10)
			results = append(results, CarrierResult{Withdrawal: &withdrawal, Cursor: cursor, CarrierID: carrier.CarrierID})
			if len(results) == int(query.MaximumResults) {
				break
			}
			continue
		}
		if !indexedProfile {
			if _, err := os.Stat(filepath.Join(carrier.Directory, ".withdrawal-"+name)); err == nil {
				continue
			}
		}
		path := filepath.Join(carrier.Directory, name)
		pathInfo, err := os.Lstat(path)
		if err != nil || !pathInfo.Mode().IsRegular() || pathInfo.Mode()&os.ModeSymlink != 0 || pathInfo.Size() <= 0 || pathInfo.Size() > 2<<20 {
			continue
		}
		file, err := os.Open(path)
		if err != nil {
			continue
		}
		opened, statErr := file.Stat()
		if statErr != nil || !os.SameFile(pathInfo, opened) {
			_ = file.Close()
			continue
		}
		raw, readErr := io.ReadAll(io.LimitReader(file, (2<<20)+1))
		_ = file.Close()
		if readErr != nil || len(raw) == 0 || len(raw) > 2<<20 {
			continue
		}
		var intent commerce.SignedAgentIntent
		decoder := json.NewDecoder(bytes.NewReader(raw))
		decoder.DisallowUnknownFields()
		if decoder.Decode(&intent) != nil || decoder.Decode(&struct{}{}) != io.EOF || !matchesQuery(intent.Body.Payload.DiscoveryCard, query) {
			continue
		}
		computed, err := commerce.IntentBodyDigest(intent.Body)
		if err != nil || computed != digest {
			continue
		}
		cursor := ""
		if indexedProfile {
			cursor = "seq:" + strconv.FormatUint(item.sequence, 10)
		}
		results = append(results, CarrierResult{Intent: intent, Cursor: cursor, CarrierID: carrier.CarrierID})
		if len(results) == int(query.MaximumResults) {
			break
		}
	}
	return results, nil
}

func (carrier DirectoryCarrier) Resolve(ctx context.Context, digest string) (CarrierResult, error) {
	if err := ctx.Err(); err != nil {
		return CarrierResult{}, err
	}
	if carrier.CarrierID == "" || !filepath.IsAbs(carrier.Directory) || filepath.Clean(carrier.Directory) != carrier.Directory || !canonicalSHA256(digest) {
		return CarrierResult{}, errors.New("directory Carrier resolution request is invalid")
	}
	root, err := os.Lstat(carrier.Directory)
	if err != nil || !root.IsDir() || root.Mode()&os.ModeSymlink != 0 {
		return CarrierResult{}, errors.New("directory Carrier root is unavailable")
	}
	path := filepath.Join(carrier.Directory, strings.TrimPrefix(digest, "sha256:")+".json")
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Size() <= 0 || info.Size() > 2<<20 {
		return CarrierResult{}, errors.New("directory Carrier object is unavailable")
	}
	file, err := os.Open(path)
	if err != nil {
		return CarrierResult{}, err
	}
	opened, statErr := file.Stat()
	if statErr != nil || !os.SameFile(info, opened) {
		_ = file.Close()
		return CarrierResult{}, errors.New("directory Carrier object changed during open")
	}
	raw, readErr := io.ReadAll(io.LimitReader(file, (2<<20)+1))
	_ = file.Close()
	if readErr != nil || len(raw) == 0 || len(raw) > 2<<20 {
		return CarrierResult{}, errors.New("directory Carrier object is invalid or oversized")
	}
	var intent commerce.SignedAgentIntent
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&intent) != nil || decoder.Decode(&struct{}{}) != io.EOF {
		return CarrierResult{}, errors.New("directory Carrier object is malformed")
	}
	computed, err := commerce.IntentBodyDigest(intent.Body)
	if err != nil || computed != digest {
		return CarrierResult{}, errors.New("directory Carrier object conflicts with requested digest")
	}
	return CarrierResult{Intent: intent, Cursor: digest, CarrierID: carrier.CarrierID}, nil
}

func lowerHex(value string) bool {
	if len(value) == 0 {
		return false
	}
	for _, character := range []byte(value) {
		if !(character >= '0' && character <= '9' || character >= 'a' && character <= 'f') {
			return false
		}
	}
	return true
}
