package earning

import "testing"

func TestDecodeStrictJSONRejectsDuplicateKeys(t *testing.T) {
	var output struct {
		Value string `json:"value"`
	}
	if err := decodeStrictJSON([]byte(`{"value":"first","value":"second"}`), &output); err == nil {
		t.Fatal("duplicate JSON key was accepted")
	}
	if err := decodeStrictJSON([]byte(`{"value":"one"}`), &output); err != nil || output.Value != "one" {
		t.Fatalf("canonical JSON was rejected: output=%+v err=%v", output, err)
	}
}
