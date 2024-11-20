package main

import (
	"fmt"
	"testing"
)

func TestParseFingerprintsFromFingerprintHub(t *testing.T) {
	paths := []string{
		"/Users/yvling/Downloads/web_fingerprint_v4.json",
		"/Users/yvling/Downloads/service_fingerprint_v4.json",
	}

	fingerprints, err := parseFingerprintsFromFingerprintHub(paths)
	if err != nil {
		t.Fatal(err)
	}

	fmt.Printf("Fingerprints numbers: %d\n", len(fingerprints))
}
