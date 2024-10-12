package main

import (
	"fmt"
	"testing"
)

func TestParseFingerprints(t *testing.T) {
	paths := []string{
		"C:/Users/Administrator/下载/web_fingerprint_v4.json",
		"C:/Users/Administrator/下载/service_fingerprint_v4.json",
	}

	fingerprints, err := parseFingerprintsFromFingerprintHub(paths)
	if err != nil {
		t.Fatal(err)
	}

	fmt.Printf("Fingerprints numbers: %d\n", len(fingerprints))
}
