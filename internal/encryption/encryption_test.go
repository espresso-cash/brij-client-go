package encryption

import (
	"crypto/ed25519"
	"testing"

	"github.com/btcsuite/btcutil/base58"
)

func TestDecodeSecretKey(t *testing.T) {
	privateKey := ed25519.NewKeyFromSeed(base58.Decode("8ui6TQMfAudigNuKycopDyZ6irMeS7DTSe73d2gzv1Hz"))

	testCases := []struct {
		name               string
		encryptedSecretKey string
		publicKey          ed25519.PublicKey
		expected           string
		expectErr          bool
	}{
		{
			name:               "success",
			encryptedSecretKey: "pyqvN8GWE4lx2/rwCduuocskONqJavyDmkficwJ3g0kwhQIWZMS8Nb1nJlLclXWp/34RYbbH7EMzlfogxgMrzKgQ+DttMf/P",
			publicKey:          base58.Decode("25AHNngVGm2rRF4HgvLCmyy4NXtwf5QcECzVbFgrn9Hu"),
			expected:           "3QZpFo1MutmY7QLArdV2ATKcwpsixvDPNkDC8JQcdsrS",
			expectErr:          false,
		},
		{
			name:               "failure with wrong public key",
			encryptedSecretKey: "pyqvN8GWE4lx2/rwCduuocskONqJavyDmkficwJ3g0kwhQIWZMS8Nb1nJlLclXWp/34RYbbH7EMzlfogxgMrzKgQ+DttMf/P",
			publicKey:          base58.Decode("4iSt3vJzosGT6JU8zfXGYwgJbMZBHgRpnJUAhRMXz7fz"),
			expected:           "",
			expectErr:          true,
		},
		{
			name:               "failure with invalid public key",
			encryptedSecretKey: "pyqvN8GWE4lx2/rwCduuocskONqJavyDmkficwJ3g0kwhQIWZMS8Nb1nJlLclXWp/34RYbbH7EMzlfogxgMrzKgQ+DttMf/P",
			publicKey:          base58.Decode("4iSt3"),
			expected:           "",
			expectErr:          true,
		},
	}

	for _, tc := range testCases {
		t.Run(
			tc.name, func(t *testing.T) {
				secretKey, err := DecodeSecretKey(tc.encryptedSecretKey, tc.publicKey, privateKey)
				if (err != nil) != tc.expectErr {
					t.Fatalf("expected error: %v, got: %v", tc.expectErr, err)
				}
				if !tc.expectErr && base58.Encode(secretKey[:]) != tc.expected {
					t.Fatalf("expected: %v, got: %v", tc.expected, secretKey)
				}
			},
		)
	}
}

func TestDeriveMasterSecretKey(t *testing.T) {
	t.Run(
		"success", func(t *testing.T) {
			seed := base58.Decode("59i6Cc3fHTfTKmj1cta7mXugDtYwvHkCvjjv8ppzzSJW")
			masterKey, err := DeriveMasterSecretKey(seed)
			if err != nil {
				t.Fatalf("expected no error, got: %v", err)
			}
			expectedKey := "6PNcp9qGCsd4mU3QbBKXjf8dgjdcDS7GKyUCVXtF1k5v"
			if base58.Encode(masterKey) != expectedKey {
				t.Fatalf("expected master key: %s, got: %s", expectedKey, base58.Encode(masterKey))
			}
		},
	)
}
