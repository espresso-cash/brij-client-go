//go:build integration

package integration_tests

import (
	"context"
	"crypto"
	"crypto/ed25519"
	"testing"

	"github.com/btcsuite/btcutil/base58"

	"github.com/stretchr/testify/assert"

	"go.brij.fi/client/pkg/config"
	"go.brij.fi/client/pkg/wallet"
)

func TestClient(t *testing.T) {
	ctx := context.Background()

	walletSK := ed25519.NewKeyFromSeed(base58.Decode("59i6Cc3fHTfTKmj1cta7mXugDtYwvHkCvjjv8ppzzSJW"))
	walletPK := walletSK.Public().(ed25519.PublicKey)

	walletAddress := base58.Encode(walletPK)

	client, err := wallet.NewClient(
		config.Demo(),
		func(data []byte) []byte {
			s, _ := walletSK.Sign(nil, data, crypto.Hash(0))
			return s
		},
	)
	if err != nil {
		t.Fatalf("failed to create wallet client: %v", err)
	}

	err = client.Init(ctx, walletAddress)
	if err != nil {
		t.Fatalf("failed to init wallet client: %v", err)
	}

	info, err := client.GetInfo(ctx)
	if err != nil {
		t.Fatalf("failed to get wallet info: %v", err)
	}

	assert.Equal(t, walletAddress, info.WalletAddress)
}
