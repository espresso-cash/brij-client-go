package wallet

import (
	"context"
	"crypto/ed25519"

	"connectrpc.com/connect"
	"github.com/btcsuite/btcutil/base58"
	"github.com/golang-jwt/jwt/v5"
	owc "go.brij.fi/protos/brij/orders/v1/wallet/walletconnect"
	sw "go.brij.fi/protos/brij/storage/v1/wallet"
	swc "go.brij.fi/protos/brij/storage/v1/wallet/walletconnect"
	vc "go.brij.fi/protos/brij/verifier/v1/v1connect"

	"go.brij.fi/client/internal/encryption"
	"go.brij.fi/client/internal/grpc"
	"go.brij.fi/client/pkg/config"
)

type Sign = func(data []byte) []byte

type Info struct {
	WalletAddress string
	PublicKey     string
	SeedMessage   string
}

type Client interface {
	Init(ctx context.Context, walletAddress string) error
	GetInfo(ctx context.Context) (*Info, error)
}

type walletClient struct {
	cfg  *config.Config
	sign Sign

	authSk ed25519.PrivateKey
	authPk ed25519.PublicKey

	secretKey [32]byte

	storageClient  swc.WalletServiceClient
	verifierClient vc.VerifierServiceClient
	ordersClient   owc.WalletServiceClient
}

func NewClient(cfg *config.Config, sign Sign) (Client, error) {
	client := &walletClient{
		cfg:  cfg,
		sign: sign,
	}

	return client, nil
}

func (c *walletClient) Init(ctx context.Context, walletAddress string) error {
	client := grpc.NewWalletStorageClient(c.cfg.StorageBaseUrl, "")
	proofResponse, err := client.GetWalletProof(
		ctx,
		connect.NewRequest(&sw.GetWalletProofRequest{WalletAddress: walletAddress}),
	)
	if err != nil {
		return err
	}

	proof := proofResponse.Msg.ProofMessage
	signature := c.sign([]byte(proof))
	encodedSignature := base58.Encode(signature)

	seedMessageResponse, err := client.RestoreConnection(
		ctx, connect.NewRequest(
			&sw.RestoreConnectionRequest{
				WalletAddress:        walletAddress,
				WalletProofSignature: encodedSignature,
			},
		),
	)

	if err != nil {
		return err
	}

	var authKeySeed []byte
	var connectToken string
	var seedMessage string

	if seedMessageResponse.Msg.GetConnected() != nil {
		connected := seedMessageResponse.Msg.GetConnected()
		seedMessage = connected.SeedMessage
	} else if seedMessageResponse.Msg.GetNotConnected() != nil {
		notConnected := seedMessageResponse.Msg.GetNotConnected()
		seedMessage = "hello" // TODO: Use a more secure seed generation method
		connectToken = notConnected.ConnectToken
	} else {
		panic("Both Connected and NotConnected messages are nil")
	}

	authKeySeed = c.generateSeed(seedMessage)
	c.authSk = ed25519.NewKeyFromSeed(authKeySeed)
	c.authPk = c.authSk.Public().(ed25519.PublicKey)

	secretKey, err := encryption.DeriveMasterSecretKey(c.authSk.Seed())
	if err != nil {
		return err
	}
	c.secretKey = [32]byte(secretKey)

	c.initStorageClient()
	c.initVerifierClient()
	c.initOrdersClient()

	if connectToken != "" {
		_, err = c.storageClient.ConnectWallet(
			ctx,
			connect.NewRequest(
				&sw.ConnectWalletRequest{
					WalletAddress: walletAddress,
					SeedMessage:   seedMessage,
					ConnectToken:  connectToken,
				},
			),
		)
		if err != nil {
			return err
		}
	}

	return nil
}

func (c *walletClient) GetInfo(ctx context.Context) (*Info, error) {
	resp, err := c.storageClient.GetInfo(ctx, connect.NewRequest(&sw.GetInfoRequest{}))

	if err != nil {
		return nil, err
	}

	return &Info{
		WalletAddress: resp.Msg.WalletAddress,
		PublicKey:     resp.Msg.PublicKey,
		SeedMessage:   resp.Msg.SeedMessage,
	}, nil
}

func (c *walletClient) generateSeed(message string) []byte {
	return c.sign([]byte(message))[:32]
}

func (c *walletClient) initStorageClient() {
	token := c.generateToken(config.AudStorage)
	c.storageClient = grpc.NewWalletStorageClient(c.cfg.StorageBaseUrl, token)
}

func (c *walletClient) initVerifierClient() {
	token := c.generateToken(config.AudVerifier)
	c.verifierClient = grpc.NewVerifierClient(c.cfg.VerifierBaseUrl, token)
}

func (c *walletClient) initOrdersClient() {
	token := c.generateToken(config.AudOrders)
	c.ordersClient = grpc.NewWalletOrdersClient(c.cfg.OrderBaseUrl, token)
}

func (c *walletClient) generateToken(audience string) string {
	token := jwt.NewWithClaims(
		jwt.SigningMethodEdDSA,
		jwt.MapClaims{"iss": base58.Encode(c.authPk), "aud": audience},
	)

	t, _ := token.SignedString(c.authSk)
	return t
}
