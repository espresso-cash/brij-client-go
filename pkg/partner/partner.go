package partner

import (
	"context"
	"crypto/ed25519"

	"connectrpc.com/connect"
	"github.com/btcsuite/btcutil/base58"
	"github.com/golang-jwt/jwt/v5"
	opc "go.brij.fi/protos/brij/orders/v1/partner/partnerconnect"
	storagecommon "go.brij.fi/protos/brij/storage/v1/common"
	"go.brij.fi/protos/brij/storage/v1/partner"
	spc "go.brij.fi/protos/brij/storage/v1/partner/partnerconnect"

	"go.brij.fi/client/internal/encryption"
	"go.brij.fi/client/internal/grpc"
	"go.brij.fi/client/pkg/config"
)

type Client interface {
	PublicKey() ed25519.PublicKey

	GetData(ctx context.Context, userPK ed25519.PublicKey) (map[string]*ValidatedData, error)
	SetValidationResult(ctx context.Context, hash string, status storagecommon.ValidationStatus) error
	Encrypt(ctx context.Context, user ed25519.PublicKey, data []byte) (encrypted []byte, hash string, err error)
	CreateKycStatus(ctx context.Context, input *storagecommon.KycEnvelope) (string, error)
	GetKycStatus(ctx context.Context, input *GetKycStatusInput) (*storagecommon.KycEnvelope, error)
	UpdateKycStatus(ctx context.Context, input *UpdateKycStatusInput) error

	GetOrders(ctx context.Context) ([]*Order, error)
	GetOrder(ctx context.Context, input *GetOrderInput) (*Order, error)
	RejectOrder(ctx context.Context, in *RejectOrderInput) error
	AcceptOnRampOrder(ctx context.Context, in *AcceptOnRampOrderInput) error
	AcceptOffRampOrder(ctx context.Context, in *AcceptOffRampOrderInput) error
	FailOrder(ctx context.Context, in *FailOrderInput) error
	CompleteOnRampOrder(ctx context.Context, in *CompleteOnRampOrderInput) error
	CompleteOffRampOrder(ctx context.Context, in *CompleteOffRampOrderInput) error
	GenerateTransaction(ctx context.Context, in *GenerateTransactionInput) (*GenerateTransactionResponse, error)
}

type kycPartnerClient struct {
	privateKey ed25519.PrivateKey
	publicKey  ed25519.PublicKey

	storageClient spc.PartnerServiceClient
	ordersClient  opc.PartnerServiceClient
}

func NewClient(privateKey ed25519.PrivateKey, cfg *config.Config) (Client, error) {
	c := &kycPartnerClient{
		privateKey: privateKey,
		publicKey:  privateKey.Public().(ed25519.PublicKey),
	}

	storageToken, err := c.createToken(config.AudStorage)
	if err != nil {
		return nil, err
	}
	c.storageClient = grpc.NewPartnerStorageClient(cfg.StorageBaseUrl, storageToken)

	ordersToken, err := c.createToken(config.AudOrders)
	if err != nil {
		return nil, err
	}
	c.ordersClient = grpc.NewPartnerOrdersClient(cfg.OrderBaseUrl, ordersToken)

	return c, nil
}

func (c *kycPartnerClient) PublicKey() ed25519.PublicKey {
	return c.publicKey
}

func (c *kycPartnerClient) createToken(aud string) (string, error) {
	token := jwt.NewWithClaims(
		jwt.SigningMethodEdDSA,
		jwt.MapClaims{"iss": base58.Encode(c.publicKey), "aud": aud},
	)
	return token.SignedString(c.privateKey)
}

func (c *kycPartnerClient) sign(data []byte) []byte {
	return encryption.SignMessage(c.privateKey, data)
}

func (c *kycPartnerClient) secretKey(ctx context.Context, user ed25519.PublicKey) ([32]byte, error) {
	rawData, err := c.storageClient.GetInfo(
		ctx,
		connect.NewRequest(&partner.GetInfoRequest{PublicKey: base58.Encode(user)}),
	)
	if err != nil {
		return [32]byte{}, err
	}

	return encryption.DecodeSecretKey(rawData.Msg.EncryptedSecretKey, user, c.privateKey)
}
