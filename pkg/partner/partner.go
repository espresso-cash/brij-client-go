package partner

import (
	"context"
	"crypto/ed25519"

	"connectrpc.com/connect"
	"github.com/btcsuite/btcutil/base58"
	"github.com/golang-jwt/jwt/v5"
	"go.brij.fi/protos/brij/storage/v1/common"
	"go.brij.fi/protos/brij/storage/v1/partner"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	"go.brij.fi/client/internal/client"
	"go.brij.fi/client/internal/encryption"
)

type Client interface {
	GetData(ctx context.Context, userPK ed25519.PublicKey) (map[string]*ValidatedData, error)
	SetValidationResult(ctx context.Context, hash string, status common.ValidationStatus) error
	Encrypt(ctx context.Context, user ed25519.PublicKey, data []byte) (encrypted []byte, hash string, err error)
	CreateKycStatus(ctx context.Context, input *common.KycEnvelope) (string, error)
	GetKycStatus(ctx context.Context, input *GetKycStatusInput) (*common.KycEnvelope, error)
	UpdateKycStatus(ctx context.Context, input *UpdateKycStatusInput) error
	Close() error
	PublicKey() ed25519.PublicKey
}

type kycPartnerClient struct {
	privateKey ed25519.PrivateKey
	publicKey  ed25519.PublicKey
	token      string
	apiClient  *client.Client
}

type ValidatedData struct {
	UserData []byte
	Status   common.ValidationStatus
	Hash     string
	Type     common.DataType
}

type GetKycStatusInput struct {
	Country string
	UserPK  ed25519.PublicKey
}

type UpdateKycStatusInput struct {
	KycID string
	Data  *common.KycEnvelope
}

func New(privateKey ed25519.PrivateKey, host string) (Client, error) {
	c := &kycPartnerClient{
		privateKey: privateKey,
		publicKey:  privateKey.Public().(ed25519.PublicKey),
	}

	token := jwt.NewWithClaims(
		jwt.SigningMethodEdDSA,
		jwt.MapClaims{"iss": base58.Encode(c.publicKey), "aud": "storage.brij.fi"},
	)
	tokenString, err := token.SignedString(c.privateKey)
	if err != nil {
		return nil, err
	}

	c.token = tokenString
	c.apiClient, err = client.New(host, tokenString)
	if err != nil {
		return nil, err
	}

	return c, nil
}

func (c *kycPartnerClient) Close() error {
	return c.apiClient.Close()
}

func (c *kycPartnerClient) PublicKey() ed25519.PublicKey {
	return c.publicKey
}

func (c *kycPartnerClient) GetData(ctx context.Context, userPK ed25519.PublicKey) (map[string]*ValidatedData, error) {
	result := map[string]*ValidatedData{}
	validationMap := map[string]*common.ValidationDataEnvelope{}

	rawData, err := c.apiClient.GetUserData(
		ctx, connect.NewRequest(
			&partner.GetUserDataRequest{
				UserPublicKey: base58.Encode(userPK),
				IncludeValues: true,
			},
		),
	)
	if err != nil {
		return result, err
	}

	sk, err := c.secretKey(ctx, userPK)
	if err != nil {
		return result, err
	}

	for _, v := range rawData.Msg.ValidationData {
		var envelope common.ValidationDataEnvelope
		if err := proto.Unmarshal(v.Payload, &envelope); err != nil {
			return result, err
		}

		// TODO: Validate the signature of the envelope

		validationMap[envelope.DataHash] = &envelope
	}

	for _, v := range rawData.Msg.UserData {
		var envelope common.UserDataEnvelope
		if err := proto.Unmarshal(v.Payload, &envelope); err != nil {
			return result, err
		}

		// TODO: Validate the signature of the envelope

		decrypted, err := encryption.DecryptUserData(sk, envelope.EncryptedValue)
		if err != nil {
			return result, err
		}

		status := common.ValidationStatus_VALIDATION_STATUS_UNSPECIFIED
		if validationData, exists := validationMap[v.Hash]; exists {
			status = validationData.Status
		}

		result[v.Hash] = &ValidatedData{
			UserData: decrypted,
			Status:   status,
			Hash:     v.Hash,
			Type:     envelope.Type,
		}
	}

	return result, nil
}

func (c *kycPartnerClient) SetValidationResult(ctx context.Context, hash string, status common.ValidationStatus) error {
	envelope := &common.ValidationDataEnvelope{
		DataHash:           hash,
		ValidatorPublicKey: base58.Encode(c.publicKey),
		Status:             status,
		ValidatedAt:        timestamppb.Now(),
	}
	payload, err := proto.Marshal(envelope)
	if err != nil {
		return err
	}
	signature := encryption.SignMessage(c.privateKey, payload)

	in := &partner.SetValidationDataRequest{
		Payload:   payload,
		Signature: signature,
	}
	_, err = c.apiClient.SetValidationData(ctx, connect.NewRequest(in))

	return err
}

func (c *kycPartnerClient) Encrypt(
	ctx context.Context,
	user ed25519.PublicKey,
	data []byte,
) (encrypted []byte, hash string, err error) {
	sk, err := c.secretKey(ctx, user)
	if err != nil {
		return nil, "", err
	}

	encrypted, hash, err = encryption.Encrypt(sk, data)
	if err != nil {
		return nil, "", err
	}
	return encrypted, hash, nil
}

func (c *kycPartnerClient) CreateKycStatus(ctx context.Context, input *common.KycEnvelope) (string, error) {
	data, err := proto.Marshal(input)
	if err != nil {
		return "", err
	}

	signature := encryption.SignMessage(c.privateKey, data)

	in := &partner.CreateKycStatusRequest{
		Payload:   data,
		Signature: signature,
	}

	resp, err := c.apiClient.CreateKycStatus(ctx, connect.NewRequest(in))
	if err != nil {
		return "", err
	}

	return resp.Msg.KycId, nil
}

func (c *kycPartnerClient) GetKycStatus(ctx context.Context, input *GetKycStatusInput) (
	*common.KycEnvelope,
	error,
) {
	in := &partner.GetKycStatusRequest{
		Country:            input.Country,
		ValidatorPublicKey: base58.Encode(c.publicKey),
		UserPublicKey:      base58.Encode(input.UserPK),
	}

	resp, err := c.apiClient.GetKycStatus(ctx, connect.NewRequest(in))
	if err != nil {
		return nil, err
	}

	var envelope common.KycEnvelope
	if err := proto.Unmarshal(resp.Msg.Payload, &envelope); err != nil {
		return nil, err
	}

	// TODO: Validate the signature of the envelope

	return &envelope, nil
}

func (c *kycPartnerClient) UpdateKycStatus(ctx context.Context, input *UpdateKycStatusInput) error {
	data, err := proto.Marshal(input.Data)
	if err != nil {
		return err
	}

	signature := encryption.SignMessage(c.privateKey, data)

	in := &partner.UpdateKycStatusRequest{
		KycId:     input.KycID,
		Payload:   data,
		Signature: signature,
	}

	_, err = c.apiClient.UpdateKycStatus(ctx, connect.NewRequest(in))
	if err != nil {
		return err
	}

	return nil
}

func (c *kycPartnerClient) secretKey(ctx context.Context, user ed25519.PublicKey) ([32]byte, error) {
	rawData, err := c.apiClient.GetInfo(
		ctx,
		connect.NewRequest(&partner.GetInfoRequest{PublicKey: base58.Encode(user)}),
	)
	if err != nil {
		return [32]byte{}, err
	}

	return encryption.DecodeSecretKey(rawData.Msg.EncryptedSecretKey, user, c.privateKey)
}
