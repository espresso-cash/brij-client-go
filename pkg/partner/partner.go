package partner

import (
	"context"
	"crypto/ed25519"
	"fmt"
	"github.com/btcsuite/btcutil/base58"
	"github.com/golang-jwt/jwt/v5"
	"github.com/golang/protobuf/proto"
	"go.brij.fi/client/internal/client"
	"go.brij.fi/client/internal/encryption"
	"go.brij.fi/protos/brij/storage/v1/common"
	"go.brij.fi/protos/brij/storage/v1/verifier"
)

type Client interface {
	GetData(ctx context.Context, userPK ed25519.PublicKey) (map[string]*ValidatedData, error)
	SetValidationResult(ctx context.Context, dataId string, user ed25519.PublicKey, hash string, status common.ValidationStatus) error
	Encrypt(ctx context.Context, user ed25519.PublicKey, data []byte) (encrypted []byte, hash string, err error)
	CreateKycStatus(ctx context.Context, input *common.KycItem) (string, error)
	GetKycStatus(ctx context.Context, input *GetKycStatusInput) (*verifier.GetKycStatusResponse, error)
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
	Data  *common.KycItem
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
	validationMap := map[string]*common.ValidationDataField{}

	rawData, err := c.apiClient.GetUserData(ctx, &verifier.GetUserDataRequest{
		UserPublicKey: base58.Encode(userPK),
		IncludeValues: true,
	})
	if err != nil {
		return result, err
	}

	sk, err := c.secretKey(ctx, userPK)
	if err != nil {
		return result, err
	}

	for _, v := range rawData.ValidationData {
		validationMap[v.DataId] = v
	}

	for _, v := range rawData.UserData {
		decrypted, err := encryption.DecryptUserData(sk, v.EncryptedValue)
		if err != nil {
			return result, err
		}

		status := common.ValidationStatus_VALIDATION_STATUS_UNSPECIFIED
		if validationData, exists := validationMap[v.Id]; exists {
			status = validationData.Status
		}

		result[v.Id] = &ValidatedData{
			UserData: decrypted,
			Status:   status,
			Hash:     v.Hash,
			Type:     v.Type,
		}
	}

	return result, nil
}

func (c *kycPartnerClient) SetValidationResult(
	ctx context.Context,
	dataId string,
	user ed25519.PublicKey,
	hash string,
	status common.ValidationStatus,
) error {
	signature := encryption.SignMessage(c.privateKey, []byte(fmt.Sprintf("%s|%s|%s|%s", dataId, base58.Encode(user), hash, status)))

	in := &verifier.SetValidationDataRequest{
		DataId:    dataId,
		Status:    status,
		Hash:      hash,
		Signature: base58.Encode(signature),
	}
	_, err := c.apiClient.SetValidationData(ctx, in)

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

func (c *kycPartnerClient) CreateKycStatus(ctx context.Context, input *common.KycItem) (string, error) {
	data, err := proto.Marshal(input)
	if err != nil {
		return "", err
	}

	signature := encryption.SignMessage(c.privateKey, data)

	in := &verifier.CreateKycStatusRequest{
		Data:      data,
		Signature: signature,
	}

	resp, err := c.apiClient.CreateKycStatus(ctx, in)
	if err != nil {
		return "", err
	}

	return resp.KycId, nil
}

func (c *kycPartnerClient) GetKycStatus(ctx context.Context, input *GetKycStatusInput) (*verifier.GetKycStatusResponse, error) {
	in := &verifier.GetKycStatusRequest{
		Country:            input.Country,
		ValidatorPublicKey: base58.Encode(c.publicKey),
		UserPublicKey:      base58.Encode(input.UserPK),
	}

	resp, err := c.apiClient.GetKycStatus(ctx, in)
	if err != nil {
		return nil, err
	}

	return resp, nil
}

func (c *kycPartnerClient) UpdateKycStatus(ctx context.Context, input *UpdateKycStatusInput) error {
	data, err := proto.Marshal(input.Data)
	if err != nil {
		return err
	}

	signature := encryption.SignMessage(c.privateKey, data)

	in := &verifier.UpdateKycStatusRequest{
		KycId:     input.KycID,
		Data:      data,
		Signature: signature,
	}

	_, err = c.apiClient.UpdateKycStatus(ctx, in)
	if err != nil {
		return err
	}

	return nil
}

func (c *kycPartnerClient) secretKey(ctx context.Context, user ed25519.PublicKey) ([32]byte, error) {
	rawData, err := c.apiClient.GetInfo(ctx, &verifier.GetInfoRequest{PublicKey: base58.Encode(user)})
	if err != nil {
		return [32]byte{}, err
	}

	return encryption.DecodeSecretKey(rawData.EncryptedSecretKey, user, c.privateKey)
}
