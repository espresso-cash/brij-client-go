package partner

import (
	"context"
	"crypto/ed25519"

	"connectrpc.com/connect"
	"github.com/btcsuite/btcutil/base58"
	storagecommon "go.brij.fi/protos/brij/storage/v1/common"
	"go.brij.fi/protos/brij/storage/v1/partner"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	"go.brij.fi/client/internal/encryption"
)

type ValidatedData struct {
	UserData []byte
	Status   storagecommon.ValidationStatus
	Hash     string
	Type     storagecommon.DataType
}

type GetKycStatusInput struct {
	Country string
	UserPK  ed25519.PublicKey
}

type UpdateKycStatusInput struct {
	KycID string
	Data  *storagecommon.KycEnvelope
}

func (c *kycPartnerClient) GetData(ctx context.Context, userPK ed25519.PublicKey) (map[string]*ValidatedData, error) {
	result := map[string]*ValidatedData{}
	validationMap := map[string]*storagecommon.ValidationDataEnvelope{}

	rawData, err := c.storageClient.GetUserData(
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
		var envelope storagecommon.ValidationDataEnvelope
		if err := proto.Unmarshal(v.Payload, &envelope); err != nil {
			return result, err
		}

		// TODO: Validate the signature of the envelope

		validationMap[envelope.DataHash] = &envelope
	}

	for _, v := range rawData.Msg.UserData {
		var envelope storagecommon.UserDataEnvelope
		if err := proto.Unmarshal(v.Payload, &envelope); err != nil {
			return result, err
		}

		// TODO: Validate the signature of the envelope

		decrypted, err := encryption.DecryptUserData(sk, envelope.EncryptedValue)
		if err != nil {
			return result, err
		}

		status := storagecommon.ValidationStatus_VALIDATION_STATUS_UNSPECIFIED
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

func (c *kycPartnerClient) SetValidationResult(
	ctx context.Context,
	hash string,
	status storagecommon.ValidationStatus,
) error {
	envelope := &storagecommon.ValidationDataEnvelope{
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
	_, err = c.storageClient.SetValidationData(ctx, connect.NewRequest(in))

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

func (c *kycPartnerClient) CreateKycStatus(ctx context.Context, input *storagecommon.KycEnvelope) (string, error) {
	data, err := proto.Marshal(input)
	if err != nil {
		return "", err
	}

	signature := encryption.SignMessage(c.privateKey, data)

	in := &partner.CreateKycStatusRequest{
		Payload:   data,
		Signature: signature,
	}

	resp, err := c.storageClient.CreateKycStatus(ctx, connect.NewRequest(in))
	if err != nil {
		return "", err
	}

	return resp.Msg.KycId, nil
}

func (c *kycPartnerClient) GetKycStatus(ctx context.Context, input *GetKycStatusInput) (
	*storagecommon.KycEnvelope,
	error,
) {
	in := &partner.GetKycStatusRequest{
		Country:            input.Country,
		ValidatorPublicKey: base58.Encode(c.publicKey),
		UserPublicKey:      base58.Encode(input.UserPK),
	}

	resp, err := c.storageClient.GetKycStatus(ctx, connect.NewRequest(in))
	if err != nil {
		return nil, err
	}

	var envelope storagecommon.KycEnvelope
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

	in := &partner.UpdateKycStatusRequest{
		KycId:     input.KycID,
		Payload:   data,
		Signature: c.sign(data),
	}

	_, err = c.storageClient.UpdateKycStatus(ctx, connect.NewRequest(in))
	if err != nil {
		return err
	}

	return nil
}
