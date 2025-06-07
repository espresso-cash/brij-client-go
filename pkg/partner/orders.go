package partner

import (
	"context"
	"crypto/ed25519"
	"fmt"
	"time"

	"connectrpc.com/connect"
	"github.com/btcsuite/btcutil/base58"
	orderscommon "go.brij.fi/protos/brij/orders/v1/common"
	"go.brij.fi/protos/brij/orders/v1/partner"
	"google.golang.org/protobuf/proto"

	"go.brij.fi/client/pkg/common"
)

type Order struct {
	OrderID           string
	ExternalID        string
	Status            string
	UserPublicKey     ed25519.PublicKey
	UserWalletAddress ed25519.PublicKey
	Type              common.RampType
	FiatAmount        *common.Amount
	CryptoAmount      *common.Amount
	CreatedAt         time.Time
}

type GetOrderInput struct {
	OrderID    string
	ExternalID string
}

func (c *kycPartnerClient) GetOrders(ctx context.Context) ([]*Order, error) {
	request := &partner.GetOrdersRequest{}
	resp, err := c.ordersClient.GetOrders(ctx, connect.NewRequest(request))
	if err != nil {
		return nil, err
	}

	orders := make([]*Order, 0, len(resp.Msg.Orders))
	for _, o := range resp.Msg.Orders {
		order, err := orderFromPayload(o)
		if err != nil {
			return orders, err
		}
		orders = append(orders, order)
	}

	return orders, nil
}

func (c *kycPartnerClient) GetOrder(ctx context.Context, in *GetOrderInput) (*Order, error) {
	request := &partner.GetOrderRequest{
		OrderId:    in.OrderID,
		ExternalId: in.ExternalID,
	}

	resp, err := c.ordersClient.GetOrder(ctx, connect.NewRequest(request))
	if err != nil {
		return nil, err
	}

	order, err := orderFromPayload(resp.Msg)
	if err != nil {
		return nil, err
	}

	return order, nil
}

type RejectOrderInput struct {
	OrderID string
	Reason  string
}

func (c *kycPartnerClient) RejectOrder(ctx context.Context, in *RejectOrderInput) error {
	request := &partner.RejectOrderRequest{
		OrderId: in.OrderID,
		Reason:  in.Reason,
	}

	_, err := c.ordersClient.RejectOrder(ctx, connect.NewRequest(request))
	return err
}

type AcceptOnRampOrderInput struct {
	OrderID     string
	ExternalID  string
	BankName    string
	BankAccount string
}

func (c *kycPartnerClient) AcceptOnRampOrder(ctx context.Context, in *AcceptOnRampOrderInput) error {
	envelope := &orderscommon.OnRampOrderPartnerEnvelope{
		OrderId:     in.OrderID,
		BankName:    in.BankName,
		BankAccount: in.BankAccount,
	}
	payload, err := proto.Marshal(envelope)
	if err != nil {
		return err
	}

	request := &partner.AcceptOrderRequest{
		ExternalId: in.ExternalID,
		Payload:    payload,
		Signature:  c.sign(payload),
	}

	_, err = c.ordersClient.AcceptOrder(ctx, connect.NewRequest(request))
	return err
}

type AcceptOffRampOrderInput struct {
	OrderID             string
	CryptoWalletAddress ed25519.PublicKey
	ExternalID          string
}

func (c *kycPartnerClient) AcceptOffRampOrder(ctx context.Context, in *AcceptOffRampOrderInput) error {
	envelope := &orderscommon.OffRampOrderPartnerEnvelope{
		OrderId:             in.OrderID,
		CryptoWalletAddress: base58.Encode(in.CryptoWalletAddress),
	}
	payload, err := proto.Marshal(envelope)
	if err != nil {
		return err
	}

	request := &partner.AcceptOrderRequest{
		Payload:    payload,
		Signature:  c.sign(payload),
		ExternalId: in.ExternalID,
	}

	if in.CryptoWalletAddress != nil {
		request.ExternalId = base58.Encode(in.CryptoWalletAddress)
	}

	_, err = c.ordersClient.AcceptOrder(ctx, connect.NewRequest(request))
	return err
}

type FailOrderInput struct {
	OrderID    string
	ExternalID string
	Reason     string
}

func (c *kycPartnerClient) FailOrder(ctx context.Context, in *FailOrderInput) error {
	request := &partner.FailOrderRequest{
		OrderId:    in.OrderID,
		ExternalId: in.ExternalID,
		Reason:     in.Reason,
	}

	_, err := c.ordersClient.FailOrder(ctx, connect.NewRequest(request))
	return err
}

type CompleteOnRampOrderInput struct {
	OrderID       string
	ExternalID    string
	TransactionID string
}

func (c *kycPartnerClient) CompleteOnRampOrder(ctx context.Context, in *CompleteOnRampOrderInput) error {
	request := &partner.CompleteOrderRequest{
		OrderId:    in.OrderID,
		ExternalId: in.ExternalID,
	}

	_, err := c.ordersClient.CompleteOrder(ctx, connect.NewRequest(request))
	return err
}

type CompleteOffRampOrderInput struct {
	OrderID    string
	ExternalID string
}

func (c *kycPartnerClient) CompleteOffRampOrder(ctx context.Context, in *CompleteOffRampOrderInput) error {
	request := &partner.CompleteOrderRequest{
		OrderId:    in.OrderID,
		ExternalId: in.ExternalID,
	}

	_, err := c.ordersClient.CompleteOrder(ctx, connect.NewRequest(request))
	return err
}

func orderFromPayload(payload *partner.GetOrderResponse) (*Order, error) {
	created, err := time.Parse(time.RFC3339, payload.Created)
	if err != nil {
		return nil, err
	}
	order := &Order{
		Status:        payload.Status,
		ExternalID:    payload.ExternalId,
		UserPublicKey: base58.Decode(payload.UserPublicKey),
		CreatedAt:     created,
	}

	rampType := payload.Type
	data := payload.UserPayload
	if rampType == orderscommon.RampType_RAMP_TYPE_ON_RAMP {
		order.Type = common.RampTypeOnRamp

		// TODO: Validate signature

		var payload orderscommon.OnRampOrderUserEnvelope
		if err := proto.Unmarshal(data, &payload); err != nil {
			return nil, err
		}

		order.OrderID = payload.OrderId
		order.UserWalletAddress = base58.Decode(payload.UserWalletAddress)
		order.FiatAmount = &common.Amount{
			Value:    payload.FiatAmount,
			Currency: payload.FiatCurrency,
		}
		order.CryptoAmount = &common.Amount{
			Value:    payload.CryptoAmount,
			Currency: payload.CryptoCurrency,
		}
	} else if rampType == orderscommon.RampType_RAMP_TYPE_OFF_RAMP {
		order.Type = common.RampTypeOffRamp

		// TODO: Validate signature

		var payload orderscommon.OffRampOrderUserEnvelope
		if err := proto.Unmarshal(data, &payload); err != nil {
			return nil, err
		}

		order.OrderID = payload.OrderId
		order.UserWalletAddress = base58.Decode(payload.UserWalletAddress)
		order.FiatAmount = &common.Amount{
			Value:    payload.FiatAmount,
			Currency: payload.FiatCurrency,
		}
		order.CryptoAmount = &common.Amount{
			Value:    payload.CryptoAmount,
			Currency: payload.CryptoCurrency,
		}
	} else {
		return nil, fmt.Errorf("unknown ramp type: %v", rampType)
	}

	return order, nil
}
