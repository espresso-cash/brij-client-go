package grpc

import (
	"context"
	"net/http"

	"connectrpc.com/connect"
	orderswallet "go.brij.fi/protos/brij/orders/v1/wallet/walletconnect"
	storagepartner "go.brij.fi/protos/brij/storage/v1/partner/partnerconnect"
	storagewallet "go.brij.fi/protos/brij/storage/v1/wallet/walletconnect"
	"go.brij.fi/protos/brij/verifier/v1/v1connect"
)

type Client struct {
	storagepartner.PartnerServiceClient
}

func NewClient(host string, token string) (*Client, error) {
	client := &Client{
		PartnerServiceClient: storagepartner.NewPartnerServiceClient(
			http.DefaultClient,
			host,
			connect.WithInterceptors(newAuthInterceptor(token)),
		),
	}

	return client, nil
}

func NewWalletStorageClient(host string, token string) storagewallet.WalletServiceClient {
	return storagewallet.NewWalletServiceClient(
		http.DefaultClient, host,
		connect.WithInterceptors(newAuthInterceptor(token)),
	)
}

func NewVerifierClient(host string, token string) v1connect.VerifierServiceClient {
	return v1connect.NewVerifierServiceClient(
		http.DefaultClient, host,
		connect.WithInterceptors(newAuthInterceptor(token)),
	)
}

func NewWalletOrdersClient(host string, token string) orderswallet.WalletServiceClient {
	return orderswallet.NewWalletServiceClient(
		http.DefaultClient, host,
		connect.WithInterceptors(newAuthInterceptor(token)),
	)
}

func newAuthInterceptor(token string) connect.UnaryInterceptorFunc {
	interceptor := func(next connect.UnaryFunc) connect.UnaryFunc {
		return func(
			ctx context.Context,
			req connect.AnyRequest,
		) (connect.AnyResponse, error) {
			if token != "" {
				req.Header().Set("Authorization", "Bearer "+token)
			}

			return next(ctx, req)
		}
	}
	return interceptor
}
