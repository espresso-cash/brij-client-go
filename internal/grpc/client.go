package grpc

import (
	"context"
	"net/http"

	"connectrpc.com/connect"
	owc "go.brij.fi/protos/brij/orders/v1/wallet/walletconnect"
	spc "go.brij.fi/protos/brij/storage/v1/partner/partnerconnect"
	swc "go.brij.fi/protos/brij/storage/v1/wallet/walletconnect"
	"go.brij.fi/protos/brij/verifier/v1/v1connect"
)

type Client struct {
	spc.PartnerServiceClient
}

func NewClient(host string, token string) (*Client, error) {
	client := &Client{
		PartnerServiceClient: spc.NewPartnerServiceClient(
			http.DefaultClient,
			host,
			connect.WithInterceptors(newAuthInterceptor(token)),
		),
	}

	return client, nil
}

func NewWalletStorageClient(host string, token string) swc.WalletServiceClient {
	return swc.NewWalletServiceClient(
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

func NewWalletOrdersClient(host string, token string) owc.WalletServiceClient {
	return owc.NewWalletServiceClient(
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
