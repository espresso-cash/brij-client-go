package client

import (
	"context"
	"net/http"

	"connectrpc.com/connect"
	"go.brij.fi/protos/brij/storage/v1/partner/partnerconnect"
)

type Client struct {
	partnerconnect.PartnerServiceClient
}

func New(host string, token string) (*Client, error) {
	client := &Client{
		PartnerServiceClient: partnerconnect.NewPartnerServiceClient(
			http.DefaultClient,
			host,
			connect.WithInterceptors(newAuthInterceptor(token)),
		),
	}

	return client, nil
}

func newAuthInterceptor(token string) connect.UnaryInterceptorFunc {
	interceptor := func(next connect.UnaryFunc) connect.UnaryFunc {
		return func(
			ctx context.Context,
			req connect.AnyRequest,
		) (connect.AnyResponse, error) {
			req.Header().Set("Authorization", "Bearer "+token)

			return next(ctx, req)
		}
	}
	return interceptor
}
