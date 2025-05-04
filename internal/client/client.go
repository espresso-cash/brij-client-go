package client

import (
	"context"
	"go.brij.fi/protos/brij/storage/v1/verifier"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

type Client struct {
	verifier.VerifierServiceClient
	conn *grpc.ClientConn
}

func New(host string, token string) (*Client, error) {
	var opts []grpc.DialOption
	opts = append(opts, grpc.WithTransportCredentials(credentials.NewTLS(nil)))
	opts = append(opts, grpc.WithPerRPCCredentials(NewBearerToken(token)))
	conn, err := grpc.NewClient(host, opts...)
	if err != nil {
		return nil, err
	}

	client := &Client{
		VerifierServiceClient: verifier.NewVerifierServiceClient(conn),
		conn:                  conn,
	}

	return client, nil
}

func (c *Client) Close() error {
	return c.conn.Close()
}

type bearerToken struct {
	token string
}

func (b *bearerToken) GetRequestMetadata(_ context.Context, _ ...string) (map[string]string, error) {
	return map[string]string{
		"authorization": "Bearer " + b.token,
	}, nil
}

func (b *bearerToken) RequireTransportSecurity() bool {
	return false
}

func NewBearerToken(token string) credentials.PerRPCCredentials {
	return &bearerToken{token: token}
}
