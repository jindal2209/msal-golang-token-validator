package token_validator

import "errors"

type Config struct {
	ApplicationId string
	TenantId      string
}

type Client struct {
	config *Config
}

func NewClient(config *Config) (*Client, error) {
	if config.ApplicationId == "" {
		return nil, errors.New("application-id cannot be empty")
	}
	if config.TenantId == "" {
		return nil, errors.New("tenant-id cannot be empty")
	}

	return &Client{
		config: config,
	}, nil
}
