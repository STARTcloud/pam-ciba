// Package config loads and provides the YAML configuration.
package config

// ProviderConfig names the OpenID Provider and the client this host signs in as.
type ProviderConfig struct {
	// Issuer is the provider's issuer identifier; its metadata is read from
	// <issuer>/.well-known/openid-configuration.
	Issuer string `yaml:"issuer" json:"issuer"`
	// ClientID is the public client registered at the provider with the CIBA
	// grant type and poll delivery.
	ClientID string `yaml:"client_id" json:"client_id"`
	// Scope is the space-separated scope of the request; it contains openid.
	Scope string `yaml:"scope" json:"scope"`
	// RequestTimeoutSeconds bounds each HTTP request to the provider.
	RequestTimeoutSeconds int `yaml:"request_timeout_seconds" json:"request_timeout_seconds"`
}

// ApprovalConfig shapes the request the end-user approves.
type ApprovalConfig struct {
	// BindingMessage is shown to the end-user beside the approval; {user},
	// {host}, {rhost} and {service} are replaced with the local account, this
	// host's name, the remote host and the PAM service.
	BindingMessage string `yaml:"binding_message" json:"binding_message"`
	// RequestedExpirySeconds asks the provider for a request lifetime; 0 takes
	// the provider's default.
	RequestedExpirySeconds int `yaml:"requested_expiry_seconds" json:"requested_expiry_seconds"`
}

// LoggingConfig controls slog output.
type LoggingConfig struct {
	Level      string `yaml:"level"       json:"level"`
	Console    bool   `yaml:"console"     json:"console"`
	File       string `yaml:"file"        json:"file"`
	MaxSizeMB  int    `yaml:"max_size_mb" json:"max_size_mb"`
	MaxBackups int    `yaml:"max_backups" json:"max_backups"`
	// Compression gzips rotated log files.
	Compression bool `yaml:"compression" json:"compression"`
	// Categories overrides the level per log category. Categories emitted:
	// app (the default), auth.
	Categories map[string]string `yaml:"categories" json:"categories"`
}
