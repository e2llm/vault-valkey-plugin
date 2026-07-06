package valkey

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

// dialTimeout bounds every per-node / per-sentinel connection attempt so a dead
// node cannot stall a credential operation indefinitely.
const dialTimeout = 5 * time.Second

func (c *Config) tlsConfig() (*tls.Config, error) {
	if !c.TLS {
		return nil, nil
	}
	t := &tls.Config{
		MinVersion:         tls.VersionTLS12,
		InsecureSkipVerify: c.InsecureTLS,
	}
	if c.CACert != "" {
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM([]byte(c.CACert)) {
			return nil, fmt.Errorf("failed to parse ca_cert PEM")
		}
		t.RootCAs = pool
	}
	if c.TLSCert != "" && c.TLSKey != "" {
		cert, err := tls.X509KeyPair([]byte(c.TLSCert), []byte(c.TLSKey))
		if err != nil {
			return nil, fmt.Errorf("failed to load client certificate: %w", err)
		}
		t.Certificates = []tls.Certificate{cert}
	}
	return t, nil
}

// nodeClient connects to a single Valkey data node as the node admin identity.
func (c *Config) nodeClient(addr string) (*redis.Client, error) {
	tc, err := c.tlsConfig()
	if err != nil {
		return nil, err
	}
	return redis.NewClient(&redis.Options{
		Addr:         addr,
		Username:     c.Username,
		Password:     c.Password,
		TLSConfig:    tc,
		DialTimeout:  dialTimeout,
		ReadTimeout:  dialTimeout,
		WriteTimeout: dialTimeout,
		MaxRetries:   2,
	}), nil
}

// sentinelClient connects to a single Sentinel as the (separate) discovery identity.
func (c *Config) sentinelClient(addr string) (*redis.SentinelClient, error) {
	tc, err := c.tlsConfig()
	if err != nil {
		return nil, err
	}
	return redis.NewSentinelClient(&redis.Options{
		Addr:        addr,
		Username:    c.SentinelUsername,
		Password:    c.SentinelPassword,
		TLSConfig:   tc,
		DialTimeout: dialTimeout,
	}), nil
}

// sentinelAdminClient connects to a single Sentinel as a regular client (not a
// SentinelClient) using the Sentinel identity, so the plugin can run ACL SETUSER/
// DELUSER on the Sentinel in shared-identity mode. The Sentinel identity must have
// ACL-admin rights on the Sentinels for these to succeed.
func (c *Config) sentinelAdminClient(addr string) (*redis.Client, error) {
	tc, err := c.tlsConfig()
	if err != nil {
		return nil, err
	}
	return redis.NewClient(&redis.Options{
		Addr:         addr,
		Username:     c.SentinelUsername,
		Password:     c.SentinelPassword,
		TLSConfig:    tc,
		DialTimeout:  dialTimeout,
		ReadTimeout:  dialTimeout,
		WriteTimeout: dialTimeout,
		MaxRetries:   2,
	}), nil
}
