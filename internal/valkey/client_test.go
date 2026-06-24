package valkey

import "testing"

func TestTLSConfig_Disabled(t *testing.T) {
	tc, err := (&Config{TLS: false}).tlsConfig()
	if err != nil || tc != nil {
		t.Errorf("disabled TLS should be (nil,nil), got (%v,%v)", tc, err)
	}
}

func TestTLSConfig_BadCA(t *testing.T) {
	if _, err := (&Config{TLS: true, CACert: "not a pem"}).tlsConfig(); err == nil {
		t.Error("expected error for malformed ca_cert")
	}
}

func TestTLSConfig_EnabledInsecure(t *testing.T) {
	tc, err := (&Config{TLS: true, InsecureTLS: true}).tlsConfig()
	if err != nil {
		t.Fatal(err)
	}
	if tc == nil || !tc.InsecureSkipVerify {
		t.Errorf("expected InsecureSkipVerify=true tls.Config, got %v", tc)
	}
}

func TestTLSConfig_BadKeyPair(t *testing.T) {
	if _, err := (&Config{TLS: true, TLSCert: "x", TLSKey: "y"}).tlsConfig(); err == nil {
		t.Error("expected error for invalid cert/key pair")
	}
}
