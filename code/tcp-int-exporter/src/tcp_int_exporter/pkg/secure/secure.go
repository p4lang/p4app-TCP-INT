package secure

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"path/filepath"

	"google.golang.org/grpc/credentials"
)

func LoadTLSCredentialsForClient(certPath string) (credentials.TransportCredentials, error) {
	// Load certificate of the CA who signed server's certificate
	pemServerCA, err := ioutil.ReadFile(certPath)
	if err != nil {
		return nil, err
	}

	certPool := x509.NewCertPool()
	if !certPool.AppendCertsFromPEM(pemServerCA) {
		return nil, fmt.Errorf("failed to add server CA's certificate")
	}

	// Create the credentials and return it
	config := &tls.Config{
		RootCAs: certPool,
	}

	return credentials.NewTLS(config), nil
}

func IsValidCert(cert string) bool {
	resolvedPath, _ := filepath.EvalSymlinks(cert)
	if filepath.Ext(resolvedPath) != ".pem" {
		return false
	} else {
		return true
	}
}
