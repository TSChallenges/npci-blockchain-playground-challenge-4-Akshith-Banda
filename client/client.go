package main

import(
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log"
	"os"
	"path/filepath"

	"github.com/hyperledger/fabric-gateway/pkg/client"
	"github.com/hyperledger/fabric-gateway/pkg/identity"
	"google.golang.org/grpc/credentials"
)

const (
	mspID        = "Org1MSP"
	cryptoPath   = "../fabric-samples/test-network/organizations/peerOrganizations/org1.example.com"
	certPath     = cryptoPath + "/users/User1@org1.example.com/msp/signcerts/cert.pem"
	keyPath      = cryptoPath + "/users/User1@org1.example.com/msp/keystore/"
	tlsCertPath  = cryptoPath + "/peers/peer0.org1.example.com/tls/ca.crt"
	peerEndpoint = "localhost:7051"
	channelName  = "assetchannel"
	chaincodeName = "assetcc"
)

func main() {
	// Load identity
	id, err := newIdentity()
	if err != nil {
		log.Fatalf("Failed to create identity: %v", err)
	}

	// Load signing identity
	signer, err := newSigner()
	if err != nil {
		log.Fatalf("Failed to create signer: %v", err)
	}

	// Create a gateway connection
	gateway, err := client.Connect(
		id,
		client.WithSign(signer),
		client.WithEndpoint(peerEndpoint),
		client.WithTLSCredentials(loadTLSCredentials()),
	)
	if err != nil {
		log.Fatalf("Failed to connect to gateway: %v", err)
	}
	defer gateway.Close()

	// Get network and contract
	network := gateway.GetNetwork(channelName)
	contract := network.GetContract(chaincodeName)

	// Submit transaction
	result, err := contract.SubmitTransaction("CreateUser", "investor123", "1000")
	if err != nil {
		log.Fatalf("Failed to submit transaction: %v", err)
	}
	fmt.Printf("Transaction committed. Result: %s\n", string(result))

	// Evaluate transaction
	result, err = contract.EvaluateTransaction("GetPortfolio", "investor123")
	if err != nil {
		log.Fatalf("Failed to evaluate transaction: %v", err)
	}
	fmt.Printf("Transaction evaluated. Result: %s\n", string(result))

	// Listen for events
	listenForEvents(network)
}

func newIdentity() (*identity.X509Identity, error) {
	certBytes, err := os.ReadFile(certPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read certificate file: %w", err)
	}

	cert, _ := pem.Decode(certBytes)
	if cert == nil {
		return nil, fmt.Errorf("failed to decode PEM certificate")
	}

	x509Cert, err := x509.ParseCertificate(cert.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse X509 certificate: %w", err)
	}

	return identity.NewX509Identity(mspID, x509Cert)
}

func newSigner() (identity.Sign, error) {
	files, err := os.ReadDir(keyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read key directory: %w", err)
	}

	if len(files) == 0 {
		return nil, fmt.Errorf("no key files found")
	}

	keyBytes, err := os.ReadFile(filepath.Join(keyPath, files[0].Name()))
	if err != nil {
		return nil, fmt.Errorf("failed to read private key file: %w", err)
	}

	key, _ := pem.Decode(keyBytes)
	if key == nil {
		return nil, fmt.Errorf("failed to decode PEM private key")
	}

	privKey, err := identity.PrivateKeyFromPEM(key.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse private key: %w", err)
	}

	return identity.NewPrivateKeySigner(privKey)
}

func loadTLSCredentials() credentials.TransportCredentials {
	certBytes, err := os.ReadFile(tlsCertPath)
	if err != nil {
		log.Fatalf("Failed to read TLS certificate: %v", err)
	}

	certPool := x509.NewCertPool()
	if !certPool.AppendCertsFromPEM(certBytes) {
		log.Fatalf("Failed to add TLS certificate to pool")
	}

	return credentials.NewClientTLSFromCert(certPool, "")
}

func listenForEvents(network *client.Network) {
	eventService := network.ChaincodeEvents(chaincodeName)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() {
		for event := range eventService.Events(ctx) {
			log.Printf("Received event: %s, Transaction ID: %s\n", event.EventName, event.TransactionID)
		}
	}()

	// Keep the application running
	select {}
}
