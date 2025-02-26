package main

import (
	"context"
	"crypto/x509"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"

	"github.com/hyperledger/fabric-gateway/pkg/client"
	"github.com/hyperledger/fabric-gateway/pkg/identity"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

const (
	mspID         = "Org1MSP"
	cryptoPath    = "../fabric-samples/test-network/organizations/peerOrganizations/org1.example.com"
	certPath      = cryptoPath + "/users/User1@org1.example.com/msp/signcerts/cert.pem"
	keyPath       = cryptoPath + "/users/User1@org1.example.com/msp/keystore/"
	tlsCertPath   = cryptoPath + "/peers/peer0.org1.example.com/tls/ca.crt"
	peerEndpoint  = "localhost:7051"
	channelName   = "assetchannel"
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

	// Create gRPC connection
	conn := newGrpcConnection(peerEndpoint)
	defer conn.Close()

	// Create a gateway connection
	gateway, err := client.Connect(
		id,
		client.WithSign(signer),
		client.WithClientConnection(conn),
	)
	if err != nil {
		log.Fatalf("Failed to connect to gateway: %v", err)
	}
	defer gateway.Close()

	// Get network and contract
	network := gateway.GetNetwork(channelName)
	contract := network.GetContract(chaincodeName)

	// Submit transaction
	result,commit, err := contract.SubmitAsync("CreateUser",client.WithArguments("investor135", "50000"))
	if err != nil {
		log.Fatalf("Failed to submit transaction: %v", err)
	}
	// Wait for commit
	if _, err := commit.Status(); err != nil {
		log.Fatalf("Transaction commit failed: %v", err)
	}
	fmt.Printf("Transaction committed. Result: %s\n", string(result))

	// // register asset
	// result,commit, err = contract.SubmitAsync("RegisterAsset",client.WithArguments("isin123", "Apple", "class-A", "100","50", "20", "5", "7"))
	// if err != nil {
	// 	log.Fatalf("Failed to register asset: %v", err)
	// }
	// // Wait for commit
	// if _, err := commit.Status(); err != nil {
	// 	log.Fatalf("register asset commit failed: %v", err)
	// }
	// fmt.Printf("registerd asset. Result: %s\n", string(result))

	// subscribe asset
	result,commit, err = contract.SubmitAsync("SubscribeAsset",client.WithArguments("isin123", "10", "investor135", time.Now().String()))
	if err != nil {
		log.Fatalf("Failed to subscribe asset: %v", err)
	}
	// Wait for commit
	if _, err := commit.Status(); err != nil {
		log.Fatalf("subscribe asset commit failed: %v", err)
	}
	fmt.Printf("subscribed asset. Result: %s\n", string(result))
	

	// Evaluate transaction
	result, err = contract.EvaluateTransaction("GetPortfolio", "investor135")
	if err != nil {
		log.Fatalf("Failed to evaluate transaction: %v", err)
	}
	fmt.Printf("Transaction evaluated. Result: %s\n", string(result))

	// Listen for events
	listenForEvents(network)
}

func newIdentity() (identity.Identity, error) {
	certBytes, err := os.ReadFile(certPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read certificate file: %w", err)
	}

	cert, err := identity.CertificateFromPEM(certBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate: %w", err)
	}

	return identity.NewX509Identity(mspID, cert)
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

	privateKey, err := identity.PrivateKeyFromPEM(keyBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse private key: %w", err)
	}

	return identity.NewPrivateKeySign(privateKey)
}

func newGrpcConnection(peerEndpoint string) *grpc.ClientConn {
	certBytes, err := os.ReadFile(tlsCertPath)
	if err != nil {
		log.Fatalf("Failed to read TLS certificate: %v", err)
	}

	certPool := x509.NewCertPool()
	if !certPool.AppendCertsFromPEM(certBytes) {
		log.Fatalf("Failed to add TLS certificate to pool")
	}

	creds := credentials.NewClientTLSFromCert(certPool, "")
	conn, err := grpc.Dial(peerEndpoint, grpc.WithTransportCredentials(creds))
	if err != nil {
		log.Fatalf("Failed to create gRPC connection: %v", err)
	}

	return conn
}

func listenForEvents(network *client.Network) {
	events, err := network.ChaincodeEvents(context.Background(), chaincodeName)
	if err != nil {
		log.Fatalf("Failed to subscribe to chaincode events: %v", err)
	}

	go func() {
		for event := range events {
			log.Printf("Received event: %s, Transaction ID: %s", event.EventName, event.TransactionID)
		}
		log.Println("Event channel closed")
	}()

	// Keep the application running
	select {}
}
