package main

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/hyperledger/fabric-contract-api-go/contractapi"
)

type Asset struct {
	ISIN             string `json:"isin"`
	CompanyName      string `json:"company_name"`
	AssetType        string `json:"asset_type"`
	TotalUnits       int    `json:"total_units"`
	PricePerUnit     int    `json:"price_per_unit"`
	AvailableUnits   int    `json:"available_units"`
	MaxAllowedUnits  int    `json:"max_allowed_units"`
	MinRedeemUnits   int    `json:"min_redeem_units"`
	LockInPeriodDays int    `json:"lock_in_period_days"`
}

type Holding struct {
	ISIN                string `json:"isin"`
	Units               int    `json:"units"`
	SubscribedTimeStamp string `json:"subscribed_timestamp"`
}

type Investor struct {
	InvestorID string             `json:"investor_id"`
	Balance    int                `json:"balance"`
	Holdings   map[string]Holding `json:"holdings"`
}

type AssetSubscription struct {
	ISIN       string `json:"isin"`
	InvestorID string `json:"investor_id"`
	Units      int    `json:"units"`
	Timestamp  string `json:"timestamp"`
}

type AssetManagementContract struct {
	contractapi.Contract
}

func (a *AssetManagementContract) CreateUser(ctx contractapi.TransactionContextInterface, investorID string, balance int) error {
	investorBytes, err := ctx.GetStub().GetState(investorID)
	if err != nil {
		return fmt.Errorf("failed to get investor details, %v", err)
	}

	if investorBytes != nil {
		return fmt.Errorf("investor already exist")
	}

	investor := Investor{
		InvestorID: investorID,
		Balance:    balance,
	}

	investorBytes, err = json.Marshal(investor)
	if err != nil {
		return fmt.Errorf("failed to marshall investor. %v", err)
	}

	err = ctx.GetStub().PutState(investor.InvestorID, investorBytes)
	if err != nil {
		return fmt.Errorf("failed to put investor to world state. %v", err)
	}

	fmt.Println("Investor created successfully...")
	return nil
}

// TODO: RegisterAsset function registers a new asset
func (a *AssetManagementContract) RegisterAsset(
	ctx contractapi.TransactionContextInterface,
	isin string,
	companyName string,
	assetType string,
	totalUnits int,
	pricePerUnit int,
	maxAllowedUnits int,
	minRedeemUnits int,
	lockInPeriodDays int,
) error {
	assetBytes, err := ctx.GetStub().GetState(isin)
	if err != nil {
		return fmt.Errorf("failed to get asset details, %v", err)
	}

	if assetBytes != nil {
		return fmt.Errorf("Asset already exist")
	}

	asset := Asset{
		ISIN:             isin,
		CompanyName:      companyName,
		AssetType:        assetType,
		TotalUnits:       totalUnits,
		PricePerUnit:     pricePerUnit,
		AvailableUnits:   totalUnits,
		MaxAllowedUnits:  maxAllowedUnits,
		MinRedeemUnits:   minRedeemUnits,
		LockInPeriodDays: lockInPeriodDays,
	}

	assetBytes, err = json.Marshal(asset)
	if err != nil {
		return fmt.Errorf("failed to marshall asset. %v", err)
	}

	err = ctx.GetStub().PutState(asset.ISIN, assetBytes)
	if err != nil {
		return fmt.Errorf("failed to put asset to world state. %v", err)
	}

	fmt.Println("Asset created successfully...")
	return nil
}

// TODO: SubscribeAsset function allows an investor to subscribe to asset units
func (a *AssetManagementContract) SubscribeAsset(
	ctx contractapi.TransactionContextInterface,
	isin string,
	unitsNeeded int,
	investorID string,
) error {
	investorBytes, err := ctx.GetStub().GetState(investorID)
	if err != nil {
		return fmt.Errorf("failed to get investor details, %v", err)
	}

	if investorBytes == nil {
		return fmt.Errorf("investorID %s is not valid investor", investorID)
	}

	assetBytes, err := ctx.GetStub().GetState(isin)
	if err != nil {
		return fmt.Errorf("failed to get asset details, %v", err)
	}

	if assetBytes == nil {
		return fmt.Errorf("Asset not found for ISIN %v", isin)
	}

	var asset Asset
	if err := json.Unmarshal(assetBytes, &asset); err != nil {
		return fmt.Errorf("failed unmarshal asset, %v", err)
	}

	var investor Investor
	if err := json.Unmarshal(investorBytes, &investor); err != nil {
		return fmt.Errorf("failed unmarshal investor, %v", err)
	}

	if asset.MaxAllowedUnits < unitsNeeded {
		return fmt.Errorf("units request should be less than MaxAllowedUnits %v", asset.MaxAllowedUnits)
	}

	if asset.AvailableUnits < unitsNeeded {
		return fmt.Errorf("insufficient assest available units")
	}

	priceForRequestedUnits := (unitsNeeded * asset.PricePerUnit)
	if investor.Balance < priceForRequestedUnits {
		return fmt.Errorf("insufficient investor balance")
	}

	asset.AvailableUnits -= unitsNeeded
	updatedAssetBytes, err := json.Marshal(asset)
	if err != nil {
		return fmt.Errorf("failed to marshal updated asset byte %v", err)
	}

	err = ctx.GetStub().PutState(asset.ISIN, updatedAssetBytes)
	if err != nil {
		return fmt.Errorf("failed to update asset to world state. %v", err)
	}

	fmt.Println("Asset updated successfully....")

	if investor.Holdings == nil {
		investor.Holdings = make(map[string]Holding)
	}

	subscribedTS := time.Now().String()
	investor.Holdings[isin] = Holding{
		ISIN:                isin,
		Units:               unitsNeeded,
		SubscribedTimeStamp: time.Now().String(),
	}
	investor.Balance -= priceForRequestedUnits

	updatedInvestorBytes, err := json.Marshal(investor)
	if err != nil {
		return fmt.Errorf("failed to marshal updated investor byte %v", err)
	}

	err = ctx.GetStub().PutState(investorID, updatedInvestorBytes)
	if err != nil {
		return fmt.Errorf("failed to update investor to world state. %v", err)
	}

	fmt.Println("Investor updated successfully....")

	assetSubscribed := AssetSubscription{
		ISIN:       isin,
		InvestorID: investorID,
		Units:      unitsNeeded,
		Timestamp:  subscribedTS,
	}
	assetSubscribedJSON, err := json.Marshal(assetSubscribed)
	if err != nil {
		return err
	}
	ctx.GetStub().SetEvent("AssetSubscribed", assetSubscribedJSON)

	return nil
}

// TODO: RedeemAsset function allows an investor to redeem asset units
func (a *AssetManagementContract) RedeemAsset(
	ctx contractapi.TransactionContextInterface,
	isin string,
	unitsNeeded int,
	investorID string,
) error {
	investorBytes, err := ctx.GetStub().GetState(investorID)
	if err != nil {
		return fmt.Errorf("failed to get investor details, %v", err)
	}

	if investorBytes == nil {
		return fmt.Errorf("investorID %s is not valid investor", investorID)
	}

	assetBytes, err := ctx.GetStub().GetState(isin)
	if err != nil {
		return fmt.Errorf("failed to get asset details, %v", err)
	}

	if assetBytes == nil {
		return fmt.Errorf("Asset not found for ISIN %v", isin)
	}

	var asset Asset
	if err := json.Unmarshal(assetBytes, &asset); err != nil {
		return fmt.Errorf("failed unmarshal asset, %v", err)
	}

	var investor Investor
	if err := json.Unmarshal(investorBytes, &investor); err != nil {
		return fmt.Errorf("failed unmarshal investor, %v", err)
	}

	if investor.Holdings == nil {
		return fmt.Errorf("no holdings available for this user")
	}

	if investor.Holdings[isin].Units < unitsNeeded {
		return fmt.Errorf("insufficient holdings for redeem")
	}

	ts, err := time.Parse(time.RFC3339, investor.Holdings[isin].SubscribedTimeStamp)
	if err != nil {
		return fmt.Errorf("failed to parse SubscribedTimeStamp %v", err)
	}

	if time.Since(ts) < time.Duration(asset.LockInPeriodDays) {
		return fmt.Errorf("redeem is not allowed in lock in period")
	}

	if unitsNeeded < asset.MinRedeemUnits {
		return fmt.Errorf("minimum redeem units should be %v", asset.MinRedeemUnits)
	}

	asset.AvailableUnits += unitsNeeded
	updatedAssetBytes, err := json.Marshal(asset)
	if err != nil {
		return fmt.Errorf("failed to marshal updated asset byte %v", err)
	}

	err = ctx.GetStub().PutState(asset.ISIN, updatedAssetBytes)
	if err != nil {
		return fmt.Errorf("failed to update asset to world state. %v", err)
	}

	fmt.Println("Asset updated successfully....")

	priceForRequestedUnits := (unitsNeeded * asset.PricePerUnit)

	holdings := investor.Holdings[isin]
	holdings.Units -= unitsNeeded
	investor.Balance += priceForRequestedUnits

	updatedInvestorBytes, err := json.Marshal(investor)
	if err != nil {
		return fmt.Errorf("failed to marshal updated investor byte %v", err)
	}

	err = ctx.GetStub().PutState(investorID, updatedInvestorBytes)
	if err != nil {
		return fmt.Errorf("failed to update investor to world state. %v", err)
	}

	fmt.Println("Investor updated successfully....")

	assetRedeemed := AssetSubscription{
		ISIN:       isin,
		InvestorID: investorID,
		Units:      unitsNeeded,
		Timestamp:  time.Now().String(),
	}
	assetRedeemedJSON, err := json.Marshal(assetRedeemed)
	if err != nil {
		return err
	}
	ctx.GetStub().SetEvent("AssetRedeemed", assetRedeemedJSON)

	return nil
}

// TODO: GetPortfolio function retrieves an investor's portfolio
func (a *AssetManagementContract) GetPortfolio(ctx contractapi.TransactionContextInterface, investorID string) (map[string]Holding, error) {
	investorBytes, err := ctx.GetStub().GetState(investorID)
	if err != nil {
		return nil, fmt.Errorf("failed to get investor details, %v", err)
	}

	if investorBytes == nil {
		return nil, fmt.Errorf("investorID %s is not valid investor", investorID)
	}

	var investor Investor
	if err := json.Unmarshal(investorBytes, &investor); err != nil {
		return nil, fmt.Errorf("failed unmarshal investor, %v", err)
	}

	return investor.Holdings, nil
}

func main() {
	chaincode, err := contractapi.NewChaincode(&AssetManagementContract{})
	if err != nil {
		fmt.Printf("Error creating asset management chaincode: %v", err)
		return
	}

	if err := chaincode.Start(); err != nil {
		fmt.Printf("Error starting asset management chaincode: %v", err)
	}
}
