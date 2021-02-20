package main

import (
	"context"
	"fmt"
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
)

var (
	valueWei  = big.NewInt(0)
	inputData []byte
)

func checkSendEthTxArguments() (err error) {
	if *keyfile == "" {
		return fmt.Errorf("must specify '-keystore' argument")
	}
	if *fromAddr == "" {
		return fmt.Errorf("must specify '-from' argument")
	}
	if *toAddr == "" {
		return fmt.Errorf("must specify '-to' argument")
	}
	if *input == "" {
		return fmt.Errorf("must specify '-input' argument")
	}
	if *gid == "" {
		return fmt.Errorf("must specify '-gid' argument")
	}
	if *ts == "" {
		return fmt.Errorf("must specify '-ts' argument")
	}
	if *pubkey == "" {
		return fmt.Errorf("must specify '-pubkey' argument")
	}

	var ok bool
	gasPrice, ok = new(big.Int).SetString(gasPriceStr, 0)
	if !ok {
		return fmt.Errorf("wrong gas price %v", gasPriceStr)
	}

	nodeChainID, ok = new(big.Int).SetString(nodeChainIDStr, 0)
	if !ok {
		return fmt.Errorf("wrong chain Id %v", nodeChainIDStr)
	}

	if accNonceStr != "" {
		accNonce, ok = new(big.Int).SetString(accNonceStr, 0)
		if !ok {
			return fmt.Errorf("wrong account nonce %v", accNonceStr)
		}
	}

	if *value != "" {
		valueWei, ok = new(big.Int).SetString(*value, 0)
		if !ok {
			return fmt.Errorf("wrong value %v", *value)
		}
	}

	inputData, err = hexutil.Decode(*input)
	if err != nil {
		return fmt.Errorf("wrong input data %v, err=%v", *input, err)
	}

	fmt.Println("send eth tx check arguments:")
	fmt.Println("full node chain ID is", nodeChainID)
	fmt.Println("gateway RPC URL is", gatewayURL)
	fmt.Println("from is", *fromAddr)
	fmt.Println("to is", *toAddr)
	fmt.Println("value is", *value)
	fmt.Println("input data is", *input)
	fmt.Println("group info is groupId", *gid, "threshold", *ts, "pubkey", *pubkey)
	fmt.Println("gas limit is", gasLimit)
	fmt.Println("gas price is", gasPrice)
	fmt.Println("dry run is", dryrun)
	fmt.Println()
	return nil
}

func sendEthTx() error {
	err := checkSendEthTxArguments()
	if err != nil {
		return err
	}

	ethClient, err := ethclient.Dial(gatewayURL)
	if err != nil {
		fmt.Printf("ethclient.Dial failed, url=%v, err=%v\n", gatewayURL, err)
		return err
	}
	ctx := context.Background()

	from := common.HexToAddress(*fromAddr)
	to := common.HexToAddress(*toAddr)

	var nonce uint64
	if accNonce != nil {
		nonce = accNonce.Uint64()
	} else {
		nonce, err := ethClient.PendingNonceAt(ctx, from)
		if err != nil {
			fmt.Printf("get account nonce failed, from=%v, err=%v\n", from.String(), err)
			return err
		}
		fmt.Printf("get account nonce success, from=%v, nonce=%v\n", from.String(), nonce)
	}

	rawTx := types.NewTransaction(nonce, to, valueWei, gasLimit, gasPrice, inputData)
	fmt.Println("create raw tx success")
	printTx(rawTx, true)
	fmt.Println()

	chainSigner := types.NewEIP155Signer(nodeChainID)
	msgHash := chainSigner.Hash(rawTx)
	msgContext := "sendEthTx"
	rsvs := signMsgHash([]string{msgHash.String()}, []string{msgContext}, -1)

	if len(rsvs) != 1 {
		err = fmt.Errorf("signMsgHash get wrong number of rsv (%v), require one rsv\n", len(rsvs))
		fmt.Println(err)
		return err
	}
	rsv := rsvs[0]

	signature := common.FromHex(rsv)
	if len(signature) != crypto.SignatureLength {
		err = fmt.Errorf("dcrm sign failed, rsv=%v\n", rsv)
		fmt.Println(err)
		return err
	}

	signedTx, err := rawTx.WithSignature(chainSigner, signature)
	if err != nil {
		fmt.Printf("sign tx failed, err=%v\n", err)
		return err
	}

	sender, err := types.Sender(chainSigner, signedTx)
	if err != nil {
		fmt.Printf("get sender from signed tx failed, err=%v\n", err)
		return err
	}

	if sender != from {
		err = fmt.Errorf("sender mismatch, signer %v != from %v\n", sender.String(), from.String())
		fmt.Println(err)
		return err
	}

	txHash := signedTx.Hash().String()

	fmt.Printf("signed tx hash is %v\n", txHash)
	fmt.Printf("sender is %v\n", sender.String())
	printTx(signedTx, false)

	if !dryrun {
		err = ethClient.SendTransaction(ctx, signedTx)
		if err != nil {
			fmt.Printf("SendTransaction failed, err=%v\n", err)
			return err
		}
		fmt.Printf("send tx success, tx hash is %v\n", txHash)
	}
	return nil
}
