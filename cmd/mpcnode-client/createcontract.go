package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"math/big"
	"strings"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/ethereum/go-ethereum/rlp"
)

var (
	nodeChainIDStr = "46688"
	nodeChainID    *big.Int

	gatewayURL   = "https://testnet.fsn.dev/api"
	gasLimit     = uint64(4000000)
	gasPriceStr  = "1000000000"
	bytecodeFile = "bytecode.txt"
	dryrun       = false

	gasPrice *big.Int
)

func checkArguments() error {
	if *keyfile == "" {
		return fmt.Errorf("must specify '-keystore' argument")
	}
	if *fromAddr == "" {
		return fmt.Errorf("must specify '-from' argument")
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

	fmt.Println("create contract check arguments:")
	fmt.Println("full node chain ID is", nodeChainID)
	fmt.Println("gateway RPC URL is", gatewayURL)
	fmt.Println("from is", *fromAddr)
	fmt.Println("group info is groupId", *gid, "threshold", *ts, "pubkey", *pubkey)
	fmt.Println("gas limit is", gasLimit)
	fmt.Println("gas price is", gasPrice)
	fmt.Println("byte code file is", bytecodeFile)
	fmt.Println("dry run is", dryrun)
	fmt.Println()
	return nil
}

func createContract() error {
	err := checkArguments()
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

	nonce, err := ethClient.PendingNonceAt(ctx, from)
	if err != nil {
		fmt.Printf("get account nonce failed, from=%v, err=%v\n", from.String(), err)
		return err
	}
	fmt.Printf("get account nonce success, from=%v, nonce=%v\n", from.String(), nonce)

	bytecodeContent, err := ioutil.ReadFile(bytecodeFile)
	if err != nil {
		fmt.Printf("read bytecode file failed, path=%v, err=%v\n", bytecodeFile, err)
		return err
	}
	fmt.Printf("read bytecode '%v' success\n", bytecodeFile)
	bytecodeStr := strings.TrimSpace(string(bytecodeContent))
	input, err := hexutil.Decode(bytecodeStr)
	if err != nil {
		fmt.Printf("bytecode is not hex string, err=%v\n", err)
		return err
	}

	rawTx := types.NewContractCreation(nonce, big.NewInt(0), gasLimit, gasPrice, input)
	fmt.Println("create raw tx success")
	printTx(rawTx, true)
	fmt.Println()

	chainSigner := types.NewEIP155Signer(nodeChainID)
	msgHash := chainSigner.Hash(rawTx)
	msgContext := "createContract"
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

func printTx(tx *types.Transaction, jsonFmt bool) error {
	if jsonFmt {
		bs, err := json.MarshalIndent(tx, "", "  ")
		if err != nil {
			return fmt.Errorf("json marshal err %v", err)
		}
		fmt.Println(string(bs))
	} else {
		bs, err := rlp.EncodeToBytes(tx)
		if err != nil {
			return fmt.Errorf("rlp encode err %v", err)
		}
		fmt.Println(hexutil.Bytes(bs))
	}
	return nil
}
