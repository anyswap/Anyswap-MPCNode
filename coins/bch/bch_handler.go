/*
 *  Copyright (C) 2018-2019  Fusion Foundation Ltd. All rights reserved.
 *  Copyright (C) 2018-2019  gaozhengxin@fusion.org
 *
 *  This library is free software; you can redistribute it and/or
 *  modify it under the Apache License, Version 2.0.
 *
 *  This library is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 *
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 */

package bch

import (
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"strings"

	"github.com/btcsuite/btcd/btcec"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcutil"
	"github.com/fsn-dev/dcrm-walletService/coins/btc"
	"github.com/fsn-dev/dcrm-walletService/coins/config"
	"github.com/fsn-dev/dcrm-walletService/coins/types"
	addrconv "github.com/schancel/cashaddr-converter/address"
)

func BCHInit() {
	allowHighFees = true
}

var allowHighFees bool

var chainconfig = &chaincfg.TestNet3Params

type BCHHandler struct {
	btcHandler *btc.BTCHandler
}

func NewBCHHandler() *BCHHandler {
	return &BCHHandler{
		btcHandler: btc.NewBTCHandlerWithConfig(config.ApiGateways.BitcoincashGateway.Host, config.ApiGateways.BitcoincashGateway.Port, config.ApiGateways.BitcoincashGateway.User, config.ApiGateways.BitcoincashGateway.Passwd, config.ApiGateways.BitcoincashGateway.Usessl),
	}
}

var BCH_DEFAULT_FEE, _ = new(big.Int).SetString("50000", 10)

func (h *BCHHandler) GetDefaultFee() types.Value {
	return types.Value{Cointype: "BCH", Val: BCH_DEFAULT_FEE}
}

func (h *BCHHandler) IsToken() bool {
	return false
}

func (h *BCHHandler) PublicKeyToAddress(pubKeyHex string) (address string, err error) {
	if len(pubKeyHex) != 132 && len(pubKeyHex) != 130 {
		return "", errors.New("invalid public key length")
	}
	if pubKeyHex[:2] == "0x" || pubKeyHex[:2] == "0X" {
		pubKeyHex = pubKeyHex[2:]
	}
	bb, err := hex.DecodeString(pubKeyHex)
	if err != nil {
		return
	}
	pubKey, err := btcec.ParsePubKey(bb, btcec.S256())
	if err != nil {
		return
	}
	b := pubKey.SerializeCompressed()
	pkHash := btcutil.Hash160(b)
	addressPubKeyHash, err := btcutil.NewAddressPubKeyHash(pkHash, chainconfig)
	if err != nil {
		return
	}
	legaddr := addressPubKeyHash.EncodeAddress() // legacy format
	addr, err := addrconv.NewFromString(legaddr)
	if err != nil {
		return
	}
	cashAddress, _ := addr.CashAddress() // bitcoin cash
	address, err = cashAddress.Encode()
	address = CovertToCashAddress(address)
	// for lockin test
	//************
	//	address = "qrky8lzm3kjv40e8sx0wve03rm6em3kmss8qnjv0aa"
	// Lockin txhash: 91287ee8bc9b8e5392f8ee2bd3a6f7aef0912508fbd398f4d3755aff4c8d1ee3
	// Lockin amount: 10000
	//************
	return
}

// NOT completed, may or not work
func (h *BCHHandler) BuildUnsignedTransaction(fromAddress, fromPublicKey, toAddress string, amount *big.Int, jsonstring string,memo string) (transaction interface{}, digests []string, err error) {
	transaction, digests, err = h.btcHandler.BuildUnsignedTransaction(fromAddress, fromPublicKey, toAddress, amount, jsonstring,memo)
	return
}

// NOT completed, may or not work
func (h *BCHHandler) SignTransaction(hash []string, wif interface{}) (rsv []string, err error) {
	return h.btcHandler.SignTransaction(hash, wif)
}

// NOT completed, may or not work
func (h *BCHHandler) MakeSignedTransaction(rsv []string, transaction interface{}) (signedTransaction interface{}, err error) {
	return h.btcHandler.MakeSignedTransaction(rsv, transaction)
}

// NOT completed, may or not work
func (h *BCHHandler) SubmitTransaction(signedTransaction interface{}) (ret string, err error) {
	return h.btcHandler.SubmitTransaction(signedTransaction)
}

func (h *BCHHandler) GetTransactionInfo(txhash string) (fromAddress string, txOutputs []types.TxOutput, jsonstring string, confirmed bool, fee types.Value, err error) {
	fromAddress, txOutputs, jsonstring, confirmed, fee, err = h.btcHandler.GetTransactionInfo(txhash)
	fee.Cointype = "BCH"
	fromAddress = CovertToCashAddress(fromAddress)
	for _, txoutput := range txOutputs {
		txoutput.ToAddress = CovertToCashAddress(txoutput.ToAddress)
	}
	return
}

func CovertToCashAddress(btcaddrAddress string) (cashAddress string) {
	if strings.HasPrefix(btcaddrAddress, "bchtest") {
		cashAddress = strings.Split(btcaddrAddress, ":")[1]
		return
	}
	if strings.HasPrefix(btcaddrAddress, "q") || strings.HasPrefix(btcaddrAddress, "p") {
		cashAddress = btcaddrAddress
		return
	}
	btcaddr, _ := addrconv.NewFromString(btcaddrAddress)
	if btcaddr != nil {
		cashAddr, _ := btcaddr.CashAddress()
		if cashAddr != nil {
			cashAddress, _ = cashAddr.Encode()
			cashAddress = strings.Split(cashAddress, ":")[1]
		}
	}
	return
}

// TODO
func (h *BCHHandler) GetAddressBalance(address string, jsonstring string) (balance types.Balance, err error) {
	err = fmt.Errorf("function currently not available")
	return types.Balance{}, err
}
