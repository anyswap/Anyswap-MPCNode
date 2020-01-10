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

package bnb

import (
	"encoding/hex"
	"fmt"
	"math/big"
	"runtime/debug"
	"strings"
	"github.com/binance-chain/go-sdk/client/basic"
	"github.com/binance-chain/go-sdk/client/query"
	ctypes "github.com/binance-chain/go-sdk/common/types"
	bnbtypes  "github.com/binance-chain/go-sdk/types"
	"github.com/binance-chain/go-sdk/types/msg"
	"github.com/binance-chain/go-sdk/types/tx"
	"github.com/btcsuite/btcd/btcec"
	"github.com/btcsuite/btcutil"
	"github.com/fsn-dev/dcrm-walletService/coins/types"
	"github.com/tendermint/tendermint/crypto"
	"github.com/tendermint/tendermint/crypto/secp256k1"
)

var Network string = "testnet"

type BNBHandler struct {
	Symbol string
}

func NewBNBHandler () *BNBHandler {
	if Network == "testnet" {
		ctypes.Network = ctypes.TestNetwork
	}
	return &BNBHandler{
		Symbol:"BNB",
	}
}

var Sep string = "_"

func NewBEP2Handler (symbol string) *BNBHandler {
	if Network == "testnet" {
		ctypes.Network = ctypes.TestNetwork
	}
	symbol = strings.TrimPrefix(symbol, "BEP2")
	symbol = strings.Replace(symbol, Sep, "-", -1)
	return &BNBHandler{
		Symbol:symbol,
	}
}

func (h *BNBHandler) GetSymbol() string {
	if h.Symbol == "BNB" {
		return "BNB"
	}
	return "BEP2" + strings.Replace(h.Symbol, "-", Sep, -1)
}

func (h *BNBHandler) IsToken() bool {
	if h.Symbol == "BNB" {
		return false
	} else {
		return true
	}
}

func (h *BNBHandler) PublicKeyToAddress(pubKeyHex string) (address string, err error) {
	pubbytes, err := hex.DecodeString(pubKeyHex)
	if err != nil {
		return
	}

	pubkey, err := btcec.ParsePubKey(pubbytes, btcec.S256())
	if err != nil {
		return
	}

	cpub := pubkey.SerializeCompressed()

	pkhash := btcutil.Hash160(cpub)

	pkhashstr := hex.EncodeToString(pkhash)

	if Network == "testnet" {
		ctypes.Network = ctypes.TestNetwork
	}

	accAddress, err := ctypes.AccAddressFromHex(pkhashstr)
	if err != nil {
		return
	}

	address = accAddress.String()

	return
}

func (h *BNBHandler) BuildUnsignedTransaction(fromAddress, fromPublicKey, toAddress string, amount *big.Int, jsonstring string) (transaction interface{}, digests []string, err error) {
	defer func () {
		if e := recover(); e != nil {
			err = fmt.Errorf("BNB_BuildUnsignedTransaction Runtime error: %v\n%v", e, string(debug.Stack()))
			return
		}
	} ()
	transaction, hexMsg, err := h.BNB_buildSendTx(fromAddress, fromPublicKey, toAddress, amount)
	if err != nil {
		return
	}
	digest := hex.EncodeToString(crypto.Sha256(hexMsg))
	digests = append(digests, digest)
	return
}

func (h *BNBHandler) BNB_buildSendTx(fromAddress, fromPublicKey, toAddress string, amount *big.Int) (transaction BNBTx, hexMsg []byte, err error) {
	defer func () {
		if e := recover(); e != nil {
			err = fmt.Errorf("BNB_BuildSendTx Runtime error: %v\n%v", e, string(debug.Stack()))
			return
		}
	} ()
	amt := amount.Int64()
	c := basic.NewClient("testnet-dex.binance.org:443")
	q := query.NewClient(c)
	acc, err := q.GetAccount(fromAddress)
	if err != nil {
		return
	}
	fromCoins := ctypes.Coins{{h.Symbol, amt}}

	fromAddr, err := ctypes.AccAddressFromBech32(fromAddress)
	if err != nil {
		fmt.Printf("\ncxknmsl\n\n")
		return
	}

	toAddr, err := ctypes.AccAddressFromBech32(toAddress)
	if err != nil {
		fmt.Printf("\ncxknmsl2\n\n")
		return
	}

	to := []msg.Transfer{{toAddr, []ctypes.Coin{{h.Symbol, amt}}}}

	sendMsg := msg.CreateSendMsg(fromAddr, fromCoins, to)

	signMsg := tx.StdSignMsg{
		ChainID:"Binance-Chain-Nile",
		AccountNumber:acc.Number,
		Sequence:acc.Sequence,
		Msgs:[]msg.Msg{sendMsg},
		Memo:"this is a Dcrm lockout transaction (^_^)",
		Source:tx.Source,
	}

	transaction = BNBTx{
		SignMsg: signMsg,
		Pubkey: fromPublicKey,
	}
	hexMsg = signMsg.Bytes()
	return
}

type BNBTx struct {
	SignMsg tx.StdSignMsg
	Pubkey string
}

func (h *BNBHandler) SignTransaction(hexTx []byte, privateKey interface{}) (rsv []string, err error) {
	rs, err := privateKey.(crypto.PrivKey).Sign(hexTx)
	if err != nil {
		return nil, err
	}
	rsv = append(rsv, hex.EncodeToString(rs)+"00")
	return
}

func (h *BNBHandler) MakeSignedTransaction(rsv []string, transaction interface{}) (signedTransaction interface{}, err error) {
	defer func () {
		if e := recover(); e != nil {
			err = fmt.Errorf("BNB_MakeSignedTransaction Runtime error: %v\n%v", e, string(debug.Stack()))
			return
		}
	} ()
	if len(rsv) < 1 {
		err := fmt.Errorf("no rsv")
		return nil, err
	}
	b, err := hex.DecodeString(rsv[0])
	if err != nil {
		return
	}
	var rs []byte
	if len(b) == 65 {
		rs = b[:64]
	}

	signMsg := transaction.(BNBTx).SignMsg
	pubkeyhex := transaction.(BNBTx).Pubkey

	pb, err := hex.DecodeString(pubkeyhex)
	if err != nil {
		return
	}

	pub, err := btcec.ParsePubKey(pb, btcec.S256())
	if err != nil {
		return
	}

	cpub := pub.SerializeCompressed()
	var arr [33]byte
	copy(arr[:], cpub[:33])
	pubkey := secp256k1.PubKeySecp256k1(arr)

	sig := tx.StdSignature{
		AccountNumber: signMsg.AccountNumber,
		Sequence:      signMsg.Sequence,
		PubKey:        pubkey,
		Signature:     rs,
	}
	newTx := tx.NewStdTx(signMsg.Msgs, []tx.StdSignature{sig}, signMsg.Memo, signMsg.Source, signMsg.Data)
	bz, err := tx.Cdc.MarshalBinaryLengthPrefixed(&newTx)
	if err != nil {
		return
	}
	signedTransaction = []byte(hex.EncodeToString(bz))

	return
}

func (h *BNBHandler) SubmitTransaction(signedTransaction interface{}) (txhash string, err error) {
	defer func () {
		if e := recover(); e != nil {
			err = fmt.Errorf("BNB_SubmitTransaction Runtime error: %v\n%v", e, string(debug.Stack()))
			return
		}
	} ()
	c := basic.NewClient("testnet-dex.binance.org:443")
	param := map[string]string{}
	param["sync"] = "true"
	commits, err := c.PostTx(signedTransaction.([]byte), param)
	if err != nil {
		return
	}
	txhash = commits[0].Hash
	return
}

func (h *BNBHandler) GetTransactionInfo(txhash string) (fromAddress string, txOutputs []types.TxOutput, jsonstring string, confirmed bool, fee types.Value, err error) {
	defer func () {
		if e := recover(); e != nil {
			err = fmt.Errorf("BNB_GetTransactionInfo Runtime error: %v\n%v", e, string(debug.Stack()))
			return
		}
	} ()
	confirmed = false
	c := basic.NewClient("testnet-dex.binance.org:443")
	resp, err := c.GetTx(txhash)
	if err != nil {
		return
	}
	// TODO
	confirmed = true
	fee.Cointype = "BNB"
	fee.Val = big.NewInt(37500)
	b, err := hex.DecodeString(resp.Data[3:len(resp.Data)-1])
	if err != nil {
		return
	}
	codec := bnbtypes.NewCodec()
	var parsedTx tx.StdTx
	err = codec.UnmarshalBinaryLengthPrefixed(b, &parsedTx)
	if err != nil {
		return
	}
	msgs := parsedTx.Msgs
	for _, m := range msgs {
		if m.Type() == "send" {
			sendmsg := m.(msg.SendMsg)
			if sendmsg.Inputs[0].Coins[0].Denom ==h.Symbol {
				fromAddress = sendmsg.Inputs[0].Address.String()
			}
			for _, out := range sendmsg.Outputs {
				if out.Coins[0].Denom == h.Symbol {
					output := types.TxOutput{
						ToAddress: out.Address.String(),
						Amount: big.NewInt(out.Coins[0].Amount),
					}
					txOutputs = append(txOutputs, output)
				}
			}
			break
		}
	}
	return
}

func (h *BNBHandler) GetAddressBalance(address string, jsonstring string) (balance types.Balance, err error) {
	defer func () {
		if e := recover(); e != nil {
			err = fmt.Errorf("BNB_GetAddressBalance Runtime error: %v\n%v", e, string(debug.Stack()))
			return
		}
	} ()
	c := basic.NewClient("testnet-dex.binance.org:443")
	q := query.NewClient(c)
	ba, err := q.GetAccount(address)
	if err != nil {
		return
	}
	if h.Symbol == "BNB" {
		for _, bal := range ba.Balances {
			var ojbk bool
			if strings.EqualFold(bal.Symbol, h.Symbol) {
				str := strings.Replace(bal.Free.String(),".","",-1)
				balance.CoinBalance.Cointype = h.GetSymbol()
				balance.CoinBalance.Val, ojbk = new(big.Int).SetString(str, 10)
				if !ojbk {
					return types.Balance{}, fmt.Errorf("parse balance error: %v", bal.Free.String())
				}
			}
		}
	} else {
		for _, bal := range ba.Balances {
			var ojbk bool
			if strings.EqualFold(bal.Symbol, h.Symbol) {
				str := strings.Replace(bal.Free.String(),".","",-1)
				balance.TokenBalance.Cointype = h.GetSymbol()
				balance.TokenBalance.Val, ojbk = new(big.Int).SetString(str, 10)
				if !ojbk {
					return types.Balance{}, fmt.Errorf("parse balance error: %v", bal.Free.String())
				}
			}
			if strings.EqualFold(bal.Symbol, "BNB") {
				str := strings.Replace(bal.Free.String(),".","",-1)
				balance.CoinBalance.Cointype = h.GetSymbol()
				balance.CoinBalance.Val, ojbk = new(big.Int).SetString(str, 10)
				if !ojbk {
					return types.Balance{}, fmt.Errorf("parse balance error: %v", bal.Free.String())
				}
			}
		}
	}
	return
}

func (h *BNBHandler) GetDefaultFee() (fee types.Value) {
	fee.Val = big.NewInt(37500)
	fee.Cointype = "BNB"
	return
}

