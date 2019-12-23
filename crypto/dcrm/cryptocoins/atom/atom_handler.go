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

package atom

import (
	"crypto/ecdsa"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/btcsuite/btcd/btcec"
	"github.com/cosmos/cosmos-sdk/client"
	"github.com/cosmos/cosmos-sdk/client/context"
	"github.com/cosmos/cosmos-sdk/codec"
	sdk "github.com/cosmos/cosmos-sdk/types"
	"github.com/cosmos/cosmos-sdk/x/auth"
	atypes "github.com/cosmos/cosmos-sdk/x/auth/types"
	ecrypto "github.com/fsn-dev/dcrm-walletService/crypto"
	"github.com/fsn-dev/dcrm-walletService/crypto/dcrm/cryptocoins/rpcutils"
	"github.com/fsn-dev/dcrm-walletService/crypto/dcrm/cryptocoins/types"
	"github.com/gorilla/mux"
	"github.com/tendermint/tendermint/crypto"
	"github.com/tendermint/tendermint/crypto/secp256k1"
	"math/big"
	"runtime/debug"
	"strings"
)

func ATOMInit() {
	DefaultSendAtomFee = big.NewInt(1)
}

var DefaultSendAtomFee *big.Int

type AtomHandler struct{}

func NewAtomHandler() *AtomHandler {
	return &AtomHandler{}
}

func (h *AtomHandler) PublicKeyToAddress(pubKeyHex string) (address string, err error) {
	if len(pubKeyHex) != 132 && len(pubKeyHex) != 130 {
		return "", errors.New("invalid public key length")
	}
	pubKeyHex = strings.TrimPrefix(pubKeyHex, "0x")
	bb, err := hex.DecodeString(pubKeyHex)
	if err != nil {
		return
	}
	pk, err := btcec.ParsePubKey(bb, btcec.S256())
	if err != nil {
		return
	}
	cpk := pk.SerializeCompressed()
	var pub [33]byte
	copy(pub[:], cpk[:33])
	pubkey := secp256k1.PubKeySecp256k1(pub)
	addr := pubkey.Address()
	accAddress, err := sdk.AccAddressFromHex(addr.String())
	if err != nil {
		return
	}
	address = accAddress.String()
	return
}

func (h *AtomHandler) BuildUnsignedTransaction(fromAddress, fromPublicKey, toAddress string, amount *big.Int, jsonstring string) (transaction interface{}, digests []string, err error) {
	fmt.Printf("\n======== atom BuildUnsignedTransaction ========\n")
	fromacc, err := sdk.AccAddressFromBech32(fromAddress)
	if err != nil {
		return
	}
	toacc, err := sdk.AccAddressFromBech32(toAddress)
	if err != nil {
		return
	}
	amt := sdk.NewCoin("muon", sdk.NewInt(amount.Int64()))
	msg := MsgSend{
		From:   fromacc,
		To:     toacc,
		Amount: sdk.Coins{amt},
	}

	fee := auth.NewStdFee(50000, sdk.Coins{sdk.NewCoin("muon", sdk.NewInt(0))}) // gaia-13006测试币最小单位叫muon, cosmos-hub2主网币的最小单位叫uatom

	c := context.NewCLIContext()
	cdc := codec.New()
	RegisterCodec(cdc)
	codec.RegisterCrypto(cdc)
	auth.RegisterCodec(cdc)
	c.Codec = cdc
	r := mux.NewRouter()
	r.Headers("Content-Type", "application/json")
	//rpc.RegisterRoutes(c, r)
	client.RegisterRoutes(c, r)
	c = c.WithTrustNode(true)
	c = c.WithNodeURI("tcp://5.189.139.168:26657")
	//c = c.WithAccountDecoder(cdc)
	/*err = c.EnsureAccountExistsFromAddr(fromacc)
	if err != nil {
		return
	}
	accnum, err := c.GetAccountNumber(fromacc.Bytes())
	if err != nil {
		return
	}
	sequence, err := c.GetAccountSequence(fromacc.Bytes())
	if err != nil {
		return
	}*/

	accGetter := atypes.NewAccountRetriever(c)
	account, err := accGetter.GetAccount(fromacc)
	if err != nil {
		return
	}
	accnum := account.GetAccountNumber()
	sequence := account.GetSequence()

	fmt.Printf("\naccnum:\n%v\nsequence:\n%v\n", accnum, sequence)
	stdtx := auth.NewStdTx([]sdk.Msg{msg}, fee, []auth.StdSignature{}, "this transaction is signed by Dcrm (^_^)")
	transaction = AtomTx{
		Pubkeyhex: fromPublicKey,
		Tx:        stdtx,
	}

	hexTx := auth.StdSignBytes("gaia-13006", accnum, sequence, fee, []sdk.Msg{msg}, "this transaction is signed by Dcrm (^_^)")
	testmsg = hexTx
	fmt.Printf("\n============\nhex tx json:\n%v\n============\n", string(hexTx))
	digest := crypto.Sha256(hexTx)
	digests = append(digests, hex.EncodeToString(digest))
	fmt.Printf("\ntransaction:\n%+v\n", transaction)
	fmt.Printf("\ndigest:\n%+v\n", digest)
	return
}

type AtomTx struct {
	Pubkeyhex string
	Tx        auth.StdTx
}

var testmsg []byte
var testhash []byte

func (h *AtomHandler) SignTransaction(hash []string, privateKey interface{}) (rsv []string, err error) {
	fmt.Printf("\n======== atom SignTransaction ========\n")
	b, _ := hex.DecodeString(hash[0])
	testhash = b
	sig, err := ecrypto.Sign(b, privateKey.(*ecdsa.PrivateKey))
	if err != nil {
		return
	}
	rsv = append(rsv, hex.EncodeToString(sig))
	fmt.Printf("\nrsv:\n%+v\n", rsv)
	return
}

func (h *AtomHandler) MakeSignedTransaction(rsv []string, transaction interface{}) (signedTransaction interface{}, err error) {
	fmt.Printf("\n======== atom MakeSignedTransaction ========\n")
	b, _ := hex.DecodeString(rsv[0])
	fmt.Printf("\nlen(b):\n%v\n", len(b))
	sig := b[:len(b)-1]

	pb, err := hex.DecodeString(transaction.(AtomTx).Pubkeyhex)
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
	fmt.Println("\nsb is:\n%v\n", pubkey)

	obok2 := pubkey.VerifyBytes(testmsg, sig)
	if !obok2 {
		return nil, fmt.Errorf("send atom verify signature fail.")
	}

	signature := auth.StdSignature{
		PubKey:    pubkey,
		Signature: sig,
	}
	stdtx := transaction.(AtomTx).Tx
	stdtx.Signatures = append(stdtx.Signatures, signature)
	signedTransaction = stdtx
	fmt.Printf("\nsigned transaction:\n%+v\n", signedTransaction)
	return
}

func (h *AtomHandler) SubmitTransaction(signedTransaction interface{}) (txhash string, err error) {
	fmt.Printf("\n======== atom SubmitTransaction ========\n")
	cdc := codec.New()
	RegisterCodec(cdc)
	codec.RegisterCrypto(cdc)
	sdk.RegisterCodec(cdc)
	stx := signedTransaction.(auth.StdTx)
	fmt.Printf("\ntx:\n%+v\n", stx)

	bb, err2 := cdc.MarshalJSON(stx)
	fmt.Printf("\nbb:\n%v\nerr2:\n%v\n", string(bb), err2)
	data := `{"tx":` + string(bb) + `,"mode":"block"}`

	res := rpcutils.DoPostRequest("http://5.189.139.168:2327", "txs", data)

	fmt.Printf("\n============\n\n%v\n\n============\n", res)
	var resstr struct {
		Height string      `json:"height"`
		Result interface{} `json:"result"`
	}

	err = json.Unmarshal([]byte(res), &resstr)
	if err != nil {
		return
	}
	fmt.Printf("\n============\n\n%+v\n\n============\n", resstr)

	txhash = resstr.Result.(map[string]interface{})["txhash"].(string)
	fmt.Printf("\ntxhash: %v\n\n", txhash)

	return
}

func (h *AtomHandler) GetTransactionInfo(txhash string) (fromAddress string, txOutputs []types.TxOutput, jsonstring string, confirmed bool, fee types.Value, err error) {
	defer func() {
		if e := recover(); e != nil {
			err = fmt.Errorf("Runtime error: %v\n%v", e, string(debug.Stack()))
			return
		}
	}()
	fee = h.GetDefaultFee()

	c := context.NewCLIContext()
	cdc := codec.New()
	RegisterCodec(cdc)
	codec.RegisterCrypto(cdc)
	sdk.RegisterCodec(cdc)
	atypes.RegisterCodec(cdc)
	c.Codec = cdc
	r := mux.NewRouter()
	r.Headers("Content-Type", "application/json")
	client.RegisterRoutes(c, r)
	c = c.WithNodeURI("tcp://5.189.139.168:26657")

	txhashb, err := hex.DecodeString(txhash)
	node, err := c.GetNode()
	if err != nil {
		return
	}
	resTx, err := node.Tx([]byte(txhashb), true)
	if err != nil {
		return
	}

	fmt.Printf("\n========\nresTx:\n%+v\n========\n", resTx)
	fmt.Printf("\n========\nresTx.Tx:\n%+v\n========\n", resTx.Tx)

	var tx auth.StdTx
	err = cdc.UnmarshalBinaryLengthPrefixed(resTx.Tx, &tx)
	fmt.Printf("tx:\n%+v\nerr:\n%v\n", tx, err)

	fromAddress = (tx.Msgs[0].(MsgSend)).From.String()
	toAddress := (tx.Msgs[0].(MsgSend)).To.String()
	amount := (tx.Msgs[0].(MsgSend)).Amount[0].Amount.String()
	amt, _ := new(big.Int).SetString(amount, 10)
	txOutputs = append(txOutputs, types.TxOutput{
		ToAddress: toAddress,
		Amount:    amt,
	})

	return

}

func (h *AtomHandler) GetAddressBalance(address string, jsonstring string) (balance types.Balance, err error) {
	defer func() {
		if e := recover(); e != nil {
			err = fmt.Errorf("Runtime error: %v\n%v", e, string(debug.Stack()))
			return
		}
	}()

	addr, err := sdk.AccAddressFromBech32(address)
	if err != nil {
		return
	}
	c := context.NewCLIContext()
	cdc := codec.New()
	codec.RegisterCrypto(cdc)
	auth.RegisterCodec(cdc)
	c.Codec = cdc
	r := mux.NewRouter()
	r.Headers("Content-Type", "application/json")
	client.RegisterRoutes(c, r)
	c = c.WithTrustNode(true)
	c = c.WithNodeURI("tcp://5.189.139.168:26657")

	accGetter := atypes.NewAccountRetriever(c)
	account, err := accGetter.GetAccount(addr)
	if err != nil {
		return
	}
	fmt.Printf("\naccount:\n%v\n", account)

	var bal *big.Int
	coins := account.GetCoins()
	for _, coin := range coins {
		if coin.Denom == "muon" {
			bal = coin.Amount.BigInt()
			break
		}
	}
	balance = types.Balance{
		CoinBalance: types.Value{
			Cointype: "ATOM",
			Val:      bal,
		},
	}
	return
}

func (h *AtomHandler) GetDefaultFee() types.Value {
	return types.Value{Cointype: "ATOM", Val: big.NewInt(50000)}
}

func (h *AtomHandler) IsToken() bool {
	return false
}
