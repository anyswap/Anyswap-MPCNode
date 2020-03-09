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

package trx

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"runtime/debug"

	tcrypto "github.com/fsn-dev/dcrm-walletService/coins/trx/crypto"
	"github.com/fsn-dev/dcrm-walletService/crypto"

	"github.com/fsn-dev/dcrm-walletService/coins/config"
	rpcutils "github.com/fsn-dev/dcrm-walletService/coins/rpcutils"
	"github.com/fsn-dev/dcrm-walletService/coins/types"
)

func TRXInit() {
	URL = config.ApiGateways.TronGateway.ApiAddress
	ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
	prefix = byte(0x41)
	TRANSFER_CONTRACT = "TransferContract"
	TRX_DEFAULT_FEE, _ = new(big.Int).SetString("50000", 10)
}

var (
	//URL = config.TRON_SOLIDITY_NODE_HTTP
	//URL = config.ApiGateways.TronGateway.ApiAddress
	URL      string
	ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
	prefix   = byte(0x41) // MainNet
	//prefix = byte(0xA0)
	TRANSFER_CONTRACT = "TransferContract"
)

type TRXHandler struct{}

func NewTRXHandler() *TRXHandler {
	return &TRXHandler{}
}

var TRX_DEFAULT_FEE *big.Int

func (h *TRXHandler) GetDefaultFee() types.Value {
	return types.Value{Cointype: "TRX", Val: TRX_DEFAULT_FEE}
}

func (h *TRXHandler) PublicKeyToAddress(pubKeyHex string) (address string, err error) {
	if len(pubKeyHex) != 132 && len(pubKeyHex) != 130 {
		return "", errors.New("invalid public key length")
	}
	pk, err := HexToPublicKey(pubKeyHex)
	if err != nil {
		return
	}
	_, address, err = pk.Address()
	return
}

func (h *TRXHandler) BuildUnsignedTransaction(fromAddress, fromPublicKey, toAddress string, amount *big.Int, jsonstring string) (transaction interface{}, digests []string, err error) {
	defer func() {
		if e := recover(); e != nil {
			err = fmt.Errorf("Runtime error: %v\n%v", e, string(debug.Stack()))
			return
		}
	}()
	if len(fromAddress) != 42 {
		b, err1 := tcrypto.Base58Decode(fromAddress, ALPHABET)
		if err1 != nil {
			err = err1
			return
		}
		fromAddress = hex.EncodeToString(b)
	}

	if len(toAddress) != 42 {
		b, err2 := tcrypto.Base58Decode(toAddress, ALPHABET)
		if err2 != nil {
			err = err2
			return
		}
		toAddress = hex.EncodeToString(b)
	}

	tf := &Transfer{
		Amount:        amount,
		Owner_address: fromAddress,
		To_address:    toAddress,
	}

	tfJson, err := tf.MarshalJSON()
	if err != nil {
		panic(err.Error())
	}

	ret := rpcutils.DoCurlRequest(URL, "wallet/createtransaction", tfJson)

	transaction = &Transaction{}
	err = transaction.(*Transaction).UnmarshalJson(ret)

	digest := transaction.(*Transaction).TxID
	digests = append(digests, digest)
	return
}

func (h *TRXHandler) SignTransaction(hash []string, privateKey interface{}) (rsv []string, err error) {
	hashBytes, err := hex.DecodeString(hash[0])
	if err != nil {
		return
	}
	for i := 0; i < 10; i++ {
		r, s, err1 := ecdsa.Sign(rand.Reader, privateKey.(*ecdsa.PrivateKey), hashBytes)
		if err1 != nil {
			err = err1
			return
		}
		rx := fmt.Sprintf("%x", r)
		sx := fmt.Sprintf("%x", s)
		if isCanonical(&privateKey.(*ecdsa.PrivateKey).PublicKey, s) {
			rsv = append(rsv, rx+sx+"00")
			break
		}
		if i == 24 {
			err = fmt.Errorf("couldn't find a canonical signature")
			return
		}
	}
	return
}

func (h *TRXHandler) MakeSignedTransaction(rsv []string, transaction interface{}) (signedTransaction interface{}, err error) {
	signedTransaction = transaction
	signedTransaction.(*Transaction).Signature = rsv[0]
	return
}

func (h *TRXHandler) SubmitTransaction(signedTransaction interface{}) (txhash string, err error) {
	req, err := signedTransaction.(*Transaction).MarshalJson()
	ret := rpcutils.DoCurlRequest(URL, "wallet/broadcasttransaction", req)
	var result interface{}
	err = json.Unmarshal([]byte(ret), &result)
	if err != nil {
		panic(err.Error())
	}
	if ok := result.(map[string]interface{})["result"]; ok != nil && ok.(bool) == true {
		txhash = signedTransaction.(*Transaction).TxID
		ret = fmt.Sprintf("success/%v", signedTransaction.(*Transaction).TxID)
	}
	return
}

func (h *TRXHandler) GetTransactionInfo(txhash string) (fromAddress string, txOutputs []types.TxOutput, jsonstring string, confirmed bool, fee types.Value, err error) {
	defer func() {
		if e := recover(); e != nil {
			err = fmt.Errorf("Runtime error: %v\n%v", e, string(debug.Stack()))
			return
		}
	}()
	fee = h.GetDefaultFee()
	confirmed = false
	data, err := json.Marshal(struct {
		Value string `json:"value"`
	}{
		Value: txhash,
	})
	reqData := string(data)
	ret := rpcutils.DoPostRequest(URL, "walletsolidity/gettransactionbyid", reqData)
	tx := &Transaction{}
	tx.UnmarshalJson(ret)

	if len(tx.Raw_data.Contract) == 0 {
		err = fmt.Errorf("Transaction not found")
		return
	}

	tf := tx.Raw_data.Contract[0].(map[string]interface{})["parameter"].(map[string]interface{})["value"].(map[string]interface{})

	fromAddress = tf["owner_address"].(string)
	toAddress := tf["to_address"].(string)
	transferAmount := big.NewInt(int64(tf["amount"].(float64)))
	txOutput := types.TxOutput{
		ToAddress: toAddress,
		Amount:    transferAmount,
	}
	txOutputs = append(txOutputs, txOutput)

	ret2 := rpcutils.DoPostRequest(URL, "walletsolidity/gettransactioninfobyid", reqData)
	//fmt.Printf("\n\nret:\n%v\n\n\n\n", ret2)
	txinfo := TransactionInfo{
		BlockTimeStamp: 0,
	}
	err1 := json.Unmarshal([]byte(ret2), &txinfo)
	if err1 != nil {
		err = fmt.Errorf("decode transaction info error: " + err1.Error())
		return
	}
	//fmt.Printf("\n\n\n\n!!!!!!!! TRX txinfo:\n%+v\n\n\n\n\n\n", txinfo)
	if &(txinfo.Receipt) != nil && txinfo.BlockTimeStamp != 0 && txinfo.BlockTimeStamp <= tx.Raw_data.Expiration && txinfo.BlockTimeStamp >= tx.Raw_data.Timestamp {
		confirmed = true
	}
	fee.Val = big.NewInt(int64(txinfo.Fee))
	fmt.Printf("\nfee: %+v\n", fee)
	fmt.Printf("\nconfirmed: %v\n\n", confirmed)
	return
}

func (h *TRXHandler) GetAddressBalance(address string, jsonstring string) (balance types.Balance, err error) {
	defer func() {
		if e := recover(); e != nil {
			err = fmt.Errorf("Runtime error: %v\n%v", e, string(debug.Stack()))
			return
		}
	}()
	reqData := `{"address":"` + address + `"}`
	ret := rpcutils.DoPostRequest(URL, "walletsolidity/getaccount", reqData)
	var retStruct map[string]interface{}
	err = json.Unmarshal([]byte(ret), &retStruct)
	if err != nil {
		return
	}
	if retStruct["balance"] == nil {
		err = fmt.Errorf(ret)
		return
	}
	balance.CoinBalance = types.Value{Cointype: "XRP", Val: big.NewInt(int64(retStruct["balance"].(float64)))}
	return
}

func (h *TRXHandler) IsToken() bool {
	return false
}

type PublicKey struct {
	*ecdsa.PublicKey
}

func PublicKeyToHex(pk *PublicKey) (ret string) {
	b := elliptic.Marshal(crypto.S256(), pk.X, pk.Y)
	ret = hex.EncodeToString(b)
	return
}

func HexToPublicKey(pubKeyHex string) (pk *PublicKey, err error) {
	pub, err := hex.DecodeString(pubKeyHex)
	if len(pub) == 65 {
		x := new(big.Int).SetBytes(pub[1:33])
		y := new(big.Int).SetBytes(pub[33:])
		pk = &PublicKey{&ecdsa.PublicKey{
			Curve: crypto.S256(),
			X:     x,
			Y:     y,
		}}
	} else if len(pub) == 64 {
		x := new(big.Int).SetBytes(pub[:32])
		y := new(big.Int).SetBytes(pub[32:])
		pk = &PublicKey{&ecdsa.PublicKey{
			Curve: crypto.S256(),
			X:     x,
			Y:     y,
		}}
	} else {
		err = fmt.Errorf("Invalid public key length %v", len(pub))
	}
	return
}

func (pk *PublicKey) Address() (addressHR, address string, err error) {
	data := append(pk.X.Bytes(), pk.Y.Bytes()...)
	sha := crypto.Keccak256(data)
	addressBytes := append([]byte{prefix}, sha[len(sha)-20:]...)
	address = hex.EncodeToString(addressBytes)
	addressHR = tcrypto.Base58Encode(addressBytes, ALPHABET)
	return
}

func AddressHRToAddress(addressHR string) (string, error) {
	b, err := tcrypto.Base58Decode(addressHR, ALPHABET)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(b), err
}

func AddressToAddressHR(address string) (string, error) {
	addressBytes, err := hex.DecodeString(address)
	if err != nil {
		return "", err
	}
	return tcrypto.Base58Encode(addressBytes, ALPHABET), nil
}

type Transaction struct {
	Signature string  `json:"signature"`
	TxID      string  `json:"txID"`
	Raw_data  RawData `json:"raw_data"`
	Error     string  `json:"Error,omitempty"`
}

type TransactionInfo struct {
	Id             string    `json:"id"`
	BlockNumber    int64     `json:"blockNumber"`
	Fee            int64     `json:"fee"`
	Receipt        TxReceipt `json:"receipt"`
	BlockTimeStamp int64     `json:"blockTimeStamp"`
}

type TxReceipt struct {
	Net_fee int64 `json:"net_fee"`
}

func (tx *Transaction) MarshalJson() (ret string, err error) {
	b, err := json.Marshal(tx)
	if err == nil {
		ret = string(b)
	}
	return
}

func (tx *Transaction) UnmarshalJson(txjson string) (err error) {
	err = json.Unmarshal([]byte(txjson), tx)
	if err == nil {
		if tx.Error != "" {
			err = fmt.Errorf(tx.Error)
		}
	}
	return
}

type RawData struct {
	Contract        []Contract `json:"contract"`
	Ref_block_bytes string     `json:"ref_block_bytes"`
	Ref_block_hash  string     `json:"ref_block_hash"`
	Expiration      int64      `json:"expiration"`
	Timestamp       int64      `json:"timestamp"`
}

type Contract interface {
}

type Transfer struct {
	Amount        *big.Int `json:"amount"`
	Owner_address string   `json:"owner_address"`
	To_address    string   `json:"to_address"`
}

func (tf *Transfer) MarshalJSON() (ret string, err error) {
	b, err := json.Marshal(tf)
	if err == nil {
		ret = string(b)
	}
	return
}

// Canonical signatures are those where 1 <= S <= N/2
func isCanonical(pk *ecdsa.PublicKey, s *big.Int) bool {
	if big.NewInt(1).Cmp(s) != 1 && s.Cmp(new(big.Int).Div(pk.Params().N, big.NewInt(2))) != 1 {
		return true
	}
	return false
}
