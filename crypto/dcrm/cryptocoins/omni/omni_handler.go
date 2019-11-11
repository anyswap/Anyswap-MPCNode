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

package omni

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"runtime/debug"
	"strconv"
	"strings"
	"github.com/btcsuite/btcd/btcec"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/btcjson"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcutil"

	"github.com/btcsuite/btcwallet/wallet/txauthor"
	"github.com/btcsuite/btcwallet/wallet/txrules"

	rpcutils "github.com/fsn-dev/dcrm5-libcoins/crypto/dcrm/cryptocoins/rpcutils"
	"github.com/fsn-dev/dcrm5-libcoins/crypto/dcrm/cryptocoins/btc"
	"github.com/fsn-dev/dcrm5-libcoins/crypto/dcrm/cryptocoins/config"
	"github.com/fsn-dev/dcrm5-libcoins/crypto/dcrm/cryptocoins/types"
)

/*
This simple send transaction is for lockin test
{
    "txid": "862010dc55c8a79c82c16eadc694b33fd8afaf5da4f8489b16d30e4af762d036",
    "fee": "0.00000514",
    "sendingaddress": "mkkKjig9MFbJfXUpWUxphnEwCTZJGdCnKp",
    "referenceaddress": "misxGZ91RLiqfUwfXRfEDmv9UCEHEKRjWP",
    "ismine": false,
    "version": 0,
    "type_int": 0,
    "type": "Simple Send",
    "propertyid": 112,
    "divisible": true,
    "amount": "10000.00000000",
    "confirmations": 0
  }
*/

func OMNIInit() {
	allowHighFees = true
	chainconfig = &chaincfg.TestNet3Params
	feeRate, _ = btcutil.NewAmount(0.0001)
	hashType = txscript.SigHashAll
}

var allowHighFees bool

var chainconfig = &chaincfg.TestNet3Params

var feeRate, _ = btcutil.NewAmount(0.0001)

var hashType = txscript.SigHashAll

var Properties map[string]string = map[string]string{
	"OMNIOmni":"1",
	"OMNITest Omni":"2",
	"OMNITetherUS":"112", // there is a plurarity of token named TetherUS on testnet3
}

// 返回property id
var GetProperty func (name string) string

func RegisterPropertyGetter (callback func (name string) string) {
	GetProperty = callback
}

type OmniHandler struct {
	propertyName string
	btcHandler *btc.BTCHandler
}

func NewOMNIHandler () *OmniHandler {
	return &OmniHandler{
		btcHandler: btc.NewBTCHandlerWithConfig(config.ApiGateways.OmniGateway.Host,config.ApiGateways.OmniGateway.Port,config.ApiGateways.OmniGateway.User,config.ApiGateways.OmniGateway.Passwd,config.ApiGateways.OmniGateway.Usessl),
	}
}

func NewOMNIPropertyHandler (propertyname string) *OmniHandler {
	if Properties[propertyname] == "" {
		return nil
	}
	return &OmniHandler{
		propertyName: propertyname,
		btcHandler: btc.NewBTCHandlerWithConfig(config.ApiGateways.OmniGateway.Host,config.ApiGateways.OmniGateway.Port,config.ApiGateways.OmniGateway.User,config.ApiGateways.OmniGateway.Passwd,config.ApiGateways.OmniGateway.Usessl),
	}
}

var OMNI_DEFAULT_FEE, _ = new(big.Int).SetString("10",10)

func (h *OmniHandler) GetDefaultFee() types.Value {
	return types.Value{Cointype:"BTC",Val:OMNI_DEFAULT_FEE}
}

func (h *OmniHandler) PublicKeyToAddress(pubKeyHex string) (address string, err error) {
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
	address = addressPubKeyHash.EncodeAddress()

	return
}

func (h *OmniHandler) BuildUnsignedTransaction(fromAddress, fromPublicKey, toAddress string, amount *big.Int, jsonstring string) (transaction interface{}, digests []string, err error) {
	defer func() {
		if e := recover(); e != nil {
			err = fmt.Errorf("Runtime error: %v\n%v\n", e, string(debug.Stack()))
		}
	} ()
	changeAddress := fromAddress
	unspentOutputs, _, err := btc.ListUnspent_electrs(fromAddress)
	if err != nil {
		return
	}
	sourceOutputs := make(map[string][]btcjson.ListUnspentResult)
	for _, unspentOutput := range unspentOutputs {
		if !unspentOutput.Spendable {
			continue
		}
		if unspentOutput.Confirmations < btc.RequiredConfirmations {
			continue
		}
		b, _ := hex.DecodeString(unspentOutput.ScriptPubKey)
		pkScript, err := txscript.ParsePkScript(b)
		if err != nil {
			continue
		}
		class := pkScript.Class().String()
		if class != "pubkeyhash" {
			continue
		}
		sourceAddressOutputs := sourceOutputs[unspentOutput.Address]
		sourceOutputs[unspentOutput.Address] = append(sourceAddressOutputs, unspentOutput)
	}

	// 设置交易输出
	var txOuts []*wire.TxOut

	//c, _ := rpcutils.NewClient(omnihost, omniport, omniuser, omnipasswd, omniusessl)
	// Vout 0
	// 1. omni_createpayload_simplesend
	propertyId := Properties[h.propertyName]
	amt := ""
	if amount.Cmp(big.NewInt(100000000)) == 1 {
		tmp := amount.String()
		amt = new(big.Int).Div(amount, big.NewInt(100000000)).String() + "." + tmp[len(tmp)-8:]
	} else {
		amt = strconv.FormatFloat(float64(amount.Int64())/100000000,'f',-1,64)
	}
	fmt.Printf("amount is %v\namt is %v\n",amount,amt)
	/*req1 := `{"jsonrpc":"1.0","id":"1","method":"omni_createpayload_simplesend","params":[` + propertyId + `,"` + amt + `"]}`
	fmt.Printf("======== req1 is %v ========\n", req1)
	retJSON1, err := c.Send(req1)
	fmt.Printf("======== retJSON1 is %v ========\n", retJSON1)
	var ret1 interface{}
	err = json.Unmarshal([]byte(retJSON1), &ret1)
	if err != nil {
		return
	}
	payload := ret1.(map[string]interface{})["result"].(string)*/
	pid, _ := strconv.Atoi(propertyId)
	pidhex := strconv.FormatInt(int64(pid), 16)
	amthex := strconv.FormatUint(amount.Uint64(), 16)
	pidScript := make16(pidhex)
	amtScript := make16(amthex)
	payload := pidScript + amtScript
	fmt.Printf("payload: %v\n", payload)
	if payload == "" {
		err = fmt.Errorf("create payload error")
		return
	}
	// 2. omni_createrawtx_opreturn
	scriptStr := "6a146f6d6e69" + payload
	script, _ := hex.DecodeString(scriptStr)
	txOut := wire.NewTxOut(0, script)
	txOuts = append(txOuts,txOut)

	// 3. 发送 1 satoshi
	toAddr, _ := btcutil.DecodeAddress(toAddress, chainconfig)
	pkscript0, _ := txscript.PayToAddrScript(toAddr)
	txOut0 := wire.NewTxOut(1, pkscript0)
	txOuts = append(txOuts, txOut0)

	if len(sourceOutputs) < 1 {
		err = fmt.Errorf("cannot find p2pkh utxo")
		return
	}
	previousOutputs := sourceOutputs[fromAddress]
	targetAmount := btc.SumOutputValues(txOuts)
	estimatedSize := btc.EstimateVirtualSize(0, 1, 0, txOuts, true)
	targetFee := txrules.FeeForSerializeSize(feeRate, estimatedSize)
	// 选择utxo作为交易输入
	// *************************************************
	var inputSource txauthor.InputSource
	for i, _ := range previousOutputs {
		inputSource = btc.MakeInputSource(previousOutputs[:i+1])
		inputAmount, _, _, _, err1 := inputSource(targetAmount + targetFee)
		if err1 != nil {
			err = err1
			return
		}
		if inputAmount < targetAmount+targetFee {
			fmt.Printf("=========inputAmount %v, targetAmount %v, targetFee %v=========\n",inputAmount,targetAmount,targetFee)
			continue
		} else {
			break
		}
	}

	// *************************************************
	// 设置找零
	changeAddr, _ := btcutil.DecodeAddress(changeAddress, chainconfig)
	changeSource := func()([]byte,error){
		return txscript.PayToAddrScript(changeAddr)
	}
	transaction, err = btc.NewUnsignedTransaction(txOuts, feeRate, inputSource, changeSource)
	if err != nil {
		return
	}

	for idx, _ := range transaction.(*btc.AuthoredTx).Tx.TxIn {
		pkscript, _ := hex.DecodeString(previousOutputs[idx].ScriptPubKey)

		txhashbytes, err1 := txscript.CalcSignatureHash(pkscript, hashType, transaction.(*btc.AuthoredTx).Tx, idx)
		if err1 != nil {
			err = err1
			return
		}
		txhash := hex.EncodeToString(txhashbytes)
		digests = append(digests, txhash)
	}
	transaction.(*btc.AuthoredTx).Digests = digests

	if fromPublicKey[:2] == "0x" || fromPublicKey[:2] == "0X" {
		fromPublicKey = fromPublicKey[2:]
	}
	bb, err := hex.DecodeString(fromPublicKey)
	if err != nil {
		return
	}
	pubKey, err := btcec.ParsePubKey(bb, btcec.S256())
	if err != nil {
		return
	}
	transaction.(*btc.AuthoredTx).PubKeyData = pubKey.SerializeCompressed()
	for i, txout := range transaction.(*btc.AuthoredTx).Tx.TxOut {
		s := hex.EncodeToString(txout.PkScript)
		fmt.Printf("script %v: %v\n", i, s)
	}

	return
}

func make16(in string) string {
	if len(in) < 16 {
		return make16("0" + in)
	} else {
		return in[:16]
	}
}

// NOT completed, may or not work
func (h *OmniHandler) SignTransaction(hash []string, wif interface{}) (rsv []string, err error){
	return h.btcHandler.SignTransaction(hash, wif)
}

// NOT completed, may or not work
func (h *OmniHandler) MakeSignedTransaction(rsv []string, transaction interface{}) (signedTransaction interface{}, err error){
	return h.btcHandler.MakeSignedTransaction(rsv, transaction)
}

// NOT completed, may or not work
func (h *OmniHandler) SubmitTransaction(signedTransaction interface{}) (ret string, err error) {
	c, _ := rpcutils.NewClient(config.ApiGateways.OmniGateway.Host,config.ApiGateways.OmniGateway.Port,config.ApiGateways.OmniGateway.User,config.ApiGateways.OmniGateway.Passwd,config.ApiGateways.OmniGateway.Usessl)

	ret, err= btc.SendRawTransaction (c, signedTransaction.(*btc.AuthoredTx).Tx, allowHighFees)
	return
}

func (h *OmniHandler) GetTransactionInfo(txhash string) (fromAddress string, txOutputs []types.TxOutput, jsonstring string, confirmed bool, fee types.Value, err error) {
	defer func () {
		if e := recover(); e != nil {
			err = fmt.Errorf("Runtime error: %v\n%v", e, string(debug.Stack()))
			return
		}
	} ()

	fee = h.GetDefaultFee()
	client, _ := rpcutils.NewClient(config.ApiGateways.OmniGateway.Host,config.ApiGateways.OmniGateway.Port,config.ApiGateways.OmniGateway.User,config.ApiGateways.OmniGateway.Passwd,config.ApiGateways.OmniGateway.Usessl)
	reqstr := `{"jsonrpc":"1.0","id":"1","method":"omni_gettransaction","params":["`+txhash+`"]}`
	ret, err1 := client.Send(reqstr)
	if err1 != nil {
		err = err1
		return
	}

	if ret == "" {
		err = fmt.Errorf("failed get transaction")
		return
	}
	omniTx := DecodeOmniTx(ret)
	if omniTx.Error != nil {
		err = omniTx.Error
		return
	}

	confirmed = (omniTx.Confirmations >= btc.RequiredConfirmations) && omniTx.Valid
//**************************
//	confirmed = true
//**************************

	fmt.Printf("omniTx is %+v\n", omniTx)
	if h.propertyName != omniTx.PropertyName && Properties[h.propertyName] != strconv.Itoa(int(omniTx.PropertyId)) {
		err = fmt.Errorf("property name does not match: have %v want %v", omniTx.PropertyName, h.propertyName)
	}

	fromAddress = omniTx.From
	txOutput := types.TxOutput{
		ToAddress:omniTx.To,
		Amount:omniTx.Amount,
	}
	txOutputs = append(txOutputs, txOutput)
	fmt.Printf("========== OMNI_GetTransactionInfo ========\n")
	fmt.Printf("fromAddress: %v\ntxOutputs: %+v\n", fromAddress, txOutputs)

	if omniTx.Fee != "" {
		feeStr := toSatoshi(omniTx.Fee)
		fee.Val, _ = new(big.Int).SetString(feeStr, 10)
	}

	return
}

func toSatoshi(str string) string {
	if strings.Contains(str, ".") {
		str = strings.Replace(str, ".", "", -1)
	}
	if strings.HasPrefix(str, "0") {
		str = strings.TrimPrefix(str, "0")
		return toSatoshi(str)
	} else {
		return str
	}
}

func (h *OmniHandler) GetAddressBalance(address string, jsonstring string) (balance types.Balance, err error) {
	defer func () {
		if e := recover(); e != nil {
			err = fmt.Errorf("Runtime error: %v\n%v", e, string(debug.Stack()))
			return
		}
	} ()

	propertyId := Properties[h.propertyName]

	client, _ := rpcutils.NewClient(config.ApiGateways.OmniGateway.Host,config.ApiGateways.OmniGateway.Port,config.ApiGateways.OmniGateway.User,config.ApiGateways.OmniGateway.Passwd,config.ApiGateways.OmniGateway.Usessl)
	reqstr := `{"jsonrpc":"1.0","id":"1","method":"omni_getbalance","params":["`+address+`",`+propertyId+`]}`

	ret, err1 := client.Send(reqstr)
	if err != nil {
		err = err1
		return
	}

	var retObj interface{}
	json.Unmarshal([]byte(ret), &retObj)

	result := retObj.(map[string]interface{})["result"]
	balanceStr := result.(map[string]interface{})["balance"].(string)
	reservedStr := result.(map[string]interface{})["reserved"].(string)
	frozenStr := result.(map[string]interface{})["frozen"].(string)
	balanceStr = strings.Replace(balanceStr,".","",-1)
	reservedStr = strings.Replace(reservedStr,".","",-1)
	frozenStr = strings.Replace(frozenStr,".","",-1)
	tokenbalance, _ := new(big.Int).SetString(balanceStr,10)
	reserved, _ := new(big.Int).SetString(reservedStr,10)
	frozen, _ := new(big.Int).SetString(frozenStr,10)

	tokenbalance.Sub(tokenbalance.Sub(tokenbalance,reserved),frozen)


	btcbalance, err := h.btcHandler.GetAddressBalance(address, "")
	if err != nil {
		return
	}

	balance = types.Balance{
		CoinBalance:btcbalance.CoinBalance,
		TokenBalance:types.Value{
			Cointype:h.propertyName,
			Val:tokenbalance,
		},
	}

	// 由于目前测试没有OMNITetherUS币,临时用OMNI代替USDT进行测试
	//"OMNIOmni":"1",
	//"OMNITest Omni":"2",
	//  参数cointype=USDT时实际上对应"OMNITetherUS"币种 :币种id="31", // there is a plurarity of token named TetherUS on testnet3
	if h.propertyName == "OMNIOmni" {
		balance.TokenBalance.Cointype = "USDT" //tmp code
	}
	//============================================

	return
}

func (h *OmniHandler) IsToken() bool {
	return true
}

func parseRPCReturn (retJSON string) (result interface{}, err error) {
	var ret interface{}
	json.Unmarshal([]byte(retJSON), &ret)
	result = ret.(map[string]interface{})["result"]
	if result == nil {
		errStr := ret.(map[string]interface{})["error"]
		if errStr == nil {
			err = fmt.Errorf("unknown error")
			return
		}
		err = fmt.Errorf(errStr.(string))
	}
	return
}

