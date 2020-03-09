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

package eos

import (
	//"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"math/big"
	"net/http"
	"strconv"
	"strings"

	"github.com/btcsuite/btcd/btcec"
	"github.com/btcsuite/btcutil"
	eos "github.com/eoscanada/eos-go"
	"github.com/eoscanada/eos-go/ecc"
	"github.com/eoscanada/eos-go/system"
	"github.com/eoscanada/eos-go/token"
	"github.com/rubblelabs/ripple/crypto"

	rpcutils "github.com/fsn-dev/dcrm-walletService/coins/rpcutils"
	"github.com/fsn-dev/dcrm-walletService/coins/types"
)

func EOSInit() {
	EOSConfigInit()
	EOS_DEFAULT_FEE = big.NewInt(1)
}

type EOSHandler struct {
}

func NewEOSHandler() *EOSHandler {
	return &EOSHandler{}
}

var EOS_DEFAULT_FEE *big.Int

func (h *EOSHandler) GetDefaultFee() types.Value {
	return types.Value{Cointype: "EOS", Val: EOS_DEFAULT_FEE}
}

func (h *EOSHandler) IsToken() bool {
	return false
}

// 用一个大账户存钱，用交易备注区分用户，交易备注是公钥hash+base58
func (h *EOSHandler) PublicKeyToAddress(pubKeyHex string) (acctName string, err error) {
	if len(pubKeyHex) != 132 && len(pubKeyHex) != 130 {
		return "", errors.New("invalid public key length")
	}
	pubKeyHex = strings.TrimPrefix(pubKeyHex, "0x")
	acctName = GenAccountName(pubKeyHex)
	return
}

// 构造Lockin交易, 开发用
func (h *EOSHandler) BuildUnsignedLockinTransaction(fromAddress, toUserKey, toAcctName string, amount *big.Int, jsonstring string) (transaction interface{}, digests []string, err error) {
	memo := toUserKey
	digest, transaction, err := EOS_newUnsignedTransaction(fromAddress, toAcctName, amount, memo)
	digests = append(digests, digest)
	return
}

// 构造交易
func (h *EOSHandler) BuildUnsignedTransaction(fromAddress, fromPublicKey, toAcctName string, amount *big.Int, jsonstring string) (transaction interface{}, digests []string, err error) {
	memo := GenAccountName(fromPublicKey)
	digest, transaction, err := EOS_newUnsignedTransaction(fromAddress, toAcctName, amount, memo)
	digests = append(digests, digest)
	return
}

func (h *EOSHandler) SignTransaction(hash []string, privateKey interface{}) (rsv []string, err error) {
	signature, err := SignDigestWithPrivKey(hash[0], privateKey.(string))
	if err != nil {
		return
	}
	vrs := signature.Content
	v := vrs[0] - byte(31)
	rsvBytes := append(vrs[1:], v)
	rsv = append(rsv, hex.EncodeToString(rsvBytes))
	return
}

func (h *EOSHandler) MakeSignedTransaction(rsv []string, transaction interface{}) (signedTransaction interface{}, err error) {
	signature, err := RSVToSignature(rsv[0])
	if err != nil {
		return
	}
	signedTransaction = MakeSignedTransaction(transaction.(*eos.SignedTransaction), signature)
	return
}

func (h *EOSHandler) SubmitTransaction(signedTransaction interface{}) (txhash string, err error) {
	res := SubmitTransaction(signedTransaction.(*eos.SignedTransaction))
	var resStr SubmitTxRes
	err = json.Unmarshal([]byte(res), &resStr)
	if err != nil {
		return
	}
	if resStr.Error != nil {
		err = fmt.Errorf("%v", resStr.Error)
		return
	}
	if resStr.Transaction_id != "" {
		txhash = resStr.Transaction_id
		return
	}
	return
}

type SubmitTxRes struct {
	Transaction_id string      `json:"transaction_id"`
	Error          interface{} `json:"error,omitempty"`
}

func (h *EOSHandler) GetTransactionInfo(txhash string) (fromAddress string, txOutputs []types.TxOutput, jsonstring string, confirmed bool, fee types.Value, err error) {
	/*	api := "v1/history/get_transaction"
		data := `{"id":"` + txhash + `","block_num_hint":"0"}`
		ret := rpcutils.DoCurlRequest(nodeos, api, data)
		var retStruct map[string]interface{}
		json.Unmarshal([]byte(ret), &retStruct)
		if retStruct["trx"] == nil {
			if reterr := retStruct["error"]; reterr != nil {
				name := reterr.(map[string]interface{})["name"]
				details := reterr.(map[string]interface{})["details"].([]interface{})
				var message string
				if details != nil {
					message = details[0].(map[string]interface{})["message"].(string)
				}
				err = fmt.Errorf("%v, message: %v", name, message)
				return
			}
			err = fmt.Errorf("  %v", ret)
			return
		}
		tfData := retStruct["trx"].(map[string]interface{})["actions"].([]interface{})[0].(map[string]interface{})["data"].(map[string]interface{})
		fromAddress = tfData["from"].(string)
		toAddress := tfData["receiver"].(string)
		transferAmount := big.NewInt(int64(tfData["transfer"].(float64)))
		txOutput := types.TxOutput{
			ToAddress: toAddress,
			Amount: transferAmount,
		}
		txOutputs = append(txOutputs, txOutput)
		return
	*/
	req := BALANCE_SERVER + "get_tx?txhash=" + txhash
	resp, err1 := http.Get(req)
	if err1 != nil {
		err = err1
		return
	}
	defer resp.Body.Close()
	body, err2 := ioutil.ReadAll(resp.Body)
	if err2 != nil {
		err = err2
		return
	}
	var b interface{}
	err3 := json.Unmarshal(body, &b)
	if err3 != nil {
		err = err3
		return
	}
	txstrI := b.(map[string]interface{})["Tx"]
	if txstrI == nil {
		return
	}
	txstr := txstrI.(string)
	txstr = strings.Replace(txstr, "\\", "", -1)
	var eostx EOSTx
	err4 := json.Unmarshal([]byte(txstr), &eostx)
	if err4 != nil {
		err = err4
		return
	}
	fromAddress = eostx.FromAddress
	for _, x := range eostx.TxOutputs {
		txOutputs = append(txOutputs, *x.ToTxOutput())
	}

	// eos transaction confirmed
	confirmed = eostx.Confirmed
	fee.Cointype = "EOS"
	fee.Val = big.NewInt(eostx.Fee)

	return
}

type EOSTx struct {
	FromAddress string
	TxOutputs   []EOSTxOutput
	Fee         int64
	Confirmed   bool
}

type EOSTxOutput struct {
	ToAddress string
	Amount    string
}

func (e *EOSTxOutput) ToTxOutput() *types.TxOutput {
	amt, _ := new(big.Int).SetString(e.Amount, 10)
	return &types.TxOutput{
		ToAddress: e.ToAddress,
		Amount:    amt,
	}
}

func (h *EOSHandler) GetAddressBalance(address string, jsonstring string) (balance types.Balance, err error) {
	req := BALANCE_SERVER + "get_balance?user_key=" + address
	resp, err := http.Get(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return
	}
	var b interface{}
	err = json.Unmarshal(body, &b)
	if err != nil {
		return
	}
	bal := b.(map[string]interface{})["balance"]
	if bal == nil {
		return
	}
	balance.CoinBalance.Cointype = "EOS"
	val, ok := new(big.Int).SetString(bal.(string), 10)
	balance.CoinBalance.Val = val
	if !ok {
		err = fmt.Errorf("parse balance error, got: %+v", bal)
	}
	return
}

func checkErr(err error) {
	if err != nil {
		panic(err.Error())
		return
	}
}

func checkAPIErr(res string) error {
	var v interface{}
	err := json.Unmarshal([]byte(res), &v)
	if err != nil {
		return err
	}
	m := v.(map[string]interface{})
	if m["error"] != nil {
		if errm := m["error"].(map[string]interface{}); len(errm) > 0 {
			err = fmt.Errorf(errm["name"].(string), errm)
			return err
		}
	}
	return nil
}

//func IsCanonical(compactSig []byte) bool {
func IsCanonical(rsv []byte) bool {
	rsvstr := hex.EncodeToString(rsv)
	compactSig, err := RSVToSignature(rsvstr)
	if err != nil {
		return false
	}
	// From EOS's codebase, our way of doing Canonical sigs.
	// https://steemit.com/steem/@dantheman/steem-and-bitshares-cryptographic-security-update

	d := compactSig.Content
	t1 := (d[1] & 0x80) == 0
	t2 := !(d[1] == 0 && ((d[2] & 0x80) == 0))
	t3 := (d[33] & 0x80) == 0
	t4 := !(d[33] == 0 && ((d[34] & 0x80) == 0))

	return t1 && t2 && t3 && t4
}

func GetHeadBlockID(nodeos string) (chainID string, err error) {
	api := "v1/chain/get_info"
	res := rpcutils.DoCurlRequest(nodeos, api, "")
	if err = checkAPIErr(res); err != nil {
		return "", err
	}
	var v interface{}
	json.Unmarshal([]byte(res), &v)
	m := v.(map[string]interface{})
	return fmt.Sprintf("%v", m["head_block_id"]), nil
}

func PubKeyToHex(pk string) (pubKeyHex string, _ error) {
	pubKey, err := ecc.NewPublicKey(pk)
	if err != nil {
		return "", err
	}
	pubKeyHex = "0x" + hex.EncodeToString(pubKey.Content)
	return
}

func HexToPubKey(pubKeyHex string) (ecc.PublicKey, error) {
	fmt.Printf("hex is %v\nlen(hex) is %v\n\n", pubKeyHex, len(pubKeyHex))
	pubKeyHex = strings.TrimPrefix(pubKeyHex, "0x")
	// TODO 判断长度
	if len(pubKeyHex) == 130 {
		uBytes, err := hex.DecodeString(pubKeyHex)
		if err != nil {
			return ecc.PublicKey{}, err
		}
		pubkey, err := btcec.ParsePubKey(uBytes, btcec.S256())
		if err != nil {
			return ecc.PublicKey{}, err
		}
		pubkeyBytes := pubkey.SerializeCompressed()
		pubkeyBytes = append([]byte{0}, pubkeyBytes...) // byte{0} 表示 curve K1, byte{1} 表示 curve R1
		return ecc.NewPublicKeyFromData(pubkeyBytes)
	}

	if len(pubKeyHex) == 66 {
		pubkeyBytes, _ := hex.DecodeString(pubKeyHex)
		pubkeyBytes = append([]byte{0}, pubkeyBytes...)
		return ecc.NewPublicKeyFromData(pubkeyBytes)
	}

	return ecc.PublicKey{}, fmt.Errorf("unexpected public key length  %v", len(pubKeyHex))
}

func SignDigestWithPrivKey(hash, wif string) (ecc.Signature, error) {
	digest := hexToChecksum256(hash)
	privKey, err := ecc.NewPrivateKey(wif)
	fmt.Printf("private key is %+v\n\n", privKey)
	//checkErr(err)
	if err != nil {
		return ecc.Signature{}, err
	}
	return privKey.Sign(digest)
}

func GetAccountNameByPubKey(pubKey string) ([]string, error) {
	api := "v1/history/get_key_accounts"
	data := "{\"public_key\":\"" + pubKey + "\"}"
	res := rpcutils.DoCurlRequest(nodeos, api, data)
	if err := checkAPIErr(res); err != nil {
		return nil, err
	}
	var v interface{}
	json.Unmarshal([]byte(res), &v)
	m := v.(map[string]interface{})
	accts := m["account_names"].([]interface{})
	var accounts []string
	for _, acct := range accts {
		accounts = append(accounts, acct.(string))
	}
	return accounts, nil
}

// dcrm签的rsv转换成eos签名
func RSVToSignature(rsvStr string) (ecc.Signature, error) {
	fmt.Printf("1111 rsvStr is %v\n\n", rsvStr)
	rsv, _ := hex.DecodeString(rsvStr)
	rsv[64] += byte(31)
	fmt.Printf("rsv is %v\n\n", rsv)
	v := rsv[64]
	fmt.Printf("v is %v\n\n", v)
	rs := rsv[:64]
	vrs := append([]byte{v}, rs...)
	fmt.Printf("1111 vrs is %v\n\n", hex.EncodeToString(vrs))
	data := append([]byte{0}, vrs...)
	return ecc.NewSignatureFromData(data)
}

func hexToChecksum256(data string) eos.Checksum256 {
	bytes, err := hex.DecodeString(data)
	//checkErr(err)
	if err != nil {
		return nil
	}
	return eos.Checksum256(bytes)
}

// 根据公钥生成地址
func GenAccountName(pubKeyHex string) string {
	b, _ := hex.DecodeString(pubKeyHex)
	fmt.Printf("!!! %v \n!!! %v\n\n", pubKeyHex, b)

	b = btcutil.Hash160(b)

	b = append([]byte{0}, b...)
	return crypto.Base58Encode(b, ALPHABET)
}

func EOS_newUnsignedTransaction(fromAcctName, toAcctName string, amount *big.Int, memo string) (string, *eos.SignedTransaction, error) {
	from := eos.AccountName(fromAcctName)
	to := eos.AccountName(toAcctName)
	s := strconv.FormatFloat(float64(amount.Int64())/10000, 'f', 4, 64) + " EOS"
	quantity, _ := eos.NewAsset(s)

	transfer := &eos.Action{
		Account: eos.AN("eosio.token"),
		Name:    eos.ActN("transfer"),
		Authorization: []eos.PermissionLevel{
			{
				Actor:      from,
				Permission: eos.PN("active"),
			},
		},
		ActionData: eos.NewActionData(token.Transfer{
			From:     from,
			To:       to,
			Quantity: quantity,
			Memo:     memo,
		}),
	}

	var actions []*eos.Action
	actions = append(actions, transfer)

	// 获取 head block id
	hbid, err := GetHeadBlockID(nodeos)
	if err != nil {
		return "", nil, err
	}
	opts.HeadBlockID = hexToChecksum256(hbid)
	tx := eos.NewTransaction(actions, opts)

	stx := eos.NewSignedTransaction(tx)

	txdata, cfd, err := stx.PackedTransactionAndCFD()
	//checkErr(err)
	if err != nil {
		return "", nil, err
	}
	digest := eos.SigDigest(opts.ChainID, txdata, cfd)
	digestStr := hex.EncodeToString(digest)
	return digestStr, stx, nil
}

func MakeSignedTransaction(stx *eos.SignedTransaction, signature ecc.Signature) *eos.SignedTransaction {
	stx.Signatures = append(stx.Signatures, signature)
	return stx
}

func SubmitTransaction(stx *eos.SignedTransaction) string {

	txjson := stx.String()

	b := "{\"signatures\":[\"" + stx.Signatures[0].String() + "\"], \"compression\":\"none\", \"transaction\":" + txjson + "}"

	res := rpcutils.DoCurlRequest(nodeos, "v1/chain/push_transaction", b)
	return res
}

// 创建eos账户
// 需要一个creator账户, creator要有余额用于购买内存
func CreateNewAccount(creatorName, creatorActivePrivKey, accountName, ownerkey, activekey string, buyram uint32) (bool, error) {
	defer func() {
		if r := recover(); r != nil {
			fmt.Printf("create new account,error = %v\n", r)
		}
	}()

	opubKey, err := ecc.NewPublicKey(ownerkey)
	if err != nil {
		return false, err
	}
	apubKey, err := ecc.NewPublicKey(activekey)
	if err != nil {
		return false, err
	}

	// 创建账户action
	action1 := &eos.Action{
		Account: eos.AccountName("eosio"),
		Name:    eos.ActionName("newaccount"),
		Authorization: []eos.PermissionLevel{
			{eos.AccountName(creatorName), eos.PermissionName("active")},
		},
		ActionData: eos.NewActionData(system.NewAccount{
			Creator: eos.AccountName(creatorName),
			Name:    eos.AccountName(accountName),
			Owner: eos.Authority{
				Threshold: 1,
				Keys: []eos.KeyWeight{
					{
						PublicKey: opubKey,
						Weight:    1,
					},
				},
			},
			Active: eos.Authority{
				Threshold: 1,
				Keys: []eos.KeyWeight{
					{
						PublicKey: apubKey,
						Weight:    1,
					},
				},
			},
		}),
	}

	// 买内存action
	action2 := system.NewBuyRAMBytes(eos.AccountName(creatorName), eos.AccountName(accountName), buyram)

	// 获取 head block id
	hbid, err := GetHeadBlockID(nodeos)
	//checkErr(err)
	if err != nil {
		return false, err
	}
	opts.HeadBlockID = hexToChecksum256(hbid)

	// 创建账户和买内存一定要同时执行
	actions := []*eos.Action{action1, action2}

	tx := eos.NewTransaction(actions, opts)

	stx := eos.NewSignedTransaction(tx)

	txdata, cfd, err := stx.PackedTransactionAndCFD()
	//checkErr(err)
	if err != nil {
		return false, err
	}
	digest := eos.SigDigest(opts.ChainID, txdata, cfd)
	digestStr := hex.EncodeToString(digest)

	signature, err := SignDigestWithPrivKey(digestStr, creatorActivePrivKey)
	if err != nil {
		return false, err
	}

	stx.Signatures = append(stx.Signatures, signature)

	txjson := stx.String()

	b := "{\"signatures\":[\"" + stx.Signatures[0].String() + "\"], \"compression\":\"none\", \"transaction\":" + txjson + "}"

	res := rpcutils.DoPostRequest(nodeos, "v1/chain/push_transaction", b)
	if err = checkAPIErr(res); err != nil {
		return false, err
	}
	return true, nil
}

// 预购cpu和net带宽, 用于帐号执行各种action
func DelegateBW(fromAcctName, fromActivePrivKey, receiverName string, stakeCPU, stakeNet int64, transfer bool) (bool, error) {
	from := eos.AccountName(fromAcctName)
	receiver := eos.AccountName(receiverName)
	action := system.NewDelegateBW(from, receiver, eos.NewEOSAsset(stakeCPU), eos.NewEOSAsset(stakeNet), transfer)

	// 获取 head block id
	hbid, err := GetHeadBlockID(nodeos)
	//checkErr(err)
	if err != nil {
		return false, err
	}
	opts.HeadBlockID = hexToChecksum256(hbid)

	actions := []*eos.Action{action}
	tx := eos.NewTransaction(actions, opts)
	stx := eos.NewSignedTransaction(tx)
	txdata, cfd, err := stx.PackedTransactionAndCFD()
	//checkErr(err)
	if err != nil {
		return false, err
	}
	digest := eos.SigDigest(opts.ChainID, txdata, cfd)
	digestStr := hex.EncodeToString(digest)
	signature, err := SignDigestWithPrivKey(digestStr, fromActivePrivKey)
	if err != nil {
		return false, err
	}
	stx.Signatures = append(stx.Signatures, signature)

	txjson := stx.String()
	b := "{\"signatures\":[\"" + stx.Signatures[0].String() + "\"], \"compression\":\"none\", \"transaction\":" + txjson + "}"
	res := rpcutils.DoPostRequest(nodeos, "v1/chain/push_transaction", b)
	if err = checkAPIErr(res); err != nil {
		return false, err
	}
	return true, nil
}
