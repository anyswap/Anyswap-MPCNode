package btc

import (
	"bytes"
	"compress/gzip"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"math/big"
	"net/http"
	"runtime/debug"
	"sort"
	"strings"

	"github.com/btcsuite/btcd/btcec"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/btcjson"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcutil"

	"github.com/btcsuite/btcwallet/wallet/txauthor"
	"github.com/btcsuite/btcwallet/wallet/txrules"

	"github.com/fsn-dev/dcrm-walletService/crypto"
	"github.com/fsn-dev/dcrm-walletService/internal/common"
	rpcutils "github.com/fsn-dev/dcrm-walletService/coins/rpcutils"
	"github.com/fsn-dev/dcrm-walletService/coins/config"
	"github.com/fsn-dev/dcrm-walletService/coins/types"
)

func BTCInit() {
	ChainConfig = chaincfg.TestNet3Params
	RequiredConfirmations = int64(1)
	allowHighFees = true
	feeRate, _ = btcutil.NewAmount(0.0001)
	hashType = txscript.SigHashAll
}

var ChainConfig = chaincfg.TestNet3Params

var RequiredConfirmations int64

var allowHighFees bool

var feeRate, _ = btcutil.NewAmount(0.0001)

var hashType = txscript.SigHashAll

type BTCHandler struct{
	serverHost string
	serverPort int
	rpcuser string
	passwd string
	usessl bool
}

func NewBTCHandler () *BTCHandler {
	return &BTCHandler{
		serverHost: config.ApiGateways.BitcoinGateway.Host,
		serverPort: config.ApiGateways.BitcoinGateway.Port,
		rpcuser: config.ApiGateways.BitcoinGateway.User,
		passwd: config.ApiGateways.BitcoinGateway.Passwd,
		usessl: config.ApiGateways.BitcoincashGateway.Usessl,
	}
}

func NewBTCHandlerWithConfig (userServerHost string, suserServerPort int, userRpcuser, userPasswd string, userUsessl bool) *BTCHandler {
		return &BTCHandler{
			serverHost: userServerHost,
			serverPort: suserServerPort,
			rpcuser: userRpcuser,
			passwd: userPasswd,
			usessl: userUsessl,
		}
}

var BTC_DEFAULT_FEE, _ = new(big.Int).SetString("50000",10)

func (h *BTCHandler) GetDefaultFee() types.Value {
	return types.Value{Cointype:"BTC",Val:BTC_DEFAULT_FEE}
}

func (h *BTCHandler) PublicKeyToAddress(pubKeyHex string) (address string, err error){
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
	addressPubKeyHash, err := btcutil.NewAddressPubKeyHash(pkHash, &ChainConfig)
	if err != nil {
		return
	}
	address = addressPubKeyHash.EncodeAddress()
	return
}

// jsonstring: '{"feeRate":0.0001,"changAddress":"mtjq9RmBBDVne7YB4AFHYCZFn3P2AXv9D5"}'
func (h *BTCHandler) BuildUnsignedTransaction(fromAddress, fromPublicKey, toAddress string, amount *big.Int, jsonstring string) (transaction interface{}, digests []string, err error) {
	defer func () {
		if e := recover(); e != nil {
			err = fmt.Errorf("Runtime error: %v\n%v", e, string(debug.Stack()))
			return
		}
	} ()
	changeAddress := fromAddress
	var args interface{}
	json.Unmarshal([]byte(jsonstring), &args)
	if args != nil {
		userFeeRate := args.(map[string]interface{})["feeRate"]
		userChangeAddress := args.(map[string]interface{})["changeAddress"]
		if userFeeRate != nil {
			feeRate, err = btcutil.NewAmount(userFeeRate.(float64))
			if err != nil {
				return
			}
		}
		if userChangeAddress != nil {
			changeAddress = userChangeAddress.(string)
		}
	}
//unspentOutputs, _, err := listUnspent_electrs(fromAddress)
	unspentOutputs, _, err := ListUnspent_BTCD(fromAddress)
//unspentOutputs, err := listUnspent_blockchaininfo(fromAddress)
//unspentOutputs, err := listUnspent(fromAddress)
	if err != nil {
		err = errContext(err, "failed to fetch unspent outputs")
		return
	}
	sourceOutputs := make(map[string][]btcjson.ListUnspentResult)
	for _, unspentOutput := range unspentOutputs {
		if !unspentOutput.Spendable {
			continue
		}
		if unspentOutput.Confirmations < RequiredConfirmations {
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
	// 生成锁定脚本
	var txOuts []*wire.TxOut
	toAddr, _ := btcutil.DecodeAddress(toAddress, &ChainConfig)
	pkscript, _ := txscript.PayToAddrScript(toAddr)
	txOut := wire.NewTxOut(amount.Int64(), pkscript)
	txOuts = append(txOuts,txOut)
	if len(sourceOutputs) < 1 {
		err = errContext(err, "cannot find p2pkh utxo")
		return
	}
	previousOutputs := sourceOutputs[fromAddress]
	targetAmount := SumOutputValues(txOuts)
	estimatedSize := EstimateVirtualSize(0, 1, 0, txOuts, true)
	targetFee := txrules.FeeForSerializeSize(feeRate, estimatedSize)
	// 选择utxo作为交易输入
	var inputSource txauthor.InputSource
	for i, _ := range previousOutputs {
		inputSource = makeInputSource(previousOutputs[:i+1])
		inputAmount, _, _, _, err1 := inputSource(targetAmount + targetFee)
		if err1 != nil {
			err = err1
			return
		}
		if inputAmount < targetAmount+targetFee {
			continue
		} else {
			break
		}
	}
	// 设置找零
	changeAddr, _ := btcutil.DecodeAddress(changeAddress, &ChainConfig)
	changeSource := func()([]byte,error){
		return txscript.PayToAddrScript(changeAddr)
	}
	transaction, err = newUnsignedTransaction(txOuts, feeRate, inputSource, changeSource)
	if err != nil {
		return
	}

	for idx, _ := range transaction.(*AuthoredTx).Tx.TxIn {
		pkscript, _ := hex.DecodeString(previousOutputs[idx].ScriptPubKey)

		txhashbytes, err1 := txscript.CalcSignatureHash(pkscript, hashType, transaction.(*AuthoredTx).Tx, idx)
		if err1 != nil {
			err = err1
			return
		}
		txhash := hex.EncodeToString(txhashbytes)
		digests = append(digests, txhash)
	}
	transaction.(*AuthoredTx).Digests = digests

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
	transaction.(*AuthoredTx).PubKeyData = pubKey.SerializeCompressed()

	return
}

func (h *BTCHandler) SignTransaction(hash []string, wif interface{}) (rsv []string, err error){
	pkwif, err :=  btcutil.DecodeWIF(wif.(string))
	if err != nil {
		return
	}
	privateKey := pkwif.PrivKey
	for _, hs := range hash {
		b, err1 := hex.DecodeString(hs)
		if err1 != nil {
			err = err1
			return
		}
		signature, err2 := privateKey.Sign(b)
		if err2 != nil {
			err = err2
			return
		}
		rr := fmt.Sprintf("%X", signature.R)
		ss := fmt.Sprintf("%X", signature.S)
fmt.Printf("r, s: %v\n%v\n\n", rr, ss)
		for len(rr) < 64 {
			rr = "0" + rr
		}
		for len(ss) < 64 {
			ss = "0" + ss
		}
		str := fmt.Sprintf("%s%s00", rr, ss)
		rsv = append(rsv, str)
	}
	return
}

func (h *BTCHandler) MakeSignedTransaction(rsv []string, transaction interface{}) (signedTransaction interface{}, err error){
	txIn := transaction.(*AuthoredTx).Tx.TxIn
	if len(txIn) != len(rsv) {
		err = fmt.Errorf("signatures number does not match transaction inputs number")
		return
	}
	if len(transaction.(*AuthoredTx).Digests) != len(txIn) {
		err = fmt.Errorf("digests number does not match transaction inputs number")
		return
	}
	for i, txin := range txIn {
		l := len(rsv[i])-2
		rs := rsv[i][0:l]

		r := rs[:64]
		s := rs[64:]

		rr, _ := new(big.Int).SetString(r,16)
		ss, _ := new(big.Int).SetString(s,16)

		sign := &btcec.Signature{
			R: rr,
			S: ss,
		}

		//fmt.Println("dcrm sign is ",sign)
		// r, s 转成BTC标准格式的签名, 添加hashType
		signbytes := append(sign.Serialize(), byte(hashType))

		// 从rsv中恢复公钥
		rsv_bytes, _ := hex.DecodeString(rsv[i])
		txhashbytes, _ := hex.DecodeString(transaction.(*AuthoredTx).Digests[i])
		pkData, err1 := crypto.Ecrecover(txhashbytes, rsv_bytes)
		if err1 != nil {
			err = err1
			return
		}
		pk, _ := btcec.ParsePubKey(pkData, btcec.S256())
		cPkData := pk.SerializeCompressed()

		cPkData1 := transaction.(*AuthoredTx).PubKeyData
		if string(cPkData) != string(cPkData1) {
			//err = fmt.Errorf("recover public key error: got %v, want %v", cPkData, cPkData1)
			//return
			cPkData = cPkData1
		}

		sigScript, err2 := txscript.NewScriptBuilder().AddData(signbytes).AddData(cPkData).Script()
		if err2 != nil {
			err = err2
			return
		}
		txin.SignatureScript = sigScript
	}
	signedTransaction = transaction
	return
}

func (h *BTCHandler) SubmitTransaction(signedTransaction interface{}) (ret string, err error) {
	c, _ := rpcutils.NewClient(h.serverHost,h.serverPort,h.rpcuser,h.passwd,h.usessl)
	ret, err = SendRawTransaction (c, signedTransaction.(*AuthoredTx).Tx, allowHighFees)
	return
}

func (h *BTCHandler) GetTransactionInfo(txhash string) (fromAddress string, txOutputs []types.TxOutput, jsonstring string, confirmed bool, fee types.Value, err error) {
	defer func () {
		if e := recover(); e != nil {
			err = fmt.Errorf("Runtime error: %v\n%v", e, string(debug.Stack()))
			return
		}
	} ()

	fee = h.GetDefaultFee()
	grtreq := `{"jsonrpc":"1.0","method":"getrawtransaction","params":["` + txhash + `",true],"id":1}`
	client, _ := rpcutils.NewClient(h.serverHost,h.serverPort,h.rpcuser,h.passwd,h.usessl)
	ret1, err := client.Send(grtreq)
	if err != nil {
		return
	} else {
		var ret1Obj interface{}
		common.Debug("==================btc.GetTransactionInfo===============","getrawtransaction result",ret1)
		json.Unmarshal([]byte(ret1), &ret1Obj)
		confirmations := ret1Obj.(map[string]interface{})["result"].(map[string]interface{})["confirmations"]
		if confirmations == nil {
			confirmed = false
		} else {
			common.Debug("=================btc.GetTransactionInfo=================","confirmations",confirmations)
			confirmed = (int64(confirmations.(float64)) >= RequiredConfirmations)
		}
	}

	cmd := btcjson.NewGetRawTransactionCmd(txhash, nil)
	common.Debug("==================btc.GetTransactionInfo===============","get raw transaction cmd",cmd)

	marshalledJSON, err := btcjson.MarshalCmd(1, cmd)
	if err != nil {
		return
	}

	common.Debug("==================btc.GetTransactionInfo===============","get raw transaction json 111111",string(marshalledJSON))
	c, _ := rpcutils.NewClient(h.serverHost,h.serverPort,h.rpcuser,h.passwd,h.usessl)
	retJSON, err := c.Send(string(marshalledJSON))
	if err != nil {
		return
	}

	common.Debug("==================btc.GetTransactionInfo===============","get raw transaction json 2222222",string(retJSON))
	var rawTx interface{}
	json.Unmarshal([]byte(retJSON), &rawTx)
	rawTxStr := rawTx.(map[string]interface{})["result"].(string)

	common.Debug("==================btc.GetTransactionInfo===============","rawTxStr",string(rawTxStr))
	cmd2 := btcjson.NewDecodeRawTransactionCmd(rawTxStr)

	common.Debug("==================btc.GetTransactionInfo===============","get raw transaction cmd2",cmd2)
	marshalledJSON2, err := btcjson.MarshalCmd(1, cmd2)
	if err != nil {
		return
	}
	common.Debug("==================btc.GetTransactionInfo===============","get raw transaction json 33333333",string(marshalledJSON2))
	
	retJSON2, err := c.Send(string(marshalledJSON2))
	common.Debug("==================btc.GetTransactionInfo===============","get raw transaction json 44444444",string(retJSON2))
	
	var tx interface{}
	json.Unmarshal([]byte(retJSON2), &tx)
	vouts := tx.(map[string]interface{})["result"].(map[string]interface{})["vout"].([]interface{})
	for _, vout := range vouts {
		toAddress := vout.(map[string]interface{})["scriptPubKey"].(map[string]interface{})["addresses"].([]interface{})[0].(string)
		flt := vout.(map[string]interface{})["value"].(float64)
		amt, _ := btcutil.NewAmount(flt)
		transferAmount := big.NewInt(int64(amt.ToUnit(btcutil.AmountSatoshi)))
		common.Debug("==================btc.GetTransactionInfo===============","toAddress",toAddress,"transferAmount",transferAmount)
		txOutputs = append(txOutputs, types.TxOutput{ToAddress:toAddress, Amount:transferAmount})
	}

	vins := tx.(map[string]interface{})["result"].(map[string]interface{})["vin"].([]interface{})
	var vintx interface{}
	for _, vin := range vins {
		vintx = vin.(map[string]interface{})["txid"]
		if vintx != nil {
			break
		}
	}
	if vintx == nil {
		coinbase := tx.(map[string]interface{})["result"].(map[string]interface{})["vin"].([]interface{})[0].(map[string]interface{})["coinbase"]
		fromAddress = coinbase.(string)
		common.Debug("==================btc.GetTransactionInfo===============","fromAddress 1111",string(fromAddress))
	}
	vintxid := vintx.(string)
	vinvout := int(tx.(map[string]interface{})["result"].(map[string]interface{})["vin"].([]interface{})[0].(map[string]interface{})["vout"].(float64))

	common.Debug("==================btc.GetTransactionInfo===============","vintxid",string(vintxid))
	cmd3 := btcjson.NewGetRawTransactionCmd(vintxid, nil)

	common.Debug("==================btc.GetTransactionInfo===============","cmd3",cmd3)
	marshalledJSON3, err := btcjson.MarshalCmd(1, cmd3)
	if err != nil {
		return
	}

	common.Debug("==================btc.GetTransactionInfo===============","marshalledJSON3",string(marshalledJSON3))
	retJSON3, err := c.Send(string(marshalledJSON3))
	if err != nil {
		return
	}
	common.Debug("==================btc.GetTransactionInfo===============","retJSON3",string(retJSON3))

	var rawTx2 interface{}
	json.Unmarshal([]byte(retJSON3), &rawTx2)
	rawTxStr2 := rawTx2.(map[string]interface{})["result"].(string)

	common.Debug("==================btc.GetTransactionInfo===============","rawTxStr2",string(rawTxStr2))
	cmd4 := btcjson.NewDecodeRawTransactionCmd(rawTxStr2)
	common.Debug("==================btc.GetTransactionInfo===============","cmd4",cmd4)

	marshalledJSON4, err := btcjson.MarshalCmd(1, cmd4)
	if err != nil {
		return
	}
	common.Debug("==================btc.GetTransactionInfo===============","marshalledJSON4",string(marshalledJSON4))

	retJSON4, err := c.Send(string(marshalledJSON4))
	if err != nil {
		return
	}
	common.Debug("==================btc.GetTransactionInfo===============","retJSON4",string(retJSON4))

	var tx2 interface{}
	json.Unmarshal([]byte(retJSON4), &tx2)

	fromAddress = tx2.(map[string]interface{})["result"].(map[string]interface{})["vout"].([]interface{})[vinvout].(map[string]interface{})["scriptPubKey"].(map[string]interface{})["addresses"].([]interface{})[0].(string)
	common.Debug("==================btc.GetTransactionInfo===============","fromAddress 2222",string(fromAddress))

	electrstx, err := GetTransaction_electrs(txhash)
	if err != nil {
		return
	}
	fee.Val = big.NewInt(int64(electrstx.Fee))

	return
}

func (h *BTCHandler) GetAddressBalance(address string, jsonstring string) (balance types.Balance, err error) {
	/*addrsUrl := "https://api.blockcypher.com/v1/btc/test3/addrs/" + address
	resstr := loginPre1("GET",addrsUrl)
	if resstr == "" {
		err = fmt.Errorf("cannot get address balance, blockcypher didnt response")
		return
	}

	addrApiResult := parseAddrApiResult(resstr)
	balance = big.NewInt(int64(addrApiResult.Balance))
	return*/
	//_, bal, err := listUnspent_electrs(address)
	_, bal, err := ListUnspent_BTCD(address)
	common.Debug("============btc.GetAddressBalance============","balance",bal,"error",err)
	balance.CoinBalance = types.Value{Cointype:"BTC",Val:bal}
	return
}

func (h *BTCHandler) IsToken() bool {
	return false
}

func NewUnsignedTransaction(outputs []*wire.TxOut, relayFeePerKb btcutil.Amount, fetchInputs txauthor.InputSource, fetchChange txauthor.ChangeSource) (*AuthoredTx, error) {
	return newUnsignedTransaction(outputs, relayFeePerKb, fetchInputs, fetchChange)
}

// noInputValue describes an error returned by the input source when no inputs
// were selected because each previous output value was zero.  Callers of
// newUnsignedTransaction need not report these errors to the user.
type noInputValue struct {
}

func (noInputValue) Error() string {
	return "no input value"
}

func errContext(err error, context string) error {
        return fmt.Errorf("%s: %v", context, err)
}

func pickNoun(n int, singularForm, pluralForm string) string {
        if n == 1 {
                return singularForm
        }
        return pluralForm
}


type AuthoredTx struct {
	Tx              *wire.MsgTx
	PrevScripts     [][]byte
	PrevInputValues []btcutil.Amount
	TotalInput      btcutil.Amount
	ChangeIndex     int // negative if no change
	Digests		[]string
	PubKeyData	[]byte
}

// newUnsignedTransaction creates an unsigned transaction paying to one or more
// non-change outputs.  An appropriate transaction fee is included based on the
// transaction size.
//
// Transaction inputs are chosen from repeated calls to fetchInputs withtxrules
// increasing targets amounts.
//
// If any remaining output value can be returned to the wallet via a change
// output without violating mempool dust rules, a P2WPKH change output is
// appended to the transaction outputs.  Since the change output may not be
// necessary, fetchChange is called zero or one times to generate this script.
// This function must return a P2WPKH script or smaller, otherwise fee estimation
// will be incorrect.
//
// If successful, the transaction, total input value spent, and all previous
// output scripts are returned.  If the input source was unable to provide
// enough input value to pay for every output any any necessary fees, an
// InputSourceError is returned.
//
// BUGS: Fee estimation may be off when redeeming non-compressed P2PKH outputs.
func newUnsignedTransaction(outputs []*wire.TxOut, relayFeePerKb btcutil.Amount,
	fetchInputs txauthor.InputSource, fetchChange txauthor.ChangeSource) (*AuthoredTx, error) {
	targetAmount := SumOutputValues(outputs)
	estimatedSize := EstimateVirtualSize(0, 1, 0, outputs, true)
	targetFee := txrules.FeeForSerializeSize(relayFeePerKb, estimatedSize)

	for {
		inputAmount, inputs, inputValues, scripts, err := fetchInputs(targetAmount + targetFee)
		if err != nil {
			return nil, err
		}
		if inputAmount < targetAmount+targetFee {
			return nil, fmt.Errorf("insufficient funds")
		}
		// We count the types of inputs, which we'll use to estimate
		// the vsize of the transaction.
		var nested, p2wpkh, p2pkh int
		for _, pkScript := range scripts {
			switch {
			// If this is a p2sh output, we assume this is a
			// nested P2WKH.
			case txscript.IsPayToScriptHash(pkScript):
				nested++
			case txscript.IsPayToWitnessPubKeyHash(pkScript):
				p2wpkh++
			default:
				p2pkh++
			}
		}
		maxSignedSize := EstimateVirtualSize(p2pkh, p2wpkh,
			nested, outputs, true)
		maxRequiredFee := txrules.FeeForSerializeSize(relayFeePerKb, maxSignedSize)
		remainingAmount := inputAmount - targetAmount
		if remainingAmount < maxRequiredFee {
			targetFee = maxRequiredFee
			continue
		}

		unsignedTransaction := &wire.MsgTx{
			Version:  wire.TxVersion,
			TxIn:     inputs,
			TxOut:    outputs,
			LockTime: 0,
		}
		changeIndex := -1
		changeAmount := inputAmount - targetAmount - maxRequiredFee
		if changeAmount != 0 && !txrules.IsDustAmount(changeAmount,
			P2WPKHPkScriptSize, relayFeePerKb) {
			changeScript, err := fetchChange()
			if err != nil {
				return nil, err
			}

			change := wire.NewTxOut(int64(changeAmount), changeScript)
			l := len(outputs)
			unsignedTransaction.TxOut = append(outputs[:l:l], change)
			changeIndex = l
		}

		return &AuthoredTx{
			Tx:              unsignedTransaction,
			PrevScripts:     scripts,
			PrevInputValues: inputValues,
			TotalInput:      inputAmount,
			ChangeIndex:     changeIndex,
		}, nil
	}
}

// 发送交易
func SendRawTransaction (c *rpcutils.RpcClient, tx *wire.MsgTx, allowHighFees bool) (ret string, err error){
	defer func () {
		if e := recover(); e != nil {
			err = fmt.Errorf("Runtime error: %v\n%v", e, string(debug.Stack()))
			return
		}
	} ()
	var txHex string
	if tx != nil {
                // Serialize the transaction and convert to hex string.
                buf := bytes.NewBuffer(make([]byte, 0, tx.SerializeSize()))
	if err := tx.Serialize(buf); err != nil {
		return "", err
                }
                txHex = hex.EncodeToString(buf.Bytes())
        }
	cmd := btcjson.NewSendRawTransactionCmd(txHex, &allowHighFees)

	marshalledJSON, err := btcjson.MarshalCmd(1, cmd)
	fmt.Printf("%v\n\n", string(marshalledJSON))
        if err != nil {
		return "", err
	}

	retJSON, err := c.Send(string(marshalledJSON))
	var res interface{}
	json.Unmarshal([]byte(retJSON),&res)
	txhash := res.(map[string]interface{})["result"]
	if txhash == nil {
		return "", fmt.Errorf("retJSON")
	}

	return txhash.(string), err

}

func MakeInputSource(outputs []btcjson.ListUnspentResult) txauthor.InputSource {
	return makeInputSource(outputs)
}

// makeInputSource creates an InputSource that creates inputs for every unspent
// output with non-zero output values.  The target amount is ignored since every
// output is consumed.  The InputSource does not return any previous output
// scripts as they are not needed for creating the unsinged transaction.
func makeInputSource(outputs []btcjson.ListUnspentResult) txauthor.InputSource {
	var (
		totalInputValue btcutil.Amount
		inputs          = make([]*wire.TxIn, 0, len(outputs))
		inputValues     = make([]btcutil.Amount, 0, len(outputs))
		sourceErr       error
	)
	for _, output := range outputs {
		outputAmount, err := btcutil.NewAmount(output.Amount)
		if err != nil {
			sourceErr = fmt.Errorf(
				"invalid amount `%v` in listunspent result",
				output.Amount)
			break
		}
		if outputAmount == 0 {
			continue
		}
		if !saneOutputValue(outputAmount) {
			sourceErr = fmt.Errorf(
				"impossible output amount `%v` in listunspent result",
				outputAmount)
			break
		}
		totalInputValue += outputAmount

		previousOutPoint, err := parseOutPoint(&output)
		if err != nil {
			sourceErr = fmt.Errorf(
				"invalid data in listunspent result: %v",
				err)
			break
		}

		inputs = append(inputs, wire.NewTxIn(&previousOutPoint, nil, nil))
		inputValues = append(inputValues, outputAmount)
	}

	if sourceErr == nil && totalInputValue == 0 {
		sourceErr = noInputValue{}
	}

	return func(btcutil.Amount) (btcutil.Amount, []*wire.TxIn, []btcutil.Amount, [][]byte, error) {
		return totalInputValue, inputs, inputValues, nil, sourceErr
	}
}

func parseOutPoint(input *btcjson.ListUnspentResult) (wire.OutPoint, error) {
        txHash, err := chainhash.NewHashFromStr(input.TxID)
        if err != nil {
                return wire.OutPoint{}, err
        }
        return wire.OutPoint{Hash: *txHash, Index: input.Vout}, nil
}

func saneOutputValue(amount btcutil.Amount) bool {
        return amount >= 0 && amount <= btcutil.MaxSatoshi
}

type AddrApiResult struct {
	Address string
	Total_received float64
	Balance float64
	Unconfirmed_balance uint64
	Final_balance float64
	N_tx int64
	Unconfirmed_n_tx int64
	Final_n_tx int64
	Txrefs []Txref
	Tx_url string
}

// Txref 表示一次交易中的第 Tx_input_n 个输入, 或第 Tx_output_n 个输出
// 如果是一个输入, Tx_input_n = -1
// 如果是一个输出, Tx_output_n = -1
// 如果表示交易输出，spent表示是否花出
type Txref struct {
	Tx_hash string
	Block_height int64
	Tx_input_n int32
	Tx_output_n int32
	Value float64
	Ref_balance float64
	Spent bool
	Confirmations int64
	Confirmed string
	Double_spend bool
}

type TxApiResult struct {
	TxHash string
	Outputs []Output
}

type Output struct {
	Script string
	Addresses []string
}

func parseAddrApiResult (resstr string) *AddrApiResult {
	resstr = strings.Replace(resstr, " ", "", -1)
	resstr = strings.Replace(resstr, "\n", "", -1)

	last_index := len(resstr)-1
	for last_index > 0 {
		if resstr[last_index] != '}' {
			last_index --
		} else {
			break
		}
	}

	res := &AddrApiResult{}
	_ = json.Unmarshal([]byte(resstr)[:last_index+1], res)
	return res
}

func parseTxApiResult (resstr string) *TxApiResult {
	resstr = strings.Replace(resstr, " ", "", -1)
	resstr = strings.Replace(resstr, "\n", "", -1)

	last_index := len(resstr)-1
	for last_index > 0 {
		if resstr[last_index] != '}' {
			last_index --
		} else {
			break
		}
	}

	res := &TxApiResult{}
	_ = json.Unmarshal([]byte(resstr)[:last_index+1], res)
	return res
}

// 使用 addrs 接口查询属于dcrm地址的交易信息，其中包含dcrm地址的utxo
func listUnspent(dcrmaddr string) ([]btcjson.ListUnspentResult, error) {
	addrsUrl := "https://api.blockcypher.com/v1/btc/test3/addrs/" + dcrmaddr
	resstr := loginPre1("GET",addrsUrl)
	if resstr == "" {
		return nil, fmt.Errorf("cannont get address's utxo, blockcypher didnt response")
	}

	addrApiResult := parseAddrApiResult(resstr)

	// addrs 接口查询到的交易信息中不包含上交易输出的锁定脚本
	// 使用 txs 接口查询交易的详细信息，得到锁定脚本，用于交易签名
fmt.Println("listUnspent lalala")
	return makeListUnspentResult(addrApiResult, dcrmaddr)
}

func getTxByTxHash (txhash string) (*TxApiResult, error) {
	addrsUrl := "https://api.blockcypher.com/v1/btc/test3/txs/" + txhash
	resstr := loginPre1("GET",addrsUrl)
	return parseTxApiResult(resstr), nil
}

func makeListUnspentResult (r *AddrApiResult, dcrmaddr string) ([]btcjson.ListUnspentResult, error) {
	//cnt := 0
	//var list []btcjson.ListUnspentResult

fmt.Println("make list unspent result")
fmt.Println(r.Txrefs)
fmt.Printf("length is %v\n\n",len(r.Txrefs))

	var list sortableLURSlice
	for _, txref := range r.Txrefs {
		// 判断 txref 是否是未花费的交易输出
		if txref.Tx_output_n >= 0 && !txref.Spent {
			res := btcjson.ListUnspentResult{
				TxID: txref.Tx_hash,
				Vout: uint32(txref.Tx_output_n),
				Address: dcrmaddr,
				//ScriptPubKey:
				//RedeemScript:
				Amount: txref.Value/1e8,
				Confirmations: txref.Confirmations,
				Spendable: !txref.Spent,
			}
			// 调用 txs 接口，获得上一笔交易输出的锁定脚本
			txRes, err := getTxByTxHash(txref.Tx_hash)
			if err != nil {
				continue
			}
if txRes == nil || len(txRes.Outputs) <= 0 {
	continue
}

fmt.Printf("txref.Tx_output_n is %v\n\n", txref.Tx_output_n)
fmt.Printf("txRes.Outputs is %v\n\n", txRes.Outputs)

			res.ScriptPubKey = txRes.Outputs[txref.Tx_output_n].Script
			list = append(list, res)
		}
        }
	sort.Sort(list)
	return list, nil
}

type sortableLURSlice []btcjson.ListUnspentResult

func (s sortableLURSlice) Len() int {
	return len(s)
}

func (s sortableLURSlice) Less(i, j int) bool {
	return s[i].Amount > s[j].Amount
}

func (s sortableLURSlice) Swap(i, j int) {
	s[i], s[j] = s[j], s[i]
}

//++++++++++++++++++caihaijun+++++++++++++++++++
func loginPre1(method string, url string) string {
	c := &http.Client{}

        //reqest, err := http.NewRequest("GET", "https://api.blockcypher.com/v1/btc/test3/addrs/" + dcrmaddr, nil)

	reqest, err := http.NewRequest(method, url, nil)

    if err != nil {
	    fmt.Println("get Fatal error ", err.Error())
	    return ""
    }

    reqest.Header.Add("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
    reqest.Header.Add("Accept-Encoding", "gzip, deflate")
    reqest.Header.Add("Accept-Language", "zh-cn,zh;q=0.8,en-us;q=0.5,en;q=0.3")
    reqest.Header.Add("Connection", "keep-alive")
    reqest.Header.Add("Host", "login.sina.com.cn")
    reqest.Header.Add("Referer", "http://weibo.com/")
    reqest.Header.Add("User-Agent", "Mozilla/5.0 (Windows NT 6.1; WOW64; rv:12.0) Gecko/20100101 Firefox/12.0")
    response, err := c.Do(reqest)
    if response == nil {
	    return ""
    }
    defer response.Body.Close()

    if err != nil {
	    fmt.Println("Fatal error ", err.Error())
	    return ""
    }

    if response.StatusCode == 200 {

	    var body string

	    switch response.Header.Get("Content-Encoding") {
	    case "gzip":
		    reader, _ := gzip.NewReader(response.Body)
		    for {
			    buf := make([]byte, 1024)
			    n, err := reader.Read(buf)

			    if err != nil && err != io.EOF {
				 panic(err)
				return ""
			    }

			    if n == 0 {
				 break
			    }
			    body += string(buf)
			}
	    default:
		    bodyByte, _ := ioutil.ReadAll(response.Body)
		    body = string(bodyByte)
	    }

	    return body
    }

    return ""
}
//+++++++++++++++++++++end++++++++++++++++++++++

