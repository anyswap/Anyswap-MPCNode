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

package erc20

import  (
	"context"
	"crypto/ecdsa"
	//"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"runtime/debug"
	"strings"
	"time"

	"github.com/fsn-dev/dcrm-sdk/internal/params"
	"github.com/fsn-dev/dcrm-sdk/internal/common"
	ethcrypto "github.com/fsn-dev/dcrm-sdk/crypto"
	"github.com/fsn-dev/dcrm-sdk/crypto/dcrm/cryptocoins/eth/ethclient"

	"github.com/fsn-dev/dcrm-sdk/crypto/dcrm/cryptocoins/config"
	rpcutils "github.com/fsn-dev/dcrm-sdk/crypto/dcrm/cryptocoins/rpcutils"

	ethhandler "github.com/fsn-dev/dcrm-sdk/crypto/dcrm/cryptocoins/eth"
	"github.com/fsn-dev/dcrm-sdk/crypto/dcrm/cryptocoins/eth/sha3"
	"github.com/fsn-dev/dcrm-sdk/crypto/dcrm/cryptocoins/erc20/token"
	"github.com/fsn-dev/dcrm-sdk/crypto/dcrm/cryptocoins/erc20/abi"
	ctypes "github.com/fsn-dev/dcrm-sdk/crypto/dcrm/cryptocoins/types"
)

func ERC20Init() {
	gasPrice = big.NewInt(8000000000)
	gasLimit = uint64(100000)
	url = config.ApiGateways.EthereumGateway.ApiAddress
	chainConfig = params.RinkebyChainConfig
}

var (
	gasPrice *big.Int
	gasLimit uint64
	//gasLimit uint64 = 30000
	//url = config.ETH_GATEWAY
	//url = config.ApiGateways.EthereumGateway.ApiAddress
	url string
	err error
	chainConfig = params.RinkebyChainConfig
	//chainID = big.NewInt(40400)
)

// 返回合约地址或空
var GetToken func (tokentype string) string

func RegisterTokenGetter(callback func (tokentype string) string) {
	GetToken = callback
}

var Tokens map[string]string = map[string]string{
	"ERC20GUSD":"0x28a79f9b0fe54a39a0ff4c10feeefa832eeceb78",
	"ERC20BNB":"0x7f30B414A814a6326d38535CA8eb7b9A62Bceae2",
	"ERC20MKR":"0x2c111ede2538400F39368f3A3F22A9ac90A496c7",
	"ERC20HT":"0x3C3d51f6BE72B265fe5a5C6326648C4E204c8B9a",
	"ERC20BNT":"0x14D5913C8396d43aB979D4B29F2102c1C65E18Db",
	"ERC20RMBT":"0x72778a05fc72dd56d5b5a6bac2f045a2a1eb78f2",
}

type ERC20Handler struct {
	TokenType string
}

func NewERC20Handler () *ERC20Handler {
	return &ERC20Handler{}
}

func NewERC20TokenHandler (tokenType string) *ERC20Handler {
	if Tokens[tokenType] == "" {
		return nil
	}
	return &ERC20Handler{
		TokenType: tokenType,
	}
}

var ERC20_DEFAULT_FEE, _ = new(big.Int).SetString("10000000000000000",10)

func (h *ERC20Handler) GetDefaultFee() ctypes.Value {
	return ctypes.Value{Cointype:"ETH",Val:ERC20_DEFAULT_FEE}
}

func (h *ERC20Handler)  IsToken() bool {
	return true
}

func (h *ERC20Handler) PublicKeyToAddress(pubKeyHex string) (address string, err error) {
	if len(pubKeyHex) != 132 && len(pubKeyHex) != 130 {
		return "", errors.New("invalid public key length")
	}
	pubKeyHex = strings.TrimPrefix(pubKeyHex,"0x")

	data := hexEncPubkey(pubKeyHex[2:])

	pub, err := decodePubkey(data)

	address = ethcrypto.PubkeyToAddress(*pub).Hex()
	return
}

// jsonstring '{"gasPrice":8000000000,"gasLimit":50000,"tokenType":"BNB"}'
func (h *ERC20Handler) BuildUnsignedTransaction(fromAddress, fromPublicKey, toAddress string, amount *big.Int, jsonstring string) (transaction interface{}, digests []string, err error) {
	defer func () {
		if e := recover(); e != nil {
			err = fmt.Errorf("Runtime error: %v\n%v", e, string(debug.Stack()))
			return
		}
	} ()
/*	var args interface{}
	json.Unmarshal([]byte(jsonstring), &args)
	userGasPrice := args.(map[string]interface{})["gasPrice"]
	userGasLimit := args.(map[string]interface{})["gasLimit"]
	userTokenType := args.(map[string]interface{})["tokenType"]
	var tokenType string
	if userTokenType == nil {
		tokenType = h.TokenType
		if tokenType == "" {
			err = fmt.Errorf("token type not specified.")
			return
		}
		if Tokens[tokenType] == "" {
			err = fmt.Errorf("token not supported")
			return
		}
	}
	if userGasPrice != nil {
		gasPrice = big.NewInt(int64(userGasPrice.(float64)))
	}
	if userGasLimit != nil {
		gasLimit = uint64(userGasLimit.(float64))
	}*/
	client, err := ethclient.Dial(url)
	if err != nil {
		return
	}
	transaction, hash, err := erc20_newUnsignedTransaction(client, fromAddress, toAddress, amount, gasPrice, gasLimit, h.TokenType)
	hashStr := hash.Hex()
	if hashStr[:2] == "0x" {
		hashStr = hashStr[2:]
	}
	digests = append(digests, hashStr)
	return
}

/*
func SignTransaction(hash string, address string) (rsv string, err error) {
	return
}
*/

func (h *ERC20Handler) SignTransaction(hash []string, privateKey interface{}) (rsv []string, err error) {
	hashBytes, err := hex.DecodeString(hash[0])
	if err != nil {
		return
	}
	/*r, s, err := ecdsa.Sign(rand.Reader, privateKey.(*ecdsa.PrivateKey), hashBytes)
	if err != nil {
		return
	}
	fmt.Printf("r: %v\ns: %v\n\n", r, s)
	rx := fmt.Sprintf("%X", r)
	sx := fmt.Sprintf("%X", s)
	rsv = append(rsv, rx + sx + "00")*/
	rsvBytes, err := ethcrypto.Sign(hashBytes, privateKey.(*ecdsa.PrivateKey))
	if err != nil {
		return
	}
	rsv = append(rsv, hex.EncodeToString(rsvBytes))
	return
}

func (h *ERC20Handler) MakeSignedTransaction(rsv []string, transaction interface{}) (signedTransaction interface{}, err error) {
	client, err := ethclient.Dial(url)
	if err != nil {
		return
	}
	return makeSignedTransaction(client, transaction.(*ctypes.Transaction), rsv[0])
}

func (h *ERC20Handler) SubmitTransaction(signedTransaction interface{}) (ret string, err error) {
	client, err := ethclient.Dial(url)
	if err != nil {
		return
	}
	return erc20_sendTx(client, signedTransaction.(*ctypes.Transaction))
}

func (h *ERC20Handler) GetTransactionInfo(txhash string) (fromAddress string, txOutputs []ctypes.TxOutput, jsonstring string, confirmed bool, fee ctypes.Value, err error) {
	defer func () {
		if e := recover(); e != nil {
			err = fmt.Errorf("Runtime error: %v\n%v", e, string(debug.Stack()))
			return
		}
	} ()
	var realGasPrice *big.Int
	realGasPrice = gasPrice
	client, err := ethclient.Dial(url)
	if err != nil {
		return
	}
	hash := common.HexToHash(txhash)
	tx, isPending, err1 := client.TransactionByHash(context.Background(), hash)
	fmt.Printf("erc20.GetTransactionInfo","hash",hash,"tx",tx,"isPending",isPending,"err1",err1)
	confirmed = !isPending
	if err1 == nil && isPending == false && tx != nil {
		msg, err2 := tx.AsMessage(ctypes.MakeSigner(chainConfig, GetLastBlock()))
		realGasPrice = msg.GasPrice()
		err = err2
		fmt.Printf("========ERC20 GetTransactionInfo========","msg",msg)
		contractAddress := msg.To().Hex()
		for token, addr := range Tokens {
		    fmt.Printf("=========ERC20 GetTransactionInfo===============","contractAddress",contractAddress,"addr",addr)
			if strings.EqualFold(contractAddress,addr) {
				jsonstring = `{"tokenType":"`+token+`"}`
				break
			}
		}
		fmt.Printf("========ERC20 GetTransactionInfo========","token type",jsonstring)
		//bug
		if  jsonstring == "" {
		    err = errors.New("get token type fail.")
		    return
		}
		//

		fromAddress = msg.From().Hex()
		data := msg.Data()

		fmt.Printf("========ERC20 GetTransactionInfo========","data",data)
		toAddress, transferAmount, decodeErr := DecodeTransferData(data)
		txOutput := ctypes.TxOutput{
			ToAddress: toAddress,
			Amount: transferAmount,
		}
		txOutputs = append(txOutputs, txOutput)
		if decodeErr != nil {
			err = decodeErr
			return
		}
	} else if err1 != nil {
		err = err1
	} else if isPending {
		err = nil//fmt.Errorf("Transaction is pending")
	} else {
		err = fmt.Errorf("Unknown error")
	}


	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	r, receipterr := client.TransactionReceipt(ctx, hash)
	if receipterr != nil {
		err = fmt.Errorf("get transaction receipt fail " + receipterr.Error())
		return
	}
		fmt.Printf("===============erc20.GetTransactionInfo,","receipt",r,"","=================")
	if r == nil {
		err = fmt.Errorf("get transaction receipt fail")
		return
	}

	// status
	if r.Status != 1 || len(r.Logs) == 0 {
		err = fmt.Errorf("excute contract error")
	}

	var flag = false
	for _, logs := range r.Logs {
		ercdata := new(big.Int).SetBytes(logs.Data)
		ercdatanum := fmt.Sprintf("%v",ercdata)
		fmt.Printf("===============erc20.GetTransactionInfo check logs","logs",logs,"ercdatanum",ercdatanum,"topics",logs.Topics,"","===============")
		for _, out := range txOutputs {
			if ercdatanum == out.Amount.String() {
				for _, top := range logs.Topics {
					aa, _ := new(big.Int).SetString(top.Hex(),0)
					bb,_ := new(big.Int).SetString(out.ToAddress,0)
					fmt.Printf("===============erc20.GetTransactionInfo check logs","aa",aa,"out.ToAddress",out.ToAddress,"","===============")
					if aa.Cmp(bb) == 0 {
						flag = true
					}
				}
				break
			} else {
				continue
			}
		}
	}

	if !flag {
		err = fmt.Errorf("excute contract error")
	}

	fee.Cointype = h.TokenType
	fee.Val = new(big.Int).Mul(realGasPrice, big.NewInt(int64(r.GasUsed)))



	return
}

// jsonstring:'{"tokenType":"BNB"}'
func (h *ERC20Handler) GetAddressBalance(address string, jsonstring string) (balance ctypes.Balance, err error) {
	defer func () {
		if e := recover(); e != nil {
			err = fmt.Errorf("Runtime error: %v\n%v", e, string(debug.Stack()))
			return
		}
	} ()
/*	var args interface{}
	json.Unmarshal([]byte(jsonstring), &args)
	tokenType := args.(map[string]interface{})["tokenType"]
	log.Debug("=============GetAddressBalance=============","tokenType",tokenType)
	if tokenType == nil {
		log.Debug("=============GetAddressBalance,token type not specified.=============")
		err = fmt.Errorf("token type not specified")
		return
	}*/

	//tokenAddr := Tokens[tokenType.(string)]
	tokenAddr := Tokens[h.TokenType]
	fmt.Printf("=============GetAddressBalance=============","tokenType.(string)",h.TokenType,"tokenAddr",tokenAddr)
	if tokenAddr == "" {
		err = fmt.Errorf("Token not supported")
		return
	}

	myABIJson := `[{"constant":true,"inputs":[{"name":"_owner","type":"address"}],"name":"balanceOf","outputs":[{"name":"balance","type":"uint256"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":true,"inputs":[],"name":"decimals","outputs":[{"name":"","type":"uint8"}],"payable":false,"stateMutability":"view","type":"function"}]`
	myABI, err := abi.JSON(strings.NewReader(myABIJson))
	if err != nil {
		return
	}

	data, err := myABI.Pack("balanceOf", common.HexToAddress(address))
	if err != nil {
		fmt.Printf("==========GetAddressBalance,3333333========================","err",err.Error())
		return
	}
	dataHex := "0x" + hex.EncodeToString(data)
	fmt.Printf("data is %v\n\n", dataHex)

	reqJson := `{"jsonrpc": "2.0","method": "eth_call","params": [{"to": "` + tokenAddr + `","data": "` + dataHex + `"},"latest"],"id": 1}`
	fmt.Printf("reqJson: %v\n\n", reqJson)

	ret := rpcutils.DoPostRequest2(url, reqJson)
	fmt.Printf("ret: %v\n\n", ret)

	var retStruct map[string]interface{}
	json.Unmarshal([]byte(ret), &retStruct)
	if retStruct["result"] == nil {
		if retStruct["error"] != nil {
			err = fmt.Errorf(retStruct["error"].(map[string]interface{})["message"].(string))
			return
		}
		err = fmt.Errorf(ret)
		fmt.Printf("==========GetAddressBalance,44444========================","err",err.Error())
		return
	}
	balanceStr := retStruct["result"].(string)[2:]
	balanceHex, _ := new(big.Int).SetString(balanceStr, 16)
	balance.TokenBalance.Val, _ = new(big.Int).SetString(fmt.Sprintf("%d",balanceHex), 10)
	balance.TokenBalance.Cointype = h.TokenType

	client, err := ethclient.Dial(url)
	if err != nil {
		fmt.Printf("============ERC20 GetAddressBalance 111111============","Error",err)
		return
	}

	tokenAddress := common.HexToAddress(tokenAddr)
	instance, err := token.NewToken(tokenAddress, client)
	if err != nil {
		fmt.Printf("===============ERC20 GetAddressBalance 222222222==========","Error",err)
		return
	}

	balance1, _ := instance.BalanceOf(&(abi.CallOpts{}), common.HexToAddress(address))
	fmt.Printf("balance1: %v\n\n", balance1)

	eh := ethhandler.NewETHHandler()
	ethbalance, err := eh.GetAddressBalance(address, "")
	if err != nil {
		fmt.Printf("===============ERC20 GetAddressBalance 3333333333==========")
		return
	}
	balance.CoinBalance = ethbalance.CoinBalance
	return
}

func GetLastBlock() *big.Int {
    last,_ := new(big.Int).SetString("10000",10)
    return last
    /*
	client, err := ethclient.Dial(url)
	if err != nil {
		return nil
	}
	blk, _ := client.BlockByNumber(context.Background(), nil)
	return blk.Number()*/
}

func hexEncPubkey(h string) (ret [64]byte) {
	b, err := hex.DecodeString(h)
	if err != nil {
		panic(err)
	}
	if len(b) != len(ret) {
		panic("invalid length")
	}
	copy(ret[:], b)
	return ret
}


func decodePubkey(e [64]byte) (*ecdsa.PublicKey, error) {
	p := &ecdsa.PublicKey{Curve: ethcrypto.S256(), X: new(big.Int), Y: new(big.Int)}
	half := len(e) / 2
	p.X.SetBytes(e[:half])
	p.Y.SetBytes(e[half:])
	if !p.Curve.IsOnCurve(p.X, p.Y) {
		return nil, errors.New("invalid secp256k1 curve point")
	}
	return p, nil
}

func DecodeTransferData(data []byte) (toAddress string, transferAmount *big.Int, err error) {
	eventData := data[:4]
	if string(eventData) == string([]byte{0xa9, 0x05, 0x9c, 0xbb}) {
		addressData := data[4:36]
		amountData := data[36:]
		num, _ := new(big.Int).SetString(hex.EncodeToString(addressData), 16)
		toAddress = "0x" + fmt.Sprintf("%x", num)
		amountHex, _ := new(big.Int).SetString(hex.EncodeToString(amountData), 16)
		transferAmount, _ = new(big.Int).SetString(fmt.Sprintf("%d", amountHex), 10)
	} else {
		err = fmt.Errorf("Invalid transfer data")
		return
	}
	return
}

func erc20_newUnsignedTransaction (client *ethclient.Client, dcrmAddress string, toAddressHex string, amount *big.Int, gasPrice *big.Int, gasLimit uint64, tokenType string) (*ctypes.Transaction, *common.Hash, error) {

	chainID, err := client.NetworkID(context.Background())

	if err != nil {
		return nil, nil, err
	}

	tokenAddressHex, ok := Tokens[tokenType]
	if ok {
	} else {
		err = errors.New("token not supported")
		return nil, nil, err
	}

	if gasPrice == nil {
		gasPrice, err = client.SuggestGasPrice(context.Background())
		if err != nil {
			return nil, nil, err
		}
	}

	fromAddress := common.HexToAddress(dcrmAddress)
/*
	nonce or pending nonce
*/
	//nonce, err := client.PendingNonceAt(context.Background(), fromAddress)
	nonce, err := client.NonceAt(context.Background(), fromAddress, nil)
	if err != nil {
		return nil, nil, err
	}

	value := big.NewInt(0)

	toAddress := common.HexToAddress(toAddressHex)
	tokenAddress := common.HexToAddress(tokenAddressHex)

	transferFnSignature := []byte("transfer(address,uint256)")
	hash := sha3.NewKeccak256()
	hash.Write(transferFnSignature)
	methodID := hash.Sum(nil)[:4]

	paddedAmount := common.LeftPadBytes(amount.Bytes(), 32)
	paddedAddress := common.LeftPadBytes(toAddress.Bytes(), 32)

	var data []byte
	data = append(data, methodID...)
	data = append(data, paddedAddress...)
	data = append(data, paddedAmount...)

	if gasLimit <= 0 {
		gasLimit, err = client.EstimateGas(context.Background(), ctypes.CallMsg{
			To:   &tokenAddress,
			Data: data,
		})
		gasLimit = gasLimit * 4
		if err != nil {
			return nil, nil, err
		}
	}

	fmt.Println("gasLimit is ", gasLimit)
	fmt.Println("gasPrice is ", gasPrice)
	tx := ctypes.NewTransaction(nonce, tokenAddress, value, gasLimit, gasPrice, data)

	signer := ctypes.NewEIP155Signer(chainID)
	txhash := signer.Hash(tx)
	return tx, &txhash, nil
}

func makeSignedTransaction(client *ethclient.Client, tx *ctypes.Transaction, rsv string) (*ctypes.Transaction, error) {
	chainID, err := client.NetworkID(context.Background())
	if err != nil {
		return nil, err
	}
	fmt.Printf("=============makeSignedTransaction============","chain Id",chainID)
	message, err := hex.DecodeString(rsv)
	if err != nil {
		return nil, err
	}
	signer := ctypes.NewEIP155Signer(chainID)
	signedtx, err := tx.WithSignature(signer, message)
	if err != nil {
		return nil, err
	}

	//////
	from, err2 := ctypes.Sender(signer, signedtx)
	if err2 != nil {
	    fmt.Printf("===================makeSignedTransaction==================","err",err2)
	    return nil,err2
	}
	fmt.Printf("===================makeSignedTransaction==================","from",from)
	////

	return signedtx, nil
}

func erc20_sendTx (client *ethclient.Client, signedTx *ctypes.Transaction) (string, error) {
	err := client.SendTransaction(context.Background(), signedTx)
	if err != nil {
		return "", err
	}
	return signedTx.Hash().Hex(), nil
}
