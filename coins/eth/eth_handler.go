/*
 *  Copyright (C) 2018-2019  Fusion Foundation Ltd. All rights reserved.
 *  Copyright (C) 2018-2019  gaozhengxin@fusion.org caihaijun@fusion.org
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

package eth

import (
	"context"
	"crypto/ecdsa"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"runtime/debug"
	"strings"

	"github.com/fsn-dev/dcrm-walletService/coins/config"
	"github.com/fsn-dev/dcrm-walletService/coins/eth/ethclient"
	"github.com/fsn-dev/dcrm-walletService/coins/eth/sha3"
	ctypes "github.com/fsn-dev/dcrm-walletService/coins/types"
	ethcrypto "github.com/fsn-dev/dcrm-walletService/crypto"
	"github.com/fsn-dev/dcrm-walletService/internal/common"
	"github.com/fsn-dev/dcrm-walletService/internal/params"
)

func ETHInit() {
	gasPrice = big.NewInt(2000000000)
	gasLimit = 40000
	url = config.ApiGateways.EthereumGateway.ApiAddress
	chainConfig = params.RinkebyChainConfig
}

var (
	gasPrice *big.Int
	gasLimit uint64
	//url = config.ETH_GATEWAY
	//url = config.ApiGateways.EthereumGateway.ApiAddress
	url         string
	err         error
	chainConfig = params.RinkebyChainConfig
)

type ETHHandler struct {
}

func NewETHHandler() *ETHHandler {
	return &ETHHandler{}
}

var ETH_DEFAULT_FEE, _ = new(big.Int).SetString("10000000000000000", 10)

func (h *ETHHandler) GetDefaultFee() ctypes.Value {
	return ctypes.Value{Cointype: "ETH", Val: ETH_DEFAULT_FEE}
}

func (h *ETHHandler) IsToken() bool {
	return false
}

func (h *ETHHandler) PublicKeyToAddress(pubKeyHex string) (address string, err error) {
	if len(pubKeyHex) != 132 && len(pubKeyHex) != 130 {
		return "", errors.New("invalid public key length")
	}
	pubKeyHex = strings.TrimPrefix(pubKeyHex, "0x")
	data := hexEncPubkey(pubKeyHex[2:])

	pub, err := decodePubkey(data)
	if err != nil {
		return
	}

	address = ethcrypto.PubkeyToAddress(*pub).Hex()
	return
}

// jsonstring '{"gasPrice":8000000000,"gasLimit":50000}'
func (h *ETHHandler) BuildUnsignedTransaction(fromAddress, fromPublicKey, toAddress string, amount *big.Int, jsonstring string,memo string) (transaction interface{}, digests []string, err error) {
	defer func() {
		if e := recover(); e != nil {
			err = fmt.Errorf("Runtime error: %v\n%v", e, string(debug.Stack()))
			return
		}
	}()
	client, err := ethclient.Dial(url)
	if err != nil {
		return
	}
	var args interface{}
	json.Unmarshal([]byte(jsonstring), &args)
	if args != nil {
		userGasPrice := args.(map[string]interface{})["gasPrice"]
		userGasLimit := args.(map[string]interface{})["gasLimit"]
		if userGasPrice != nil {
			gasPrice = big.NewInt(int64(userGasPrice.(float64)))
		}
		if userGasLimit != nil {
			gasLimit = uint64(userGasLimit.(float64))
		}
	}
	transaction, hash, err := eth_newUnsignedTransaction(client, fromAddress, toAddress, amount, gasPrice, gasLimit,memo)
	if err != nil || transaction == nil || hash == nil {
		return
	}

	hashStr := hash.Hex()
	if hashStr[:2] == "0x" {
		hashStr = hashStr[2:]
	}
	digests = append(digests, hashStr)
	return
}

func (h *ETHHandler) SignTransaction(hash []string, privateKey interface{}) (rsv []string, err error) {
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

func (h *ETHHandler) MakeSignedTransaction(rsv []string, transaction interface{}) (signedTransaction interface{}, err error) {
	client, err := ethclient.Dial(url)
	if err != nil {
		return
	}
	return makeSignedTransaction(client, transaction.(*ctypes.Transaction), rsv[0])
}

func (h *ETHHandler) SubmitTransaction(signedTransaction interface{}) (txhash string, err error) {
	fmt.Printf("!!! ETH Submit Transaction\n")
	client, err := ethclient.Dial(url)
	if err != nil {
		return
	}
	return eth_sendTx(client, signedTransaction.(*ctypes.Transaction))
}

func (h *ETHHandler) GetTransactionInfo(txhash string) (fromAddress string, txOutputs []ctypes.TxOutput, jsonstring string, confirmed bool, fee ctypes.Value, err error) {
	client, err := ethclient.Dial(url)
	if err != nil {
		return
	}
	hash := common.HexToHash(txhash)
	tx, isPending, err1 := client.TransactionByHash(context.Background(), hash)
	confirmed = !isPending
	var realGasPrice *big.Int
	realGasPrice = gasPrice
	if err1 == nil && isPending == false && tx != nil {
		msg, err2 := tx.AsMessage(ctypes.MakeSigner(chainConfig, GetLastBlock()))
		realGasPrice = msg.GasPrice()
		err = err2
		fromAddress = msg.From().Hex()
		toAddress := msg.To().Hex()
		transferAmount := msg.Value()
		txOutput := ctypes.TxOutput{
			ToAddress: toAddress,
			Amount:    transferAmount,
		}
		txOutputs = append(txOutputs, txOutput)
	} else if err1 != nil {
		err = err1
	} else {
		err = fmt.Errorf("Unknown error")
	}

	r, receipterr := client.TransactionReceipt(context.Background(), hash)
	if receipterr != nil {
		err = fmt.Errorf("get transaction receipt fail " + receipterr.Error())
		return
	}
	//fmt.Printf("===============eth.GetTransactionInfo,","receipt",r,"","=================")
	fmt.Printf("===============eth.GetTransactionInfo,receipt = %v=================\n", r)
	if r == nil {
		err = fmt.Errorf("get transaction receipt fail")
		return
	}

	fee.Val = new(big.Int).Mul(realGasPrice, big.NewInt(int64(r.GasUsed)))

	return
}

func (h *ETHHandler) GetAddressBalance(address string, jsonstring string) (balance ctypes.Balance, err error) {
	// TODO
	fmt.Printf("=====================eth.GetAddressBalance, address = %v, url = %v ===========================\n",address,url)
	client, err := ethclient.Dial(url)
	if err != nil {
		return
	}
	account := common.HexToAddress(address)
	fmt.Printf("=====================eth.GetAddressBalance, address = %v, url = %v, account = %v ===========================\n",address,url,account)
	bal, err := client.BalanceAt(context.Background(), account, nil)
	if err != nil {
		return
	}
	balance.CoinBalance = ctypes.Value{Cointype: "ETH", Val: bal}
	return
}

func GetLastBlock() *big.Int {
	last, _ := new(big.Int).SetString("100000", 10)
	return last
	/*	client, err := ethclient.Dial(url)
		if err != nil {
			return nil
		}
		blk, _ := client.BlockByNumber(context.Background(), nil)
		return blk.Number()
	*/
}

func hexEncPubkey(h string) (ret [64]byte) {
	b, err := hex.DecodeString(h)
	if err != nil {
		//panic(err)
		fmt.Printf("=============== parse pubkey error = %v ==============\n", err)
		return ret
	}
	if len(b) != len(ret) {
		//panic("invalid length")
		fmt.Printf("invalid length\n")
		return ret
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

func eth_newUnsignedTransaction(client *ethclient.Client, dcrmAddress string, toAddressHex string, amount *big.Int, gasPrice *big.Int, gasLimit uint64,memo string) (*ctypes.Transaction, *common.Hash, error) {

	fmt.Printf("================ amount = %v ================\n", amount)
	fmt.Printf("================ gasPrice = %v ================\n", gasPrice)
	fmt.Printf("================ gasLimit = %v ================\n", gasLimit)
	chainID, err := client.NetworkID(context.Background())
	if err != nil {
		return nil, nil, err
	}
	fmt.Printf("================== eth_newUnsignedTransaction,chain id = %v ==================\n", chainID)

	if gasPrice == nil {
		gasPrice, err = client.SuggestGasPrice(context.Background())
		if err != nil {
			return nil, nil, err
		}
	}

	fromAddress := common.HexToAddress(dcrmAddress)
	fmt.Printf("eth_newUnsignedTransaction,from addr = %v\n", fromAddress)
	nonce, err := client.PendingNonceAt(context.Background(), fromAddress)
	if err != nil {
		return nil, nil, err
	}

	value := amount

	toAddress := common.HexToAddress(toAddressHex)

	transferFnSignature := []byte("transfer(address,uint256)")
	hash := sha3.NewKeccak256()
	hash.Write(transferFnSignature)

	if gasLimit <= 0 {
		gasLimit, err = client.EstimateGas(context.Background(), ctypes.CallMsg{
			To: &toAddress,
		})
		gasLimit = gasLimit * 4
		if err != nil {
			return nil, nil, err
		}
	}

	fmt.Printf("================ gasLimit = %v ================\n", gasLimit)
	fmt.Printf("================ gasPrice = %v ================\n", gasPrice)
	tx := ctypes.NewTransaction(nonce, toAddress, value, gasLimit, gasPrice, []byte(memo))

	signer := ctypes.NewEIP155Signer(chainID)
	txhash := signer.Hash(tx)
	return tx, &txhash, nil
}

func makeSignedTransaction(client *ethclient.Client, tx *ctypes.Transaction, rsv string) (*ctypes.Transaction, error) {
	chainID, err := client.NetworkID(context.Background())
	if err != nil {
		return nil, err
	}
	fmt.Println("=============== makeSignedTransaction,chain id = %v ===============", chainID)

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
		fmt.Println("===================makeSignedTransaction,err = %v ==================", err2)
		return nil, err2
	}
	fmt.Println("===================makeSignedTransaction,from = %v ==================", from.Hex())
	////

	return signedtx, nil
}

func eth_sendTx(client *ethclient.Client, signedTx *ctypes.Transaction) (string, error) {
	//data, _:= rlp.EncodeToBytes(signedTx)

	signer := ctypes.NewEIP155Signer(signedTx.ChainId())
	from, err2 := ctypes.Sender(signer, signedTx)
	if err2 != nil {
		fmt.Printf("===========eth_sendTx,from = %+v=============", from)
		return "", err2
	}

	err := client.SendTransaction(context.Background(), signedTx)
	if err != nil {
		if strings.Contains(err.Error(), "known transaction") {
			txhash := strings.Split(err.Error(), ":")[1]
			txhash = strings.TrimSpace(txhash)
			return txhash, nil
		}
		return "", err
	}
	return signedTx.Hash().Hex(), nil
}
