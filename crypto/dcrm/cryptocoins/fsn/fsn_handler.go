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

package fsn

import  (
	"context"
	"crypto/ecdsa"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"runtime/debug"
	"strings"
	"github.com/fsn-dev/dcrm-walletService/internal/params"
	"github.com/fsn-dev/dcrm-walletService/internal/common"
	ethcrypto "github.com/fsn-dev/dcrm-walletService/crypto"
	"github.com/fsn-dev/dcrm-walletService/crypto/dcrm/cryptocoins/eth/sha3"
	"github.com/fsn-dev/dcrm-walletService/crypto/dcrm/cryptocoins/eth/ethclient"
	"github.com/fsn-dev/dcrm-walletService/crypto/dcrm/cryptocoins/config"
	ctypes "github.com/fsn-dev/dcrm-walletService/crypto/dcrm/cryptocoins/types"
)

func FSNInit() {
	gasPrice = big.NewInt(2000000000)
	gasLimit = 40000
	url = config.ApiGateways.FusionGateway.ApiAddress
	//chainConfig = params.FsnChainConfig
	chainConfig = params.TestnetChainConfig
}

var (
	gasPrice *big.Int
	gasLimit uint64
	url string
	err error
	//chainConfig = params.FsnChainConfig
	chainConfig = params.TestnetChainConfig
)

type FSNHandler struct {
}

func NewFSNHandler() *FSNHandler {
    return &FSNHandler{}
}

var FSN_DEFAULT_FEE, _ = new(big.Int).SetString("10000000000000000",10)

func (h *FSNHandler) GetDefaultFee() ctypes.Value {
	return ctypes.Value{Cointype:"FSN",Val:FSN_DEFAULT_FEE}
}

func (h *FSNHandler) IsToken() bool {
	return false
}

func (h *FSNHandler) PublicKeyToAddress (pubKeyHex string) (address string, err error) {
	if len(pubKeyHex) != 132 && len(pubKeyHex) != 130 {
		return "", errors.New("invalid public key length")
	}
        pubKeyHex = strings.TrimPrefix(pubKeyHex,"0x")
	data := hexEncPubkey(pubKeyHex[2:])

	pub, err := decodePubkey(data)
	if err != nil {
		return
	}

	address = ethcrypto.PubkeyToAddress(*pub).Hex()
	return
}

// jsonstring '{"gasPrice":8000000000,"gasLimit":50000}'
func (h *FSNHandler) BuildUnsignedTransaction(fromAddress, fromPublicKey, toAddress string, amount *big.Int, jsonstring string) (transaction interface{}, digests []string, err error) {
	defer func () {
		if e := recover(); e != nil {
			err = fmt.Errorf("Runtime error: %v\n%v", e, string(debug.Stack()))
			return
		}
	} ()

	fmt.Println("==================fsn.BuildUnsignedTransaction,url =%s===================",url)
	client, err := ethclient.Dial(url)
	if err != nil {
		fmt.Println("==================fsn.BuildUnsignedTransaction,url =%s,err =%v===================",url,err)
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
	transaction, hash, err := fsn_newUnsignedTransaction(client, fromAddress, toAddress, amount, gasPrice, gasLimit)
	if transaction == nil || hash == nil || err != nil {
	    fmt.Println("================fsn_newUnsignedTransaction,new unsigned tx fail================",)
	    return
	}

	hashStr := hash.Hex()
	if hashStr[:2] == "0x" {
		hashStr = hashStr[2:]
	}
	digests = append(digests, hashStr)
	return
}

func (h *FSNHandler) SignTransaction(hash []string, privateKey interface{}) (rsv []string, err error) {
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

func (h *FSNHandler) MakeSignedTransaction(rsv []string, transaction interface{}) (signedTransaction interface{}, err error) {
	client, err := ethclient.Dial(url)
	if err != nil {
		return
	}
	return makeSignedTransaction(client, transaction.(*ctypes.Transaction), rsv[0])
}

func (h *FSNHandler) SubmitTransaction(signedTransaction interface{}) (txhash string, err error) {
	client, err := ethclient.Dial(url)
	if err != nil {
		return
	}
	return fsn_sendTx(client, signedTransaction.(*ctypes.Transaction))
}

func (h *FSNHandler) GetTransactionInfo(txhash string) (fromAddress string, txOutputs []ctypes.TxOutput, jsonstring string, confirmed bool, fee ctypes.Value, err error) {
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
			Amount: transferAmount,
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
		fmt.Printf("===============fsn.GetTransactionInfo,receipt = %v=================\n",r)
	if r == nil {
		err = fmt.Errorf("get transaction receipt fail")
		return
	}

	fee.Val = new(big.Int).Mul(realGasPrice, big.NewInt(int64(r.GasUsed)))

	return
}

func (h *FSNHandler) GetAddressBalance(address string, jsonstring string) (balance ctypes.Balance, err error) {
	// TODO
	client, err := ethclient.Dial(url)
	if err != nil {
		return
	}
	account := common.HexToAddress(address)
	bal, err := client.BalanceAt(context.Background(), account, nil)
	if err != nil {
		return
	}
	balance.CoinBalance = ctypes.Value{Cointype:"FSN",Val:bal}
	return
}

func GetLastBlock() *big.Int {
	last,_ := new(big.Int).SetString("100000",10)
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
		fmt.Printf("=============== parse pubkey error = %v ==============\n",err)
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

func fsn_newUnsignedTransaction (client *ethclient.Client, dcrmAddress string, toAddressHex string, amount *big.Int, gasPrice *big.Int, gasLimit uint64) (*ctypes.Transaction, *common.Hash, error) {

        fmt.Printf("================ amount = %v ================\n", amount)
	fmt.Printf("================ gasPrice = %v ================\n", gasPrice)
	fmt.Printf("================ gasLimit = %v ================\n", gasLimit)
	chainID, err := client.NetworkID(context.Background())
	if err != nil {
		return nil, nil, err
	}

	if gasPrice == nil {
		gasPrice, err = client.SuggestGasPrice(context.Background())
		if err != nil {
			return nil, nil, err
		}
	}

	fromAddress := common.HexToAddress(dcrmAddress)
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
			To:   &toAddress,
		})
		gasLimit = gasLimit * 4
		if err != nil {
			return nil, nil, err
		}
	}

	fmt.Printf("================ gasLimit = %v ================\n", gasLimit)
	fmt.Printf("================ gasPrice = %v ================\n", gasPrice)
	tx := ctypes.NewTransaction(nonce, toAddress, value, gasLimit, gasPrice, nil)

	signer := ctypes.NewEIP155Signer(chainID)
	txhash := signer.Hash(tx)
	return tx, &txhash, nil
}

func makeSignedTransaction(client *ethclient.Client, tx *ctypes.Transaction, rsv string) (*ctypes.Transaction, error) {
	chainID, err := client.NetworkID(context.Background())
	if err != nil {
		return nil, err
	}
	fmt.Println("=============== makeSignedTransaction,chain id = %v ===============",chainID)

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
	    fmt.Println("===================makeSignedTransaction,err = %v ==================",err2)
	    return nil,err2
	}
	fmt.Println("===================makeSignedTransaction,from = %v ==================",from.Hex())
	////

	return signedtx, nil
}

func fsn_sendTx (client *ethclient.Client, signedTx *ctypes.Transaction) (string, error) {
	//data, _:= rlp.EncodeToBytes(signedTx)

	signer:= ctypes.NewEIP155Signer(signedTx.ChainId())
	_, err2 := ctypes.Sender(signer, signedTx)
	if err2 != nil {
	    return "",err2
	}

	err := client.SendTransaction(context.Background(), signedTx)
	if err != nil {
		if strings.Contains(err.Error(),"known transaction") {
			txhash := strings.Split(err.Error(),":")[1]
			txhash = strings.TrimSpace(txhash)
			return txhash, nil
		}
		return "", err
	}
	return signedTx.Hash().Hex(), nil
}
