package main

import (
	"crypto/ecdsa"
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"math/big"
	"strings"

	"github.com/binance-chain/go-sdk/keys"
	"github.com/btcsuite/btcd/btcec"
	"github.com/btcsuite/btcutil"
	api "github.com/fsn-dev/cryptoCoins/coins"
	"github.com/fsn-dev/cryptoCoins/coins/bnb"
	"github.com/fsn-dev/cryptoCoins/coins/config"
	"github.com/fsn-dev/cryptoCoins/coins/eos"
	"github.com/fsn-dev/cryptoCoins/coins/trx"
	"github.com/fsn-dev/cryptoCoins/coins/xrp"
	"github.com/anyswap/Anyswap-MPCNode/crypto"
)

func init() {
	config.Init()
	api.Init()
}

func mustnotnil(name string) {
	if flg := flag.Lookup(name); flg == nil || flg.Value.String() == flg.DefValue {
		log.Fatal(name + " is nil.")
	}
}

/*
func main () {
	send_eth2 ()
}

func send_eth2 () {
	fmt.Printf("=========================\n           ETH           \n=========================\n\n")
	h := api.NewCryptocoinHandler("ETH")
	toAddress := "0xd92c6581cb000367c10a1997070ccd870287f2da"
	amount, _ := new(big.Int).SetString("100000000",10)

	fromPubKeyHex := "0468c49efefda03befa22343941238b2d6940622e61ddfa4daf6646ed80797664f711e9050649de84b9c6f110a861b0e74612ecb195cb503ab113eacb71e4c90d9"

	fromAddress := "0x4045bA13a6080fB02A29B9298e9926A6720ADb5c"

	build_tx_args := `{"gasPrice":2000000000,"gasLimit":40000}`

	fmt.Printf("========== %s ==========\n\n", "build unsigned transfer transaction")
	transaction, _, _ := h.BuildUnsignedTransaction(fromAddress, fromPubKeyHex, toAddress, amount, build_tx_args)
	fmt.Printf("transaction is %+v\n", transaction)

	rsv := []string{"157ADAF69C6B3696DE885165F5D034A39D57BD17C785044EAD7E133EA99D459A02A9D10FC2B9B7944DA4AAEE6F60D219F5BB559D1A75EA6329174B831C82CB2E00"}
	fmt.Printf("rsv is %+v\n", rsv)

	signedTransaction, _ := h.MakeSignedTransaction(rsv, transaction)
	fmt.Printf("signed transaction is %+v", signedTransaction)

	ret, err := h.SubmitTransaction(signedTransaction)
	if err != nil {
		fmt.Printf("Error: %v\n\n", err.Error())
	}
	fmt.Printf("%s\n\n", ret)
}
*/

func main() {
	to := flag.String("to", "", "to address")
	ct := flag.String("cointype", "", "coin type")
	amount := flag.String("amount", "", "amount")
	eb := flag.String("eosbase", "", "eos base account")
	flag.Parse()
	mustnotnil("to")
	mustnotnil("cointype")
	mustnotnil("amount")
	if strings.EqualFold(*ct, "EOS") {
		mustnotnil("eosbase")
		eosbase = *eb
	}
	toAddress := *to
	cointype := *ct
	amt, ok := new(big.Int).SetString(*amount, 10)
	if !ok {
		log.Fatal("invalid amount.")
	}
	sender := GetSender(cointype)
	sender(toAddress, amt)
}

var eosbase string

func GetSender(coinType string) func(toAddress string, amt *big.Int) {
	coinTypeC := strings.ToUpper(coinType)
	switch coinTypeC {
	case "BTC":
		return func(toAddress string, amt *big.Int) { send_btc(toAddress, amt) }
	case "ETH":
		return func(toAddress string, amt *big.Int) { send_eth(toAddress, amt) }
	case "TRX":
		return func(toAddress string, amt *big.Int) { send_tron(toAddress, amt) }
	case "XRP":
		return func(toAddress string, amt *big.Int) { send_xrp(toAddress, amt) }
	case "EOS":
		return func(toUserKey string, amt *big.Int) { send_eos(toUserKey, amt) }
	case "BNB":
		return func(toAddress string, amt *big.Int) { send_bnb(toAddress, amt) }
	default:
		if isErc20(coinTypeC) {
			return func(toAddress string, amt *big.Int) { send_erc20(toAddress, amt, coinTypeC) }
		}
		if isOmni(coinTypeC) {
			return func(toAddress string, amt *big.Int) {
				send_omni(toAddress, amt, coinTypeC)
			}
		}
		if isEVT(coinTypeC) {
			return func(toAddress string, amt *big.Int) { send_evt(toAddress, amt, coinTypeC) }
		}
		if isBEP2(coinTypeC) {
			return func(toAddress string, amt *big.Int) { send_bep2(toAddress, amt, coinTypeC) }
		}
		return nil
	}
}

func isErc20(tokentype string) bool {
	return strings.HasPrefix(tokentype, "ERC20")
}

func isOmni(tokentype string) bool {
	if tokentype == "USDT" {
		return true
	}
	return strings.HasPrefix(tokentype, "OMNI")
}

func isEVT(tokentype string) bool {
	return strings.HasPrefix(tokentype, "EVT")
}

func isBEP2(tokentype string) bool {
	return strings.HasPrefix(tokentype, "BEP2")
}

func send_common(h api.CryptocoinHandler, fromPrivateKey *ecdsa.PrivateKey, fromPubKeyHex, fromAddress, toAddress string, amt *big.Int, build_tx_args string) {
	fmt.Printf("========== %s ==========\n\n", "build unsigned transfer transaction")
	transaction, digest, err := h.BuildUnsignedTransaction(fromAddress, fromPubKeyHex, toAddress, amt, build_tx_args,"")
	if err != nil {
		//fmt.Printf("Error: %v\n\n", err.Error())
		panic(err)
	}
	fmt.Printf("transaction: %+v\n\ndigest: %v\n\n", transaction, digest)

	fmt.Printf("========== %s ==========\n\n", "sign with private key")
	rsv, err := SignTransaction(digest, fromPrivateKey)
	if err != nil {
		//fmt.Printf("Error: %v\n\n", err.Error())
		panic(err)
	}
	fmt.Printf("rsv is %+v\n\n", rsv)

	fmt.Printf("========== %s ==========\n\n", "make signed transaction")
	signedTransaction, err := h.MakeSignedTransaction(rsv, transaction)
	if err != nil {
		//fmt.Printf("Error: %v\n\n", err.Error())
		panic(err)
	}
	fmt.Printf("%+v\n\n", signedTransaction)

	fmt.Printf("========== %s ==========\n\n", "submit transaction")
	ret, err := h.SubmitTransaction(signedTransaction)
	if err != nil {
		//fmt.Printf("Error: %v\n\n", err.Error())
		panic(err)
	}
	fmt.Printf("%s\n\n", ret)

}

func send_btc(toAddress string, amt *big.Int) {
	fmt.Printf("=========================\n           BTC           \n=========================\n\n")
	h := api.NewCryptocoinHandler("BTC")
	wif := "93N2nFzgr1cPRU8ppswy8HrgBMaoba8aH5sGZn9NdgG9weRFrA1"
	pkwif, _ := btcutil.DecodeWIF(wif)
	fromPrivateKey := pkwif.PrivKey.ToECDSA()
	fromPubKeyHex := "04c1a8dd2d6acd8891bddfc02bc4970a0569756ed19a2ed75515fa458e8cf979fdef6ebc5946e90a30c3ee2c1fadf4580edb1a57ad356efd7ce3f5c13c9bb4c78f"
	fromAddress := "mtjq9RmBBDVne7YB4AFHYCZFn3P2AXv9D5"
	build_tx_args := `{"feeRate":0.0001}`
	send_common(h, fromPrivateKey, fromPubKeyHex, fromAddress, toAddress, amt, build_tx_args)
}

func send_eth(toAddress string, amt *big.Int) {
	fmt.Printf("=========================\n           ETH           \n=========================\n\n")
	h := api.NewCryptocoinHandler("ETH")

	fromPrivateKey, _ := crypto.HexToECDSA("d55b502bd4867b2c1b505af9b7cefeeb910b6cfbb570e2e47680bc89ee123eab")
	//fromPrivateKey, _ := crypto.HexToECDSA("a751c37b0a6e4b7605512fefb28cd4bd141bc3c06863557624800140eddf13be")
	pub := crypto.FromECDSAPub(&fromPrivateKey.PublicKey)
	fromPubKeyHex := hex.EncodeToString(pub)

	fromAddress := "0x426B635fD6CdAf5E4e7Bf5B2A2Dd7bc6c7360FBd"

	send_common(h, fromPrivateKey, fromPubKeyHex, fromAddress, toAddress, amt, "")
}

func send_erc20(toAddress string, amt *big.Int, tokentype string) {
	fmt.Printf("=========================\n           ERC20           \n=========================\n\n")
	h := api.NewCryptocoinHandler(tokentype)

	fromPrivateKey, _ := crypto.HexToECDSA("a751c37b0a6e4b7605512fefb28cd4bd141bc3c06863557624800140eddf13be")

	pub := crypto.FromECDSAPub(&fromPrivateKey.PublicKey)
	fromPubKeyHex := hex.EncodeToString(pub)

	fromAddress := "0x7b5Ec4975b5fB2AA06CB60D0187563481bcb6140"

	build_tx_args := `"tokenType":"` + tokentype + `"`

	send_common(h, fromPrivateKey, fromPubKeyHex, fromAddress, toAddress, amt, build_tx_args)
}

// transfer at least 100000000 drops to fund a new ripple account
// 9979999990
// 79999990
func send_xrp(toAddress string, amt *big.Int) {
	fmt.Printf("=========================\n           XRP           \n=========================\n\n")
	h := api.NewCryptocoinHandler("XRP")
	fromKey := xrp.XRP_importKeyFromSeed("ssfL5tmpTTqCw5sHjnRHQ4yyUCQKf", "ecdsa")
	keyseq := uint32(0)
	fromPubKeyHex := hex.EncodeToString(fromKey.Public(&keyseq))
	fmt.Printf("++++++++++++\nfromPubKeyHex is %v\n++++++++++++\n", fromPubKeyHex)
	fromAddress := "rwLc28nRV7WZiBv6vsHnpxUGAVcj8qpAtE"
	build_tx_args := `{"fee":10}`
	//fromPrivateKey := "ssfL5tmpTTqCw5sHjnRHQ4yyUCQKf/0"
	btcecpk, _ := btcec.PrivKeyFromBytes(btcec.S256(), fromKey.Private(&keyseq))
	fromPrivateKey := btcecpk.ToECDSA()

	send_common(h, fromPrivateKey, fromPubKeyHex, fromAddress, toAddress, amt, build_tx_args)
}

type Seed struct{}

func (s *Seed) Read(p []byte) (n int, err error) {
	n = 5
	return
}

func send_tron(toAddress string, amt *big.Int) {
	fmt.Printf("=========================\n           TRX           \n=========================\n\n")
	h := api.NewCryptocoinHandler("TRX")
	fromPrivateKey, _ := ecdsa.GenerateKey(crypto.S256(), &Seed{})
	fromPubKeyHex := trx.PublicKeyToHex(&trx.PublicKey{&fromPrivateKey.PublicKey})
	fromAddress := "417e5f4552091a69125d5dfcb7b8c2659029395bdf"

	send_common(h, fromPrivateKey, fromPubKeyHex, fromAddress, toAddress, amt, "")
}

func send_eos(toUserKey string, amt *big.Int) {
	fmt.Printf("=========================\n           EOS           \n=========================\n\n")
	h := eos.NewEOSHandler()
	fromPrivateKey := "5JqBVZS4shWHBhcht6bn3ecWDoZXPk3TRSVpsLriQz5J3BKZtqH"
	fromAcctName := "gzx123454321"
	toAcctName := eosbase

	// 构建lockin交易
	fmt.Printf("========== %s ==========\n\n", "test build unsigned transfer transaction")
	transaction, digest, err := h.BuildUnsignedLockinTransaction(fromAcctName, toUserKey, toAcctName, amt, "")
	if err != nil {
		panic(err)
		//fmt.Printf("Error: %v\n\n", err.Error())
	}
	fmt.Printf("transaction: %+v\n\ndigest: %v\n\n", transaction, digest)

	fmt.Printf("========== %s ==========\n\n", "test sign with private key")
	rsv, err := h.SignTransaction(digest, fromPrivateKey)
	if err != nil {
		panic(err)
		//fmt.Printf("Error: %v\n\n", err.Error())
	}
	fmt.Printf("rsv is %+v\n\n", rsv)

	// 组装交易
	fmt.Printf("========== %s ==========\n\n", "test make signed transaction")
	signedTransaction, err := h.MakeSignedTransaction(rsv, transaction)
	if err != nil {
		panic(err)
		//fmt.Printf("Error: %v\n\n", err.Error())
	}
	fmt.Printf("%+v\n\n", signedTransaction)

	// 发送交易
	fmt.Printf("========== %s ==========\n\n", "test submit transaction")
	ret, err := h.SubmitTransaction(signedTransaction)
	if err != nil {
		panic(err)
		//fmt.Printf("Error: %v\n\n", err.Error())
	}
	fmt.Printf("%s\n\n", ret)
}

func send_omni(toAddress string, amt *big.Int, tokentype string) {
	fmt.Printf("=========================\n           OMNI           \n=========================\n\n")
	if tokentype == "USDT" {
		tokentype = "OMNIOmni"
	}
	h := api.NewCryptocoinHandler(tokentype)
	wif := "93N2nFzgr1cPRU8ppswy8HrgBMaoba8aH5sGZn9NdgG9weRFrA1"
	pkwif, _ := btcutil.DecodeWIF(wif)
	fromPrivateKey := pkwif.PrivKey.ToECDSA()
	fromPubKeyHex := "04c1a8dd2d6acd8891bddfc02bc4970a0569756ed19a2ed75515fa458e8cf979fdef6ebc5946e90a30c3ee2c1fadf4580edb1a57ad356efd7ce3f5c13c9bb4c78f"
	fromAddress := "mtjq9RmBBDVne7YB4AFHYCZFn3P2AXv9D5"
	send_common(h, fromPrivateKey, fromPubKeyHex, fromAddress, toAddress, amt, "")
}

func send_evt(toAddress string, amt *big.Int, tokentype string) {
	fmt.Printf("=========================\n           EVT           \n=========================\n\n")
	h := api.NewCryptocoinHandler(tokentype)
	wif := "93N2nFzgr1cPRU8ppswy8HrgBMaoba8aH5sGZn9NdgG9weRFrA1"
	pkwif, _ := btcutil.DecodeWIF(wif)
	fromPrivateKey := pkwif.PrivKey.ToECDSA()
	fromPubKeyHex := "04c1a8dd2d6acd8891bddfc02bc4970a0569756ed19a2ed75515fa458e8cf979fdef6ebc5946e90a30c3ee2c1fadf4580edb1a57ad356efd7ce3f5c13c9bb4c78f"
	fromAddress := "EVT8JXJf7nuBEs8dZ8Pc5NpS8BJJLt6bMAmthWHE8CSqzX4VEFKtq"
	send_common(h, fromPrivateKey, fromPubKeyHex, fromAddress, toAddress, amt, "")
}

func send_bnb(toAddress string, amt *big.Int) {
	fmt.Printf("=========================\n           BNB           \n=========================\n\n")
	h := bnb.NewBNBHandler()
	fromAddress := "tbnb1sgudr8w8kfjz0lyuf44sr0x6y29wc96hgm8r5d"
	fromPublicKey := "046377500e127f76b8403aa4e15346dbcde31c54c3914939c8216271ff159fbab5b0713615dbcf7afd262a27f4f65cbf5c5c0e41e13749fcb2956a3a008fcfc939"
	km, _ := keys.NewMnemonicKeyManager("govern cancel early excite other fox canvas satoshi social shiver version inch correct web soap always water wine grid fashion voyage finish canal subject")
	fromPrivateKey := km.GetPrivKey()
	tx, hexTx, err := h.BNB_buildSendTx(fromAddress, fromPublicKey, toAddress, amt)
	if err != nil {
		panic(err)
	}
	sig, err := h.SignTransaction(hexTx, fromPrivateKey)
	if err != nil {
		panic(err)
	}
	signTx, err := h.MakeSignedTransaction(sig, tx)
	if err != nil {
		panic(err)
	}
	txhash, err := h.SubmitTransaction(signTx)
	if err != nil {
		panic(err)
	}
	fmt.Printf("\ntxhash:\n%v\n\n", txhash)
}

func send_bep2(toAddress string, amt *big.Int, cointype string) {
	fmt.Printf("=========================\n           BEP2           \n=========================\n\n")
	h := bnb.NewBEP2Handler(cointype)
	fromAddress := "tbnb1sgudr8w8kfjz0lyuf44sr0x6y29wc96hgm8r5d"
	fromPublicKey := "046377500e127f76b8403aa4e15346dbcde31c54c3914939c8216271ff159fbab5b0713615dbcf7afd262a27f4f65cbf5c5c0e41e13749fcb2956a3a008fcfc939"
	km, _ := keys.NewMnemonicKeyManager("govern cancel early excite other fox canvas satoshi social shiver version inch correct web soap always water wine grid fashion voyage finish canal subject")
	fromPrivateKey := km.GetPrivKey()
	tx, hexTx, err := h.BNB_buildSendTx(fromAddress, fromPublicKey, toAddress, amt)
	if err != nil {
		panic(err)
	}
	sig, err := h.SignTransaction(hexTx, fromPrivateKey)
	if err != nil {
		panic(err)
	}
	signTx, err := h.MakeSignedTransaction(sig, tx)
	if err != nil {
		panic(err)
	}
	txhash, err := h.SubmitTransaction(signTx)
	if err != nil {
		panic(err)
	}
	fmt.Printf("\ntxhash:\n%v\n\n", txhash)
}
