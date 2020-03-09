package btc

import (
	"fmt"
	"log"
	"math/big"
	"sync"

	"github.com/btcsuite/btcd/btcjson"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	btcrpcclient "github.com/btcsuite/btcd/rpcclient"
	"github.com/btcsuite/btcutil"
)

var ChainConfig2 = chaincfg.TestNet3Params

var certs = []byte(`-----BEGIN CERTIFICATE-----
MIIDJjCCAoigAwIBAgIQLdezPiER6uPim0Siiot+ljAKBggqhkjOPQQDBDAyMREw
DwYDVQQKEwhnZW5jZXJ0czEdMBsGA1UEAxMUZXpyZWFsLU9wdGlQbGV4LTcwNjAw
HhcNMjAwMjIzMTY0MzA4WhcNMzAwMjIxMTY0MzA4WjAyMREwDwYDVQQKEwhnZW5j
ZXJ0czEdMBsGA1UEAxMUZXpyZWFsLU9wdGlQbGV4LTcwNjAwgZswEAYHKoZIzj0C
AQYFK4EEACMDgYYABAHHql7NmyjEZZZ7Myrtl7rPovj5tEqbJSOQt4FDUHcDlXrz
zasEWmIfGMGy02Y1F7sBYbHj3K88mO/g9RplKW596AFrNcvx2bDPE+rh3yRgtLS/
LCM39UTPhirnkhWTMC70FDPCzfHTPEiWCw0XNaSZiL8PjK86wMDMjNzwwkpgMzsu
n6OCATswggE3MA4GA1UdDwEB/wQEAwICpDAPBgNVHRMBAf8EBTADAQH/MIIBEgYD
VR0RBIIBCTCCAQWCFGV6cmVhbC1PcHRpUGxleC03MDYwgglsb2NhbGhvc3SHBH8A
AAGHEAAAAAAAAAAAAAAAAAAAAAGHBMCoAQOHBKwTAAGHBKwXAAGHBKwUAAGHBKwV
AAGHBKwRAAGHBKwWAAGHBMCoIAGHBKwSAAGHECQOAOBM9ZUA9IjsB2PiupqHECQO
AOBM9ZUAVV32AbAiCTKHECQOAOBM9ZUA/QBpm3fKQY6HECQOAOBM9ZUAvRqvTRuj
UgKHECQOAOBM9ZUAVOqzQKaIlBCHECQOAOBM9ZUA1KDm95YdQY+HECQOAOBM9ZUA
Lg3nk/3eByeHEP6AAAAAAAAAfpc0vas6b1eHBC9rMlMwCgYIKoZIzj0EAwQDgYsA
MIGHAkIBgf0XQ46Bi2BhGtrM9bel0U6FEwD1mcNkodvOCDDMKJpMDjiRwmkEyo0M
9ThdYw3nZ3876b3RxrYOpKiBqWF0qr8CQUn3Ue+MYYHWiIWG1dVeHB5rXaKxbZ08
ogDQ8C8BAPW4eHe3lq06Wx2LeG2/2PjN7s1jye8jWFoFDm7n+lVxNtWI
-----END CERTIFICATE-----`)

var client *btcrpcclient.Client

func init() {
	// Create a new RPC client using websockets.  Since this example is
	// not long-lived, the connection will be closed as soon as the program
	// exits.
	connCfg := &btcrpcclient.ConnConfig{
		Host:         "47.107.50.83:19334",
		Endpoint:     "ws",
		User:         "xxmm",
		Pass:         "123456",
		HTTPPostMode: true,
		Certificates: certs,
	}
	c, err := btcrpcclient.New(connCfg, nil)
	if err != nil {
		log.Fatal(err)
	}
	client = c
}

/*
func main() {
	//_, bal, err := ListUnspent_BTCD("mtjq9RmBBDVne7YB4AFHYCZFn3P2AXv9D5")
	utxos, bal, err := ListUnspent_BTCD("mwz72UEwKmu2cNRWFYtiVyU5NXZ2XCmied")
	fmt.Printf("utxos: %+v, bal: %v, err: %v\n", utxos, bal, err)
}
*/

func ListUnspent_BTCD(address string) (utxos []btcjson.ListUnspentResult, balance *big.Int, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("%v", r)
		}
	}()
	defer client.Shutdown()

	// Query txout
	//addr, err := btcutil.DecodeAddress("mtjq9RmBBDVne7YB4AFHYCZFn3P2AXv9D5", &ChainConfig)
	addr, err := btcutil.DecodeAddress(address, &ChainConfig2)
	if err != nil {
		log.Fatal(err)
	}
	res, ok := SearchRawTransaction(GetTxOut)(addr).([]interface{})
	if !ok {
		err = fmt.Errorf("list unspent error")
	}
	utxos = make([]btcjson.ListUnspentResult, 0)
	balance = new(big.Int)
	for _, v := range res {
		utxo, ok := v.(btcjson.ListUnspentResult)
		if !ok {
			continue
		}
		utxos = append(utxos, utxo)
		balance = balance.Add(balance, big.NewInt(int64(utxo.Amount*1e8)))
	}
	return
}

func SearchRawTransaction(do func([]*btcjson.SearchRawTransactionsResult, btcutil.Address) []interface{}) func(btcutil.Address) interface{} {
	return func(addr btcutil.Address) interface{} {
		type ft func(skip int)
		count := 50
		var finish bool = false
		res := make([]interface{}, 0)
		wg := new(sync.WaitGroup)
		reslock := new(sync.Mutex)
		var f ft
		f = func(skip int) {
			fr_st := client.SearchRawTransactionsVerboseAsync(addr, skip, count, true, false, nil)
			go func() {
				if finish {
					return
				}
				wg.Add(1)
				defer wg.Done()
				if strs, err := fr_st.Receive(); err == nil && strs != nil {
					if len(strs) < count {
						finish = true
					}
					res0 := do(strs, addr)
					reslock.Lock()
					res = append(res, res0...)
					reslock.Unlock()
				} else {
					finish = true
				}
				return
			}()
			if !finish {
				f(skip + count)
			}
		}
		f(0)

		wg.Wait()
		return res
	}
}

func GetTxOut(txs []*btcjson.SearchRawTransactionsResult, toaddr btcutil.Address) []interface{} {
	utxos := make([]interface{}, 0)
	wg := new(sync.WaitGroup)
	utxolock := new(sync.Mutex)
	for _, tx := range txs {
		txid, err := chainhash.NewHashFromStr(tx.Txid)
		if err != nil {
			continue
		}
		for i := 0; i < len(tx.Vout); i++ {
			vout := tx.Vout[i]
			addr := ""
			if len(vout.ScriptPubKey.Addresses) > 0 {
				addr = vout.ScriptPubKey.Addresses[0]
			}
			if addr != toaddr.String() {
				continue
			}
			fr_gt := client.GetTxOutAsync(txid, uint32(i), false)
			go func() {
				wg.Add(1)
				defer wg.Done()
				if txo, err := fr_gt.Receive(); err == nil && txo != nil {
					utxo := btcjson.ListUnspentResult{
						TxID:          tx.Txid,
						Vout:          uint32(len(tx.Vout)),
						Address:       addr,
						ScriptPubKey:  vout.ScriptPubKey.Hex,
						Amount:        vout.Value,
						Confirmations: int64(tx.Confirmations),
						Spendable:     true,
					}
					utxolock.Lock()
					utxos = append(utxos, utxo)
					utxolock.Unlock()
				}
			}()
		}
	}
	wg.Wait()
	return utxos
}
