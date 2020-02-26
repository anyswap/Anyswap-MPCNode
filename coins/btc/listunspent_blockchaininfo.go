package btc

import (
	"encoding/json"
	//"fmt"
	"sort"
	"strings"

	"github.com/btcsuite/btcd/btcjson"
)

//var addr string = "mtjq9RmBBDVne7YB4AFHYCZFn3P2AXv9D5"

/*func main() {
	ls, err := listUnspent_blockchaininfo(addr)
	if err != nil {
		fmt.Printf("error: %v",err)
		return
	}
	fmt.Printf("blockchaininfo: utxos are %+v\n",ls)

	ls2, err := listUnspent(addr)
	if err != nil {
		fmt.Printf("error: %v",err)
		return
	}
	fmt.Printf("blockcypher: utxos are %+v\n",ls2)
}*/

func listUnspent_blockchaininfo(addr string) ([]btcjson.ListUnspentResult, error) {
	resstr := getUTXO_BlockChainInfo(addr)
	utxoLsRes, err := parseUnspent(resstr)
	if err != nil {
		return nil, err
	}
	//var list []btcjson.ListUnspentResult
	var list sortableLURSlice
	for _, utxo := range utxoLsRes.Unspent_outputs {
		res := btcjson.ListUnspentResult{
			TxID: utxo.Tx_hash_big_endian,
			Vout: uint32(utxo.Tx_output_n),
			Address: addr,
			ScriptPubKey: utxo.Script,
			//RedeemScript:
			Amount: utxo.Value/1e8,
			Confirmations: utxo.Confirmations,
			Spendable: true,
		}
		list = append(list, res)
	}
	sort.Sort(list)
	return list, nil
}

func parseUnspent(resstr string) (UtxoLsRes, error) {
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
	res := &UtxoLsRes{}
	err := json.Unmarshal([]byte(resstr)[:last_index+1], res)
	return *res, err
}

type UtxoLsRes struct {
	Unspent_outputs []UtxoRes
}

type UtxoRes struct {
	Tx_hash_big_endian	string
	Script			string
	Tx_output_n		uint32
	Value			float64
	Confirmations		int64
}

func getUTXO_BlockChainInfo (addr string) string {
	addrReceivedUrl := "https://testnet.blockchain.info/unspent?active=" + addr
	blockchaininfores := loginPre1("GET",addrReceivedUrl)
	return blockchaininfores
}

