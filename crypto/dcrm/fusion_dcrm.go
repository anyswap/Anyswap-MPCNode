/*
 *  Copyright (C) 2018-2019  Fusion Foundation Ltd. All rights reserved.
 *  Copyright (C) 2018-2019  caihaijun@fusion.org
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

package dcrm

import (
	"fmt"
	"math/big"
	"strings"
	p2pdcrm "github.com/fsn-dev/dcrm-walletService/p2p/layer2"
	"github.com/fsn-dev/dcrm-walletService/p2p/rlp"
	"strconv"
	"time"
	"sync"
	"github.com/fsn-dev/dcrm-walletService/crypto/dcrm/dev"
	"github.com/fsn-dev/dcrm-walletService/internal/common"
	"github.com/fsn-dev/dcrm-walletService/crypto/dcrm/cryptocoins"
	"github.com/fsn-dev/dcrm-walletService/crypto/dcrm/cryptocoins/types"
	cryptocoinsconfig "github.com/fsn-dev/dcrm-walletService/crypto/dcrm/cryptocoins/config"
	"encoding/json"
	//"github.com/syndtr/goleveldb/leveldb"
	//"github.com/fsn-dev/dcrm-walletService/ethdb"
	"encoding/hex"
)

var (
    tmp2 string
    cur_enode string
    init_times = 0
    PubLock sync.Mutex
    SignLock sync.Mutex
    KeyFile string
)

func Start() {
    cryptocoinsconfig.Init()
    cryptocoins.Init()
}

type DcrmAccountsBalanceRes struct {
    PubKey string
    Balances []SubAddressBalance
}

type SubAddressBalance struct {
    Cointype string
    DcrmAddr string
    Balance string
}

type DcrmAddrRes struct {
    Account string
    PubKey string
    DcrmAddr string
    Cointype string
}

type DcrmPubkeyRes struct {
    Account string
    PubKey string
    DcrmAddress map[string]string
}

/*func GetPubKeyData(key []byte,account string,cointype string) (string,string,error) {
    if key == nil || cointype == "" {
	return "","dcrm back-end internal error:parameter error in func GetPubKeyData",fmt.Errorf("get pubkey data param error.")
    }

    PubLock.Lock()
    dir := dev.GetDbDir()
    ////////
    db,err := ethdb.NewLDBDatabase(dir, 0, 0)
    //bug
    if err != nil {
	for i:=0;i<1000;i++ {
	    db,err = ethdb.NewLDBDatabase(dir, 0, 0)
	    if err == nil {
		break
	    }
	    
	    time.Sleep(time.Duration(1000000))
	}
    }
    //
    if err != nil {
        PubLock.Unlock()
	return "","dcrm back-end internal error:open level db fail",err
    }
    
    da,err := db.Get(key)
    ///////
    if err != nil {
	db.Close()
	PubLock.Unlock()
	return "","dcrm back-end internal error:get data from db fail in func GetPubKeyData",err
    }

    ds,err := dev.UnCompress(string(da))
    if err != nil {
	db.Close()
	PubLock.Unlock()
	return "","dcrm back-end internal error:uncompress data fail in func GetPubKeyData",err
    }

    dss,err := dev.Decode2(ds,"PubKeyData")
    if err != nil {
	db.Close()
	PubLock.Unlock()
	return "","dcrm back-end internal error:decode PubKeyData fail",err
    }

    pubs := dss.(*dev.PubKeyData)
    pubkey := hex.EncodeToString([]byte(pubs.Pub))
    db.Close()
    PubLock.Unlock()
    ///////////
    var m interface{}
    if !strings.EqualFold(cointype, "ALL") {

	h := cryptocoins.NewCryptocoinHandler(cointype)
	if h == nil {
	    return "","cointype is not supported",fmt.Errorf("req addr fail.cointype is not supported.")
	}

	ctaddr, err := h.PublicKeyToAddress(pubkey)
	if err != nil {
	    return "","dcrm back-end internal error:get dcrm addr fail from pubkey:"+pubkey,fmt.Errorf("req addr fail.")
	}

	m = &DcrmAddrRes{Account:account,PubKey:pubkey,DcrmAddr:ctaddr,Cointype:cointype}
	b,_ := json.Marshal(m)
	return string(b),"",nil
    }
    
    addrmp := make(map[string]string)
    for _, ct := range cryptocoins.Cointypes {
	if strings.EqualFold(ct, "ALL") {
	    continue
	}

	h := cryptocoins.NewCryptocoinHandler(ct)
	if h == nil {
	    continue
	}
	ctaddr, err := h.PublicKeyToAddress(pubkey)
	if err != nil {
	    continue
	}
	
	addrmp[ct] = ctaddr
    }

    m = &DcrmPubkeyRes{Account:account, PubKey:pubkey, DcrmAddress:addrmp}
    b,_ := json.Marshal(m)
    return string(b),"",nil
}

func ExsitPubKey(account string,cointype string) (string,bool) {
     //db
    PubLock.Lock()
    dir := dev.GetDbDir()
    ////////
    db,err := ethdb.NewLDBDatabase(dir, 0, 0)
    //bug
    if err != nil {
	for i:=0;i<1000;i++ {
	    db,err = ethdb.NewLDBDatabase(dir, 0, 0)
	    if err == nil {
		break
	    }
	    
	    time.Sleep(time.Duration(1000000))
	}
    }
    //
    if err != nil {
        PubLock.Unlock()
        return "",false
    }
    
    key := dev.Keccak256Hash([]byte(strings.ToLower(account + ":" + cointype))).Hex()
    da,err := db.Get([]byte(key))
    ///////
    if err != nil {
	key = dev.Keccak256Hash([]byte(strings.ToLower(account + ":" + "ALL"))).Hex()
	da,err = db.Get([]byte(key))
	///////
	if err != nil {
	    db.Close()
	    PubLock.Unlock()
	    return "",false
	}
    }

    ds,err := dev.UnCompress(string(da))
    if err != nil {
	db.Close()
	PubLock.Unlock()
	return "",false
    }

    dss,err := dev.Decode2(ds,"PubKeyData")
    if err != nil {
	db.Close()
	PubLock.Unlock()
	return "",false
    }

    pubs := dss.(*dev.PubKeyData)
    pubkey := hex.EncodeToString([]byte(pubs.Pub))
    db.Close()
    PubLock.Unlock()
    return pubkey,true
}
*/

func GetPubKeyData(key string,account string,cointype string) (string,string,error) {
    if key == "" || cointype == "" {
	return "","dcrm back-end internal error:parameter error in func GetPubKeyData",fmt.Errorf("get pubkey data param error.")
    }

    da,exsit := dev.LdbPubKeyData[key]
    ///////
    if exsit == false {
	return "","dcrm back-end internal error:get data from db fail in func GetPubKeyData",fmt.Errorf("dcrm back-end internal error:get data from db fail in func GetPubKeyData")
    }

    ds,err := dev.UnCompress(string(da))
    if err != nil {
	return "","dcrm back-end internal error:uncompress data fail in func GetPubKeyData",err
    }

    dss,err := dev.Decode2(ds,"PubKeyData")
    if err != nil {
	return "","dcrm back-end internal error:decode PubKeyData fail",err
    }

    pubs := dss.(*dev.PubKeyData)
    pubkey := hex.EncodeToString([]byte(pubs.Pub))
    ///////////
    var m interface{}
    if !strings.EqualFold(cointype, "ALL") {

	h := cryptocoins.NewCryptocoinHandler(cointype)
	if h == nil {
	    return "","cointype is not supported",fmt.Errorf("req addr fail.cointype is not supported.")
	}

	ctaddr, err := h.PublicKeyToAddress(pubkey)
	if err != nil {
	    return "","dcrm back-end internal error:get dcrm addr fail from pubkey:"+pubkey,fmt.Errorf("req addr fail.")
	}

	m = &DcrmAddrRes{Account:account,PubKey:pubkey,DcrmAddr:ctaddr,Cointype:cointype}
	b,_ := json.Marshal(m)
	return string(b),"",nil
    }
    
    addrmp := make(map[string]string)
    for _, ct := range cryptocoins.Cointypes {
	if strings.EqualFold(ct, "ALL") {
	    continue
	}

	h := cryptocoins.NewCryptocoinHandler(ct)
	if h == nil {
	    continue
	}
	ctaddr, err := h.PublicKeyToAddress(pubkey)
	if err != nil {
	    continue
	}
	
	addrmp[ct] = ctaddr
    }

    m = &DcrmPubkeyRes{Account:account, PubKey:pubkey, DcrmAddress:addrmp}
    b,_ := json.Marshal(m)
    return string(b),"",nil
}

func ExsitPubKey(account string,cointype string) (string,bool) {
    key := dev.Keccak256Hash([]byte(strings.ToLower(account + ":" + cointype))).Hex()
    da,exsit := dev.LdbPubKeyData[key]
    ///////
    if exsit == false {
	key = dev.Keccak256Hash([]byte(strings.ToLower(account + ":" + "ALL"))).Hex()
	da,exsit = dev.LdbPubKeyData[key]
	///////
	if exsit == false {
	    return "",false
	}
    }

    ds,err := dev.UnCompress(string(da))
    if err != nil {
	return "",false
    }

    dss,err := dev.Decode2(ds,"PubKeyData")
    if err != nil {
	return "",false
    }

    pubs := dss.(*dev.PubKeyData)
    pubkey := hex.EncodeToString([]byte(pubs.Pub))
    return pubkey,true
}

func SendReqToGroup(msg string,rpctype string) (string,string,error) {
    if strings.EqualFold(rpctype,"rpc_req_dcrmaddr") {
	//msg = account:cointype:groupid:nonce:threshold:mode
	msgs := strings.Split(msg,":")
	if len(msgs) < 6 {
	    return "","dcrm back-end internal parameter error in func SendReqToGroup",fmt.Errorf("param error.")
	}

	coin := "ALL"
	if types.IsDefaultED25519(msgs[1]) {
	    coin = msgs[1]
	}

	//account:cointype:groupid:nonce:threshold:mode
	str := msgs[0] + ":" + coin + ":" + msgs[2] + ":" + msgs[3] + ":" + msgs[4] + ":" + msgs[5]
	ret,tip,err := dev.SendReqToGroup(str,rpctype)
	if err != nil || ret == "" {
	    return "",tip,err
	}

	pubkeyhex := ret
	fmt.Println("====================dcrm.SendReqToGroup,pubkey = %s =====================",ret)

	var m interface{}
	if !strings.EqualFold(msgs[1], "ALL") {
	    h := cryptocoins.NewCryptocoinHandler(msgs[1])
	    if h == nil {
		return "","cointype is not supported",fmt.Errorf("req addr fail.cointype is not supported.")
	    }

	    ctaddr, err := h.PublicKeyToAddress(pubkeyhex)
	    if err != nil {
		return "","get dcrm addr fail from pubkey:" + pubkeyhex,err
	    }

	    m = &DcrmAddrRes{Account:msgs[0],PubKey:pubkeyhex,DcrmAddr:ctaddr,Cointype:msgs[1]}
	    b,_ := json.Marshal(m)
	    return string(b),"",nil
	}
	
	addrmp := make(map[string]string)
	for _, ct := range cryptocoins.Cointypes {
	    if strings.EqualFold(ct, "ALL") {
		continue
	    }

	    h := cryptocoins.NewCryptocoinHandler(ct)
	    if h == nil {
		continue
	    }
	    ctaddr, err := h.PublicKeyToAddress(pubkeyhex)
	    if err != nil {
		continue
	    }
	    
	    addrmp[ct] = ctaddr
	}

	m = &DcrmPubkeyRes{Account:msgs[0],PubKey:pubkeyhex,DcrmAddress:addrmp}
	b,_ := json.Marshal(m)
	return string(b),"",nil
    }
    
    ret,tip,err := dev.SendReqToGroup(msg,rpctype)
    if err != nil || ret == "" {
	return "",tip,err
    }

    return ret,"",nil
}

func ReqDcrmAddr(raw string,mode string) (string,string,error) {
    tx := new(types.Transaction)
    raws := common.FromHex(raw)
    if err := rlp.DecodeBytes(raws, tx); err != nil {
	return "","raw data error",err
    }

    signer := types.NewEIP155Signer(big.NewInt(30400)) //
    from, err := types.Sender(signer, tx)
    if err != nil {
	signer = types.NewEIP155Signer(big.NewInt(4)) //
	from, err = types.Sender(signer, tx)
	if err != nil {
	    return "","recover fusion account fail from raw data,maybe raw data error",err
	}
    }

    fmt.Println("===============ReqDcrmAddr,fusion account = %s================",from.Hex())

    data := string(tx.Data())
    datas := strings.Split(data,":")
    if len(datas) < 3 {
	return "","transacion data format error",fmt.Errorf("tx.data error.")
    }

    if datas[0] != "REQDCRMADDR" {
	return "","transaction data format error,it is not REQDCRMADDR tx",fmt.Errorf("tx type error.")
    }

    if mode == "1" { //non self-group
	if da,b := ExsitPubKey(from.Hex(),"ALL"); b == true {
	    ///
	    var m interface{}
	    addrmp := make(map[string]string)
	    for _, ct := range cryptocoins.Cointypes {
		if strings.EqualFold(ct, "ALL") {
		    continue
		}

		h := cryptocoins.NewCryptocoinHandler(ct)
		if h == nil {
		    continue
		}
		ctaddr, err := h.PublicKeyToAddress(da)
		if err != nil {
		    continue
		}
		
		addrmp[ct] = ctaddr
	    }

	    m = &DcrmPubkeyRes{Account:from.Hex(),PubKey:da,DcrmAddress:addrmp}
	    bb,_ := json.Marshal(m)
	    return string(bb),"",nil
	    ///
	}
    }

    groupid := datas[1]
    if groupid == "" {
	return "","group id error",fmt.Errorf("get group id fail.")
    }
    
    threshold := datas[2]
    if threshold == "" {
	return "","no threshold value",fmt.Errorf("get threshold fail.")
    }

    Nonce := tx.Nonce() 
    
    fmt.Println("========================================dcrm_reqDcrmAddr,fusion account = %s,groupid = %s,threshold = %s,mode =%s,nonce = %v ====================================",from.Hex(),groupid,threshold,mode,Nonce)

    go func() {
	msg := from.Hex() + ":" + "ALL" + ":" + groupid + ":" + fmt.Sprintf("%v",Nonce) + ":" + threshold + ":" + mode
	addr,_,err := SendReqToGroup(msg,"rpc_req_dcrmaddr")
	if addr != "" && err == nil {
	    return
	}
    }()

    key := dev.Keccak256Hash([]byte(strings.ToLower(from.Hex() + ":" + "ALL" + ":" + groupid + ":" + fmt.Sprintf("%v",Nonce) + ":" + threshold + ":" + mode))).Hex()
    fmt.Println("===============ReqDcrmAddr,return key =%s================",key)
    return key,"",nil
}

func AcceptReqAddr(raw string) (string,string,error) {
    tx := new(types.Transaction)
    raws := common.FromHex(raw)
    if err := rlp.DecodeBytes(raws, tx); err != nil {
	return "","raw data error",err
    }

    signer := types.NewEIP155Signer(big.NewInt(30400)) //
    _, err := types.Sender(signer, tx)
    if err != nil {
	signer = types.NewEIP155Signer(big.NewInt(4)) //
	_, err = types.Sender(signer, tx)
	if err != nil {
	    return "","recover fusion account fail from raw data,maybe raw data error",err
	}
    }

    data := string(tx.Data())
    datas := strings.Split(data,":")

    if len(datas) < 8 {
	return "","transacion data format error",fmt.Errorf("tx.data error.")
    }

    //ACCEPTREQADDR:account:cointype:groupid:nonce:threshold:mode:accept
    if datas[0] != "ACCEPTREQADDR" {
	return "","transaction data format error,it is not ACCEPTREQADDR tx",fmt.Errorf("tx.data error,it is not ACCEPTREQADDR tx.")
    }

    if datas[7] != "AGREE" && datas[7] != "DISAGREE" {
	return "","transaction data format error,the lastest segment is not AGREE or DISAGREE",fmt.Errorf("transaction data format error")
    }

    accept := "false"
    if datas[7] == "AGREE" {
	accept = "true"
    }

    tip,err := dev.AcceptReqAddr(datas[1],datas[2],datas[3],datas[4],datas[5],datas[6],false,accept,"Pending","","","","")
    if err != nil {
	return "",tip,err
    }

    return "","",nil
}

func AcceptLockOut(raw string) (string,string,error) {
    tx := new(types.Transaction)
    raws := common.FromHex(raw)
    if err := rlp.DecodeBytes(raws, tx); err != nil {
	return "","raw data error",err
    }

    signer := types.NewEIP155Signer(big.NewInt(30400)) //
    _, err := types.Sender(signer, tx)
    if err != nil {
	signer = types.NewEIP155Signer(big.NewInt(4)) //
	_, err = types.Sender(signer, tx)
	if err != nil {
	    return "","recover fusion account fail from raw data,maybe raw data error",err
	}
    }

    data := string(tx.Data())
    datas := strings.Split(data,":")

    if len(datas) < 11 {
	return "","transacion data format error",fmt.Errorf("tx.data error.")
    }

    //ACCEPTLOCKOUT:account:groupid:nonce:dcrmaddr:dcrmto:value:cointype:threshold:mode:accept
    if datas[0] != "ACCEPTLOCKOUT" {
	return "","transaction data format error,it is not ACCEPTLOCKOUT tx",fmt.Errorf("tx.data error,it is not ACCEPTLOCKOUT tx.")
    }

    if datas[10] != "AGREE" && datas[10] != "DISAGREE" {
	return "","transaction data format error,the lastest segment is not AGREE or DISAGREE",fmt.Errorf("transaction data format error")
    }

    key2 := dev.Keccak256Hash([]byte(strings.ToLower(datas[4]))).Hex()
    pubdata,tip,err := GetPubKeyData(key2,datas[1],datas[7])
    if err != nil {
	return "",tip,err
    }

    accept := "false"
    if datas[10] == "AGREE" {
	accept = "true"
    }

    tip,err = dev.AcceptLockOut(datas[1],datas[2],datas[3],datas[4],datas[8],false,accept,"Pending","","","","")
    if err != nil {
	return "",tip,err
    }

    return pubdata,"",nil
}

func LockOut(raw string) (string,string,error) {
    tx := new(types.Transaction)
    raws := common.FromHex(raw)
    if err := rlp.DecodeBytes(raws, tx); err != nil {
	return "","raw data error",err
    }

    signer := types.NewEIP155Signer(big.NewInt(30400)) //
    from, err := types.Sender(signer, tx)
    if err != nil {
	signer = types.NewEIP155Signer(big.NewInt(4)) //
	from, err = types.Sender(signer, tx)
	if err != nil {
	    return "","recover fusion account fail from raw data,maybe raw data error",err
	}
    }

    fmt.Println("===================LockOut,fusion account =%s======================",from.Hex())

    data := string(tx.Data())
    datas := strings.Split(data,":")
    //LOCKOUT:dcrmaddr:dcrmto:value:cointype:groupid:threshold:mode
    if datas[0] != "LOCKOUT" {
	return "","transaction data format error,it is not LOCKOUT tx",fmt.Errorf("lock raw data error,it is not lockout tx.")
    }

    dcrmaddr := datas[1]
    dcrmto := datas[2]
    value := datas[3]
    cointype := datas[4]
    groupid := datas[5]
    threshold := datas[6]
    mode := datas[7]
    Nonce := tx.Nonce() 

    fmt.Println("========================================dcrm_lockOut,fusion account = %s,dcrm from = %s,dcrm to = %s,value = %s,cointype = %s,groupid = %s,threshold = %s,mode =%s,nonce = %v ====================================",from.Hex(),dcrmaddr,dcrmto,value,cointype,groupid,threshold,mode,Nonce)
    if from.Hex() == "" || dcrmaddr == "" || dcrmto == "" || cointype == "" || value == "" || groupid == "" || threshold == "" || mode == "" {
	return "","parameter error from raw data,maybe raw data error",fmt.Errorf("param error.")
    }
   
    go func() {
	for i:=0;i<1;i++ {
	    msg := from.Hex() + ":" + dcrmaddr + ":" + dcrmto + ":" + value + ":" + cointype + ":" + groupid + ":" + fmt.Sprintf("%v",Nonce) + ":" + threshold + ":" + mode
	    txhash,_,err2 := SendReqToGroup(msg,"rpc_lockout")
	    if err2 == nil && txhash != "" {
		return
	    }

	    time.Sleep(time.Duration(1000000)) //1000 000 000 == 1s
	}
    }()
    
    key := dev.Keccak256Hash([]byte(strings.ToLower(from.Hex() + ":" + groupid + ":" + fmt.Sprintf("%v",Nonce) + ":" + dcrmaddr + ":" + threshold))).Hex()
    return key,"",nil
}

func GetReqAddrStatus(key string) (string,string,error) {
    return dev.GetReqAddrStatus(key)
}

func GetLockOutStatus(key string) (string,string,error) {
    return dev.GetLockOutStatus(key)
}

func GetAccountsBalance(pubkey string) (interface{}, string, error) {
    key,err2 := hex.DecodeString(pubkey)
    if err2 != nil {
	fmt.Printf("==============GetAccountsBalance,decode string fail,err =%v=============",err2)
	return nil,"decode pubkey fail",err2
    }

    ret, tip, err := GetPubKeyData(string(key), pubkey, "ALL")
    fmt.Printf("================GetAccountsBalance, ret =%s, err =%v============\n", ret,err)
    var m interface{}
    if err == nil {
        dp := DcrmPubkeyRes{}
        _ = json.Unmarshal([]byte(ret), &dp)
        balances := make([]SubAddressBalance, 0)
        var wg sync.WaitGroup
	var ret map[string]*SubAddressBalance = make(map[string]*SubAddressBalance, 0)
        for cointype, subaddr := range dp.DcrmAddress {
            wg.Add(1)
            go func (cointype, subaddr string) {
                defer wg.Done()
                balance, _, err := GetBalance(pubkey,cointype, subaddr)
                fmt.Println("===============GetAccountsBalance,cointype =%s, dcrmaddr =%s, balance =%s, err =%v================", cointype, subaddr, balance, err)
                if err != nil {
                    balance = "0"
                }
		ret[cointype] = &SubAddressBalance{Cointype: cointype, DcrmAddr: subaddr, Balance: balance}
            }(cointype, subaddr)
        }
        wg.Wait()
	for _, cointype := range cryptocoins.Cointypes {
	     if ret[cointype] != nil {
		 balances = append(balances, *(ret[cointype]))
		 fmt.Printf("balances: %v\n", balances)
		 delete(ret, cointype)
	     }
	}
        m = &DcrmAccountsBalanceRes{PubKey:pubkey,Balances:balances}
    }
    
    return m, tip, err
}

func GetBalance(account string, cointype string,dcrmaddr string) (string,string,error) {

    if strings.EqualFold(cointype, "BCH") {
	return "0","",nil  //TODO
    }

    if strings.EqualFold(cointype, "USDT") {
	return "0","",nil  //TODO
    }

    if strings.EqualFold(cointype, "BEP2GZX_754") {
	return "0","",nil  //TODO
    }

    h := cryptocoins.NewCryptocoinHandler(cointype)
    if h == nil {
	return "","coin type is not supported",fmt.Errorf("coin type is not supported")
    }

    /*ctaddr, err := h.PublicKeyToAddress(pubkey)
    if err != nil {
	fmt.Println("================GetBalance 11111,err =%v =================",err)
	return err.Error()
    }*/

    //ba,err := h.GetAddressBalance(ctaddr,"")
    ba,err := h.GetAddressBalance(dcrmaddr,"")
    if err != nil {
	fmt.Println("================GetBalance 22222,err =%v =================",err)
	return "","dcrm back-end internal error:get dcrm addr balance fail",err
    }

    if h.IsToken() {
	ret := fmt.Sprintf("%v",ba.TokenBalance.Val)
	return ret,"",nil
    } 
    
    ret := fmt.Sprintf("%v",ba.CoinBalance.Val)
    return ret,"",nil
}

func GetReqAddrNonce(account string) (string,string,error) {
    nonce,tip,err := dev.GetReqAddrNonce(account)
    if err != nil {
	return "",tip,err
    }

    return nonce,"",nil
}

func GetLockOutNonce(account string,cointype string,dcrmaddr string) (string,string,error) {
    nonce,tip,err := dev.GetLockOutNonce(account,cointype,dcrmaddr)
    if err != nil {
	return "",tip,err
    }

    return nonce,"",nil
}

func GetReqAddrReply() ([]string,string,error) {
    fmt.Println("=========== call dcrm.GetReqAddrReply ============")
    reply,tip,err := SendReqToGroup("","rpc_get_reqaddr_reply")
    if reply == "" || err != nil {
	fmt.Println("===========dcrm.GetReqAddrReply,err =%v ============",err)
	return nil,tip,err 
    }

    ss := strings.Split(reply,"|")
    return ss,"",nil 
}

func GetLockOutReply() ([]string,string,error) {
    fmt.Println("=========== call dcrm.GetLockOutReply ============")
    reply,tip,err := SendReqToGroup("","rpc_get_lockout_reply")
    if reply == "" || err != nil {
	fmt.Println("===========call dcrm.GetLockOutReply,err =%v ============",err)
	return nil,tip,err 
    }

    ss := strings.Split(reply,"|")
    return ss,"",nil 
}

func init(){
	p2pdcrm.RegisterRecvCallback(Call)
	p2pdcrm.SdkProtocol_registerBroadcastInGroupCallback(dev.Call)
	p2pdcrm.SdkProtocol_registerSendToGroupCallback(dev.Dcrmcall)
	p2pdcrm.SdkProtocol_registerSendToGroupReturnCallback(dev.Dcrmcallret)
	p2pdcrm.RegisterCallback(dev.Call)

	dev.RegP2pGetGroupCallBack(p2pdcrm.SdkProtocol_getGroup)
	dev.RegP2pSendToGroupAllNodesCallBack(p2pdcrm.SdkProtocol_SendToGroupAllNodes)
	dev.RegP2pGetSelfEnodeCallBack(p2pdcrm.GetSelfID)
	dev.RegP2pBroadcastInGroupOthersCallBack(p2pdcrm.SdkProtocol_broadcastInGroupOthers)
	dev.RegP2pSendMsgToPeerCallBack(p2pdcrm.SendMsgToPeer)
	dev.RegP2pParseNodeCallBack(p2pdcrm.ParseNodeID)
	dev.RegDcrmGetEosAccountCallBack(GetEosAccount)
	dev.InitChan()
}

func Call(msg interface{}) {
	fmt.Println("===========dcrm.Call==============","msg",msg)
    s := msg.(string)
    SetUpMsgList(s)
}

var parts = make(map[int]string)
func receiveSplitKey(msg interface{}){
	fmt.Println("===========receiveSplitKey==============","msg",msg)
	cur_enode = p2pdcrm.GetSelfID()
	
	m := strings.Split(msg.(string),"|")
	if len(m) != 2 {
	    return
	}

	splitkey := m[1]

	head := strings.Split(splitkey, ":")[0]
	body := strings.Split(splitkey, ":")[1]
	if a := strings.Split(body, "#"); len(a) > 1 {
	    tmp2 = a[0]
	    body = a[1]
	}
	p, _ := strconv.Atoi(strings.Split(head, "dcrmslash")[0])
	total, _ := strconv.Atoi(strings.Split(head, "dcrmslash")[1])
	parts[p] = body

	if len(parts) == total {
		var c string = ""
		for i := 1; i <= total; i++ {
			c += parts[i]
		}
		 time.Sleep(time.Duration(2)*time.Second) //1000 == 1s
		////
		Init(m[0])
	}
}

func Init(groupId string) {
    out := "=============Init================" + " get group id = " + groupId
    fmt.Println(out)
    dev.InitDev(KeyFile,groupId)
}

func SetUpMsgList(msg string) {

    mm := strings.Split(msg,"dcrmslash")
    if len(mm) >= 2 {
	receiveSplitKey(msg)
	return
    }
}

func GetAccounts(gid,mode string) (interface{}, string, error) {
    return dev.GetAccounts(gid, mode)
}

