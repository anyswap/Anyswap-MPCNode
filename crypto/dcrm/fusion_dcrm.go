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
	p2pdcrm "github.com/fsn-dev/dcrm5-libcoins/p2p/layer2"
	"github.com/fsn-dev/dcrm5-libcoins/p2p/rlp"
	"strconv"
	"time"
	"sync"
	"github.com/fsn-dev/dcrm5-libcoins/crypto/dcrm/dev"
	"github.com/fsn-dev/dcrm5-libcoins/internal/common"
	"github.com/fsn-dev/dcrm5-libcoins/crypto/dcrm/cryptocoins"
	"github.com/fsn-dev/dcrm5-libcoins/crypto/dcrm/cryptocoins/types"
	cryptocoinsconfig "github.com/fsn-dev/dcrm5-libcoins/crypto/dcrm/cryptocoins/config"
	"encoding/json"
	"github.com/syndtr/goleveldb/leveldb"
	"encoding/hex"
)

var (
    tmp2 string
    cur_enode string
    init_times = 0
    PubLock sync.Mutex
    SignLock sync.Mutex
)

func Start() {
    cryptocoinsconfig.Init()
    cryptocoins.Init()
}

type DcrmPubkeyRes struct {
    Account string
    PubKey string
    Address map[string]string
}

type DcrmAddrRes struct {
    Account string
    PubKey string
    DcrmAddr string
    Cointype string
}

func GetPubKeyData(key []byte,account string,cointype string) (string,error) {
    if key == nil || cointype == "" {
	return "",fmt.Errorf("get pubkey data param error.")
    }

    PubLock.Lock()
    dir := dev.GetDbDir()
    ////////
    db, err := leveldb.OpenFile(dir, nil)
    if err != nil {
        PubLock.Unlock()
        return "",err
    }
    
    da,err := db.Get(key,nil)
    ///////
    if err != nil {
	db.Close()
	PubLock.Unlock()
	return "",err
    }

    ds,err := dev.UnCompress(string(da))
    if err != nil {
	db.Close()
	PubLock.Unlock()
	return "",err
    }

    dss,err := dev.Decode2(ds,"PubKeyData")
    if err != nil {
	db.Close()
	PubLock.Unlock()
	return "",err
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
	    return "",fmt.Errorf("req addr fail.cointype is not supported.")
	}

	ctaddr, err := h.PublicKeyToAddress(pubkey)
	if err != nil {
	    return "",fmt.Errorf("req addr fail.")
	}

	m = &DcrmAddrRes{Account:account,PubKey:pubkey,DcrmAddr:ctaddr,Cointype:cointype}
	b,_ := json.Marshal(m)
	return string(b),nil
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

    m = &DcrmPubkeyRes{Account:account,PubKey:pubkey,Address:addrmp}
    b,_ := json.Marshal(m)
    return string(b),nil
}

func ExsitPubKey(account string,cointype string) (string,bool) {
     //db
    PubLock.Lock()
    dir := dev.GetDbDir()
    ////////
    db, err := leveldb.OpenFile(dir, nil)
    if err != nil {
        PubLock.Unlock()
        return "",false
    }
    
    key := dev.Keccak256Hash([]byte(strings.ToLower(account + ":" + cointype))).Hex()
    da,err := db.Get([]byte(key),nil)
    ///////
    if err != nil {
	key = dev.Keccak256Hash([]byte(strings.ToLower(account + ":" + "ALL"))).Hex()
	da,err = db.Get([]byte(key),nil)
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

func SendReqToGroup(msg string,rpctype string) (string,error) {
    if strings.EqualFold(rpctype,"rpc_req_dcrmaddr") {
	msgs := strings.Split(msg,":")
	if len(msgs) < 4 {
	    return "",fmt.Errorf("param error.")
	}

	coin := "ALL"
	if types.IsDefaultED25519(msgs[1]) {
	    coin = msgs[1]
	}

	//account:cointype:groupid:threshold
	str := msgs[0] + ":" + coin + ":" + msgs[2] + ":" + msgs[3]
	ret,err := dev.SendReqToGroup(str,rpctype)
	if err != nil || ret == "" {
	    return "",err
	}

	ss,err := dev.UnCompress(ret)
	if err != nil {
	    return "",err
	}
	pubs,err := dev.Decode2(ss,"PubKeyData")
	if err != nil {
	    return "",err
	}
	
	pubkeyhex := hex.EncodeToString([]byte((pubs.(*dev.PubKeyData)).Pub))

	var m interface{}
	if !strings.EqualFold(msgs[1], "ALL") {
	    PubLock.Lock()
	    dir := dev.GetDbDir()
	    db, err := leveldb.OpenFile(dir, nil) 
	    if err != nil { 
		PubLock.Unlock()
		return "",err
	    }

	    h := cryptocoins.NewCryptocoinHandler(msgs[1])
	    if h == nil {
		db.Close()
		PubLock.Unlock()
		return "",fmt.Errorf("req addr fail.cointype is not supported.")
	    }

	    ctaddr, err := h.PublicKeyToAddress(pubkeyhex)
	    if err != nil {
		db.Close()
		PubLock.Unlock()
		return "",fmt.Errorf("req addr fail.")
	    }

	    db.Put([]byte((pubs.(*dev.PubKeyData)).Pub),[]byte(ret),nil)
	    key := dev.Keccak256Hash([]byte(strings.ToLower(msgs[0] + ":" + msgs[1]))).Hex()
	    db.Put([]byte(key),[]byte(ret),nil)
	    db.Put([]byte(ctaddr),[]byte(ret),nil)
	    db.Close()
	    PubLock.Unlock()
	    //
	    
	    m = &DcrmAddrRes{Account:msgs[0],PubKey:pubkeyhex,DcrmAddr:ctaddr,Cointype:msgs[1]}
	    b,_ := json.Marshal(m)
	    return string(b),nil
	}
	
	PubLock.Lock()
	dir := dev.GetDbDir()
	db, err := leveldb.OpenFile(dir, nil) 
	if err != nil { 
	    PubLock.Unlock()
	    return "",err
	}

	db.Put([]byte((pubs.(*dev.PubKeyData)).Pub),[]byte(ret),nil)
	key := dev.Keccak256Hash([]byte(strings.ToLower(msgs[0] + ":" + msgs[1]))).Hex()
	db.Put([]byte(key),[]byte(ret),nil)
	
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
		fmt.Printf("============ generate address,error = %+v ==========\n", err.Error())
		continue
	    }
	    
	    addrmp[ct] = ctaddr
	    
	    db.Put([]byte(ctaddr),[]byte(ret),nil)
	}

	db.Close()
	PubLock.Unlock()
	
	m = &DcrmPubkeyRes{Account:msgs[0],PubKey:pubkeyhex,Address:addrmp}
	b,_ := json.Marshal(m)
	return string(b),nil
    }
    
    ret,err := dev.SendReqToGroup(msg,rpctype)
    if err != nil || ret == "" {
	return "",err
    }

    return ret,nil
}

func ReqDcrmAddr(raw string,model string) (string,error) {
    fmt.Println("==========ReqDcrmAddr,raw = %s,model = %s ===========",raw,model)
    tx := new(types.Transaction)
    raws := common.FromHex(raw)
    if err := rlp.DecodeBytes(raws, tx); err != nil {
	fmt.Println("==========ReqDcrmAddr,raw = %s,err = %s ===========",raw,err)
	return "",err
    }

    signer := types.NewEIP155Signer(big.NewInt(30400)) //
    from, err := types.Sender(signer, tx)
    if err != nil {
	signer = types.NewEIP155Signer(big.NewInt(4)) //
	from, err = types.Sender(signer, tx)
	if err != nil {
	    return "",err
	}
    }

    data := string(tx.Data())
    datas := strings.Split(data,":")
    if len(datas) < 3 {
	return "",fmt.Errorf("tx.data error.")
    }

    if datas[0] != "REQDCRMADDR" {
	return "",fmt.Errorf("tx type error.")
    }

    if model == "1" { //non self-group
	if da,b := ExsitPubKey(from.Hex(),"ALL"); b == true {
	    return da,nil
	}
    }

    groupid := datas[1]
    if groupid == "" {
	return "",fmt.Errorf("get group id fail.")
    }
    
    threshold := datas[2]
    if threshold == "" {
	return "",fmt.Errorf("get threshold fail.")
    }

    msg := from.Hex() + ":" + "ALL" + ":" + groupid + ":" + threshold
    addr,err := SendReqToGroup(msg,"rpc_req_dcrmaddr")
    if addr == "" && err != nil {
	fmt.Println("===========ReqDcrmAddr,err= ============",err)
	return "",err
    }

    return addr,nil
}

type AcceptLockOutData struct {
    Account string
    GroupId string
    Nonce string
    DcrmFrom string
    DcrmTo string
    Value string
    Cointype string
    LimitNum string
}

func AcceptLockOut(raw string) (string,error) {
    fmt.Println("==========AcceptLockOut,raw = %s ===========",raw)
    tx := new(types.Transaction)
    raws := common.FromHex(raw)
    if err := rlp.DecodeBytes(raws, tx); err != nil {
	fmt.Println("==========AcceptLockOut,raw = %s,err = %s ===========",raw,err)
	return "",err
    }

    signer := types.NewEIP155Signer(big.NewInt(30400)) //
    _, err := types.Sender(signer, tx)
    if err != nil {
	signer = types.NewEIP155Signer(big.NewInt(4)) //
	_, err = types.Sender(signer, tx)
	if err != nil {
	    return "",err
	}
    }

    data := string(tx.Data())
    datas := strings.Split(data,":")

    if len(datas) < 9 {
	return "",fmt.Errorf("tx.data error.")
    }

    //ACCEPTLOCKOUT:account:groupid:nonce:dcrmaddr:dcrmto:value:cointype:threshold
    if datas[0] != "ACCEPTLOCKOUT" {
	return "",fmt.Errorf("tx.data error,it is not ACCEPTLOCKOUT tx.")
    }

    pubdata,err := GetPubKeyData([]byte(datas[4]),datas[1],datas[7])
    if err != nil {
	return "",err
    }

    SignLock.Lock()
    dir := dev.GetAcceptLockOutDir()
    db, err := leveldb.OpenFile(dir, nil)
    if err != nil {
        SignLock.Unlock()
        return "",err
    }
    
    key := dev.Keccak256Hash([]byte(strings.ToLower(datas[1] + ":" + datas[2] + ":" + datas[3] + ":" + datas[4] + ":" + datas[8]))).Hex()
    alo := &AcceptLockOutData{Account:datas[1],GroupId:datas[2],Nonce:datas[3],DcrmFrom:datas[4],DcrmTo:datas[5],Value:datas[6],Cointype:datas[7],LimitNum:datas[8]}
    
    alos,err := dev.Encode2(alo)
    if err != nil {
	db.Close()
	SignLock.Unlock()
	return "",err
    }
    
    ss,err := dev.Compress([]byte(alos))
    if err != nil {
	db.Close()
	SignLock.Unlock()
	return "",err 
    }
   
    db.Put([]byte(key),[]byte(ss),nil)
    db.Close()
    SignLock.Unlock()
    return pubdata,nil
}

func LockOut(raw string) (string,error) {

    fmt.Println("==========LockOut,raw = %v ===========",raw)
    tx := new(types.Transaction)
    raws := common.FromHex(raw)
    if err := rlp.DecodeBytes(raws, tx); err != nil {
	fmt.Println("==========LockOut,raw = %s,err = %s ===========",raw,err)
	return "",err
    }

    signer := types.NewEIP155Signer(big.NewInt(30400)) //
    from, err := types.Sender(signer, tx)
    if err != nil {
	signer = types.NewEIP155Signer(big.NewInt(4)) //
	from, err = types.Sender(signer, tx)
	if err != nil {
	    return "",err
	}
    }

    data := string(tx.Data())
    datas := strings.Split(data,":")
    to := datas[1]
    value := datas[2]
    cointype := datas[3]
    Nonce := tx.Nonce() 

    fmt.Println("========================================dcrm_lockOut,from = %s,to = %s,value = %s,cointype = %s ====================================",from.Hex(),to,value,cointype)
    if from.Hex() == "" || cointype == "" || value == "" || to == "" {
	return "",fmt.Errorf("param error.")
    }
   
    var errtmp error
    for i:=0;i<10;i++ {
	msg := from.Hex() + ":" + cointype + ":" + value + ":" + to + ":" + fmt.Sprintf("%v",Nonce)
	txhash,err2 := SendReqToGroup(msg,"rpc_lockout")
	fmt.Println("============dcrm_lockOut,txhash = %s,err = %s ================",txhash,err2)
	if err2 == nil && txhash != "" {
	    return txhash,nil
	}

	errtmp = err2
	
	time.Sleep(time.Duration(1000000)) //1000 000 000 == 1s
    }

    if errtmp != nil {
	fmt.Println("============dcrm_lockOut,err = %s ================",errtmp.Error())
	return "",errtmp
    }

    return "",fmt.Errorf("LockOut fail.")
}

func GetBalance(account string, cointype string) string {
    pubkey,b := ExsitPubKey(account,cointype) 
    if b == false {
	return "get balance fail,there is no dcrm addr in account."
    }

    h := cryptocoins.NewCryptocoinHandler(cointype)
    if h == nil {
	return "coin type is not supported."
    }

    ctaddr, err := h.PublicKeyToAddress(pubkey)
    if err != nil {
	return err.Error()
    }

    ba,err := h.GetAddressBalance(ctaddr,"")
    if err != nil {
	return err.Error()
    }

    if h.IsToken() {
	ret := fmt.Sprintf("%v",ba.TokenBalance.Val)
	return ret
    } 
    
    ret := fmt.Sprintf("%v",ba.CoinBalance.Val)
    return ret
}

func GetNonce(account string,cointype string) string {
    nonce,err := dev.GetNonce(account,cointype)
    if err != nil {
	return err.Error()
    }

    return nonce
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
    dev.InitDev(groupId)
}

func SetUpMsgList(msg string) {

    mm := strings.Split(msg,"dcrmslash")
    if len(mm) >= 2 {
	receiveSplitKey(msg)
	return
    }
}
//==========================================================

