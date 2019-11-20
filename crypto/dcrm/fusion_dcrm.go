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

func GetPubKeyByDcrmAddr(account string,cointype string,dcrmaddr string) (string,error) {
    fmt.Println("============GetPubKeyByDcrmAddr,account =%s,cointype =%s,dcrmaddr =%s =============",account,cointype,dcrmaddr)
     //db
    PubLock.Lock()
    dir := dev.GetDbDir()
    ////////
    db, err := leveldb.OpenFile(dir, nil)
    if err != nil {
        PubLock.Unlock()
	fmt.Println("============GetPubKeyByDcrmAddr,err 11111 =%v =============",err)
        return "",err
    }
    
    key2 := dev.Keccak256Hash([]byte(strings.ToLower(dcrmaddr))).Hex()
    da,err := db.Get([]byte(key2),nil)
    ///////
    if err != nil {
	db.Close()
	PubLock.Unlock()
	fmt.Println("============GetPubKeyByDcrmAddr,err 22222 =%v =============",err)
	return "",err
    }

    ds,err := dev.UnCompress(string(da))
    if err != nil {
	db.Close()
	PubLock.Unlock()
	fmt.Println("============GetPubKeyByDcrmAddr,err 33333 =%v =============",err)
	return "",err
    }

    dss,err := dev.Decode2(ds,"PubKeyData")
    if err != nil {
	db.Close()
	PubLock.Unlock()
	fmt.Println("============GetPubKeyByDcrmAddr,err 44444 =%v =============",err)
	return "",err
    }

    pubs := dss.(*dev.PubKeyData)
    fmt.Println("================GetPubKeyByDcrmAddr,pubs =%v =================",pubs)
    pubkey := hex.EncodeToString([]byte(pubs.Pub))
    fmt.Println("================GetPubKeyByDcrmAddr,pubkey =%s =================",pubkey)
    db.Close()
    PubLock.Unlock()
    return pubkey,nil
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

	/*ss,err := dev.UnCompress(ret)
	if err != nil {
	    return "",err
	}
	pubs,err := dev.Decode2(ss,"PubKeyData")
	if err != nil {
	    return "",err
	}
	
	pubkeyhex := hex.EncodeToString([]byte((pubs.(*dev.PubKeyData)).Pub))*/
	pubkeyhex := ret
	fmt.Println("====================dcrm.SendReqToGroup,pubkey = %s =====================",ret)

	var m interface{}
	if !strings.EqualFold(msgs[1], "ALL") {
	    /*PubLock.Lock()
	    dir := dev.GetDbDir()
	    db, err := leveldb.OpenFile(dir, nil) 
	    if err != nil { 
		PubLock.Unlock()
		return "",err
	    }*/

	    h := cryptocoins.NewCryptocoinHandler(msgs[1])
	    if h == nil {
	//	db.Close()
	//	PubLock.Unlock()
		return "",fmt.Errorf("req addr fail.cointype is not supported.")
	    }

	    ctaddr, err := h.PublicKeyToAddress(pubkeyhex)
	    if err != nil {
	//	db.Close()
	//	PubLock.Unlock()
		return "",err
	    }

	    //db.Put([]byte((pubs.(*dev.PubKeyData)).Pub),[]byte(ret),nil)
	    //key := dev.Keccak256Hash([]byte(strings.ToLower(msgs[0] + ":" + msgs[1]))).Hex()
	    //db.Put([]byte(key),[]byte(ret),nil)
	    //db.Put([]byte(ctaddr),[]byte(ret),nil)
	    //db.Close()
	    //PubLock.Unlock()
	    //
	    
	    m = &DcrmAddrRes{Account:msgs[0],PubKey:pubkeyhex,DcrmAddr:ctaddr,Cointype:msgs[1]}
	    b,_ := json.Marshal(m)
	    return string(b),nil
	}
	
	/*PubLock.Lock()
	dir := dev.GetDbDir()
	db, err := leveldb.OpenFile(dir, nil) 
	if err != nil { 
	    PubLock.Unlock()
	    return "",err
	}*/

	//db.Put([]byte((pubs.(*dev.PubKeyData)).Pub),[]byte(ret),nil)
	//key := dev.Keccak256Hash([]byte(strings.ToLower(msgs[0] + ":" + msgs[1]))).Hex()
	//db.Put([]byte(key),[]byte(ret),nil)
	
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
	    
	    //db.Put([]byte(ctaddr),[]byte(ret),nil)
	}

	//db.Close()
	//PubLock.Unlock()
	
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
    tx := new(types.Transaction)
    raws := common.FromHex(raw)
    if err := rlp.DecodeBytes(raws, tx); err != nil {
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
	return "",err
    }

    return addr,nil
}

func AcceptLockOut(raw string) (string,error) {
    tx := new(types.Transaction)
    raws := common.FromHex(raw)
    if err := rlp.DecodeBytes(raws, tx); err != nil {
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

    err = dev.AcceptLockOut(datas[1],datas[2],datas[3],datas[4],datas[8],false,true)
    if err != nil {
	return "",err
    }

    return pubdata,nil
}

func LockOut(raw string) (string,error) {
    tx := new(types.Transaction)
    raws := common.FromHex(raw)
    if err := rlp.DecodeBytes(raws, tx); err != nil {
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
    //LOCKOUT:dcrmaddr:dcrmto:value:cointype:groupid:threshold
    if datas[0] != "LOCKOUT" {
	return "",fmt.Errorf("lock raw data error,it is not lockout tx.")
    }

    dcrmaddr := datas[1]
    dcrmto := datas[2]
    value := datas[3]
    cointype := datas[4]
    groupid := datas[5]
    threshold := datas[6]
    Nonce := tx.Nonce() 

    fmt.Println("========================================dcrm_lockOut,fusion account = %s,dcrm from = %s,dcrm to = %s,value = %s,cointype = %s,groupid = %s,threshold = %s,nonce = %v ====================================",from.Hex(),dcrmaddr,dcrmto,value,cointype,groupid,threshold,Nonce)
    if from.Hex() == "" || dcrmaddr == "" || dcrmto == "" || cointype == "" || value == "" || groupid == "" || threshold == "" {
	return "",fmt.Errorf("param error.")
    }
   
    var errtmp error
    for i:=0;i<1;i++ {
	msg := from.Hex() + ":" + dcrmaddr + ":" + dcrmto + ":" + value + ":" + cointype + ":" + groupid + ":" + fmt.Sprintf("%v",Nonce) + ":" + threshold
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

func GetBalance(account string, cointype string,dcrmaddr string) string {
    /*pubkey,err := GetPubKeyByDcrmAddr(account,cointype,dcrmaddr) 
    if err != nil {
	return err.Error()
    }*/

    if strings.EqualFold(cointype, "BCH") {
	return "0"  //TODO
    }

    if strings.EqualFold(cointype, "USDT") {
	return "0"  //TODO
    }

    if strings.EqualFold(cointype, "BEP2GZX_754") {
	return "0"  //TODO
    }

    h := cryptocoins.NewCryptocoinHandler(cointype)
    if h == nil {
	return "coin type is not supported."
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
	return err.Error()
    }

    if h.IsToken() {
	ret := fmt.Sprintf("%v",ba.TokenBalance.Val)
	return ret
    } 
    
    ret := fmt.Sprintf("%v",ba.CoinBalance.Val)
    return ret
}

func GetNonce(account string,cointype string,dcrmaddr string) string {
    nonce,err := dev.GetNonce(account,cointype,dcrmaddr)
    if err != nil {
	return err.Error()
    }

    return nonce
}

func GetLockOutReply(enode string) ([]string,error) {
    reply,err := SendReqToGroup(enode,"rpc_get_lockout_reply")
    if reply == "" || err != nil {
	fmt.Println("===========GetLockOutReply,err =%s ============",err)
	return nil,err 
    }

    ss := strings.Split(reply,"|")
    return ss,nil 
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

