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
	"github.com/fsn-dev/dcrm-walletService/coins"
	"github.com/fsn-dev/dcrm-walletService/coins/eos"
	"github.com/fsn-dev/dcrm-walletService/coins/types"
	cryptocoinsconfig "github.com/fsn-dev/dcrm-walletService/coins/config"
	"encoding/json"
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
    coins.Init()
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

    //da,exsit := dev.LdbPubKeyData[key]
    var da []byte
    datmp,exsit := dev.LdbPubKeyData.ReadMap(key)
    if exsit == false {
	da2 := dev.GetPubKeyDataValueFromDb(key)
	if da2 == nil {
	    exsit = false
	} else {
	    exsit = true
	    da = da2
	}
    } else {
	da = datmp.([]byte)
    }

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

	h := coins.NewCryptocoinHandler(cointype)
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
    for _, ct := range coins.Cointypes {
	if strings.EqualFold(ct, "ALL") {
	    continue
	}

	h := coins.NewCryptocoinHandler(ct)
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
    var da []byte
    datmp,exsit := dev.LdbPubKeyData.ReadMap(key)
    if exsit == false {
	da2 := dev.GetPubKeyDataValueFromDb(key)
	if da2 == nil {
	    exsit = false
	} else {
	    exsit = true
	    da = da2
	}
    } else {
	da = datmp.([]byte)
    }
    ///////
    if exsit == false {
	key = dev.Keccak256Hash([]byte(strings.ToLower(account + ":" + "ALL"))).Hex()
	datmp,exsit = dev.LdbPubKeyData.ReadMap(key)
	if exsit == false {
	    da2 := dev.GetPubKeyDataValueFromDb(key)
	    if da2 == nil {
		exsit = false
	    } else {
		exsit = true
		da = da2
	    }
	} else {
	    da = datmp.([]byte)
	}
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
	//msg = account:cointype:groupid:nonce:threshold:mode:tx1:tx2:tx3...:txn
	msgs := strings.Split(msg,":")
	if len(msgs) < 6 {
	    return "","dcrm back-end internal parameter error in func SendReqToGroup",fmt.Errorf("param error.")
	}

	//coin := "ALL"
	if !types.IsDefaultED25519(msgs[1]) {
	    //coin = msgs[1]
	    msgs[1] = "ALL"
	}

	str := strings.Join(msgs,":")

	//account:cointype:groupid:nonce:threshold:mode:tx1:tx2:tx3....:txn
	//str := msgs[0] + ":" + coin + ":" + msgs[2] + ":" + msgs[3] + ":" + msgs[4] + ":" + msgs[5]
	ret,tip,err := dev.SendReqToGroup(str,rpctype)
	if err != nil || ret == "" {
	    return "",tip,err
	}

	pubkeyhex := ret
	keytest := dev.Keccak256Hash([]byte(strings.ToLower(msgs[0] + ":" + msgs[1] + ":" + msgs[2] + ":" + msgs[3] + ":" + msgs[4] + ":" + msgs[5]))).Hex()
	common.Info("====================call dcrm.SendReqToGroup,finish calc dcrm addrs, ","pubkey = ",ret,"key = ",keytest,"","=======================")

	var m interface{}
	if !strings.EqualFold(msgs[1], "ALL") {
	    h := coins.NewCryptocoinHandler(msgs[1])
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
	for _, ct := range coins.Cointypes {
	    if strings.EqualFold(ct, "ALL") {
		continue
	    }

	    h := coins.NewCryptocoinHandler(ct)
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
	common.Info("====================call dcrm.SendReqToGroup,finish calc dcrm addrs,get all dcrm addrs. ","addrs = ",string(b),"key = ",keytest,"","=======================")
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

    //fmt.Println("===============ReqDcrmAddr,fusion account = %s================",from.Hex())

    data := string(tx.Data()) //REQDCRMADDR:gid:threshold:tx1:tx2:tx3...
    datas := strings.Split(data,":")
    if len(datas) < 3 {
	return "","transacion data format error",fmt.Errorf("tx.data error.")
    }

    if datas[0] != "REQDCRMADDR" {
	return "","transaction data format error,it is not REQDCRMADDR tx",fmt.Errorf("tx type error.")
    }

    groupid := datas[1]
    if groupid == "" {
	return "","group id error",fmt.Errorf("get group id fail.")
    }
    
    threshold := datas[2]
    if threshold == "" {
	return "","no threshold value",fmt.Errorf("get threshold fail.")
    }

    nums := strings.Split(threshold,"/")
    if len(nums) != 2 {
	return "","transacion data format error,threshold is not right",fmt.Errorf("tx.data error.")
    }

    nodecnt,_ := strconv.Atoi(nums[1])
    if len(datas) < (3+nodecnt) {
	return "","transacion data format error",fmt.Errorf("tx.data error.")
    }

    Nonce := tx.Nonce()
    
    key := dev.Keccak256Hash([]byte(strings.ToLower(from.Hex() + ":" + "ALL" + ":" + groupid + ":" + fmt.Sprintf("%v",Nonce) + ":" + threshold + ":" + mode))).Hex()
    
    if mode == "1" { //non self-group
	if da,b := ExsitPubKey(from.Hex(),"ALL"); b == true {
	    ///
	    var m interface{}
	    addrmp := make(map[string]string)
	    for _, ct := range coins.Cointypes {
		if strings.EqualFold(ct, "ALL") {
		    continue
		}

		h := coins.NewCryptocoinHandler(ct)
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
    } else {
	////////bug
	var da []byte
	datmp,exsit := dev.LdbReqAddr.ReadMap(key)
	if exsit == false {
	    da2 := dev.GetReqAddrValueFromDb(key)
	    if da2 == nil {
		exsit = false
	    } else {
		exsit = true
		da = da2
	    }
	} else {
	    da = datmp.([]byte)
	}

	if exsit == true {
	    ds,err := dev.UnCompress(string(da))
	    if err == nil {
		dss,err := dev.Decode2(ds,"AcceptReqAddrData")
		if err == nil {
		    ac := dss.(*dev.AcceptReqAddrData)
		    if ac != nil && strings.EqualFold(ac.Status, "Pending") {
			common.Info("===================!!!!dcrm_reqDcrmAddr,this req addr has already handle,!!!!============================","account = ",from.Hex(),"group id = ",groupid,"nonce = ",Nonce,"threshold = ",threshold,"mode = ",mode,"key = ",key)
			return "","the req dcrm addr has already handle,status is pending",fmt.Errorf("the req dcrm addr has already handle,status is pending.")
		    }
		}
	    }
	}

	//nonce check
	if exsit == true {
	    return "","req addr nonce error",fmt.Errorf("nonce error.")
	}

	/*cur_nonce_str,tip,err := dev.GetReqAddrNonce(from.Hex())
	if err != nil {
	    return "",tip,err
	}

	if strings.EqualFold(fmt.Sprintf("%v",Nonce),cur_nonce_str) == false {
	    return "","req addr nonce error",fmt.Errorf("nonce error.")
	}*/
	//

	tip,err := dev.SetReqAddrNonce(from.Hex(),fmt.Sprintf("%v",Nonce))
	if err != nil {
	    return "",tip,fmt.Errorf("update nonce error.")
	}
	////////bug
    }

    common.Info("========================================ReqDcrmAddr, ","account = ",from.Hex(),"group id = ",groupid,"threshold = ",threshold,"mode = ",mode,"nonce = ",Nonce,"key = ",key,"","============================================")

    go func() {
	/////////////////////tmp code //////////////////////
	mp := []string{key,cur_enode}
	enode := strings.Join(mp,"-")
	s0 := "GroupAccounts"
	s1 := nums[1]
	ss := enode + common.Sep + s0 + common.Sep + s1
	
	for j:=0;j<nodecnt;j++ {
	    tx2 := new(types.Transaction)
	    vs := common.FromHex(datas[3+j])
	    if err := rlp.DecodeBytes(vs, tx2); err != nil {
		return
	    }

	    signer := types.NewEIP155Signer(big.NewInt(30400)) //
	    from2, err := types.Sender(signer, tx2)
	    if err != nil {
		signer = types.NewEIP155Signer(big.NewInt(4)) //
		from2, err = types.Sender(signer, tx2)
		if err != nil {
		    return
		}
	    }

	    eid := string(tx2.Data())
	    acc := from2.Hex()
	    ss += common.Sep
	    ss += eid
	    ss += common.Sep
	    ss += acc
	}
	
	kd := dev.KeyData{Key:[]byte(key),Data:ss}
	dev.GAccsDataChan <-kd
	dev.GAccs.WriteMap(key,ss)
	dev.SendMsgToDcrmGroup(ss,groupid)
	common.Info("===============ReqDcrmAddr,send group accounts to other nodes ","msg = ",ss,"key = ",key,"","===========================")

	////////////////////////////////////////////////////

	coin := "ALL"
	//if !types.IsDefaultED25519(msgs[1]) {  //TODO
	//}

	addr,_,err := dev.SendReqDcrmAddr(from.Hex(),coin,groupid,fmt.Sprintf("%v",Nonce),threshold,mode,key)
	common.Info("===============ReqDcrmAddr,finish calc dcrm addrs. ","addr = ",addr,"err = ",err,"key = ",key,"","===========================")
	if addr != "" && err == nil {
	    return
	}
    }()

    common.Info("===============ReqDcrmAddr finish,return","key = ",key,"","=================================")
    return key,"",nil
}

func AcceptReqAddr(raw string) (string,string,error) {
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

    status := "Pending"
    accept := "false"
    if datas[7] == "AGREE" {
	accept = "true"
    } else {
	status = "Failure"
    }

    ////bug,check valid accepter
    key := dev.Keccak256Hash([]byte(strings.ToLower(datas[1] + ":" + datas[2] + ":" + datas[3] + ":" + datas[4] + ":" + datas[5] + ":" + datas[6]))).Hex()
    var da []byte
    datmp,exsit := dev.LdbReqAddr.ReadMap(key)
    if exsit == false {
	da2 := dev.GetReqAddrValueFromDb(key)
	if da2 == nil {
	    exsit = false
	} else {
	    exsit = true
	    da = da2
	}
    } else {
	da = datmp.([]byte)
    }

    if exsit == false {
	return "","dcrm back-end internal error:get accept data fail from db",fmt.Errorf("dcrm back-end internal error:get accept data fail from db")
    }

    ds,err := dev.UnCompress(string(da))
    if err != nil {
	return "","dcrm back-end internal error:uncompress accept data fail",err
    }

    dss,err := dev.Decode2(ds,"AcceptReqAddrData")
    if err != nil {
	return "","dcrm back-end internal error:decode accept data fail",err
    }

    ac := dss.(*dev.AcceptReqAddrData)
    //if ac == nil || len(ac.NodeSigs) == 0 {
    if ac == nil {
	return "","dcrm back-end internal error:decode accept data fail",fmt.Errorf("decode accept data fail")
    }

    ///////
    if dev.CheckAcc(cur_enode,from.Hex(),key) == false {
	return "","invalid accepter",fmt.Errorf("invalid accepter")
    }
    /////

    /*check := false
    for _,v := range ac.NodeSigs {
	tx2 := new(types.Transaction)
	vs := common.FromHex(v)
	if err = rlp.DecodeBytes(vs, tx2); err != nil {
	    //return "","check accepter fail",err
	    continue
	}

	signer = types.NewEIP155Signer(big.NewInt(30400)) //
	from2, err := types.Sender(signer, tx2)
	if err != nil {
	    signer = types.NewEIP155Signer(big.NewInt(4)) //
	    from2, err = types.Sender(signer, tx2)
	    if err != nil {
		//return "","check accepter fail",err
		continue
	    }
	}
	
	eid := string(tx2.Data())
	fmt.Println("==================!!! AcceptReqAddr,eid = %s,cur_enode =%s,from =%s,from2 =%s !!!===============",eid,cur_enode,from.Hex(),from2.Hex())
	if strings.EqualFold(eid,cur_enode) && strings.EqualFold(from.Hex(),from2.Hex()) {
	    check = true
	    break
	}
    }

    if check == false {
	return "","invalid accepter",fmt.Errorf("invalid accepter")
    }*/
    ////////////////////////////

    tip,err := dev.AcceptReqAddr(datas[1],datas[2],datas[3],datas[4],datas[5],datas[6],false,accept,status,"","","","",ac.WorkId)
    if err != nil {
	return "",tip,err
    }

   ///////
    mp := []string{key,cur_enode}
    enode := strings.Join(mp,"-")
    s0 := "AcceptReqAddrRes"
    s1 := accept 
    //s2 := strconv.Itoa(ac.WorkId)
    ss := enode + dev.Sep + s0 + dev.Sep + s1
    dev.SendMsgToDcrmGroup(ss,datas[3])
   common.Info("================== AcceptReqAddr, finish send AcceptReqAddrRes to other nodes ","key = ",key,"","============================")
    
   return "","",nil
}

func AcceptLockOut(raw string) (string,string,error) {
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

    status := "Pending"
    accept := "false"
    if datas[10] == "AGREE" {
	accept = "true"
    } else {
	status = "Failure"
    }

    ////bug,check valid accepter
    //da,exsit := dev.LdbPubKeyData[key2]
    var da []byte
    datmp,exsit := dev.LdbPubKeyData.ReadMap(key2)
    if exsit == false {
	da2 := dev.GetPubKeyDataValueFromDb(key2)
	if da2 == nil {
	    exsit = false
	} else {
	    exsit = true
	    da = da2
	}
    } else {
	da = datmp.([]byte)
    }

    if exsit == false {
	return "","dcrm back-end internal error:get lockout data from db fail",fmt.Errorf("get lockout data from db fail")
    }

    ss,err := dev.UnCompress(string(da))
    if err != nil {
	return "","dcrm back-end internal error:uncompress lockout data from db fail",fmt.Errorf("uncompress lockout data from db fail")
    }
    
    pubs,err := dev.Decode2(ss,"PubKeyData")
    if err != nil {
	return "","dcrm back-end internal error:decode lockout data from db fail",fmt.Errorf("decode lockout data from db fail")
    }
    
    pd := pubs.(*dev.PubKeyData)
    if pd == nil {
	return "","dcrm back-end internal error:decode lockout data from db fail",fmt.Errorf("decode lockout data from db fail")
    }

    ///////
    rk := dev.Keccak256Hash([]byte(strings.ToLower(pd.Account + ":" + "ALL" + ":" + pd.GroupId + ":" + pd.Nonce + ":" + pd.LimitNum + ":" + pd.Mode))).Hex()
    if dev.CheckAcc(cur_enode,from.Hex(),rk) == false {
	return "","invalid accepter",fmt.Errorf("invalid accepter")
    }
    /////

    /*check := false
    for _,v := range pd.NodeSigs {
	tx2 := new(types.Transaction)
	vs := common.FromHex(v)
	if err = rlp.DecodeBytes(vs, tx2); err != nil {
	    //return "","check accepter fail",err
	    continue
	}

	signer = types.NewEIP155Signer(big.NewInt(30400)) //
	from2, err := types.Sender(signer, tx2)
	if err != nil {
	    signer = types.NewEIP155Signer(big.NewInt(4)) //
	    from2, err = types.Sender(signer, tx2)
	    if err != nil {
		//return "","check accepter fail",err
		continue
	    }
	}
	
	eid := string(tx2.Data())
	fmt.Println("===================!!! AcceptLockOut,eid = %s,cur_enode =%s,from =%s,from2 =%s !!!===============",eid,cur_enode,from.Hex(),from2.Hex())
	if strings.EqualFold(eid,cur_enode) && strings.EqualFold(from.Hex(),from2.Hex()) {
	    check = true
	    break
	}
    }

    if check == false {
	return "","invalid accepter",fmt.Errorf("invalid accepter")
    }*/
    ////////////////////////////

    //ACCEPTLOCKOUT:account:groupid:nonce:dcrmaddr:dcrmto:value:cointype:threshold:mode:accept
    key := dev.Keccak256Hash([]byte(strings.ToLower(datas[1] + ":" + datas[2] + ":" + datas[3] + ":" + datas[4] + ":" + datas[8]))).Hex()
    datmp,exsit = dev.LdbLockOut.ReadMap(key)
    if exsit == false {
	da2 := dev.GetLockOutValueFromDb(key)
	if da2 == nil {
	    exsit = false
	} else {
	    exsit = true
	    da = da2
	}
    } else {
	da = datmp.([]byte)
    }
    ///////
    if exsit == false {
	return "","dcrm back-end internal error:get accept result from db fail",fmt.Errorf("get accept result from db fail")
    }

    ds,err := dev.UnCompress(string(da))
    if err != nil {
	return "","dcrm back-end internal error:uncompress accept result fail",fmt.Errorf("uncompress accept result fail")
    }

    dss,err := dev.Decode2(ds,"AcceptLockOutData")
    if err != nil {
	return "","dcrm back-end internal error:decode accept result fail",fmt.Errorf("decode accept result fail")
    }

    ac := dss.(*dev.AcceptLockOutData)
    if ac == nil {
	return "","dcrm back-end internal error:get accept result from db fail",fmt.Errorf("get accept result from db fail")
    }

    tip,err = dev.AcceptLockOut(datas[1],datas[2],datas[3],datas[4],datas[8],false,accept,status,"","","","",ac.WorkId)
    if err != nil {
	return "",tip,err
    }

   ///////
    mp := []string{key,cur_enode}
    enode := strings.Join(mp,"-")
    s0 := "AcceptLockOutRes"
    s1 := accept
    ss2 := enode + dev.Sep + s0 + dev.Sep + s1
    dev.SendMsgToDcrmGroup(ss2,datas[2])
   common.Info("================== AcceptLockOut , finish send AcceptLockOutRes to other nodes ","key = ",key,"","============================")

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

    //fmt.Println("========================================dcrm_lockOut,fusion account = %s,dcrm from = %s,dcrm to = %s,value = %s,cointype = %s,groupid = %s,threshold = %s,mode =%s,nonce = %v ====================================",from.Hex(),dcrmaddr,dcrmto,value,cointype,groupid,threshold,mode,Nonce)
    if from.Hex() == "" || dcrmaddr == "" || dcrmto == "" || cointype == "" || value == "" || groupid == "" || threshold == "" || mode == "" {
	return "","parameter error from raw data,maybe raw data error",fmt.Errorf("param error.")
    }

    ///////bug
    key2 := dev.Keccak256Hash([]byte(strings.ToLower(from.Hex() + ":" + groupid + ":" + fmt.Sprintf("%v",Nonce) + ":" + dcrmaddr + ":" + threshold))).Hex()
    var da []byte
    datmp,exsit := dev.LdbLockOut.ReadMap(key2)
    if exsit == false {
	da2 := dev.GetLockOutValueFromDb(key2)
	if da2 == nil {
	    exsit = false
	} else {
	    exsit = true
	    da = da2
	}
    } else {
	da = datmp.([]byte)
    }

    if exsit == true {
	ds,err := dev.UnCompress(string(da))
	if err == nil {
	    dss,err := dev.Decode2(ds,"AcceptLockOutData")
	    if err == nil {
		ac := dss.(*dev.AcceptLockOutData)
		if ac != nil && strings.EqualFold(ac.Status, "Pending") {
		    common.Info("===================!!!!dcrm_lockOut,this lockout has already handle,","account = ",from.Hex(),"group id = ",groupid,"nonce = ",Nonce,"dcrm from = ",dcrmaddr,"threshold = ",threshold,"key = ",key2)
		    return "","the lockout has already handle,status is pending",fmt.Errorf("the lockout has already handle,status is pending.")
		}
	    }
	}
    }

    //nonce check
    /*cur_nonce_str,tip,err := dev.GetLockOutNonce(from.Hex(),cointype,dcrmaddr)
    if err != nil {
	return "",tip,err
    }

    if strings.EqualFold(fmt.Sprintf("%v",Nonce),cur_nonce_str) == false {
	return "","lockout tx nonce error",fmt.Errorf("nonce error.")
    }*/
    
    _,exsit = dev.LdbLockOut.ReadMap(key2)
    if exsit == false {
	da2 := dev.GetLockOutValueFromDb(key2)
	if da2 == nil {
	    exsit = false
	} else {
	    exsit = true
	}
    }
    
    ///////
    if exsit == true {
	return "","lockout tx nonce error",fmt.Errorf("nonce error.")
    }
    //
    
    tip,err := dev.SetLockOutNonce(from.Hex(),cointype,dcrmaddr,fmt.Sprintf("%v",Nonce))
    if err != nil {
	return "",tip,fmt.Errorf("update nonce error.")
    }

    //////////
   
    go func() {
	for i:=0;i<1;i++ {
	    txhash,_,err2 := dev.SendLockOut(from.Hex(),dcrmaddr,dcrmto,value,cointype,groupid,fmt.Sprintf("%v",Nonce),threshold,mode,key2) 
	    if err2 == nil && txhash != "" {
		return
	    }

	    time.Sleep(time.Duration(1000000)) //1000 000 000 == 1s
	}
    }()
    
    common.Info("=================== LockOut return ","key = ",key2,"","===========================")

    return key2,"",nil
}

func GetReqAddrStatus(key string) (string,string,error) {
    return dev.GetReqAddrStatus(key)
}

func GetLockOutStatus(key string) (string,string,error) {
    return dev.GetLockOutStatus(key)
}

func GetAccountsBalance(pubkey string,geter_acc string) (interface{}, string, error) {
    _,lmvalue := dev.AllAccounts.ListMap()
    for _,v := range lmvalue {
	if v == nil {
	    continue
	}

	vv := v.(*dev.PubKeyData)

	if vv.Pub == "" || vv.GroupId == "" || vv.Mode == "" {
	    continue
	}

	pb := vv.Pub
	pubkeyhex := hex.EncodeToString([]byte(pb))
	if strings.EqualFold(pubkey,pubkeyhex) == false {
	    continue
	}

	///////
	rk := dev.Keccak256Hash([]byte(strings.ToLower(vv.Account + ":" + "ALL" + ":" + vv.GroupId + ":" + vv.Nonce + ":" + vv.LimitNum + ":" + vv.Mode))).Hex()
	if dev.CheckAcc(cur_enode,geter_acc,rk) == false {
	    return "","invalid accepter",fmt.Errorf("invalid accepter")
	}
	/////

	////bug,check valid accepter
	/*check := false
	for _,v := range vv.NodeSigs {
	    tx2 := new(types.Transaction)
	    vs := common.FromHex(v)
	    if err := rlp.DecodeBytes(vs, tx2); err != nil {
		continue
	    }

	    signer := types.NewEIP155Signer(big.NewInt(30400)) //
	    from2, err := types.Sender(signer, tx2)
	    if err != nil {
		signer = types.NewEIP155Signer(big.NewInt(4)) //
		from2, err = types.Sender(signer, tx2)
		if err != nil {
		    continue
		}
	    }
	    
	    eid := string(tx2.Data())
	    fmt.Println("============GetAccountsBalance,eid = %s,cur_enode =%s,from =%s,from2 =%s===============",eid,cur_enode,geter_acc,from2.Hex())
	    if strings.EqualFold(eid,cur_enode) && strings.EqualFold(geter_acc,from2.Hex()) {
		check = true
		break
	    }
	}

	if check == false {
	    continue
	}*/
	
	key,err2 := hex.DecodeString(pubkey)
	if err2 != nil {
//	    fmt.Printf("==============GetAccountsBalance,decode pubkey string fail,err =%v=============",err2)
	    return nil,"decode pubkey fail",err2
	}

	ret, tip, err := GetPubKeyData(string(key), pubkey, "ALL")
	var m interface{}
	if err == nil {
//	    fmt.Println("================GetAccountsBalance,get pubkey data success============")
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
//		    fmt.Println("===============GetAccountsBalance,call GetBalance,pubkey =%s,cointype =%s, dcrmaddr =%s, balance =%s, err =%v================",pubkey,cointype, subaddr, balance, err)
		    if err != nil {
			balance = "0"
		    }
		    ret[cointype] = &SubAddressBalance{Cointype: cointype, DcrmAddr: subaddr, Balance: balance}
		}(cointype, subaddr)
	    }
	    wg.Wait()
	    for _, cointype := range coins.Cointypes {
		 if ret[cointype] != nil {
		     balances = append(balances, *(ret[cointype]))
		     fmt.Printf("balances: %v\n", balances)
		     delete(ret, cointype)
		 }
	    }
	    m = &DcrmAccountsBalanceRes{PubKey:pubkey,Balances:balances}
	} else {
//	    fmt.Println("================GetAccountsBalance,get pubkey data fail,err =%v============",err)
	}
	
	return m, tip, err
    }

    return nil,"get accounts balance fail",fmt.Errorf("get accounts balance fail")
}

func GetBalance(account string, cointype string,dcrmaddr string) (string,string,error) {

    if strings.EqualFold(cointype, "BTC") {  ///tmp code
	return "0","",nil  //TODO
    }

    if strings.EqualFold(cointype, "BCH") {
	return "0","",nil  //TODO
    }

    if strings.EqualFold(cointype, "USDT") {
	return "0","",nil  //TODO
    }

    if strings.EqualFold(cointype, "BEP2GZX_754") {
	return "0","",nil  //TODO
    }

    h := coins.NewCryptocoinHandler(cointype)
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
//	fmt.Println("================GetBalance 22222,err =%v =================",err)
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

func GetCurNodeReqAddrInfo(geter_acc string) ([]string,string,error) {
    reply,tip,err := SendReqToGroup(geter_acc,"rpc_get_cur_node_reqaddr_info")
    if reply == "" || err != nil {
	//fmt.Println("===========dcrm.GetCurNodeReqAddrInfo,no get result,err =%v ============",err)
	return nil,tip,err 
    }

    ss := strings.Split(reply,"|")
    return ss,"",nil 
}

func GetCurNodeLockOutInfo(geter_acc string) ([]string,string,error) {
    reply,tip,err := SendReqToGroup(geter_acc,"rpc_get_cur_node_lockout_info")
    if reply == "" || err != nil {
	//fmt.Println("===========dcrm.GetCurNodeLockOutInfo,no get result,err =%v ============",err)
	return nil,tip,err 
    }

    ss := strings.Split(reply,"|")
    return ss,"",nil 
}

func init(){
	p2pdcrm.RegisterRecvCallback(Call)
	p2pdcrm.SdkProtocol_registerBroadcastInGroupCallback(dev.Call)
	p2pdcrm.SdkProtocol_registerSendToGroupCallback(dev.DcrmCall)
	p2pdcrm.SdkProtocol_registerSendToGroupReturnCallback(dev.DcrmCallRet)
	p2pdcrm.RegisterCallback(dev.Call)

	dev.RegP2pGetGroupCallBack(p2pdcrm.SdkProtocol_getGroup)
	dev.RegP2pSendToGroupAllNodesCallBack(p2pdcrm.SdkProtocol_SendToGroupAllNodes)
	dev.RegP2pGetSelfEnodeCallBack(p2pdcrm.GetSelfID)
	dev.RegP2pBroadcastInGroupOthersCallBack(p2pdcrm.SdkProtocol_broadcastInGroupOthers)
	dev.RegP2pSendMsgToPeerCallBack(p2pdcrm.SendMsgToPeer)
	dev.RegP2pParseNodeCallBack(p2pdcrm.ParseNodeID)
	dev.RegDcrmGetEosAccountCallBack(eos.GetEosAccount)
	dev.InitChan()
}

func Call(msg interface{}) {
    fmt.Println("===========dcrm.Call,msg =%v==============",msg)
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

