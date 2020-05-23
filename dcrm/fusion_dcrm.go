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
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"strconv"
	"strings"
	"sync"
	"time"
	"bytes"

	"github.com/fsn-dev/cryptoCoins/coins"
	"github.com/fsn-dev/dcrm-walletService/crypto/secp256k1"
	"github.com/fsn-dev/dcrm-walletService/crypto"
	cryptocoinsconfig "github.com/fsn-dev/cryptoCoins/coins/config"
	"github.com/fsn-dev/cryptoCoins/coins/eos"
	"github.com/fsn-dev/cryptoCoins/coins/types"
	"github.com/fsn-dev/dcrm-walletService/internal/common"
	p2pdcrm "github.com/fsn-dev/dcrm-walletService/p2p/layer2"
	"github.com/fsn-dev/cryptoCoins/tools/rlp"
	"github.com/fsn-dev/dcrm-walletService/ethdb"
	"github.com/fsn-dev/dcrm-walletService/mpcdsa/crypto/ec2"
	"github.com/fsn-dev/dcrm-walletService/p2p/discover"
	"encoding/gob"
	"sort"
	"compress/zlib"
	"github.com/fsn-dev/dcrm-walletService/crypto/sha3"
	"io"
	"github.com/fsn-dev/dcrm-walletService/internal/common/hexutil"
)

var (
	cur_enode  string
	init_times = 0
	sendtogroup_lilo_timeout = 130000  
	sendtogroup_timeout      = 130000
	KeyFile    string
	ReqAddrCh  = make(chan ReqAddrData, 1000)
	LockOutCh  = make(chan LockOutData, 1000)
	SignCh  = make(chan SignData, 1000)
	ReShareCh  = make(chan ReShareData, 1000)
	
	lock5                    sync.Mutex
	lock                     sync.Mutex
)

func Start() {
	cryptocoinsconfig.Init()
	coins.Init()
	go RecivReqAddr()
	go RecivLockOut()
	go RecivReShare()
	go RecivSign()
	InitDev(KeyFile)
	cur_enode = p2pdcrm.GetSelfID()
}

func PutGroup(groupId string) bool {
	return true

	if groupId == "" {
		return false
	}

	lock.Lock()
	dir := GetGroupDir()
	//db, err := leveldb.OpenFile(dir, nil)

	db, err := ethdb.NewLDBDatabase(dir, 0, 0)
	//bug
	if err != nil {
		for i := 0; i < 100; i++ {
			db, err = ethdb.NewLDBDatabase(dir, 0, 0)
			if err == nil && db != nil {
				break
			}

			time.Sleep(time.Duration(1000000))
		}
	}
	//

	if err != nil {
		lock.Unlock()
		return false
	}

	var data string
	var b bytes.Buffer
	b.WriteString("")
	b.WriteByte(0)
	b.WriteString("")
	iter := db.NewIterator()
	for iter.Next() {
		key := string(iter.Key())
		value := string(iter.Value())
		if strings.EqualFold(key, "GroupIds") {
			data = value
			break
		}
	}
	iter.Release()
	///////
	if data == "" {
		db.Put([]byte("GroupIds"), []byte(groupId))
		db.Close()
		lock.Unlock()
		return true
	}

	m := strings.Split(data, ":")
	for _, v := range m {
		if strings.EqualFold(v, groupId) {
			db.Close()
			lock.Unlock()
			return true
		}
	}

	data += ":" + groupId
	db.Put([]byte("GroupIds"), []byte(data))

	db.Close()
	lock.Unlock()
	return true
}

func GetGroupIdByEnode(enode string) string {
	if enode == "" {
		return ""
	}

	lock.Lock()
	dir := GetGroupDir()
	//db, err := leveldb.OpenFile(dir, nil)

	db, err := ethdb.NewLDBDatabase(dir, 0, 0)
	//bug
	if err != nil {
		for i := 0; i < 100; i++ {
			db, err = ethdb.NewLDBDatabase(dir, 0, 0)
			if err == nil && db != nil {
				break
			}

			time.Sleep(time.Duration(1000000))
		}
	}
	//

	if err != nil {
		lock.Unlock()
		return ""
	}

	var data string
	var b bytes.Buffer
	b.WriteString("")
	b.WriteByte(0)
	b.WriteString("")
	iter := db.NewIterator()
	for iter.Next() {
		key := string(iter.Key())
		value := string(iter.Value())
		if strings.EqualFold(key, "GroupIds") {
			data = value
			break
		}
	}
	iter.Release()
	///////
	if data == "" {
		db.Close()
		lock.Unlock()
		return ""
	}

	m := strings.Split(data, ":")
	for _, v := range m {
		if IsInGroup(enode, v) {
			db.Close()
			lock.Unlock()
			return v
		}
	}

	db.Close()
	lock.Unlock()
	return ""
}

func IsInGroup(enode string, groupId string) bool {
	if groupId == "" || enode == "" {
		return false
	}

	cnt, enodes := GetGroup(groupId)
	if cnt <= 0 || enodes == "" {
		return false
	}

	fmt.Printf("==== dev.IsInGroup() ====, gid: %v, enodes: %v\n", groupId, enodes)
	nodes := strings.Split(enodes, common.Sep2)
	fmt.Printf("==== dev.IsInGroup() ====, gid: %v, enodes: %v, split: %v, nodes: %v\n", groupId, enodes, common.Sep2, nodes)
	for _, node := range nodes {
		fmt.Printf("==== dev.IsInGroup() ====, call ParseNode enode: %v\n", node)
		node2 := ParseNode(node)
		if strings.EqualFold(node2, enode) {
			return true
		}
	}

	return false
}

func InitDev(keyfile string) {
	cur_enode = discover.GetLocalID().String() //GetSelfEnode()

	LdbPubKeyData = GetAllPubKeyDataFromDb()

	go SavePubKeyDataToDb()
	go CommitRpcReq()
	go ec2.GenRandomInt(2048)
	go ec2.GenRandomSafePrime(2048)
}

func InitGroupInfo(groupId string) {
	//cur_enode = GetSelfEnode()
	cur_enode = discover.GetLocalID().String() //GetSelfEnode()
	//fmt.Printf("%v ==================InitGroupInfo,cur_enode = %v ====================\n", common.CurrentTime(), cur_enode)
}

func GenRandomSafePrime(length int) {
	ec2.GenRandomSafePrime(length)
}

//=======================================================================

type RpcDcrmRes struct {
	Ret string
	Tip string
	Err error
}

type DcrmAccountsBalanceRes struct {
	PubKey   string
	Balances []SubAddressBalance
}

type SubAddressBalance struct {
	Cointype string
	DcrmAddr string
	Balance  string
}

type DcrmAddrRes struct {
	Account  string
	PubKey   string
	DcrmAddr string
	Cointype string
}

type DcrmPubkeyRes struct {
	Account     string
	PubKey      string
	DcrmAddress map[string]string
}

func GetPubKeyData(key string, account string, cointype string) (string, string, error) {
	if key == "" || cointype == "" {
		return "", "dcrm back-end internal error:parameter error in func GetPubKeyData", fmt.Errorf("get pubkey data param error.")
	}

	exsit,da := GetValueFromPubKeyData(key)
	///////
	if exsit == false {
		return "", "dcrm back-end internal error:get data from db fail in func GetPubKeyData", fmt.Errorf("dcrm back-end internal error:get data from db fail in func GetPubKeyData")
	}

	pubs,ok := da.(*PubKeyData)
	if ok == false {
		return "", "dcrm back-end internal error:get data from db fail in func GetPubKeyData", fmt.Errorf("dcrm back-end internal error:get data from db fail in func GetPubKeyData")
	}

	pubkey := hex.EncodeToString([]byte(pubs.Pub))
	///////////
	var m interface{}
	if !strings.EqualFold(cointype, "ALL") {

		h := coins.NewCryptocoinHandler(cointype)
		if h == nil {
			return "", "cointype is not supported", fmt.Errorf("req addr fail.cointype is not supported.")
		}

		ctaddr, err := h.PublicKeyToAddress(pubkey)
		if err != nil {
			return "", "dcrm back-end internal error:get dcrm addr fail from pubkey:" + pubkey, fmt.Errorf("req addr fail.")
		}

		m = &DcrmAddrRes{Account: account, PubKey: pubkey, DcrmAddr: ctaddr, Cointype: cointype}
		b, _ := json.Marshal(m)
		return string(b), "", nil
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

	m = &DcrmPubkeyRes{Account: account, PubKey: pubkey, DcrmAddress: addrmp}
	b, _ := json.Marshal(m)
	return string(b), "", nil
}

func GetDcrmAddr(pubkey string) (string, string, error) {
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
		ctaddr, err := h.PublicKeyToAddress(pubkey)
		if err != nil {
			continue
		}

		addrmp[ct] = ctaddr
	}

	m = &DcrmPubkeyRes{Account: "", PubKey: pubkey, DcrmAddress: addrmp}
	b,_ := json.Marshal(m)
	return string(b), "", nil
}

func ExsitPubKey(account string, cointype string) (string, bool) {
	key := Keccak256Hash([]byte(strings.ToLower(account + ":" + cointype))).Hex()
	exsit,da := GetValueFromPubKeyData(key)
	///////
	if exsit == false {
		key = Keccak256Hash([]byte(strings.ToLower(account + ":" + "ALL"))).Hex()
		exsit,da = GetValueFromPubKeyData(key)
		///////
		if exsit == false {
			return "", false
		}
	}

	pubs,ok  := da.(*PubKeyData)
	if ok == false {
	    return "",false
	}

	pubkey := hex.EncodeToString([]byte(pubs.Pub))
	return pubkey, true
}

type ReqAddrData struct {
	Account   string
	Nonce     string
	JsonStr   string
	Key       string
}

func RecivReqAddr() {
	for {
		select {
		case data := <-ReqAddrCh:
			////////bug
			exsit,_ := GetValueFromPubKeyData(data.Key)
			if exsit == false {
				req := TxDataReqAddr{}
				json.Unmarshal([]byte(data.JsonStr), &req)
				
				cur_nonce, _, _ := GetReqAddrNonce(data.Account)
				cur_nonce_num, _ := new(big.Int).SetString(cur_nonce, 10)
				new_nonce_num, _ := new(big.Int).SetString(data.Nonce, 10)
				if new_nonce_num.Cmp(cur_nonce_num) >= 0 {
					_, err := SetReqAddrNonce(data.Account,data.Nonce)
					//fmt.Printf("%v =================================RecivReqAddr,SetReqAddrNonce, account = %v,group id = %v,threshold = %v,mode = %v,nonce = %v,err = %v,key = %v, =================================\n", common.CurrentTime(), data.Account, req.GroupId, req.ThresHold,req.Mode, data.Nonce, err, data.Key)
					if err == nil {
					    ars := GetAllReplyFromGroup(-1,req.GroupId,Rpc_REQADDR,cur_enode)

					    ac := &AcceptReqAddrData{Initiator:cur_enode,Account: data.Account, Cointype: "ALL", GroupId: req.GroupId, Nonce: data.Nonce, LimitNum: req.ThresHold, Mode: req.Mode, TimeStamp: req.TimeStamp, Deal: "false", Accept: "false", Status: "Pending", PubKey: "", Tip: "", Error: "", AllReply: ars, WorkId: -1,Sigs:""}
						err := SaveAcceptReqAddrData(ac)
						fmt.Printf("%v ===================call SaveAcceptReqAddrData finish, account = %v,err = %v,key = %v, ========================\n", common.CurrentTime(), data.Account, err, data.Key)
						if err == nil {
						    ///////add decdsa log
						    var enodeinfo string
						    groupinfo := make([]string,0)
						    _, enodes := GetGroup(req.GroupId)
						    nodes := strings.Split(enodes, common.Sep2)
						    for _, node := range nodes {
							groupinfo = append(groupinfo,node)
							node2 := ParseNode(node)
							if strings.EqualFold(cur_enode,node2) {
							    enodeinfo = node 
							}
						    }

						    log, exist := DecdsaMap.ReadMap(strings.ToLower(data.Key))
						    if exist == false {
							logs := &DecdsaLog{CurEnode:enodeinfo,GroupEnodes:groupinfo,DcrmCallTime:"",RecivAcceptRes:nil,SendAcceptRes:nil,RecivDcrm:nil,SendDcrm:nil,FailTime:"",FailInfo:"",No_Reciv:nil}
							DecdsaMap.WriteMap(strings.ToLower(data.Key),logs)
							//fmt.Printf("%v ===============RecivReqAddr,write map success,enodeinfo = %v,key = %v=================\n", common.CurrentTime(),enodeinfo,data.Key)
						    } else {
							logs,ok := log.(*DecdsaLog)
							if ok == true {
							    logs.CurEnode = enodeinfo
							    logs.GroupEnodes = groupinfo
							    DecdsaMap.WriteMap(strings.ToLower(data.Key),logs)
							    //fmt.Printf("%v ===============RecivReqAddr,write map success,enodeinfo = %v,key = %v=================\n", common.CurrentTime(),enodeinfo,data.Key)
							}
						    }
						    //////////////////
							////////bug
							go func(d ReqAddrData,reqda *TxDataReqAddr,rad *AcceptReqAddrData) {
								nums := strings.Split(reqda.ThresHold, "/")
								nodecnt, _ := strconv.Atoi(nums[1])
								if nodecnt <= 1 {
								    return
								}

								sigs := strings.Split(reqda.Sigs,"|")
								//SigN = enode://xxxxxxxx@ip:portxxxxxxxxxxxxxxxxxxxxxx
								_, enodes := GetGroup(reqda.GroupId)
								nodes := strings.Split(enodes, common.Sep2)
								/////////////////////tmp code //////////////////////
								if reqda.Mode == "0" {
								        if nodecnt != len(sigs) {
									    return
									}

									mp := []string{d.Key, cur_enode}
									enode := strings.Join(mp, "-")
									s0 := "GroupAccounts"
									s1 := strconv.Itoa(nodecnt)
									ss := enode + common.Sep + s0 + common.Sep + s1

									sstmp := s1
									for j := 0; j < nodecnt; j++ {
									    //fmt.Printf("%v==================RecivReqAddr, j = %v, sig data = %v, key = %v ==================\n",common.CurrentTime(),j,sigs[j],data.Key)
										en := strings.Split(sigs[j], "@")
										for _, node := range nodes {
										    node2 := ParseNode(node)
										    enId := strings.Split(en[0],"//")
										    if len(enId) < 2 {
											return
										    }

										    //fmt.Printf("%v==================RecivReqAddr, j = %v, sig data = %v, node = %v, node2 = %v, key = %v ==================\n",common.CurrentTime(),j,sigs[j],enId[1],node2,data.Key)
										    if strings.EqualFold(node2, enId[1]) {
											enodesigs := []rune(sigs[j])
											if len(enodesigs) <= len(node) {
											    return
											}

											sig := enodesigs[len(node):]
											//sigbit, _ := hex.DecodeString(string(sig[:]))
											sigbit := common.FromHex(string(sig[:]))
											if sigbit == nil {
											    return
											}

											//fmt.Printf("%v=====================RecivReqAddr, j = %v, sig data = %v, hex raw sig = %v, raw sig = %v, key = %v ==================\n",common.CurrentTime(),j,sigs[j],string(sig[:]),string(sigbit),data.Key)
											pub,err := secp256k1.RecoverPubkey(crypto.Keccak256([]byte(node2)),sigbit)
											if err != nil {
											    fmt.Printf("%v=====================RecivReqAddr, recover pubkey fail and return, err = %v, j = %v, sig = %v, key = %v ==================\n",common.CurrentTime(),err,j,string(sig[:]),data.Key)
											    return
											}
											
											h := coins.NewCryptocoinHandler("FSN")
											if h != nil {
											    pubkey := hex.EncodeToString(pub)
											    from, err := h.PublicKeyToAddress(pubkey)
											    if err != nil {
												fmt.Printf("%v=====================RecivReqAddr, pubkey to addr fail and return, err = %v, j = %v, sig = %v, key = %v ==================\n",common.CurrentTime(),err,j,string(sig[:]),data.Key)
												return
											    }
											    
											    //key-enode:GroupAccounts:5:eid1:acc1:eid2:acc2:eid3:acc3:eid4:acc4:eid5:acc5
											    ss += common.Sep
											    ss += node2 
											    ss += common.Sep
											    ss += from
											    
											    sstmp += common.Sep
											    sstmp += node2
											    sstmp += common.Sep
											    sstmp += from
											    
											    exsit,da := GetValueFromPubKeyData(strings.ToLower(from))
											    if exsit == false {
												kdtmp := KeyData{Key: []byte(strings.ToLower(from)), Data: d.Key}
												PubKeyDataChan <- kdtmp
												LdbPubKeyData.WriteMap(strings.ToLower(from), []byte(d.Key))
											    } else {
												//
												found := false
												keys := strings.Split(string(da.([]byte)),":")
												for _,v := range keys {
												    if strings.EqualFold(v,d.Key) {
													found = true
													break
												    }
												}
												//

												if !found {
												    da2 := string(da.([]byte)) + ":" + d.Key
												    kdtmp := KeyData{Key: []byte(strings.ToLower(from)), Data: da2}
												    PubKeyDataChan <- kdtmp
												    LdbPubKeyData.WriteMap(strings.ToLower(from), []byte(da2))
												}
											    }
											}
										    }
										}

									}

									SendMsgToDcrmGroup(ss, reqda.GroupId)
									//fmt.Printf("%v ===============RecivReqAddr,send group accounts to other nodes,msg = %v,key = %v,===========================\n", common.CurrentTime(), ss, d.Key)
									rad.Sigs = sstmp
									if SaveAcceptReqAddrData(rad) != nil { //re-save
									    return
									}
								} else {
									    exsit,da := GetValueFromPubKeyData(strings.ToLower(d.Account))
									    if exsit == false {
										kdtmp := KeyData{Key: []byte(strings.ToLower(d.Account)), Data: d.Key}
										PubKeyDataChan <- kdtmp
										LdbPubKeyData.WriteMap(strings.ToLower(d.Account), []byte(d.Key))
									    } else {
										da2 := string(da.([]byte)) + ":" + d.Key
										kdtmp := KeyData{Key: []byte(strings.ToLower(d.Account)), Data: da2}
										PubKeyDataChan <- kdtmp
										LdbPubKeyData.WriteMap(strings.ToLower(d.Account), []byte(da2))
									    }
								}
								////////////////////////////////////////////////////

								//coin := "ALL"
								//if !types.IsDefaultED25519(msgs[1]) {  //TODO
								//}

								addr, _, err := SendReqDcrmAddr(d.Account, d.Nonce, d.JsonStr, d.Key)
								fmt.Printf("%v ===============RecivReqAddr,finish calc dcrm addrs,addr = %v,err = %v,key = %v,===========================\n", common.CurrentTime(), addr, err, d.Key)
								if addr != "" && err == nil {
									return
								}
							}(data,&req,ac)
							//
						}
					}
				}
			}
		}
	}
}

func ReqDcrmAddr(raw string) (string, string, error) {
	tx := new(types.Transaction)
	raws := common.FromHex(raw)
	if err := rlp.DecodeBytes(raws, tx); err != nil {
		return "", "raw data error", err
	}

	signer := types.NewEIP155Signer(big.NewInt(30400)) //
	from, err := types.Sender(signer, tx)
	if err != nil {
	    return "", "recover fusion account fail from raw data,maybe raw data error", err
	}

	req := TxDataReqAddr{}
	err = json.Unmarshal(tx.Data(), &req)
	if err != nil {
	    return "", "recover tx.data json string fail from raw data,maybe raw data error", err
	}

	if req.TxType != "REQDCRMADDR" {
		return "", "transaction data format error,it is not REQDCRMADDR tx", fmt.Errorf("tx type error.")
	}

	groupid := req.GroupId 
	if groupid == "" {
		return "", "group id error", fmt.Errorf("get group id fail.")
	}

	threshold := req.ThresHold
	if threshold == "" {
		return "", "no threshold value", fmt.Errorf("get threshold fail.")
	}

	mode := req.Mode
	if mode == "" {
		return "", "get mode fail", fmt.Errorf("get mode fail.")
	}

	timestamp := req.TimeStamp
	if timestamp == "" {
		return "", "no timestamp value", fmt.Errorf("get timestamp fail.")
	}

	nums := strings.Split(threshold, "/")
	if len(nums) != 2 {
		return "", "transacion data format error,threshold is not right", fmt.Errorf("tx.data error.")
	}

	nodecnt, err := strconv.Atoi(nums[1])
	if err != nil {
		return "", err.Error(),err
	}

	ts, err := strconv.Atoi(nums[0])
	if err != nil {
		return "", err.Error(),err
	}

	if nodecnt < ts || ts < 2 {
	    return "","threshold format error",fmt.Errorf("threshold format error")
	}

	Nonce := tx.Nonce()

	////
	nc,_ := GetGroup(groupid)
	if nc != nodecnt {
	    return "","check group node count error",fmt.Errorf("check group node count error")
	}
	////

	key := Keccak256Hash([]byte(strings.ToLower(from.Hex() + ":" + "ALL" + ":" + groupid + ":" + fmt.Sprintf("%v", Nonce) + ":" + threshold + ":" + mode))).Hex()

	data := ReqAddrData{Account: from.Hex(), Nonce: fmt.Sprintf("%v", Nonce), JsonStr:string(tx.Data()), Key: key}
	ReqAddrCh <- data

	fmt.Printf("%v ===============ReqDcrmAddr finish,return,key = %v,raw = %v,mode = %v ================================\n", common.CurrentTime(), key, raw, mode)
	return key, "", nil
}

func RpcAcceptReqAddr(raw string) (string, string, error) {
	tx := new(types.Transaction)
	raws := common.FromHex(raw)
	if err := rlp.DecodeBytes(raws, tx); err != nil {
		return "Failure", "raw data error", err
	}

	signer := types.NewEIP155Signer(big.NewInt(30400)) //
	from, err := types.Sender(signer, tx)
	if err != nil {
	    return "Failure", "recover fusion account fail from raw data,maybe raw data error", err
	}

	acceptreq := TxDataAcceptReqAddr{}
	err = json.Unmarshal(tx.Data(), &acceptreq)
	if err != nil {
	    return "Failure", "recover tx.data json string fail from raw data,maybe raw data error", err
	}

	//ACCEPTREQADDR:account:cointype:groupid:nonce:threshold:mode:accept:timestamp
	if acceptreq.TxType != "ACCEPTREQADDR" {
		return "Failure", "transaction data format error,it is not ACCEPTREQADDR tx", fmt.Errorf("tx.data error,it is not ACCEPTREQADDR tx.")
	}

	if acceptreq.Accept != "AGREE" && acceptreq.Accept != "DISAGREE" {
		return "Failure", "transaction data format error,the lastest segment is not AGREE or DISAGREE", fmt.Errorf("transaction data format error")
	}

	status := "Pending"
	accept := "false"
	if acceptreq.Accept == "AGREE" {
		accept = "true"
	} else {
		status = "Failure"
	}

	////bug,check valid accepter
	exsit,da := GetValueFromPubKeyData(acceptreq.Key)
	if exsit == false {
		return "Failure", "dcrm back-end internal error:get accept data fail from db", fmt.Errorf("dcrm back-end internal error:get accept data fail from db")
	}

	ac,ok := da.(*AcceptReqAddrData)
	if ok == false {
		return "Failure", "dcrm back-end internal error:decode accept data fail", fmt.Errorf("decode accept data fail")
	}

	if ac == nil {
		return "Failure", "dcrm back-end internal error:decode accept data fail", fmt.Errorf("decode accept data fail")
	}

	///////
	if ac.Mode == "1" {
		return "Failure", "mode = 1,do not need to accept", fmt.Errorf("mode = 1,do not need to accept")
	}
	
	if !CheckAcc(cur_enode,from.Hex(),ac.Sigs) {
	    return "Failure", "invalid accepter", fmt.Errorf("invalid accepter")
	}

	if ac.Mode == "0" {
	    exsit,data := GetValueFromPubKeyData(strings.ToLower(from.Hex()))
	    if exsit == false {
		return "Failure", "invalid accepter", fmt.Errorf("invalid accepter")
	    }

	    found := false
	    keys := strings.Split(string(data.([]byte)),":")
	    for _,k := range keys {
		if strings.EqualFold(k,acceptreq.Key) {
		    found = true
		    break
		}
	    }
	    
	    if found == false {
		return "Failure", "invalid accepter", fmt.Errorf("invalid accepter")
	    }
	}
	/////

	///////
	mp := []string{acceptreq.Key, cur_enode}
	enode := strings.Join(mp, "-")
	s0 := "AcceptReqAddrRes"
	s1 := accept
	s2 := acceptreq.TimeStamp
	ss := enode + common.Sep + s0 + common.Sep + s1 + common.Sep + s2
	SendMsgToDcrmGroup(ss, ac.GroupId)
	
	//////////add decdsa log
	cur_time := fmt.Sprintf("%v",common.CurrentTime())
	log, exist := DecdsaMap.ReadMap(strings.ToLower(acceptreq.Key))
	if exist == false {
	    tmp := make([]SendAcceptResTime,0)
	    rat := SendAcceptResTime{SendTime:cur_time,Reply:ss}
	    tmp = append(tmp,rat)
	    logs := &DecdsaLog{CurEnode:"",GroupEnodes:nil,DcrmCallTime:"",RecivAcceptRes:nil,SendAcceptRes:tmp,RecivDcrm:nil,SendDcrm:nil,FailTime:"",FailInfo:"",No_Reciv:nil}
	    DecdsaMap.WriteMap(strings.ToLower(acceptreq.Key),logs)
	    //fmt.Printf("%v ===============AcceptReqAddr,write map success, code is AcceptReqAddrRes,exist is false, msg = %v, key = %v=================\n", common.CurrentTime(),ss,acceptreq.Key)
	} else {
	    logs,ok := log.(*DecdsaLog)
	    if ok == false {
		fmt.Printf("%v ===============AcceptReqAddr,code is AcceptReqAddrRes,ok if false, key = %v=================\n", common.CurrentTime(),acceptreq.Key)
		return "Failure", "get dcrm log fail", fmt.Errorf("get dcrm log fail.")
	    }

	    rats := logs.SendAcceptRes
	    rat := SendAcceptResTime{SendTime:cur_time,Reply:ss}
	    rats = append(rats,rat)
	    logs.SendAcceptRes = rats
	    DecdsaMap.WriteMap(strings.ToLower(acceptreq.Key),logs)
	    //fmt.Printf("%v ===============AcceptReqAddr,write map success,code is AcceptReqAddrRes,exist is true,key = %v=================\n", common.CurrentTime(),acceptreq.Key)
	}
	///////////////////////

	DisMsg(ss)
	//fmt.Printf("%v ================== AcceptReqAddr, finish send AcceptReqAddrRes to other nodes,key = %v ====================\n", common.CurrentTime(), acceptreq.Key)
	////fix bug: get C1 timeout
	_, enodes := GetGroup(ac.GroupId)
	nodes := strings.Split(enodes, common.Sep2)
	for _, node := range nodes {
	    node2 := ParseNode(node)
	    c1data := acceptreq.Key + "-" + node2 + common.Sep + "AcceptReqAddrRes"
	    c1, exist := C1Data.ReadMap(strings.ToLower(c1data))
	    if exist {
		DisMsg(c1.(string))
		go C1Data.DeleteMap(strings.ToLower(c1data))
	    }
	}
	////
	
	w, err := FindWorker(acceptreq.Key)
	if err != nil {
	    return "Failure",err.Error(),err
	}

	id,_ := GetWorkerId(w)
	ars := GetAllReplyFromGroup(id,ac.GroupId,Rpc_REQADDR,ac.Initiator)
	tip, err := AcceptReqAddr(ac.Initiator,ac.Account, ac.Cointype, ac.GroupId, ac.Nonce, ac.LimitNum, ac.Mode, "false", accept, status, "", "", "", ars, ac.WorkId,"")
	if err != nil {
		return "Failure", tip, err
	}

	return "Success", "", nil
}

func RpcAcceptLockOut(raw string) (string, string, error) {
	tx := new(types.Transaction)
	raws := common.FromHex(raw)
	if err := rlp.DecodeBytes(raws, tx); err != nil {
		return "Failure", "raw data error", err
	}

	signer := types.NewEIP155Signer(big.NewInt(30400)) //
	from, err := types.Sender(signer, tx)
	if err != nil {
	    return "Failure", "recover fusion account fail from raw data,maybe raw data error", err
	}

	acceptlo := TxDataAcceptLockOut{}
	err = json.Unmarshal(tx.Data(), &acceptlo)
	if err != nil {
	    return "Failure", "recover tx.data json string fail from raw data,maybe raw data error", err
	}

	//ACCEPTLOCKOUT:account:groupid:nonce:dcrmaddr:dcrmto:value:cointype:threshold:mode:accept:timestamp
	if acceptlo.TxType != "ACCEPTLOCKOUT" {
	    return "Failure", "transaction data format error,it is not ACCEPTLOCKOUT tx", fmt.Errorf("tx.data error,it is not ACCEPTLOCKOUT tx.")
	}

	if acceptlo.Accept != "AGREE" && acceptlo.Accept != "DISAGREE" {
	    return "Failure", "transaction data format error,the lastest segment is not AGREE or DISAGREE", fmt.Errorf("transaction data format error")
	}

	status := "Pending"
	accept := "false"
	if acceptlo.Accept == "AGREE" {
		accept = "true"
	} else {
		status = "Failure"
	}

	////bug,check valid accepter
	exsit,da := GetValueFromPubKeyData(strings.ToLower(from.Hex()))
	if exsit == false {
		return "Failure", "dcrm back-end internal error:get lockout data from db fail", fmt.Errorf("get lockout data from db fail")
	}

	check := false
	found := false
	keys := strings.Split(string(da.([]byte)),":")
	for _,key := range keys {
	    exsit,data2 := GetValueFromPubKeyData(key)
	    if exsit == false {
		continue
	    }

	    ac,ok := data2.(*AcceptReqAddrData)
	    if ok == false || ac == nil {
		continue
	    }

	    if ac.Mode == "0" && !CheckAcc(cur_enode,from.Hex(),ac.Sigs) {
		continue
	    }

	    dcrmpks, _ := hex.DecodeString(ac.PubKey)
	    exsit,data3 := GetValueFromPubKeyData(string(dcrmpks[:]))
	    if exsit == false || data3 == nil {
		continue
	    }

	    pd,ok := data3.(*PubKeyData)
	    if ok == false {
		continue
	    }

	    if pd == nil {
		continue
	    }

	    if pd.RefLockOutKeys == "" {
		continue
	    }

	    lockoutkeys := strings.Split(pd.RefLockOutKeys,":")
	    for _,lockoutkey := range lockoutkeys {
		if strings.EqualFold(lockoutkey,acceptlo.Key) {
		    found = true
		    exsit,data3 := GetValueFromPubKeyData(lockoutkey)
		    if exsit == false {
			break
		    }

		    ac3,ok := data3.(*AcceptLockOutData)
		    if ok == false {
			break
		    }

		    if ac3 == nil {
			    break
		    }

		    if ac3.Mode == "1" {
			    break
		    }

		    check = true
		    break
		}
	    }

	    if check == true || found == true {
		break
	    }
	    ////
	}

	if !check {
		return "Failure", "invalid accepter", fmt.Errorf("invalid accepter")
	}

	//ACCEPTLOCKOUT:account:groupid:nonce:dcrmaddr:dcrmto:value:cointype:threshold:mode:accept:timestamp
	exsit,da = GetValueFromPubKeyData(acceptlo.Key)
	///////
	if exsit == false {
		return "Failure", "dcrm back-end internal error:get accept result from db fail", fmt.Errorf("get accept result from db fail")
	}

	ac,ok := da.(*AcceptLockOutData)
	if ok == false {
		return "Failure", "dcrm back-end internal error:get accept result from db fail", fmt.Errorf("get accept result from db fail")
	}

	if ac == nil {
		return "Failure", "dcrm back-end internal error:get accept result from db fail", fmt.Errorf("get accept result from db fail")
	}

	if ac.Mode == "1" {
		return "Failure", "mode = 1,do not need to accept", fmt.Errorf("mode = 1,do not need to accept")
	}

	///////
	mp := []string{acceptlo.Key, cur_enode}
	enode := strings.Join(mp, "-")
	s0 := "AcceptLockOutRes"
	s1 := accept
	s2 := acceptlo.TimeStamp
	ss2 := enode + common.Sep + s0 + common.Sep + s1 + common.Sep + s2
	SendMsgToDcrmGroup(ss2, ac.GroupId)
	DisMsg(ss2)
	//fmt.Printf("%v ================== AcceptLockOut , finish send AcceptLockOutRes to other nodes ,key = %v ============================\n", common.CurrentTime(), acceptlo.Key)
	////fix bug: get C11 timeout
	_, enodes := GetGroup(ac.GroupId)
	nodes := strings.Split(enodes, common.Sep2)
	for _, node := range nodes {
	    node2 := ParseNode(node)
	    c1data := acceptlo.Key + "-" + node2 + common.Sep + "AcceptLockOutRes"
	    c1, exist := C1Data.ReadMap(strings.ToLower(c1data))
	    if exist {
		DisMsg(c1.(string))
		go C1Data.DeleteMap(strings.ToLower(c1data))
	    }
	}
	////

	w, err := FindWorker(acceptlo.Key)
	if err != nil {
	    return "Failure",err.Error(),err
	}

	id,_ := GetWorkerId(w)
	ars := GetAllReplyFromGroup(id,ac.GroupId,Rpc_LOCKOUT,ac.Initiator)
	tip, err := AcceptLockOut(ac.Initiator,ac.Account, ac.GroupId, ac.Nonce, ac.DcrmFrom, ac.LimitNum, "false", accept, status, "", "", "", ars, ac.WorkId)
	if err != nil {
		return "Failure", tip, err
	}

	return "Success", "", nil
}

func RpcAcceptSign(raw string) (string, string, error) {
	tx := new(types.Transaction)
	raws := common.FromHex(raw)
	if err := rlp.DecodeBytes(raws, tx); err != nil {
		return "Failure", "raw data error", err
	}

	signer := types.NewEIP155Signer(big.NewInt(30400)) //
	from, err := types.Sender(signer, tx)
	if err != nil {
	    return "Failure", "recover fusion account fail from raw data,maybe raw data error", err
	}

	acceptsig := TxDataAcceptSign{}
	err = json.Unmarshal(tx.Data(), &acceptsig)
	if err != nil {
	    return "Failure", "recover tx.data json string fail from raw data,maybe raw data error", err
	}

	//ACCEPTSIGN:account:pubkey:msghash:keytype:groupid:nonce:threshold:mode:accept:timestamp
	if acceptsig.TxType != "ACCEPTSIGN" {
	    return "Failure", "transaction data format error,it is not ACCEPTSIGN tx", fmt.Errorf("tx.data error,it is not ACCEPTSIGN tx.")
	}

	if acceptsig.Accept != "AGREE" && acceptsig.Accept != "DISAGREE" {
	    return "Failure", "transaction data format error,the lastest segment is not AGREE or DISAGREE", fmt.Errorf("transaction data format error")
	}

	status := "Pending"
	accept := "false"
	if acceptsig.Accept == "AGREE" {
		accept = "true"
	} else {
		status = "Failure"
	}

	////bug,check valid accepter
	exsit,da := GetValueFromPubKeyData(strings.ToLower(from.Hex()))
	if exsit == false {
		return "Failure", "dcrm back-end internal error:get sign data from db fail", fmt.Errorf("get sign data from db fail")
	}

	//key := hash(acc + nonce + pubkey + hash + keytype + groupid + threshold + mode)
	check := false
	found := false
	keys := strings.Split(string(da.([]byte)),":")
	for _,key := range keys {
	    exsit,data2 := GetValueFromPubKeyData(key)
	    if exsit == false {
		continue
	    }

	    ac,ok := data2.(*AcceptReqAddrData)
	    if ok == false || ac == nil {
		continue
	    }

	    if ac.Mode == "0" && !CheckAcc(cur_enode,from.Hex(),ac.Sigs) {
		continue
	    }

	    dcrmpks, _ := hex.DecodeString(ac.PubKey)
	    exsit,data3 := GetValueFromPubKeyData(string(dcrmpks[:]))
	    if exsit == false || data3 == nil {
		continue
	    }

	    pd,ok := data3.(*PubKeyData)
	    if ok == false {
		continue
	    }

	    if pd == nil {
		continue
	    }

	    if pd.RefSignKeys == "" {
		continue
	    }

	    signkeys := strings.Split(pd.RefSignKeys,":")
	    for _,signkey := range signkeys {
		if strings.EqualFold(signkey, acceptsig.Key) {
		    found = true
		    exsit,data3 := GetValueFromPubKeyData(signkey)
		    if exsit == false {
			break
		    }

		    ac3,ok := data3.(*AcceptSignData)
		    if ok == false {
			break
		    }

		    if ac3 == nil {
			    break
		    }

		    if ac3.Mode == "1" {
			    break
		    }

		    check = true
		    break
		}
	    }

	    if check == true || found == true {
		break
	    }
	    ////
	}

	if !check {
	    return "Failure", "invalid accepter", fmt.Errorf("invalid accepter")
	}

	//ACCEPTSIGN:account:pubkey:msghash:keytype:groupid:nonce:threshold:mode:accept:timestamp
	exsit,da = GetValueFromPubKeyData(acceptsig.Key)
	///////
	if exsit == false {
		return "Failure", "dcrm back-end internal error:get accept result from db fail", fmt.Errorf("get accept result from db fail")
	}

	ac,ok := da.(*AcceptSignData)
	if ok == false {
	    return "Failure", "dcrm back-end internal error:get accept result from db fail", fmt.Errorf("get accept result from db fail")
	}

	if ac == nil {
	    return "Failure", "dcrm back-end internal error:get accept result from db fail", fmt.Errorf("get accept result from db fail")
	}

	if ac.Mode == "1" {
	    return "Failure", "mode = 1,do not need to accept", fmt.Errorf("mode = 1,do not need to accept")
	}

	///////
	mp := []string{acceptsig.Key, cur_enode}
	enode := strings.Join(mp, "-")
	s0 := "AcceptSignRes"
	s1 := accept
	s2 := acceptsig.TimeStamp
	ss2 := enode + common.Sep + s0 + common.Sep + s1 + common.Sep + s2
	SendMsgToDcrmGroup(ss2, ac.GroupId)
	DisMsg(ss2)
	fmt.Printf("%v ================== AcceptSign, finish send AcceptSignRes to other nodes ,key = %v ============================\n", common.CurrentTime(), acceptsig.Key)
	////fix bug: get C11 timeout
	_, enodes := GetGroup(ac.GroupId)
	nodes := strings.Split(enodes, common.Sep2)
	for _, node := range nodes {
	    node2 := ParseNode(node)
	    c1data := acceptsig.Key + "-" + node2 + common.Sep + "AcceptSignRes"
	    c1, exist := C1Data.ReadMap(strings.ToLower(c1data))
	    if exist {
		DisMsg(c1.(string))
		go C1Data.DeleteMap(strings.ToLower(c1data))
	    }
	}
	////

	w, err := FindWorker(acceptsig.Key)
	if err != nil {
	    return "Failure",err.Error(),err
	}

	id,_ := GetWorkerId(w)
	ars := GetAllReplyFromGroup(id,ac.GroupId,Rpc_SIGN,ac.Initiator)
	
	//ACCEPTSIGN:account:pubkey:msghash:keytype:groupid:nonce:threshold:mode:accept:timestamp
	tip, err := AcceptSign(ac.Initiator,ac.Account, ac.PubKey, ac.MsgHash, ac.Keytype, ac.GroupId, ac.Nonce,ac.LimitNum,ac.Mode,"false", accept, status, "", "", "", ars, ac.WorkId)
	if err != nil {
		return "Failure", tip, err
	}

	return "Success", "", nil
}

type LockOutData struct {
    Account string
    Nonce string
    JsonStr string
    Key       string
}

func RecivLockOut() {
	for {
		select {
		case data := <-LockOutCh:
			exsit,_ := GetValueFromPubKeyData(data.Key)
			if exsit == false {
				lo := TxDataLockOut{}
				_ = json.Unmarshal([]byte(data.JsonStr), &lo)
				//if err != nil {
				    //TODO
				//}

				dcrmaddr := lo.DcrmAddr
				dcrmto := lo.DcrmTo
				value := lo.Value
				cointype := lo.Cointype
				groupid := lo.GroupId
				threshold := lo.ThresHold
				mode := lo.Mode
				timestamp := lo.TimeStamp
				
				cur_nonce, _, _ := GetLockOutNonce(data.Account)
				cur_nonce_num, _ := new(big.Int).SetString(cur_nonce, 10)
				new_nonce_num, _ := new(big.Int).SetString(data.Nonce, 10)
				if new_nonce_num.Cmp(cur_nonce_num) >= 0 {
					_, err := SetLockOutNonce(data.Account,data.Nonce)
					if err == nil {
						//fmt.Printf("%v ==============================RecivLockOut,SetLockOutNonce, err = %v,account = %v,group id = %v,threshold = %v,mode = %v,nonce = %v,key = %v ============================================\n", common.CurrentTime(), err, data.Account, groupid, threshold, mode, data.Nonce, data.Key)
					    ars := GetAllReplyFromGroup(-1,groupid,Rpc_LOCKOUT,cur_enode)

					    ac := &AcceptLockOutData{Initiator:cur_enode,Account: data.Account, GroupId: groupid, Nonce: data.Nonce, DcrmFrom: dcrmaddr, DcrmTo: dcrmto, Value: value, Cointype: cointype, LimitNum: threshold, Mode: mode, TimeStamp: timestamp, Deal: "false", Accept: "false", Status: "Pending", OutTxHash: "", Tip: "", Error: "", AllReply: ars, WorkId: -1}
						err := SaveAcceptLockOutData(ac)
						if err == nil {
							fmt.Printf("%v ==============================RecivLockOut,finish call SaveAcceptLockOutData, err = %v,account = %v,group id = %v,threshold = %v,mode = %v,nonce = %v,key = %v ============================================\n", common.CurrentTime(), err, data.Account, groupid, threshold, mode, data.Nonce, data.Key)

							/////
							dcrmkey := Keccak256Hash([]byte(strings.ToLower(dcrmaddr))).Hex()
							exsit,da := GetValueFromPubKeyData(dcrmkey)
							if exsit {
							    _,ok := da.(*PubKeyData)
							    if ok == true {
								    dcrmpub := (da.(*PubKeyData)).Pub
								    exsit,da2 := GetValueFromPubKeyData(dcrmpub)
								    if exsit {
									_,ok = da2.(*PubKeyData)
									if ok == true {
									    keys := (da2.(*PubKeyData)).RefLockOutKeys
									    if keys == "" {
										keys = data.Key
									    } else {
										keys = keys + ":" + data.Key
									    }

									    pubs3 := &PubKeyData{Key:(da2.(*PubKeyData)).Key,Account: (da2.(*PubKeyData)).Account, Pub: (da2.(*PubKeyData)).Pub, Save: (da2.(*PubKeyData)).Save, Nonce: (da2.(*PubKeyData)).Nonce, GroupId: (da2.(*PubKeyData)).GroupId, LimitNum: (da2.(*PubKeyData)).LimitNum, Mode: (da2.(*PubKeyData)).Mode,KeyGenTime:(da2.(*PubKeyData)).KeyGenTime,RefLockOutKeys:keys,RefSignKeys:(da2.(*PubKeyData)).RefSignKeys}
									    epubs, err := Encode2(pubs3)
									    if err == nil {
										ss3, err := Compress([]byte(epubs))
										if err == nil {
										    kd := KeyData{Key: []byte(dcrmpub), Data: ss3}
										    PubKeyDataChan <- kd
										    LdbPubKeyData.WriteMap(dcrmpub, pubs3)
										    //fmt.Printf("%v ==============================RecivLockOut,reset PubKeyData success, key = %v ============================================\n", common.CurrentTime(), data.Key)
										    go func(d LockOutData) {
											    for i := 0; i < 1; i++ {
												    txhash, _, err2 := SendLockOut(d.Account, d.Nonce, d.JsonStr,d.Key)
												    if err2 == nil && txhash != "" {
													    return
												    }

												    time.Sleep(time.Duration(1000000)) //1000 000 000 == 1s
											    }
										    }(data)
										}
									    }
									}
								    }
							    }
							}
							/////
						}
					}
				}
			}
		}
	}
}

func LockOut(raw string) (string, string, error) {
	tx := new(types.Transaction)
	raws := common.FromHex(raw)
	if err := rlp.DecodeBytes(raws, tx); err != nil {
		return "", "raw data error", err
	}

	signer := types.NewEIP155Signer(big.NewInt(30400)) //
	from, err := types.Sender(signer, tx)
	if err != nil {
	    return "", "recover fusion account fail from raw data,maybe raw data error", err
	}

	lo := TxDataLockOut{}
	err = json.Unmarshal(tx.Data(), &lo)
	if err != nil {
	    return "", "recover tx.data json string fail from raw data,maybe raw data error", err
	}

	//LOCKOUT:dcrmaddr:dcrmto:value:cointype:groupid:threshold:mode:timestamp:{xxx:xxx}
	if lo.TxType != "LOCKOUT" {
		return "", "transaction data format error,it is not LOCKOUT tx", fmt.Errorf("lock raw data error,it is not lockout tx.")
	}

	dcrmaddr := lo.DcrmAddr
	dcrmto := lo.DcrmTo
	value := lo.Value
	cointype := lo.Cointype
	groupid := lo.GroupId
	threshold := lo.ThresHold
	mode := lo.Mode
	timestamp := lo.TimeStamp
	//memo := lo.Memo
	Nonce := tx.Nonce()

	if from.Hex() == "" || dcrmaddr == "" || dcrmto == "" || cointype == "" || value == "" || groupid == "" || threshold == "" || mode == "" || timestamp == "" {
		return "", "parameter error from raw data,maybe raw data error", fmt.Errorf("param error.")
	}

	////
	nums := strings.Split(threshold, "/")
	if len(nums) != 2 {
		return "", "transacion data format error,threshold is not right", fmt.Errorf("tx.data error.")
	}
	nodecnt, err := strconv.Atoi(nums[1])
	if err != nil {
		return "", err.Error(),err
	}
	limit, err := strconv.Atoi(nums[0])
	if err != nil {
		return "", err.Error(),err
	}
	if nodecnt < limit || limit < 2 {
	    return "","threshold format error",fmt.Errorf("threshold format error")
	}

	nc,_ := GetGroup(groupid)
	if nc < limit || nc > nodecnt {
	    return "","check group node count error",fmt.Errorf("check group node count error")
	}
	////

	//check mode
	key2 := Keccak256Hash([]byte(strings.ToLower(dcrmaddr))).Hex()
	exsit,da := GetValueFromPubKeyData(key2)
	if exsit == false {
		return "", "dcrm back-end internal error:get data from db fail in func lockout", fmt.Errorf("dcrm back-end internal error:get data from db fail in lockout")
	}

	pubs,ok := da.(*PubKeyData)
	if pubs == nil || ok == false {
		return "", "dcrm back-end internal error:get data from db fail in func lockout", fmt.Errorf("dcrm back-end internal error:get data from db fail in func lockout")
	}

	if pubs.Mode != mode {
	    return "","can not lockout with different mode in dcrm addr.",fmt.Errorf("can not lockout with different mode in dcrm addr.")
	}

	////bug:check accout
	if pubs.Mode == "1" && !strings.EqualFold(pubs.Account,from.Hex()) {
	    return "","invalid lockout account",fmt.Errorf("invalid lockout account")
	}
	
	exsit,da = GetValueFromPubKeyData(pubs.Key)
	if exsit == false {
	    return "","no exist dcrm addr pubkey data",fmt.Errorf("no exist dcrm addr pubkey data")
	}

	if da == nil {
	    return "","no exist dcrm addr pubkey data",fmt.Errorf("no exist dcrm addr pubkey data")
	}

	ac,ok := da.(*AcceptReqAddrData)
	if ok == false {
	    return "","no exist dcrm addr pubkey data",fmt.Errorf("no exist dcrm addr pubkey data")
	}

	if ac == nil {
	    return "","no exist dcrm addr pubkey data",fmt.Errorf("no exist dcrm addr pubkey data")
	}

	if pubs.Mode == "0" && !CheckAcc(cur_enode,from.Hex(),ac.Sigs) {
	    return "","invalid lockout account",fmt.Errorf("invalid lockout account")
	}
	////////////////////

	//check to addr
	validator := coins.NewDcrmAddressValidator(cointype)
	if validator == nil {
	    return "","unsupported cointype",fmt.Errorf("unsupported cointype")
	}
	if !validator.IsValidAddress(dcrmto) {
	    return "","invalid to addr",fmt.Errorf("invalid to addr")
	}
	//

	key := Keccak256Hash([]byte(strings.ToLower(from.Hex() + ":" + groupid + ":" + fmt.Sprintf("%v", Nonce) + ":" + dcrmaddr + ":" + threshold))).Hex()
	data := LockOutData{Account:from.Hex(),Nonce:fmt.Sprintf("%v", Nonce),JsonStr:string(tx.Data()),Key: key}
	LockOutCh <- data

	fmt.Printf("%v =================== LockOut, return, key = %v ===========================\n", common.CurrentTime(), key)
	return key, "", nil
}

////////reshare start//////

type ReShareData struct {
    Account string
    Nonce string
    JsonStr string
    Key       string
}

func RecivReShare() {
	for {
		select {
		case data := <-ReShareCh:
			fmt.Printf("%v ==============================RecivReShare,get new job, key = %v ============================================\n", common.CurrentTime(),data.Key)
			exsit,_ := GetValueFromPubKeyData(data.Key)
			if exsit == false {
				rh := TxDataReShare{}
				err2 := json.Unmarshal([]byte(data.JsonStr), &rh)
				if err2 != nil {
				    fmt.Printf("%v ==============================RecivReShare,unmarshal fail, err = %v, key = %v ============================================\n", common.CurrentTime(),err2,data.Key)
				}

				ars := GetAllReplyFromGroup(-1,rh.GroupId,Rpc_RESHARE,cur_enode)
				ac := &AcceptReShareData{Initiator:cur_enode,Account: data.Account, GroupId: rh.GroupId,TSGroupId:rh.TSGroupId, TSCount:rh.TSCount, PubKey: rh.PubKey, LimitNum: rh.ThresHold,TimeStamp: rh.TimeStamp, Deal: "false", Accept: "false", Status: "Pending", NewSk: "", Tip: "", Error: "", AllReply: ars, WorkId: -1}
				    err := SaveAcceptReShareData(ac)
				    fmt.Printf("%v ==============================RecivReShare,save acceptdata fail, err = %v, key = %v ============================================\n", common.CurrentTime(),err,data.Key)
				    if err == nil {
					    fmt.Printf("%v ==============================RecivReShare,finish call SaveAcceptReShareData, err = %v,account = %v,group id = %v,threshold = %v,key = %v ============================================\n", common.CurrentTime(), err, data.Account, rh.GroupId, rh.ThresHold, data.Key)

					    /////
					    dcrmpks, _ := hex.DecodeString(rh.PubKey)
					    exsit,da := GetValueFromPubKeyData(string(dcrmpks[:]))
					    if exsit {
						_,ok := da.(*PubKeyData)
						if ok == true {
						    keys := (da.(*PubKeyData)).RefReShareKeys
						    if keys == "" {
							keys = data.Key
						    } else {
							keys = keys + ":" + data.Key
						    }

						    pubs3 := &PubKeyData{Key:(da.(*PubKeyData)).Key,Account: (da.(*PubKeyData)).Account, Pub: (da.(*PubKeyData)).Pub, Save: (da.(*PubKeyData)).Save, Nonce: (da.(*PubKeyData)).Nonce, GroupId: (da.(*PubKeyData)).GroupId, LimitNum: (da.(*PubKeyData)).LimitNum, Mode: (da.(*PubKeyData)).Mode,KeyGenTime:(da.(*PubKeyData)).KeyGenTime,RefLockOutKeys:(da.(*PubKeyData)).RefLockOutKeys,RefSignKeys:(da.(*PubKeyData)).RefSignKeys,RefReShareKeys:keys}
						    epubs, err := Encode2(pubs3)
						    if err == nil {
							ss3, err := Compress([]byte(epubs))
							if err == nil {
							    kd := KeyData{Key:dcrmpks[:], Data: ss3}
							    PubKeyDataChan <- kd
							    LdbPubKeyData.WriteMap(string(dcrmpks[:]), pubs3)
							    //fmt.Printf("%v ==============================RecivReShare,reset PubKeyData success, key = %v ============================================\n", common.CurrentTime(), data.Key)
							    go func(d ReShareData) {
								    for i := 0; i < 1; i++ {
									    ret, _, err2 := SendReShare(d.Account, "0", d.JsonStr,d.Key)
									    if err2 == nil && ret != "" {
										    return
									    }

									    time.Sleep(time.Duration(1000000)) //1000 000 000 == 1s
								    }
							    }(data)
							}
						    }
						}
					    }
					    /////
				    }
			}
		}
	}
}

func ReShare(raw string) (string, string, error) {
	tx := new(types.Transaction)
	raws := common.FromHex(raw)
	if err := rlp.DecodeBytes(raws, tx); err != nil {
		return "", "raw data error", err
	}

	signer := types.NewEIP155Signer(big.NewInt(30400)) //
	from, err := types.Sender(signer, tx)
	if err != nil {
	    return "", "recover fusion account fail from raw data,maybe raw data error", err
	}
	
	h := coins.NewCryptocoinHandler("FSN")
	if h == nil {
	    return "", "get fsn cointy handle fail", fmt.Errorf("get fsn cointy handle fail")
	}
	
	//pk := hex.EncodeToString(cur_enode)
	pk := "04" + cur_enode
	fr, err := h.PublicKeyToAddress(pk)
	if err != nil {
	    fmt.Printf("%v=====================ReShare, pubkey to addr fail and return, cur_enode = %v, pk = %v, from = %v, fr = %v, err = %v, ==================\n",common.CurrentTime(),cur_enode,pk,from.Hex(),fr,err)
	    return "", "check current enode account fail from raw data,maybe raw data error", err
	}

	if !strings.EqualFold(from.Hex(), fr) {
	    fmt.Printf("%v=====================ReShare, pubkey to addr fail and return, cur_enode = %v, pk = %v, from = %v, fr = %v, err = %v, ==================\n",common.CurrentTime(),cur_enode,pk,from.Hex(),fr,err)
	    return "", "check current enode account fail from raw data,maybe raw data error", err
	}

	rh := TxDataReShare{}
	err = json.Unmarshal(tx.Data(), &rh)
	if err != nil {
	    return "", "recover tx.data json string fail from raw data,maybe raw data error", err
	}

	if rh.TxType != "RESHARE" {
		return "", "transaction data format error,it is not RESHARE tx", fmt.Errorf("tx raw data error,it is not reshare tx.")
	}

	if from.Hex() == "" || rh.PubKey == "" || rh.TSGroupId == "" || rh.TSCount == "" || rh.ThresHold == "" || rh.TimeStamp == "" {
		return "", "parameter error from raw data,maybe raw data error", fmt.Errorf("param error.")
	}

	dcrmpks, _ := hex.DecodeString(rh.PubKey)
	exsit,da := GetValueFromPubKeyData(string(dcrmpks[:]))
	if exsit == false {
		return "", "dcrm back-end internal error:get data from db fail in func reshare", fmt.Errorf("dcrm back-end internal error:get data from db fail in reshare")
	}

	pubs,ok := da.(*PubKeyData)
	if pubs == nil || ok == false {
		return "", "dcrm back-end internal error:get data from db fail in func reshare", fmt.Errorf("dcrm back-end internal error:get data from db fail in func reshare")
	}

	exsit,da = GetValueFromPubKeyData(pubs.Key)
	if exsit == false {
	    return "","no exist dcrm addr pubkey data",fmt.Errorf("no exist dcrm addr pubkey data")
	}

	if da == nil {
	    return "","no exist dcrm addr pubkey data",fmt.Errorf("no exist dcrm addr pubkey data")
	}

	ac,ok := da.(*AcceptReqAddrData)
	if ok == false {
	    return "","no exist dcrm addr pubkey data",fmt.Errorf("no exist dcrm addr pubkey data")
	}

	if ac == nil {
	    return "","no exist dcrm addr pubkey data",fmt.Errorf("no exist dcrm addr pubkey data")
	}

	////////////////////

	if rh.GroupId == "" {
	    rh.GroupId = pubs.GroupId
	}

	////
	nums := strings.Split(rh.ThresHold, "/")
	if len(nums) != 2 {
		return "", "transacion data format error,threshold is not right", fmt.Errorf("tx.data error.")
	}
	nodecnt, err := strconv.Atoi(nums[1])
	if err != nil {
		return "", err.Error(),err
	}
	limit, err := strconv.Atoi(nums[0])
	if err != nil {
		return "", err.Error(),err
	}
	if nodecnt < limit || limit < 2 {
	    return "","threshold format error",fmt.Errorf("threshold format error")
	}

	nc,_ := GetGroup(rh.GroupId)
	if nc < limit || nc > nodecnt {
	    return "","check group node count error",fmt.Errorf("check group node count error")
	}
	
	tscount, err := strconv.Atoi(rh.TSCount)
	if err != nil {
		return "", err.Error(),err
	}
	if tscount < limit || tscount > nodecnt {
	    return "","check ts count error",fmt.Errorf("check ts count error")
	}
	////

	//

	//key = hash(account + groupid + tsgroupid + pubkey + threshold )
	key := Keccak256Hash([]byte(strings.ToLower(from.Hex() + ":" + rh.GroupId + ":" + rh.TSGroupId + ":" + rh.PubKey + ":" + rh.ThresHold ))).Hex()
	data := ReShareData{Account:from.Hex(),Nonce:"0",JsonStr:string(tx.Data()),Key: key}
	ReShareCh <- data

	fmt.Printf("%v =================== ReShare, return, key = %v ===========================\n", common.CurrentTime(), key)
	return key, "", nil
}

func RpcAcceptReShare(raw string) (string, string, error) {
	tx := new(types.Transaction)
	raws := common.FromHex(raw)
	if err := rlp.DecodeBytes(raws, tx); err != nil {
		return "Failure", "raw data error", err
	}

	signer := types.NewEIP155Signer(big.NewInt(30400)) //
	from, err := types.Sender(signer, tx)
	if err != nil {
	    return "Failure", "recover fusion account fail from raw data,maybe raw data error", err
	}

	h := coins.NewCryptocoinHandler("FSN")
	if h == nil {
	    return "Failure", "get fsn cointy handle fail", fmt.Errorf("get fsn cointy handle fail")
	}

	pk := "04" + cur_enode
	fr, err := h.PublicKeyToAddress(pk)
	if err != nil {
	    fmt.Printf("%v===============RpcAcceptReShare, pubkey to addr fail,from = %v, fr = %v, err = %v ====================\n",common.CurrentTime(),from.Hex(),fr,err)
	    return "Failure", "check current enode account fail from raw data,maybe raw data error", err
	}

	if !strings.EqualFold(from.Hex(), fr) {
	    fmt.Printf("%v===============RpcAcceptReShare, from != fr, from = %v, fr = %v, ====================\n",common.CurrentTime(),from.Hex(),fr)
	    return "Failure", "check current enode account fail from raw data,maybe raw data error", err
	}

	acceptreshare := TxDataAcceptReShare{}
	err = json.Unmarshal(tx.Data(), &acceptreshare)
	if err != nil {
	    fmt.Printf("%v===============RpcAcceptReShare, unmarshal txdata fail, err = %v, ====================\n",common.CurrentTime(),err)
	    return "Failure", "recover tx.data json string fail from raw data,maybe raw data error", err
	}

	if acceptreshare.TxType != "ACCEPTRESHARE" {
	    return "Failure", "transaction data format error,it is not ACCEPTRESHARE tx", fmt.Errorf("tx.data error,it is not ACCEPTRESHARE tx.")
	}

	if acceptreshare.Accept != "AGREE" && acceptreshare.Accept != "DISAGREE" {
	    return "Failure", "transaction data format error,the lastest segment is not AGREE or DISAGREE", fmt.Errorf("transaction data format error")
	}

	status := "Pending"
	accept := "false"
	if acceptreshare.Accept == "AGREE" {
		accept = "true"
	} else {
		status = "Failure"
	}

	exsit,da := GetValueFromPubKeyData(acceptreshare.Key)
	///////
	if exsit == false {
		return "Failure", "dcrm back-end internal error:get accept result from db fail", fmt.Errorf("get accept result from db fail")
	}

	ac,ok := da.(*AcceptReShareData)
	if ok == false {
	    return "Failure", "dcrm back-end internal error:get accept result from db fail", fmt.Errorf("get accept result from db fail")
	}

	if ac == nil {
	    return "Failure", "dcrm back-end internal error:get accept result from db fail", fmt.Errorf("get accept result from db fail")
	}

	///////
	mp := []string{acceptreshare.Key, cur_enode}
	enode := strings.Join(mp, "-")
	s0 := "AcceptReShareRes"
	s1 := accept
	s2 := acceptreshare.TimeStamp
	ss2 := enode + common.Sep + s0 + common.Sep + s1 + common.Sep + s2
	SendMsgToDcrmGroup(ss2, ac.GroupId)
	DisMsg(ss2)
	fmt.Printf("%v ================== AcceptReShare, finish send AcceptReShareRes to other nodes ,key = %v ============================\n", common.CurrentTime(), acceptreshare.Key)
	////fix bug: get C11 timeout
	_, enodes := GetGroup(ac.GroupId)
	nodes := strings.Split(enodes, common.Sep2)
	for _, node := range nodes {
	    node2 := ParseNode(node)
	    c1data := acceptreshare.Key + "-" + node2 + common.Sep + "AcceptReShareRes"
	    c1, exist := C1Data.ReadMap(strings.ToLower(c1data))
	    if exist {
		DisMsg(c1.(string))
		go C1Data.DeleteMap(strings.ToLower(c1data))
	    }
	}
	////

	w, err := FindWorker(acceptreshare.Key)
	if err != nil {
	    return "Failure",err.Error(),err
	}

	id,_ := GetWorkerId(w)
	ars := GetAllReplyFromGroup(id,ac.GroupId,Rpc_RESHARE,ac.Initiator)
	
	tip,err := AcceptReShare(ac.Initiator,ac.Account, ac.GroupId, ac.TSGroupId,ac.PubKey, ac.LimitNum, "false", accept, status, "", "", "", ars,ac.WorkId)
	if err != nil {
		return "Failure", tip, err
	}

	return "Success", "", nil
}

///////reshare end////////

type SignData struct {
	Account   string
	Nonce     string
	JsonStr string
	Key       string
}

func Sign(raw string) (string, string, error) {
	tx := new(types.Transaction)
	raws := common.FromHex(raw)
	if err := rlp.DecodeBytes(raws, tx); err != nil {
		return "", "raw data error", err
	}

	signer := types.NewEIP155Signer(big.NewInt(30400)) //
	from, err := types.Sender(signer, tx)
	if err != nil {
	    return "", "recover fusion account fail from raw data,maybe raw data error", err
	}

	sig := TxDataSign{}
	err = json.Unmarshal(tx.Data(), &sig)
	if err != nil {
	    return "", "recover tx.data json string fail from raw data,maybe raw data error", err
	}

	//SIGN : pubkey : hash : keytype : groupid : threshold : mode : timestamp
	if sig.TxType != "SIGN" {
	    return "", "transaction data format error,it is not SIGN tx", fmt.Errorf("lock raw data error,it is not SIGN tx.")
	}

	pubkey := sig.PubKey
	hash := sig.MsgHash
	//context := sig.MsgContext
	keytype := sig.Keytype
	groupid := sig.GroupId
	threshold := sig.ThresHold
	mode := sig.Mode
	timestamp := sig.TimeStamp
	Nonce := tx.Nonce()

	if from.Hex() == "" || pubkey == "" || hash == "" || keytype == "" || groupid == "" || threshold == "" || mode == "" || timestamp == "" {
		return "", "parameter error from raw data,maybe raw data error", fmt.Errorf("param error from raw data.")
	}

	////
	nums := strings.Split(threshold, "/")
	if len(nums) != 2 {
		return "", "transacion data format error,threshold is not right", fmt.Errorf("tx.data error.")
	}
	nodecnt, err := strconv.Atoi(nums[1])
	if err != nil {
		return "", err.Error(),err
	}
	limit, err := strconv.Atoi(nums[0])
	if err != nil {
		return "", err.Error(),err
	}
	if nodecnt < limit || limit < 2 {
	    return "","threshold format error",fmt.Errorf("threshold format error")
	}

	nc,_ := GetGroup(groupid)
	if nc < limit || nc > nodecnt {
	    return "","check group node count error",fmt.Errorf("check group node count error")
	}
	////

	//check mode
	dcrmpks, _ := hex.DecodeString(pubkey)
	exsit,da := GetValueFromPubKeyData(string(dcrmpks[:]))
	if exsit == false {
		return "", "dcrm back-end internal error:get data from db fail in func sign", fmt.Errorf("dcrm back-end internal error:get data from db fail in sign")
	}

	pubs,ok := da.(*PubKeyData)
	if pubs == nil || ok == false {
		return "", "dcrm back-end internal error:get data from db fail in func sign", fmt.Errorf("dcrm back-end internal error:get data from db fail in func sign")
	}

	if pubs.Mode != mode {
	    return "","can not sign with different mode in pubkey.",fmt.Errorf("can not sign with different mode in pubkey.")
	}

	//

	//key := hash(acc + nonce + pubkey + hash + keytype + groupid + threshold + mode)
	key := Keccak256Hash([]byte(strings.ToLower(from.Hex() + ":" + fmt.Sprintf("%v", Nonce) + ":" + pubkey + ":" + hash + ":" + keytype + ":" + groupid + ":" + threshold + ":" + mode))).Hex()
	data := SignData{Account: from.Hex(), Nonce: fmt.Sprintf("%v", Nonce), JsonStr:string(tx.Data()), Key: key}
	SignCh <- data

	fmt.Printf("%v =================== Sign, return key = %v ===========================\n", common.CurrentTime(),key)
	return key,"",nil
}

func RecivSign() {
	for {
		select {
		case data := <-SignCh:
			exsit,_ := GetValueFromPubKeyData(data.Key)
			if exsit == false {
				sig := TxDataSign{}
				json.Unmarshal([]byte(data.JsonStr), &sig)
				
				cur_nonce, _, _ := GetSignNonce(data.Account)
				cur_nonce_num, _ := new(big.Int).SetString(cur_nonce, 10)
				new_nonce_num, _ := new(big.Int).SetString(data.Nonce, 10)
				if new_nonce_num.Cmp(cur_nonce_num) >= 0 {
					_, err := SetSignNonce(data.Account,data.Nonce)
					if err == nil {
						fmt.Printf("%v ==============================RecivSign, SetSignNonce, err = %v,pubkey = %v, account = %v,group id = %v,threshold = %v,mode = %v,nonce = %v,key = %v ============================================\n", common.CurrentTime(), err, sig.PubKey, data.Account, sig.GroupId, sig.ThresHold, sig.Mode, data.Nonce, data.Key)
					    ars := GetAllReplyFromGroup(-1,sig.GroupId,Rpc_SIGN,cur_enode)

					    ac := &AcceptSignData{Initiator:cur_enode,Account: data.Account, GroupId: sig.GroupId, Nonce: data.Nonce, PubKey: sig.PubKey, MsgHash: sig.MsgHash, MsgContext:sig.MsgContext, Keytype: sig.Keytype, LimitNum: sig.ThresHold, Mode: sig.Mode, TimeStamp: sig.TimeStamp, Deal: "false", Accept: "false", Status: "Pending", Rsv: "", Tip: "", Error: "", AllReply: ars, WorkId: -1}
						err := SaveAcceptSignData(ac)
						if err == nil {
							fmt.Printf("%v ==============================RecivSign,finish call SaveAcceptSignData, err = %v,account = %v,group id = %v,threshold = %v,mode = %v,nonce = %v,key = %v ============================================\n", common.CurrentTime(), err, data.Account, sig.GroupId, sig.ThresHold, sig.Mode, data.Nonce, data.Key)

							/////
							dcrmpks, _ := hex.DecodeString(ac.PubKey)
							exsit,da := GetValueFromPubKeyData(string(dcrmpks[:]))
							if exsit {
							    _,ok := da.(*PubKeyData)
							    if ok == true {
								    keys := (da.(*PubKeyData)).RefSignKeys
								    if keys == "" {
									keys = data.Key
								    } else {
									keys = keys + ":" + data.Key
								    }

								    pubs3 := &PubKeyData{Key:(da.(*PubKeyData)).Key,Account: (da.(*PubKeyData)).Account, Pub: (da.(*PubKeyData)).Pub, Save: (da.(*PubKeyData)).Save, Nonce: (da.(*PubKeyData)).Nonce, GroupId: (da.(*PubKeyData)).GroupId, LimitNum: (da.(*PubKeyData)).LimitNum, Mode: (da.(*PubKeyData)).Mode,KeyGenTime:(da.(*PubKeyData)).KeyGenTime,RefLockOutKeys:(da.(*PubKeyData)).RefLockOutKeys,RefSignKeys:keys}
								    epubs, err := Encode2(pubs3)
								    if err == nil {
									ss3, err := Compress([]byte(epubs))
									if err == nil {
									    kd := KeyData{Key: dcrmpks[:], Data: ss3}
									    PubKeyDataChan <- kd
									    LdbPubKeyData.WriteMap(string(dcrmpks[:]), pubs3)
									    fmt.Printf("%v ==============================RecivSign,reset PubKeyData success, key = %v ============================================\n", common.CurrentTime(), data.Key)
									    go func(d SignData) {
										    for i := 0; i < 1; i++ {
											    rsv, _, err2 := SendSign(d.Account, d.Nonce, d.JsonStr, d.Key)
											    if err2 == nil && rsv != "" {
												return
											    }

											    time.Sleep(time.Duration(1000000)) //1000 000 000 == 1s
										    }
									    }(data)
									}
								    }
							    }
							}
							/////
						}
					}
				}
			}
		}
	}
}

func GetAccountsBalance(pubkey string, geter_acc string) (interface{}, string, error) {
	exsit,da := GetValueFromPubKeyData(strings.ToLower(geter_acc))
	if exsit == false {
	    return nil,"",fmt.Errorf("get value from pubkeydata fail.")
	}

	keys := strings.Split(string(da.([]byte)),":")
	for _,key := range keys {
	    exsit,data := GetValueFromPubKeyData(key)
	    if exsit == false {
		continue
	    }

	    ac,ok := data.(*AcceptReqAddrData)
	    if ok == false {
		continue
	    }

	    if ac == nil {
		    continue
	    }

	    if ac.Mode == "1" {
		    if !strings.EqualFold(ac.Account,geter_acc) {
			continue
		    }
	    }

	    if ac.Mode == "0" && !CheckAcc(cur_enode,geter_acc,ac.Sigs) {
		continue
	    }

	    dcrmpks, _ := hex.DecodeString(ac.PubKey)
	    exsit,data2 := GetValueFromPubKeyData(string(dcrmpks[:]))
	    if exsit == false || data2 == nil {
		continue
	    }

	    pd,ok := data2.(*PubKeyData)
	    if ok == false {
		continue
	    }

	    if pd == nil {
		continue
	    }

	    if pd.Pub == "" || pd.GroupId == "" || pd.Mode == "" {
		    continue
	    }

	    pb := pd.Pub
	    pubkeyhex := hex.EncodeToString([]byte(pb))
	    if strings.EqualFold(pubkey, pubkeyhex) == false {
		    continue
	    }

	    keytmp, err2 := hex.DecodeString(pubkey)
	    if err2 != nil {
		    return nil, "decode pubkey fail", err2
	    }

	    ret, tip, err := GetPubKeyData(string(keytmp), pubkey, "ALL")
	    var m interface{}
	    if err == nil {
		    dp := DcrmPubkeyRes{}
		    _ = json.Unmarshal([]byte(ret), &dp)
		    balances := make([]SubAddressBalance, 0)
		    var wg sync.WaitGroup
		    var ret map[string]*SubAddressBalance = make(map[string]*SubAddressBalance, 0)
		    for cointype, subaddr := range dp.DcrmAddress {
			    wg.Add(1)
			    go func(cointype, subaddr string) {
				    defer wg.Done()
				    balance, _, err := GetBalance(pubkey, cointype, subaddr)
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
		    m = &DcrmAccountsBalanceRes{PubKey: pubkey, Balances: balances}
	    } else {
	    }

	    return m, tip, err
	}

	return nil, "get accounts balance fail", fmt.Errorf("get accounts balance fail")
}

func GetBalance(account string, cointype string, dcrmaddr string) (string, string, error) {

	if strings.EqualFold(cointype, "BTC") { ///tmp code
		//return "0","",nil  //TODO
	}

	if strings.EqualFold(cointype, "BCH") {
		return "0", "", nil //TODO
	}

	if strings.EqualFold(cointype, "USDT") {
		return "0", "", nil //TODO
	}

	if strings.EqualFold(cointype, "BEP2GZX_754") {
		return "0", "", nil //TODO
	}

	h := coins.NewCryptocoinHandler(cointype)
	if h == nil {
		return "", "coin type is not supported", fmt.Errorf("coin type is not supported")
	}

	ba, err := h.GetAddressBalance(dcrmaddr, "")
	if err != nil {
		//	fmt.Println("================GetBalance 22222,err =%v =================",err)
		return "", "dcrm back-end internal error:get dcrm addr balance fail", err
	}

	if h.IsToken() {
		ret := fmt.Sprintf("%v", ba.TokenBalance.Val)
		return ret, "", nil
	}

	ret := fmt.Sprintf("%v", ba.CoinBalance.Val)
	fmt.Printf("%v =========GetBalance,dcrmaddr = %v ,cointype = %v ,ret = %v=============\n", common.CurrentTime(), dcrmaddr, cointype, ret)
	return ret, "", nil
}

func init() {
	p2pdcrm.RegisterRecvCallback(Call2)
	p2pdcrm.SdkProtocol_registerBroadcastInGroupCallback(Call)
	p2pdcrm.SdkProtocol_registerSendToGroupCallback(DcrmCall)
	p2pdcrm.SdkProtocol_registerSendToGroupReturnCallback(DcrmCallRet)
	p2pdcrm.RegisterCallback(Call)

	RegP2pGetGroupCallBack(p2pdcrm.SdkProtocol_getGroup)
	RegP2pSendToGroupAllNodesCallBack(p2pdcrm.SdkProtocol_SendToGroupAllNodes)
	RegP2pGetSelfEnodeCallBack(p2pdcrm.GetSelfID)
	RegP2pBroadcastInGroupOthersCallBack(p2pdcrm.SdkProtocol_broadcastInGroupOthers)
	RegP2pSendMsgToPeerCallBack(p2pdcrm.SendMsgToPeer)
	RegP2pParseNodeCallBack(p2pdcrm.ParseNodeID)
	RegDcrmGetEosAccountCallBack(eos.GetEosAccount)
	InitChan()
}

func Call2(msg interface{}) {
	s := msg.(string)
	SetUpMsgList2(s)
}

var parts  = common.NewSafeMap(10)

func receiveGroupInfo(msg interface{}) {
	//fmt.Println("===========receiveGroupInfo==============", "msg", msg)
	cur_enode = p2pdcrm.GetSelfID()

	m := strings.Split(msg.(string), "|")
	if len(m) != 2 {
		return
	}

	splitkey := m[1]

	head := strings.Split(splitkey, ":")[0]
	body := strings.Split(splitkey, ":")[1]
	if a := strings.Split(body, "#"); len(a) > 1 {
		body = a[1]
	}
	p, _ := strconv.Atoi(strings.Split(head, "dcrmslash")[0])
	total, _ := strconv.Atoi(strings.Split(head, "dcrmslash")[1])
	//parts[p] = body
	parts.WriteMap(strconv.Itoa(p),body)

	if parts.MapLength() == total {
		var c string = ""
		for i := 1; i <= total; i++ {
			da,exist := parts.ReadMap(strconv.Itoa(i))
			if exist == true {
			    datmp,ok := da.(string)
			    if ok == true {
				c += datmp
			    }
			}
		}

		time.Sleep(time.Duration(2) * time.Second) //1000 == 1s
		////
		Init(m[0])
	}
}

func Init(groupId string) {
	out := "=============Init================" + " get group id = " + groupId + ", init_times = " + strconv.Itoa(init_times)
	fmt.Println(out)

	if !PutGroup(groupId) {
		out := "=============Init================" + " get group id = " + groupId + ", put group id fail "
		fmt.Println(out)
		return
	}

	if init_times >= 1 {
		return
	}

	init_times = 1
	InitGroupInfo(groupId)
}

func SetUpMsgList2(msg string) {

	mm := strings.Split(msg, "dcrmslash")
	if len(mm) >= 2 {
		receiveGroupInfo(msg)
		return
	}
}

//===================================================================

type ReqAddrStatus struct {
	Status    string
	PubKey    string
	Tip       string
	Error     string
	AllReply  []NodeReply 
	TimeStamp string
}

func GetReqAddrStatus(key string) (string, string, error) {
	exsit,da := GetValueFromPubKeyData(key)
	///////
	if exsit == false {
		fmt.Printf("%v =====================GetReqAddrStatus,no exist key, key = %v ======================\n", common.CurrentTime(), key)
		return "", "dcrm back-end internal error:get accept data fail from db", fmt.Errorf("dcrm back-end internal error:get accept data fail from db")
	}

	if da == nil {
		return "", "dcrm back-end internal error:get accept data fail from db", fmt.Errorf("dcrm back-end internal error:get accept data fail from db")
	}

	ac,ok := da.(*AcceptReqAddrData)
	if ok == false {
		return "", "dcrm back-end internal error:get accept data fail from db", fmt.Errorf("dcrm back-end internal error:get accept data fail from db")
	}

	los := &ReqAddrStatus{Status: ac.Status, PubKey: ac.PubKey, Tip: ac.Tip, Error: ac.Error, AllReply: ac.AllReply, TimeStamp: ac.TimeStamp}
	ret, err := json.Marshal(los)
	fmt.Printf("%v =====================GetReqAddrStatus,status = %v,ret = %v,err = %v,key = %v ======================\n", common.CurrentTime(),ac.Status,string(ret),err, key)
	return string(ret), "", nil
}

type LockOutStatus struct {
	Status    string
	OutTxHash string
	Tip       string
	Error     string
	AllReply  []NodeReply 
	TimeStamp string
}

func GetLockOutStatus(key string) (string, string, error) {
	exsit,da := GetValueFromPubKeyData(key)
	///////
	if exsit == false {
		return "", "dcrm back-end internal error:get accept data fail from db", fmt.Errorf("dcrm back-end internal error:get accept data fail from db")
	}

	if da == nil {
		return "", "dcrm back-end internal error:get accept data fail from db", fmt.Errorf("dcrm back-end internal error:get accept data fail from db")
	}

	ac,ok := da.(*AcceptLockOutData)
	if ok == false {
		return "", "dcrm back-end internal error:get accept data fail from db", fmt.Errorf("dcrm back-end internal error:get accept data fail from db")
	}
	los := &LockOutStatus{Status: ac.Status, OutTxHash: ac.OutTxHash, Tip: ac.Tip, Error: ac.Error, AllReply: ac.AllReply, TimeStamp: ac.TimeStamp}
	ret,_ := json.Marshal(los)
	return string(ret), "",nil 
}

type SignStatus struct {
	Status    string
	Rsv string
	Tip       string
	Error     string
	AllReply  []NodeReply 
	TimeStamp string
}

func GetSignStatus(key string) (string, string, error) {
	exsit,da := GetValueFromPubKeyData(key)
	///////
	if exsit == false {
		return "", "dcrm back-end internal error:get accept data fail from db", fmt.Errorf("dcrm back-end internal error:get accept data fail from db")
	}

	if da == nil {
		return "", "dcrm back-end internal error:get accept data fail from db", fmt.Errorf("dcrm back-end internal error:get accept data fail from db")
	}

	ac,ok := da.(*AcceptSignData)
	if ok == false {
		return "", "dcrm back-end internal error:get accept data fail from db", fmt.Errorf("dcrm back-end internal error:get accept data fail from db")
	}

	los := &SignStatus{Status: ac.Status, Rsv: ac.Rsv, Tip: ac.Tip, Error: ac.Error, AllReply: ac.AllReply, TimeStamp: ac.TimeStamp}
	ret,_ := json.Marshal(los)
	return string(ret), "",nil 
}

type ReShareStatus struct {
	Status    string
	Pubkey string
	Tip       string
	Error     string
	AllReply  []NodeReply 
	TimeStamp string
}

func GetReShareStatus(key string) (string, string, error) {
	exsit,da := GetValueFromPubKeyData(key)
	///////
	if exsit == false {
		return "", "dcrm back-end internal error:get accept data fail from db", fmt.Errorf("dcrm back-end internal error:get accept data fail from db")
	}

	if da == nil {
		return "", "dcrm back-end internal error:get accept data fail from db", fmt.Errorf("dcrm back-end internal error:get accept data fail from db")
	}

	ac,ok := da.(*AcceptReShareData)
	if ok == false {
		return "", "dcrm back-end internal error:get accept data fail from db", fmt.Errorf("dcrm back-end internal error:get accept data fail from db")
	}

	los := &ReShareStatus{Status: ac.Status, Pubkey: ac.PubKey, Tip: ac.Tip, Error: ac.Error, AllReply: ac.AllReply, TimeStamp: ac.TimeStamp}
	ret,_ := json.Marshal(los)
	return string(ret), "",nil 
}

type EnAcc struct {
	Enode    string
	Accounts []string
}

type EnAccs struct {
	EnodeAccounts []EnAcc
}

type ReqAddrReply struct {
	Key       string
	Account   string
	Cointype  string
	GroupId   string
	Nonce     string
	ThresHold  string
	Mode      string
	TimeStamp string
}

func SortCurNodeInfo(value []interface{}) []interface{} {
	if len(value) == 0 {
		return value
	}

	var ids sortableIDSSlice
	for _, v := range value {
		uid := DoubleHash(string(v.([]byte)), "ALL")
		ids = append(ids, uid)
	}

	sort.Sort(ids)

	var ret = make([]interface{}, 0)
	for _, v := range ids {
		for _, vv := range value {
			uid := DoubleHash(string(vv.([]byte)), "ALL")
			if v.Cmp(uid) == 0 {
				ret = append(ret, vv)
				break
			}
		}
	}

	return ret
}

func GetCurNodeReqAddrInfo(geter_acc string) ([]*ReqAddrReply, string, error) {
	exsit,da := GetValueFromPubKeyData(strings.ToLower(geter_acc))
	if exsit == false {
	    return nil,"",nil
	}

	//check obj type
	_,ok := da.([]byte)
	if ok == false {
	    return nil,"get value from dcrm back-end fail ",fmt.Errorf("get value from PubKey Data fail")
	}
	//

	fmt.Printf("%v=================GetCurNodeReqAddrInfo,da = %v,geter_acc = %v ====================\n",common.CurrentTime(),string(da.([]byte)),geter_acc)
	var ret []*ReqAddrReply
	keys := strings.Split(string(da.([]byte)),":")
	for _,key := range keys {
	    exsit,data := GetValueFromPubKeyData(key)
	    if exsit == false {
		continue
	    }

	    if data == nil {
		continue
	    }

	    ac,ok := data.(*AcceptReqAddrData)
	    if ok == false {
		continue
	    }

	    if ac == nil {
		    continue
	    }

	    if ac.Mode == "1" {
		    continue
	    }
	    
	    if ac.Mode == "0" && !CheckAcc(cur_enode,geter_acc,ac.Sigs) {
		continue
	    }

	    if ac.Deal == "true" || ac.Status == "Success" {
		    continue
	    }

	    if ac.Status != "Pending" {
		    continue
	    }

	    los := &ReqAddrReply{Key: key, Account: ac.Account, Cointype: ac.Cointype, GroupId: ac.GroupId, Nonce: ac.Nonce, ThresHold: ac.LimitNum, Mode: ac.Mode, TimeStamp: ac.TimeStamp}
	    ret = append(ret, los)
	    ////

	}

	///////
	return ret, "", nil
}

type LockOutCurNodeInfo struct {
	Key       string
	Account   string
	GroupId   string
	Nonce     string
	DcrmFrom  string
	DcrmTo    string
	Value     string
	Cointype  string
	ThresHold  string
	Mode      string
	TimeStamp string
}

func GetCurNodeLockOutInfo(geter_acc string) ([]*LockOutCurNodeInfo, string, error) {
	exsit,da := GetValueFromPubKeyData(strings.ToLower(geter_acc))
	if exsit == false {
	    return nil,"",nil
	}

	//check obj type
	_,ok := da.([]byte)
	if ok == false {
	    return nil,"get value from dcrm back-end fail ",fmt.Errorf("get value from PubKey Data fail")
	}
	//

	var ret []*LockOutCurNodeInfo
	keys := strings.Split(string(da.([]byte)),":")
	for _,key := range keys {
	    exsit,data := GetValueFromPubKeyData(key)
	    if exsit == false {
		continue
	    }

	    if data == nil {
		continue
	    }

	    ac,ok := data.(*AcceptReqAddrData)
	    if ok == false {
		continue
	    }

	    if ac == nil {
		continue
	    }

	    if ac.Mode == "0" && !CheckAcc(cur_enode,geter_acc,ac.Sigs) {
		continue
	    }

	    dcrmpks, _ := hex.DecodeString(ac.PubKey)
	    exsit,data2 := GetValueFromPubKeyData(string(dcrmpks[:]))
	    if exsit == false || data2 == nil {
		continue
	    }

	    pd,ok := data2.(*PubKeyData)
	    if ok == false {
		continue
	    }

	    if pd == nil {
		continue
	    }

	    if pd.RefLockOutKeys == "" {
		continue
	    }

	    lockoutkeys := strings.Split(pd.RefLockOutKeys,":")
	    for _,lockoutkey := range lockoutkeys {
		exsit,data3 := GetValueFromPubKeyData(lockoutkey)
		if exsit == false {
		    continue
		}

		////
		ac3,ok := data3.(*AcceptLockOutData)
		if ok == false {
		    continue
		}

		if ac3 == nil {
			continue
		}
		
		if ac3.Mode == "1" {
			continue
		}
		
		if ac3.Deal == "true" || ac3.Status == "Success" {
			continue
		}

		if ac3.Status != "Pending" {
			continue
		}

		keytmp := Keccak256Hash([]byte(strings.ToLower(ac3.Account + ":" + ac3.GroupId + ":" + ac3.Nonce + ":" + ac3.DcrmFrom + ":" + ac3.LimitNum))).Hex()

		los := &LockOutCurNodeInfo{Key: keytmp, Account: ac3.Account, GroupId: ac3.GroupId, Nonce: ac3.Nonce, DcrmFrom: ac3.DcrmFrom, DcrmTo: ac3.DcrmTo, Value: ac3.Value, Cointype: ac3.Cointype, ThresHold: ac3.LimitNum, Mode: ac3.Mode, TimeStamp: ac3.TimeStamp}
		ret = append(ret, los)
	    }
	    ////
	}

	///////
	return ret, "", nil
}

type SignCurNodeInfo struct {
	Key       string
	Account   string
	PubKey   string
	MsgHash   string
	MsgContext   string
	KeyType   string
	GroupId   string
	Nonce     string
	ThresHold  string
	Mode      string
	TimeStamp string
}

func GetCurNodeSignInfo(geter_acc string) ([]*SignCurNodeInfo, string, error) {
	exsit,da := GetValueFromPubKeyData(strings.ToLower(geter_acc))
	if exsit == false {
	    return nil,"",nil
	}

	//check obj type
	_,ok := da.([]byte)
	if ok == false {
	    return nil,"get value from dcrm back-end fail ",fmt.Errorf("get value from PubKey Data fail")
	}
	//

	var ret []*SignCurNodeInfo
	keys := strings.Split(string(da.([]byte)),":")
	for _,key := range keys {
	    exsit,data := GetValueFromPubKeyData(key)
	    if exsit == false {
		continue
	    }

	    if data == nil {
		continue
	    }

	    ac,ok := data.(*AcceptReqAddrData)
	    if ok == false {
		continue
	    }

	    if ac == nil {
		continue
	    }

	    if ac.Mode == "0" && !CheckAcc(cur_enode,geter_acc,ac.Sigs) {
		continue
	    }

	    dcrmpks, _ := hex.DecodeString(ac.PubKey)
	    exsit,data2 := GetValueFromPubKeyData(string(dcrmpks[:]))
	    if exsit == false || data2 == nil {
		continue
	    }

	    pd,ok := data2.(*PubKeyData)
	    if ok == false {
		continue
	    }

	    if pd == nil {
		continue
	    }

	    if pd.RefSignKeys == "" {
		continue
	    }

	    signkeys := strings.Split(pd.RefSignKeys,":")
	    for _,signkey := range signkeys {
		exsit,data3 := GetValueFromPubKeyData(signkey)
		if exsit == false {
		    continue
		}

		////
		ac3,ok := data3.(*AcceptSignData)
		if ok == false {
		    continue
		}

		if ac3 == nil {
			continue
		}
		
		if ac3.Mode == "1" {
			continue
		}
		
		if ac3.Deal == "true" || ac3.Status == "Success" {
			continue
		}

		if ac3.Status != "Pending" {
			continue
		}

		//key := hash(acc + nonce + pubkey + hash + keytype + groupid + threshold + mode)
		keytmp := Keccak256Hash([]byte(strings.ToLower(ac3.Account + ":" + ac3.Nonce + ":" + ac3.PubKey + ":" + ac3.MsgHash + ":" + ac3.Keytype + ":" + ac3.GroupId + ":" + ac3.LimitNum + ":" + ac3.Mode))).Hex()

		los := &SignCurNodeInfo{Key: keytmp, Account: ac3.Account, PubKey:ac3.PubKey, MsgHash:ac3.MsgHash, MsgContext:ac3.MsgContext, KeyType:ac3.Keytype, GroupId: ac3.GroupId, Nonce: ac3.Nonce, ThresHold: ac3.LimitNum, Mode: ac3.Mode, TimeStamp: ac3.TimeStamp}
		ret = append(ret, los)
	    }
	    ////
	}

	///////
	return ret, "", nil
}

type ReShareCurNodeInfo struct {
	Key       string
	PubKey   string
	GroupId   string
	TSGroupId   string
	ThresHold  string
	TimeStamp string
}

func GetCurNodeReShareInfo() ([]*ReShareCurNodeInfo, string, error) {
    //fmt.Printf("%v================GetCurNodeReShareInfo start,====================\n",common.CurrentTime())
    var ret []*ReShareCurNodeInfo
    var wg sync.WaitGroup
    LdbPubKeyData.RLock()
    for k, v := range LdbPubKeyData.Map {
	wg.Add(1)
	go func(key string,value interface{}) {
	    defer wg.Done()

	    vv,ok := value.(*AcceptReShareData)
//	    fmt.Printf("%v================GetCurNodeReShareInfo, k = %v, value = %v, vv = %v, ok = %v ====================\n",common.CurrentTime(),key,value,vv,ok)
	    if vv == nil || ok == false {
		return
	    }

//	    fmt.Printf("%v================GetCurNodeReShareInfo, vv = %v, vv.Status = %v ====================\n",common.CurrentTime(),vv,vv.Status)
	    if vv.Deal == "true" || vv.Status == "Success" {
		return
	    }

	    if vv.Status != "Pending" {
		return
	    }

	    keytmp := Keccak256Hash([]byte(strings.ToLower(vv.Account + ":" + vv.GroupId + ":" + vv.TSGroupId + ":" + vv.PubKey + ":" + vv.LimitNum))).Hex()

	    los := &ReShareCurNodeInfo{Key: keytmp, PubKey:vv.PubKey, GroupId:vv.GroupId, TSGroupId:vv.TSGroupId,ThresHold: vv.LimitNum,TimeStamp: vv.TimeStamp}
	    ret = append(ret, los)
//	    fmt.Printf("%v================GetCurNodeReShareInfo ret = %v,====================\n",common.CurrentTime(),ret)
	}(k,v)
    }
    LdbPubKeyData.RUnlock()
  //  fmt.Printf("%v================GetCurNodeReShareInfo end lock,====================\n",common.CurrentTime())
    wg.Wait()
    //fmt.Printf("%v================GetCurNodeReShareInfo end, ret = %v====================\n",common.CurrentTime(),ret)
    return ret, "", nil
}

type LockOutReply struct {
	Enode string
	Reply string
}

type LockOutReplys struct {
	Replys []LockOutReply
}

type TxDataLockOut struct {
    TxType string
    DcrmAddr string
    DcrmTo string
    Value string
    Cointype string
    GroupId string
    ThresHold string
    Mode string
    TimeStamp string
    Memo string
}

type TxDataReShare struct {
    TxType string
    PubKey string
    GroupId string
    TSGroupId string
    TSCount string
    ThresHold string
    TimeStamp string
}

type TxDataSign struct {
    TxType string
    PubKey string
    MsgHash string
    MsgContext string
    Keytype string
    GroupId string
    ThresHold string
    Mode string
    TimeStamp string
}

func Encode2(obj interface{}) (string, error) {
	switch obj.(type) {
	case *SendMsg:
		/*ch := obj.(*SendMsg)
		ret,err := json.Marshal(ch)
		if err != nil {
		    return "",err
		}
		return string(ret),nil*/
		ch := obj.(*SendMsg)

		var buff bytes.Buffer
		enc := gob.NewEncoder(&buff)

		err1 := enc.Encode(ch)
		if err1 != nil {
			return "", err1
		}
		return buff.String(), nil
	case *PubKeyData:
		ch := obj.(*PubKeyData)

		var buff bytes.Buffer
		enc := gob.NewEncoder(&buff)

		err1 := enc.Encode(ch)
		if err1 != nil {
			return "", err1
		}
		return buff.String(), nil
	case *AcceptLockOutData:
		ch := obj.(*AcceptLockOutData)

		var buff bytes.Buffer
		enc := gob.NewEncoder(&buff)

		err1 := enc.Encode(ch)
		if err1 != nil {
			return "", err1
		}
		return buff.String(), nil
	case *AcceptReqAddrData:
		ch := obj.(*AcceptReqAddrData)
		ret,err := json.Marshal(ch)
		if err != nil {
		    return "",err
		}
		return string(ret),nil
		/*ch := obj.(*AcceptReqAddrData)

		var buff bytes.Buffer
		enc := gob.NewEncoder(&buff)

		err1 := enc.Encode(ch)
		if err1 != nil {
			return "", err1
		}
		return buff.String(), nil*/
	case *AcceptSignData:
		ch := obj.(*AcceptSignData)

		var buff bytes.Buffer
		enc := gob.NewEncoder(&buff)

		err1 := enc.Encode(ch)
		if err1 != nil {
		    return "", err1
		}
		return buff.String(), nil
	case *AcceptReShareData:
		ch := obj.(*AcceptReShareData)

		var buff bytes.Buffer
		enc := gob.NewEncoder(&buff)

		err1 := enc.Encode(ch)
		if err1 != nil {
		    return "", err1
		}
		return buff.String(), nil
	default:
		return "", fmt.Errorf("encode obj fail.")
	}
}

func Decode2(s string, datatype string) (interface{}, error) {

	if datatype == "SendMsg" {
		/*var m SendMsg
		err := json.Unmarshal([]byte(s), &m)
		if err != nil {
		    fmt.Println("================Decode2,json Unmarshal err =%v===================",err)
		    return nil,err
		}

		return &m,nil*/
		var data bytes.Buffer
		data.Write([]byte(s))

		dec := gob.NewDecoder(&data)

		var res SendMsg
		err := dec.Decode(&res)
		if err != nil {
			return nil, err
		}

		return &res, nil
	}

	if datatype == "PubKeyData" {
		var data bytes.Buffer
		data.Write([]byte(s))

		dec := gob.NewDecoder(&data)

		var res PubKeyData
		err := dec.Decode(&res)
		if err != nil {
			return nil, err
		}

		return &res, nil
	}

	if datatype == "AcceptLockOutData" {
		var data bytes.Buffer
		data.Write([]byte(s))

		dec := gob.NewDecoder(&data)

		var res AcceptLockOutData
		err := dec.Decode(&res)
		if err != nil {
			return nil, err
		}

		return &res, nil
	}

	if datatype == "AcceptReqAddrData" {
		var m AcceptReqAddrData
		err := json.Unmarshal([]byte(s), &m)
		if err != nil {
		    return nil,err
		}

		return &m,nil
		/*var data bytes.Buffer
		data.Write([]byte(s))

		dec := gob.NewDecoder(&data)

		var res AcceptReqAddrData
		err := dec.Decode(&res)
		if err != nil {
			return nil, err
		}

		return &res, nil*/
	}

	if datatype == "AcceptSignData" {
		var data bytes.Buffer
		data.Write([]byte(s))

		dec := gob.NewDecoder(&data)

		var res AcceptSignData
		err := dec.Decode(&res)
		if err != nil {
			return nil, err
		}

		return &res, nil
	}

	if datatype == "AcceptReShareData" {
		var data bytes.Buffer
		data.Write([]byte(s))

		dec := gob.NewDecoder(&data)

		var res AcceptReShareData
		err := dec.Decode(&res)
		if err != nil {
			return nil, err
		}

		return &res, nil
	}

	return nil, fmt.Errorf("decode obj fail.")
}

///////

////compress
func Compress(c []byte) (string, error) {
	if c == nil {
		return "", fmt.Errorf("compress fail.")
	}

	var in bytes.Buffer
	w, err := zlib.NewWriterLevel(&in, zlib.BestCompression-1)
	if err != nil {
		return "", err
	}

	w.Write(c)
	w.Close()

	s := in.String()
	return s, nil
}

////uncompress
func UnCompress(s string) (string, error) {

	if s == "" {
		return "", fmt.Errorf("param error.")
	}

	var data bytes.Buffer
	data.Write([]byte(s))

	r, err := zlib.NewReader(&data)
	if err != nil {
		return "", err
	}

	var out bytes.Buffer
	io.Copy(&out, r)
	return out.String(), nil
}

////

type DcrmHash [32]byte

func (h DcrmHash) Hex() string { return hexutil.Encode(h[:]) }

// Keccak256Hash calculates and returns the Keccak256 hash of the input data,
// converting it to an internal Hash data structure.
func Keccak256Hash(data ...[]byte) (h DcrmHash) {
	d := sha3.NewKeccak256()
	for _, b := range data {
		d.Write(b)
	}
	d.Sum(h[:0])
	return h
}

type TxDataReqAddr struct {
    TxType string
    GroupId string
    ThresHold string
    Mode string
    TimeStamp string
    Sigs string
}

type ReqAddrSendMsgToDcrm struct {
	Account   string
	Nonce     string
	TxData string
	Key       string
}

func (self *ReqAddrSendMsgToDcrm) Run(workid int, ch chan interface{}) bool {
	if workid < 0 || workid >= RpcMaxWorker {
		res := RpcDcrmRes{Ret: "", Tip: "dcrm back-end internal error:no worker id", Err: GetRetErr(ErrGetWorkerIdError)}
		ch <- res
		return false
	}

	cur_enode = discover.GetLocalID().String() //GetSelfEnode()
	msg, err := json.Marshal(self)
	if err != nil {
		res := RpcDcrmRes{Ret: "", Tip: err.Error(), Err: err}
		ch <- res
		return false
	}

	sm := &SendMsg{MsgType: "rpc_req_dcrmaddr", Nonce: self.Key, WorkId: workid, Msg: string(msg)}
	res, err := Encode2(sm)
	if err != nil {
		res := RpcDcrmRes{Ret: "", Tip: "dcrm back-end internal error:encode SendMsg fail in req addr", Err: err}
		ch <- res
		return false
	}

	res, err = Compress([]byte(res))
	if err != nil {
		res := RpcDcrmRes{Ret: "", Tip: "dcrm back-end internal error:compress SendMsg data fail in req addr", Err: err}
		ch <- res
		return false
	}

	req := TxDataReqAddr{}
	err = json.Unmarshal([]byte(self.TxData), &req)
	if err != nil {
	    res := RpcDcrmRes{Ret: "", Tip: "recover tx.data json string fail from raw data,maybe raw data error", Err: err}
	    ch <- res
	    return false
	}

	w := workers[workid]
	
	AcceptReqAddr(cur_enode,self.Account, "ALL", req.GroupId, self.Nonce, req.ThresHold, req.Mode, "false", "true", "Pending", "", "", "", nil, workid,"")

	SendToGroupAllNodes(req.GroupId, res)

	fmt.Printf("%v ===================ReqAddrSendMsgToDcrm.Run, Waiting For Result.key = %v============================\n", common.CurrentTime(), self.Key)
	<-w.acceptWaitReqAddrChan
	fmt.Printf("%v ===================ReqAddrSendMsgToDcrm.Run, get w.acceptWaitReqAddrChan success. key = %v============================\n", common.CurrentTime(), self.Key)

	tt := fmt.Sprintf("%v",time.Now().UnixNano()/1e6)
	///////
	if req.Mode == "0" {
		mp := []string{self.Key, cur_enode}
		enode := strings.Join(mp, "-")
		s0 := "AcceptReqAddrRes"
		s1 := "true"
		ss := enode + common.Sep + s0 + common.Sep + s1 + common.Sep + tt
		SendMsgToDcrmGroup(ss, req.GroupId)
		
		//////////add decdsa log
		cur_time := fmt.Sprintf("%v",common.CurrentTime())
		log, exist := DecdsaMap.ReadMap(strings.ToLower(self.Key))
		if exist == false {
		    tmp := make([]SendAcceptResTime,0)
		    rat := SendAcceptResTime{SendTime:cur_time,Reply:ss}
		    tmp = append(tmp,rat)
		    logs := &DecdsaLog{CurEnode:"",GroupEnodes:nil,DcrmCallTime:"",RecivAcceptRes:nil,SendAcceptRes:tmp,RecivDcrm:nil,SendDcrm:nil,FailTime:"",FailInfo:"",No_Reciv:nil}
		    DecdsaMap.WriteMap(strings.ToLower(self.Key),logs)
		    //fmt.Printf("%v ===============ReqAddrSendMsgToDcrm.Run,write map success, code is AcceptReqAddrRes,exist is false, msg = %v, key = %v=================\n", common.CurrentTime(),ss,self.Key)
		} else {
		    logs,ok := log.(*DecdsaLog)
		    if ok == false {
			//fmt.Printf("%v ===============ReqAddrSendMsgToDcrm.Run,code is AcceptReqAddrRes,ok if false, key = %v=================\n", common.CurrentTime(),self.Key)
			res := RpcDcrmRes{Ret: "", Tip: "dcrm back-end internal error:get dcrm log fail in req addr", Err: err}
			ch <- res
			return false
		    }

		    rats := logs.SendAcceptRes
		    rat := SendAcceptResTime{SendTime:cur_time,Reply:ss}
		    rats = append(rats,rat)
		    logs.SendAcceptRes = rats
		    DecdsaMap.WriteMap(strings.ToLower(self.Key),logs)
		    //fmt.Printf("%v ===============ReqAddrSendMsgToDcrm.Run,write map success,code is AcceptReqAddrRes,exist is true,key = %v=================\n", common.CurrentTime(),self.Key)
		}
		///////////////////////

		DisMsg(ss)
		//fmt.Printf("%v ===================ReqAddrSendMsgToDcrm.Run, finish send AcceptReqAddrRes to other nodes. key = %v============================\n", common.CurrentTime(), self.Key)
		////fix bug: get C1 timeout
		_, enodes := GetGroup(req.GroupId)
		nodes := strings.Split(enodes, common.Sep2)
		for _, node := range nodes {
		    node2 := ParseNode(node)
		    c1data := self.Key + "-" + node2 + common.Sep + "AcceptReqAddrRes"
		    c1, exist := C1Data.ReadMap(strings.ToLower(c1data))
		    if exist {
			DisMsg(c1.(string))
			go C1Data.DeleteMap(strings.ToLower(c1data))
		    }
		}
		////
	}

	time.Sleep(time.Duration(1) * time.Second)
	ars := GetAllReplyFromGroup(-1,req.GroupId,Rpc_REQADDR,cur_enode)
	AcceptReqAddr(cur_enode,self.Account, "ALL", req.GroupId, self.Nonce, req.ThresHold, req.Mode, "", "", "", "", "", "", ars, workid,"")
	fmt.Printf("%v ===================ReqAddrSendMsgToDcrm.Run, finish agree this req addr oneself.key = %v============================\n", common.CurrentTime(), self.Key)
	chret, tip, cherr := GetChannelValue(sendtogroup_timeout, w.ch)
	fmt.Printf("%v ===================ReqAddrSendMsgToDcrm.Run, Get Result. result = %v,cherr = %v,key = %v============================\n", common.CurrentTime(), chret, cherr, self.Key)
	if cherr != nil {
		res2 := RpcDcrmRes{Ret: chret, Tip: tip, Err: cherr}
		ch <- res2
		return false
	}

	res2 := RpcDcrmRes{Ret: chret, Tip: tip, Err: cherr}
	ch <- res2

	return true
}

//msg = fusionaccount:dcrmaddr:dcrmto:value:cointype:groupid:nonce:threshold
type LockOutSendMsgToDcrm struct {
	Account   string
	Nonce     string
	TxData     string
	Key       string
}

func (self *LockOutSendMsgToDcrm) Run(workid int, ch chan interface{}) bool {
	if workid < 0 || workid >= RpcMaxWorker {
		res := RpcDcrmRes{Ret: "", Tip: "dcrm back-end internal error:get worker id error", Err: GetRetErr(ErrGetWorkerIdError)}
		ch <- res
		return false
	}

	cur_enode = discover.GetLocalID().String() //GetSelfEnode()
	msg, err := json.Marshal(self)
	if err != nil {
		res := RpcDcrmRes{Ret: "", Tip: err.Error(), Err: err}
		ch <- res
		return false
	}

	sm := &SendMsg{MsgType: "rpc_lockout", Nonce: self.Key, WorkId: workid, Msg: string(msg)}
	res, err := Encode2(sm)
	if err != nil {
		res := RpcDcrmRes{Ret: "", Tip: "dcrm back-end internal error:encode SendMsg fail in lockout", Err: err}
		ch <- res
		return false
	}

	res, err = Compress([]byte(res))
	if err != nil {
		res := RpcDcrmRes{Ret: "", Tip: "dcrm back-end internal error:compress SendMsg data error in lockout", Err: err}
		ch <- res
		return false
	}

	lo := TxDataLockOut{}
	err = json.Unmarshal([]byte(self.TxData), &lo)
	if err != nil {
	    res := RpcDcrmRes{Ret: "", Tip: "recover tx.data json string fail from raw data,maybe raw data error", Err: err}
	    ch <- res
	    return false
	}

	AcceptLockOut(cur_enode,self.Account, lo.GroupId, self.Nonce, lo.DcrmAddr, lo.ThresHold, "false", "true", "Pending", "", "", "", nil, workid)
	
	SendToGroupAllNodes(lo.GroupId, res)

	w := workers[workid]

	////
	fmt.Printf("%v =============LockOutSendMsgToDcrm.Run,Waiting For Result, key = %v ========================\n", common.CurrentTime(), self.Key)
	<-w.acceptWaitLockOutChan
	var tip string

	///////
	tt := fmt.Sprintf("%v",time.Now().UnixNano()/1e6)
	if lo.Mode == "0" {
		mp := []string{self.Key, cur_enode}
		enode := strings.Join(mp, "-")
		s0 := "AcceptLockOutRes"
		s1 := "true"
		ss := enode + common.Sep + s0 + common.Sep + s1 + common.Sep + tt
		SendMsgToDcrmGroup(ss, lo.GroupId)
		DisMsg(ss)
		//fmt.Printf("%v ================== LockOutSendMsgToDcrm.Run , finish send AcceptLockOutRes to other nodes, key = %v ============================\n", common.CurrentTime(), self.Key)
		
		////fix bug: get C11 timeout
		_, enodes := GetGroup(lo.GroupId)
		nodes := strings.Split(enodes, common.Sep2)
		for _, node := range nodes {
		    node2 := ParseNode(node)
		    c1data := self.Key + "-" + node2 + common.Sep + "AcceptLockOutRes"
		    c1, exist := C1Data.ReadMap(strings.ToLower(c1data))
		    if exist {
			DisMsg(c1.(string))
			go C1Data.DeleteMap(strings.ToLower(c1data))
		    }
		}
		////
	}

	time.Sleep(time.Duration(1) * time.Second)
	ars := GetAllReplyFromGroup(-1,lo.GroupId,Rpc_LOCKOUT,cur_enode)
	AcceptLockOut(cur_enode,self.Account, lo.GroupId, self.Nonce, lo.DcrmAddr, lo.ThresHold, "", "", "", "", "", "", ars, workid)
	//fmt.Printf("%v ===================LockOutSendMsgToDcrm.Run, finish agree this lockout oneself. key = %v ============================\n", common.CurrentTime(), self.Key)
	
	chret, tip, cherr := GetChannelValue(sendtogroup_lilo_timeout, w.ch)
	fmt.Printf("%v ==============LockOutSendMsgToDcrm.Run,Get Result = %v, err = %v, key = %v =================\n", common.CurrentTime(), chret, cherr, self.Key)
	if cherr != nil {
		res2 := RpcDcrmRes{Ret: "", Tip: tip, Err: cherr}
		ch <- res2
		return false
	}

	res2 := RpcDcrmRes{Ret: chret, Tip: tip, Err: cherr}
	ch <- res2

	return true
}

type ReShareSendMsgToDcrm struct {
	Account   string
	Nonce     string
	TxData     string
	Key       string
}

func (self *ReShareSendMsgToDcrm) Run(workid int, ch chan interface{}) bool {
	if workid < 0 || workid >= RpcMaxWorker {
		res := RpcDcrmRes{Ret: "", Tip: "dcrm back-end internal error:get worker id error", Err: GetRetErr(ErrGetWorkerIdError)}
		ch <- res
		return false
	}

	cur_enode = discover.GetLocalID().String() //GetSelfEnode()
	msg, err := json.Marshal(self)
	if err != nil {
		res := RpcDcrmRes{Ret: "", Tip: err.Error(), Err: err}
		ch <- res
		return false
	}

	sm := &SendMsg{MsgType: "rpc_reshare", Nonce: self.Key, WorkId: workid, Msg: string(msg)}
	res, err := Encode2(sm)
	if err != nil {
		res := RpcDcrmRes{Ret: "", Tip: "dcrm back-end internal error:encode SendMsg fail in reshare", Err: err}
		ch <- res
		return false
	}

	res, err = Compress([]byte(res))
	if err != nil {
		res := RpcDcrmRes{Ret: "", Tip: "dcrm back-end internal error:compress SendMsg data error in reshare", Err: err}
		ch <- res
		return false
	}

	rh := TxDataReShare{}
	err = json.Unmarshal([]byte(self.TxData), &rh)
	if err != nil {
	    res := RpcDcrmRes{Ret: "", Tip: "recover tx.data json string fail from raw data,maybe raw data error", Err: err}
	    ch <- res
	    return false
	}

	AcceptReShare(cur_enode,self.Account, rh.GroupId, rh.TSGroupId,rh.PubKey, rh.ThresHold,"false", "true", "Pending", "", "", "", nil, workid)
	
	SendToGroupAllNodes(rh.GroupId, res)

	w := workers[workid]

	////
	fmt.Printf("%v =============ReShareSendMsgToDcrm.Run,Waiting For Result, key = %v ========================\n", common.CurrentTime(), self.Key)
	<-w.acceptWaitReShareChan
	var tip string

	///////
	tt := fmt.Sprintf("%v",time.Now().UnixNano()/1e6)
	//if rh.Mode == "0" {
		mp := []string{self.Key, cur_enode}
		enode := strings.Join(mp, "-")
		s0 := "AcceptReShareRes"
		s1 := "true"
		ss := enode + common.Sep + s0 + common.Sep + s1 + common.Sep + tt
		SendMsgToDcrmGroup(ss, rh.GroupId)
		DisMsg(ss)
		//fmt.Printf("%v ================== ReShareSendMsgToDcrm.Run , finish send AcceptReShareRes to other nodes, key = %v ============================\n", common.CurrentTime(), self.Key)
		
		////fix bug: get C11 timeout
		_, enodes := GetGroup(rh.GroupId)
		nodes := strings.Split(enodes, common.Sep2)
		for _, node := range nodes {
		    node2 := ParseNode(node)
		    c1data := self.Key + "-" + node2 + common.Sep + "AcceptReShareRes"
		    c1, exist := C1Data.ReadMap(strings.ToLower(c1data))
		    if exist {
			DisMsg(c1.(string))
			go C1Data.DeleteMap(strings.ToLower(c1data))
		    }
		}
		////
	//}

	time.Sleep(time.Duration(1) * time.Second)
	ars := GetAllReplyFromGroup(-1,rh.GroupId,Rpc_RESHARE,cur_enode)
	AcceptReShare(cur_enode,self.Account, rh.GroupId, rh.TSGroupId,rh.PubKey, rh.ThresHold,"", "", "", "", "", "", ars, workid)
	//fmt.Printf("%v ===================ReShareSendMsgToDcrm.Run, finish agree this reshare oneself. key = %v ============================\n", common.CurrentTime(), self.Key)
	
	chret, tip, cherr := GetChannelValue(sendtogroup_lilo_timeout, w.ch)
	fmt.Printf("%v ==============ReShareSendMsgToDcrm.Run,Get Result = %v, err = %v, key = %v =================\n", common.CurrentTime(), chret, cherr, self.Key)
	if cherr != nil {
		res2 := RpcDcrmRes{Ret: "", Tip: tip, Err: cherr}
		ch <- res2
		return false
	}

	res2 := RpcDcrmRes{Ret: chret, Tip: tip, Err: cherr}
	ch <- res2

	return true
}

type SignSendMsgToDcrm struct {
	Account   string
	Nonce     string
	TxData string
	Key       string
}

func (self *SignSendMsgToDcrm) Run(workid int, ch chan interface{}) bool {
	if workid < 0 || workid >= RpcMaxWorker {
		res := RpcDcrmRes{Ret: "", Tip: "dcrm back-end internal error:get worker id error", Err: GetRetErr(ErrGetWorkerIdError)}
		ch <- res
		return false
	}

	cur_enode = discover.GetLocalID().String() //GetSelfEnode()
	msg, err := json.Marshal(self)
	if err != nil {
		res := RpcDcrmRes{Ret: "", Tip: err.Error(), Err: err}
		ch <- res
		return false
	}

	sm := &SendMsg{MsgType: "rpc_sign", Nonce: self.Key, WorkId: workid, Msg: string(msg)}
	res, err := Encode2(sm)
	if err != nil {
		res := RpcDcrmRes{Ret: "", Tip: "dcrm back-end internal error:encode SendMsg fail in sign", Err: err}
		ch <- res
		return false
	}

	res, err = Compress([]byte(res))
	if err != nil {
		res := RpcDcrmRes{Ret: "", Tip: "dcrm back-end internal error:compress SendMsg data error in sign", Err: err}
		ch <- res
		return false
	}

	sig := TxDataSign{}
	err = json.Unmarshal([]byte(self.TxData), &sig)
	if err != nil {
	    res := RpcDcrmRes{Ret: "", Tip: "recover tx.data json string fail from raw data,maybe raw data error", Err: err}
	    ch <- res
	    return false
	}

	AcceptSign(cur_enode,self.Account, sig.PubKey,sig.MsgHash,sig.Keytype,sig.GroupId, self.Nonce,sig.ThresHold,sig.Mode,"false", "true", "Pending", "", "", "", nil, workid)
	
	SendToGroupAllNodes(sig.GroupId, res)

	w := workers[workid]

	////
	fmt.Printf("%v =============SignSendMsgToDcrm.Run,Waiting For Result, key = %v ========================\n", common.CurrentTime(), self.Key)
	<-w.acceptWaitSignChan
	var tip string

	///////
	tt := fmt.Sprintf("%v",time.Now().UnixNano()/1e6)
	if sig.Mode == "0" {
		mp := []string{self.Key, cur_enode}
		enode := strings.Join(mp, "-")
		s0 := "AcceptSignRes"
		s1 := "true"
		ss := enode + common.Sep + s0 + common.Sep + s1 + common.Sep + tt
		SendMsgToDcrmGroup(ss, sig.GroupId)
		DisMsg(ss)
		//fmt.Printf("%v ================== SignSendMsgToDcrm.Run , finish send AcceptSignRes to other nodes, key = %v ============================\n", common.CurrentTime(), self.Key)
		
		////fix bug: get C11 timeout
		_, enodes := GetGroup(sig.GroupId)
		nodes := strings.Split(enodes, common.Sep2)
		for _, node := range nodes {
		    node2 := ParseNode(node)
		    c1data := self.Key + "-" + node2 + common.Sep + "AcceptSignRes"
		    c1, exist := C1Data.ReadMap(strings.ToLower(c1data))
		    if exist {
			DisMsg(c1.(string))
			go C1Data.DeleteMap(strings.ToLower(c1data))
		    }
		}
		////
	}

	time.Sleep(time.Duration(1) * time.Second)
	ars := GetAllReplyFromGroup(-1,sig.GroupId,Rpc_SIGN,cur_enode)
	AcceptSign(cur_enode,self.Account,sig.PubKey,sig.MsgHash,sig.Keytype,sig.GroupId, self.Nonce,sig.ThresHold,sig.Mode,"", "","","","","", ars,workid)
	//fmt.Printf("%v ===================SignSendMsgToDcrm.Run, finish agree this sign oneself. key = %v ============================\n", common.CurrentTime(), self.Key)
	
	chret, tip, cherr := GetChannelValue(sendtogroup_lilo_timeout, w.ch)
	fmt.Printf("%v ==============SignSendMsgToDcrm.Run,Get Result = %v, err = %v, key = %v =================\n", common.CurrentTime(), chret, cherr, self.Key)
	if cherr != nil {
		res2 := RpcDcrmRes{Ret: "", Tip: tip, Err: cherr}
		ch <- res2
		return false
	}

	res2 := RpcDcrmRes{Ret: chret, Tip: tip, Err: cherr}
	ch <- res2

	return true
}

type RpcType int32

const (
    Rpc_REQADDR      RpcType = 0
    Rpc_LOCKOUT     RpcType = 1
    Rpc_SIGN      RpcType = 2
    Rpc_RESHARE     RpcType = 3
)

func GetAllReplyFromGroup(wid int,gid string,rt RpcType,initiator string) []NodeReply {
    if gid == "" {
	return nil
    }

    var ars []NodeReply
    _, enodes := GetGroup(gid)
    nodes := strings.Split(enodes, common.Sep2)
    
    if wid < 0 || wid >= len(workers) {
	for _, node := range nodes {
		node2 := ParseNode(node)
		sta := "Pending"
		ts := ""
		in := "0"
		if strings.EqualFold(initiator,node2) {
		    in = "1"
		}

		nr := NodeReply{Enode:node2,Status:sta,TimeStamp:ts,Initiator:in}
		ars = append(ars,nr)
	}

	return ars
    }

    w := workers[wid]
    if w == nil {
	return nil
    }

    if rt == Rpc_LOCKOUT {
	for _, node := range nodes {
		node2 := ParseNode(node)
		sta := "Pending"
		ts := ""
		in := "0"
		if strings.EqualFold(initiator,node2) {
		    in = "1"
		}

		iter := w.msg_acceptlockoutres.Front()
		for iter != nil {
		    mdss := iter.Value.(string)
		    ms := strings.Split(mdss, common.Sep)
		    prexs := strings.Split(ms[0], "-")
		    node3 := prexs[1]
		    if strings.EqualFold(node3,node2) {
			if strings.EqualFold(ms[2],"false") {
			    sta = "DisAgree"
			} else {
			    sta = "Agree"
			}

			ts = ms[3]
			break
		    }
		    
		    iter = iter.Next()
		}
		
		nr := NodeReply{Enode:node2,Status:sta,TimeStamp:ts,Initiator:in}
		ars = append(ars,nr)
	}
    } 
    
    if rt == Rpc_SIGN {
	for _, node := range nodes {
		node2 := ParseNode(node)
		sta := "Pending"
		ts := ""
		in := "0"
		if strings.EqualFold(initiator,node2) {
		    in = "1"
		}

		iter := w.msg_acceptsignres.Front()
		for iter != nil {
		    mdss := iter.Value.(string)
		    ms := strings.Split(mdss, common.Sep)
		    prexs := strings.Split(ms[0], "-")
		    node3 := prexs[1]
		    if strings.EqualFold(node3,node2) {
			if strings.EqualFold(ms[2],"false") {
			    sta = "DisAgree"
			} else {
			    sta = "Agree"
			}

			ts = ms[3]
			break
		    }
		    
		    iter = iter.Next()
		}
		
		nr := NodeReply{Enode:node2,Status:sta,TimeStamp:ts,Initiator:in}
		ars = append(ars,nr)
	}
    } 
    
    if rt == Rpc_RESHARE {
	for _, node := range nodes {
		node2 := ParseNode(node)
		sta := "Pending"
		ts := ""
		in := "0"
		if strings.EqualFold(initiator,node2) {
		    in = "1"
		}

		iter := w.msg_acceptreshareres.Front()
		for iter != nil {
		    mdss := iter.Value.(string)
		    ms := strings.Split(mdss, common.Sep)
		    prexs := strings.Split(ms[0], "-")
		    node3 := prexs[1]
		    if strings.EqualFold(node3,node2) {
			if strings.EqualFold(ms[2],"false") {
			    sta = "DisAgree"
			} else {
			    sta = "Agree"
			}

			ts = ms[3]
			break
		    }
		    
		    iter = iter.Next()
		}
		
		nr := NodeReply{Enode:node2,Status:sta,TimeStamp:ts,Initiator:in}
		ars = append(ars,nr)
	}
    } 
    
    if rt == Rpc_REQADDR {
	for _, node := range nodes {
	    node2 := ParseNode(node)
	    sta := "Pending"
	    ts := ""
	    in := "0"
	    if strings.EqualFold(initiator,node2) {
		in = "1"
	    }

	    iter := w.msg_acceptreqaddrres.Front()
	    for iter != nil {
		mdss := iter.Value.(string)
		ms := strings.Split(mdss, common.Sep)
		prexs := strings.Split(ms[0], "-")
		node3 := prexs[1]
		if strings.EqualFold(node3,node2) {
		    if strings.EqualFold(ms[2],"false") {
			sta = "DisAgree"
		    } else {
			sta = "Agree"
		    }

		    ts = ms[3]
		    break
		}
		
		iter = iter.Next()
	    }
	    
	    nr := NodeReply{Enode:node2,Status:sta,TimeStamp:ts,Initiator:in}
	    ars = append(ars,nr)
	}
    }

    return ars
}

type NodeReply struct {
    Enode string
    Status string
    TimeStamp string
    Initiator string // "1"/"0"
}

func SendReqDcrmAddr(acc string, nonce string, txdata string, key string) (string, string, error) {
	v := ReqAddrSendMsgToDcrm{Account: acc, Nonce: nonce, TxData: txdata, Key: key}
	rch := make(chan interface{}, 1)
	req := RpcReq{rpcdata: &v, ch: rch}

	RpcReqQueueCache <- req
	chret, tip, cherr := GetChannelValue(600, req.ch)

	if cherr != nil {
		return chret, tip, cherr
	}

	return chret, "", nil
}

func SendLockOut(acc string, nonce string, txdata string,key string) (string, string, error) {
	v := LockOutSendMsgToDcrm{Account: acc, Nonce: nonce, TxData:txdata, Key: key}
	rch := make(chan interface{}, 1)
	req := RpcReq{rpcdata: &v, ch: rch}

	RpcReqQueueCache <- req
	chret, tip, cherr := GetChannelValue(600, req.ch)

	if cherr != nil {
		return chret, tip, cherr
	}

	return chret, "", nil
}

func SendReShare(acc string, nonce string, txdata string,key string) (string, string, error) {
	v := ReShareSendMsgToDcrm{Account: acc, Nonce: nonce, TxData:txdata, Key: key}
	rch := make(chan interface{}, 1)
	req := RpcReq{rpcdata: &v, ch: rch}

	RpcReqQueueCache <- req
	chret, tip, cherr := GetChannelValue(600, req.ch)

	if cherr != nil {
		return chret, tip, cherr
	}

	return chret, "", nil
}

func SendSign(acc string, nonce string, txdata string, key string) (string, string, error) {
    v := SignSendMsgToDcrm{Account: acc, Nonce: nonce, TxData: txdata, Key: key}
	rch := make(chan interface{}, 1)
	req := RpcReq{rpcdata: &v, ch: rch}

	RpcReqQueueCache <- req
	chret, tip, cherr := GetChannelValue(600, req.ch)

	if cherr != nil {
		return chret, tip, cherr
	}

	return chret, "", nil
}

func GetChannelValue(t int, obj interface{}) (string, string, error) {
	timeout := make(chan bool, 1)
	go func() {
		time.Sleep(time.Duration(t) * time.Second) //1000 == 1s
		timeout <- true
	}()

	switch obj.(type) {
	case chan interface{}:
		ch := obj.(chan interface{})
		select {
		case v := <-ch:
			ret, ok := v.(RpcDcrmRes)
			if ok == true {
				return ret.Ret, ret.Tip, ret.Err
			}
		case <-timeout:
			return "", "dcrm back-end internal error:get result from channel timeout", fmt.Errorf("get data from node fail.")
		}
	case chan string:
		ch := obj.(chan string)
		select {
		case v := <-ch:
			return v, "", nil
		case <-timeout:
			return "", "dcrm back-end internal error:get result from channel timeout", fmt.Errorf("get data from node fail.")
		}
	case chan int64:
		ch := obj.(chan int64)
		select {
		case v := <-ch:
			return strconv.Itoa(int(v)), "", nil
		case <-timeout:
			return "", "dcrm back-end internal error:get result from channel timeout", fmt.Errorf("get data from node fail.")
		}
	case chan int:
		ch := obj.(chan int)
		select {
		case v := <-ch:
			return strconv.Itoa(v), "", nil
		case <-timeout:
			return "", "dcrm back-end internal error:get result from channel timeout", fmt.Errorf("get data from node fail.")
		}
	case chan bool:
		ch := obj.(chan bool)
		select {
		case v := <-ch:
			if !v {
				return "false", "", nil
			} else {
				return "true", "", nil
			}
		case <-timeout:
			return "", "dcrm back-end internal error:get result from channel timeout", fmt.Errorf("get data from node fail.")
		}
	default:
		return "", "dcrm back-end internal error:unknown channel type", fmt.Errorf("unknown ch type.")
	}

	return "", "dcrm back-end internal error:unknown error.", fmt.Errorf("get value fail.")
}

//error type 1
type Err struct {
	Info string
}

func (e Err) Error() string {
	return e.Info
}

type PubAccounts struct {
	Group []AccountsList
}
type AccountsList struct {
	GroupID  string
	Accounts []PubKeyInfo
}

func CheckAcc(eid string, geter_acc string, sigs string) bool {

	if eid == "" || geter_acc == "" || sigs == "" {
	    return false
	}

	//sigs:  5:eid1:acc1:eid2:acc2:eid3:acc3:eid4:acc4:eid5:acc5
	mms := strings.Split(sigs, common.Sep)
	for _, mm := range mms {
		//if strings.EqualFold(mm, eid) {
		//	if len(mms) >= (k+1) && strings.EqualFold(mms[k+1], geter_acc) {
		//	    return true
		//	}
		//}
		if strings.EqualFold(geter_acc,mm) { //allow user login diffrent node
		    return true
		}
	}
	
	return false
}

type PubKeyInfo struct {
    PubKey string
    ThresHold string
    TimeStamp string
}

func GetAccounts(geter_acc, mode string) (interface{}, string, error) {
    exsit,da := GetValueFromPubKeyData(strings.ToLower(geter_acc))
	if exsit == false {
	    fmt.Printf("%v================GetAccounts, no exist, geter_acc = %v,=================\n",common.CurrentTime(),geter_acc)
	    return nil,"",fmt.Errorf("get value from pubkeydata fail.")
	}

	fmt.Printf("%v================GetAccounts, da = %v, geter_acc = %v,=================\n",common.CurrentTime(),string(da.([]byte)),geter_acc)
	gp := make(map[string][]PubKeyInfo)
	keys := strings.Split(string(da.([]byte)),":")
	for _,key := range keys {
	    exsit,data := GetValueFromPubKeyData(key)
	    if exsit == false {
		continue
	    }

	    ac,ok := data.(*AcceptReqAddrData)
	    if ok == false {
		fmt.Printf("%v================GetAccounts, ac = %v, key = %v,geter_acc = %v,=================\n",common.CurrentTime(),ac,key,geter_acc)
		continue
	    }

	    if ac == nil {
		    continue
	    }

	    if ac.Mode == "1" {
		    if !strings.EqualFold(ac.Account,geter_acc) {
			fmt.Printf("%v================GetAccounts, ac.Account = %v,geter_acc = %v,key = %v,=================\n",common.CurrentTime(),ac.Account,geter_acc,key)
			continue
		    }
	    }

	    if ac.Mode == "0" && !CheckAcc(cur_enode,geter_acc,ac.Sigs) {
		continue
	    }

	    dcrmpks, _ := hex.DecodeString(ac.PubKey)
	    exsit,data2 := GetValueFromPubKeyData(string(dcrmpks[:]))
	    if exsit == false || data2 == nil {
		fmt.Printf("%v================GetAccounts, ac.PubKey = %v, data2 = %v,geter_acc = %v,=================\n",common.CurrentTime(),ac.PubKey,data2,geter_acc)
		continue
	    }

	    pd,ok := data2.(*PubKeyData)
	    if ok == false {
		fmt.Printf("%v================GetAccounts, pd = %v, geter_acc = %v,=================\n",common.CurrentTime(),pd,geter_acc)
		continue
	    }

	    if pd == nil {
		continue
	    }

	    pb := pd.Pub
	    pubkeyhex := hex.EncodeToString([]byte(pb))
	    gid := pd.GroupId
	    md := pd.Mode
	    limit := pd.LimitNum
	    if mode == md {
		    al, exsit := gp[gid]
		    if exsit {
			    tmp := PubKeyInfo{PubKey:pubkeyhex,ThresHold:limit,TimeStamp:pd.KeyGenTime}
			    al = append(al, tmp)
			    gp[gid] = al
		    } else {
			    a := make([]PubKeyInfo, 0)
			    tmp := PubKeyInfo{PubKey:pubkeyhex,ThresHold:limit,TimeStamp:pd.KeyGenTime}
			    a = append(a, tmp)
			    gp[gid] = a
		    }
	    }
	}

	als := make([]AccountsList, 0)
	for k, v := range gp {
		alNew := AccountsList{GroupID: k, Accounts: v}
		als = append(als, alNew)
	}

	pa := &PubAccounts{Group: als}
	return pa, "", nil
}

