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

	"github.com/fsn-dev/cryptoCoins/coins"
	"github.com/fsn-dev/dcrm-walletService/crypto/secp256k1"
	"github.com/fsn-dev/dcrm-walletService/crypto"
	cryptocoinsconfig "github.com/fsn-dev/cryptoCoins/coins/config"
	"github.com/fsn-dev/cryptoCoins/coins/eos"
	"github.com/fsn-dev/cryptoCoins/coins/types"
	"github.com/fsn-dev/dcrm-walletService/crypto/dcrm/dev"
	"github.com/fsn-dev/dcrm-walletService/internal/common"
	p2pdcrm "github.com/fsn-dev/dcrm-walletService/p2p/layer2"
	"github.com/fsn-dev/cryptoCoins/tools/rlp"
)

var (
	tmp2       string
	cur_enode  string
	init_times = 0
	PubLock    sync.Mutex
	SignLock   sync.Mutex
	KeyFile    string
	ReqAddrCh  = make(chan ReqAddrData, 1000)
	LockOutCh  = make(chan LockOutData, 1000)
	SignCh  = make(chan SignData, 1000)
)

func Start() {
	cryptocoinsconfig.Init()
	coins.Init()
	go RecivReqAddr()
	go RecivLockOut()
	go RecivSign()
	dev.InitDev(KeyFile)
	cur_enode = p2pdcrm.GetSelfID()
	fmt.Printf("%v ==================dcrm.Start(),cur_enode = %v ====================\n", common.CurrentTime(), cur_enode)
	
	///////////only for test///////////////////
	Sigs := "enode://e6e6240b78b4d1f293693e14042099ad86b7277824d23534ffef720c31470342b7daf0a34289913b837e2ec45aee68eaab62c7170c22eb5328324037f34ad7a6@47.92.168.85:133330x1ef33f72c7894bc0ff130b3de4db8575adad59d506c762902a2381f1a13ca89a6dfb32b2d2273a3ac69a5b43964b38efab7135a502d41104bc5fc8cc97db97021b|enode://fa93e6d82b859ddf5344ae39a6e1de3c38e0172f0678e0fda5b83cd245cbbabea5e89ff80c65dfac4aee25b93051b0e460388fb6c7f3ed5a368d501a48b96099@47.92.168.85:133310xd608be1aba865b699e0fc19c12172d8bd2c2f022a5f7b3a47fdfd613d2c330530283af5509355a2a19bd331a8018bf4cb2b6d9b645b4a911aa1e1f9fd0ab76b21c|enode://15dfed9e836d2259066921412413b295e6c97f3dddb9a1078a9f7778099a56bd00d31a248fd1d2853e7c09e2adefb8870f98b232220293c815d0b2610e8bcc6e@47.92.168.85:133320x88bda080e0a9ed3d851b9728bcd189ee1cb0eaa737b6d3eafd7fd566aa7f975c02fb58a188bef0239102fa69c8adf12499c75be097f9e5499e03133851543d6e1b"
	sigs := strings.Split(Sigs,"|")
	for j := 0; j < len(sigs); j++ {
	    en := strings.Split(sigs[j], "@")
		enId := strings.Split(en[0],"//")
		if len(enId) < 2 {
		    return
		}

		if j == 0 {
		    sigbit := common.FromHex("0x1ef33f72c7894bc0ff130b3de4db8575adad59d506c762902a2381f1a13ca89a6dfb32b2d2273a3ac69a5b43964b38efab7135a502d41104bc5fc8cc97db970200")
		    if sigbit == nil {
		    return
		    }

		    pub,err := secp256k1.RecoverPubkey(crypto.Keccak256([]byte("e6e6240b78b4d1f293693e14042099ad86b7277824d23534ffef720c31470342b7daf0a34289913b837e2ec45aee68eaab62c7170c22eb5328324037f34ad7a6")),sigbit)
		    if err != nil {
			fmt.Printf("%v==============dcrm.Start(),recover pubkey err = %v ===================\n",common.CurrentTime(),err)
		    return
		    }
		    pubkey := hex.EncodeToString(pub)
		    fmt.Printf("%v==============dcrm.Start(),recover pubkey = %v, pubkey str = %v ===================\n",common.CurrentTime(),pub,pubkey)
		}
	}

	enode := "e6e6240b78b4d1f293693e14042099ad86b7277824d23534ffef720c31470342b7daf0a34289913b837e2ec45aee68eaab62c7170c22eb5328324037f34ad7a6"
	a := []byte(enode)
	b := crypto.Keccak256(a)
	/*priv := "0x1da03e8cbf28a9d4ceca118516a1e3b985f8baa004d1fabfa7b1d7a0a6568fc4"
	p1 := common.FromHex(priv) //FromHex
	sig1, err := crypto.Sign(b,p1)
	if err != nil {
		panic(err)
	}
	sig11 := common.ToHex(sig1)
	fmt.Printf("================b str(EncodeToString) = %v, b str(common.ToHex) = %v,sig11 = %v =======================\n", hex.EncodeToString(b),common.ToHex(b),"enode://0294fd278d8db6fe2c0a917dfb6f5777993ff4d31c5d7b44dc3228197dee180cbea39509c167914eabe2979d9167927843ebfd52dfebfbb0c50103ab1ee2a1b3@47.92.168.85:13335"+sig11)
	p2,_ := hex.DecodeString(priv) //DecodeString
	sig2, err := crypto.Sign(b,p2)
	if err != nil {
		panic(err)
	}
	sig22 := common.ToHex(sig2)
	fmt.Printf("================b str(EncodeToString) = %v, b str(common.ToHex) = %v,sig22 = %v =======================\n", hex.EncodeToString(b),common.ToHex(b),"enode://0294fd278d8db6fe2c0a917dfb6f5777993ff4d31c5d7b44dc3228197dee180cbea39509c167914eabe2979d9167927843ebfd52dfebfbb0c50103ab1ee2a1b3@47.92.168.85:13335"+sig22)*/
	fmt.Printf("================b str(EncodeToString) = %v, b str(common.ToHex) = %v =======================\n", hex.EncodeToString(b),common.ToHex(b))
	////////////////////////////////////////
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

	exsit,da := dev.GetValueFromPubKeyData(key)
	///////
	if exsit == false {
		return "", "dcrm back-end internal error:get data from db fail in func GetPubKeyData", fmt.Errorf("dcrm back-end internal error:get data from db fail in func GetPubKeyData")
	}

	pubs,ok := da.(*dev.PubKeyData)
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
	key := dev.Keccak256Hash([]byte(strings.ToLower(account + ":" + cointype))).Hex()
	exsit,da := dev.GetValueFromPubKeyData(key)
	///////
	if exsit == false {
		key = dev.Keccak256Hash([]byte(strings.ToLower(account + ":" + "ALL"))).Hex()
		exsit,da = dev.GetValueFromPubKeyData(key)
		///////
		if exsit == false {
			return "", false
		}
	}

	pubs,ok  := da.(*dev.PubKeyData)
	if ok == false {
	    return "",false
	}

	pubkey := hex.EncodeToString([]byte(pubs.Pub))
	return pubkey, true
}

func SendReqToGroup(msg string, rpctype string) (string, string, error) {
	if strings.EqualFold(rpctype, "rpc_req_dcrmaddr") {
		//msg = account:cointype:groupid:nonce:threshold:mode:tx1:tx2:tx3...:txn
		msgs := strings.Split(msg, ":")
		if len(msgs) < 6 {
			return "", "dcrm back-end internal parameter error in func SendReqToGroup", fmt.Errorf("param error.")
		}

		//coin := "ALL"
		if !types.IsDefaultED25519(msgs[1]) {
			//coin = msgs[1]
			msgs[1] = "ALL"
		}

		str := strings.Join(msgs, ":")

		//account:cointype:groupid:nonce:threshold:mode:tx1:tx2:tx3....:txn
		//str := msgs[0] + ":" + coin + ":" + msgs[2] + ":" + msgs[3] + ":" + msgs[4] + ":" + msgs[5]
		ret, tip, err := dev.SendReqToGroup(str, rpctype)
		if err != nil || ret == "" {
			return "", tip, err
		}

		pubkeyhex := ret
		keytest := dev.Keccak256Hash([]byte(strings.ToLower(msgs[0] + ":" + msgs[1] + ":" + msgs[2] + ":" + msgs[3] + ":" + msgs[4] + ":" + msgs[5]))).Hex()
		common.Info("====================call dcrm.SendReqToGroup,finish calc dcrm addrs, ", "pubkey = ", ret, "key = ", keytest, "", "=======================")

		var m interface{}
		if !strings.EqualFold(msgs[1], "ALL") {
			h := coins.NewCryptocoinHandler(msgs[1])
			if h == nil {
				return "", "cointype is not supported", fmt.Errorf("req addr fail.cointype is not supported.")
			}

			ctaddr, err := h.PublicKeyToAddress(pubkeyhex)
			if err != nil {
				return "", "get dcrm addr fail from pubkey:" + pubkeyhex, err
			}

			m = &DcrmAddrRes{Account: msgs[0], PubKey: pubkeyhex, DcrmAddr: ctaddr, Cointype: msgs[1]}
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
			ctaddr, err := h.PublicKeyToAddress(pubkeyhex)
			if err != nil {
				continue
			}

			addrmp[ct] = ctaddr
		}

		m = &DcrmPubkeyRes{Account: msgs[0], PubKey: pubkeyhex, DcrmAddress: addrmp}
		b, _ := json.Marshal(m)
		common.Info("====================call dcrm.SendReqToGroup,finish calc dcrm addrs,get all dcrm addrs. ", "addrs = ", string(b), "key = ", keytest, "", "=======================")
		return string(b), "", nil
	}

	ret, tip, err := dev.SendReqToGroup(msg, rpctype)
	if err != nil || ret == "" {
		return "", tip, err
	}

	return ret, "", nil
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
			exsit,_ := dev.GetValueFromPubKeyData(data.Key)
			if exsit == false {
				req := dev.TxDataReqAddr{}
				json.Unmarshal([]byte(data.JsonStr), &req)
				
				cur_nonce, _, _ := dev.GetReqAddrNonce(data.Account)
				cur_nonce_num, _ := new(big.Int).SetString(cur_nonce, 10)
				new_nonce_num, _ := new(big.Int).SetString(data.Nonce, 10)
				if new_nonce_num.Cmp(cur_nonce_num) >= 0 {
					_, err := dev.SetReqAddrNonce(data.Account,data.Nonce)
					//fmt.Printf("%v =================================RecivReqAddr,SetReqAddrNonce, account = %v,group id = %v,threshold = %v,mode = %v,nonce = %v,err = %v,key = %v, =================================\n", common.CurrentTime(), data.Account, req.GroupId, req.ThresHold,req.Mode, data.Nonce, err, data.Key)
					if err == nil {
					    ars := dev.GetAllReplyFromGroup(-1,req.GroupId,dev.Rpc_REQADDR,cur_enode)

					    ac := &dev.AcceptReqAddrData{Initiator:cur_enode,Account: data.Account, Cointype: "ALL", GroupId: req.GroupId, Nonce: data.Nonce, LimitNum: req.ThresHold, Mode: req.Mode, TimeStamp: req.TimeStamp, Deal: "false", Accept: "false", Status: "Pending", PubKey: "", Tip: "", Error: "", AllReply: ars, WorkId: -1,Sigs:""}
						err := dev.SaveAcceptReqAddrData(ac)
						fmt.Printf("%v ===================call SaveAcceptReqAddrData finish, account = %v,err = %v,key = %v, ========================\n", common.CurrentTime(), data.Account, err, data.Key)
						if err == nil {
						    ///////add decdsa log
						    var enodeinfo string
						    groupinfo := make([]string,0)
						    _, enodes := dev.GetGroup(req.GroupId)
						    nodes := strings.Split(enodes, dev.SepSg)
						    for _, node := range nodes {
							groupinfo = append(groupinfo,node)
							node2 := dev.ParseNode(node)
							if strings.EqualFold(cur_enode,node2) {
							    enodeinfo = node 
							}
						    }

						    log, exist := dev.DecdsaMap.ReadMap(strings.ToLower(data.Key))
						    if exist == false {
							logs := &dev.DecdsaLog{CurEnode:enodeinfo,GroupEnodes:groupinfo,DcrmCallTime:"",RecivAcceptRes:nil,SendAcceptRes:nil,RecivDcrm:nil,SendDcrm:nil,FailTime:"",FailInfo:"",No_Reciv:nil}
							dev.DecdsaMap.WriteMap(strings.ToLower(data.Key),logs)
							//fmt.Printf("%v ===============RecivReqAddr,write map success,enodeinfo = %v,key = %v=================\n", common.CurrentTime(),enodeinfo,data.Key)
						    } else {
							logs,ok := log.(*dev.DecdsaLog)
							if ok == true {
							    logs.CurEnode = enodeinfo
							    logs.GroupEnodes = groupinfo
							    dev.DecdsaMap.WriteMap(strings.ToLower(data.Key),logs)
							    //fmt.Printf("%v ===============RecivReqAddr,write map success,enodeinfo = %v,key = %v=================\n", common.CurrentTime(),enodeinfo,data.Key)
							}
						    }
						    //////////////////
							////////bug
							go func(d ReqAddrData,reqda *dev.TxDataReqAddr,rad *dev.AcceptReqAddrData) {
								nums := strings.Split(reqda.ThresHold, "/")
								nodecnt, _ := strconv.Atoi(nums[1])
								if nodecnt <= 1 {
								    return
								}

								sigs := strings.Split(reqda.Sigs,"|")
								//SigN = enode://xxxxxxxx@ip:portxxxxxxxxxxxxxxxxxxxxxx
								_, enodes := dev.GetGroup(reqda.GroupId)
								nodes := strings.Split(enodes, dev.SepSg)
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
										    node2 := dev.ParseNode(node)
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
											    
											    exsit,da := dev.GetValueFromPubKeyData(strings.ToLower(from))
											    if exsit == false {
												kdtmp := dev.KeyData{Key: []byte(strings.ToLower(from)), Data: d.Key}
												dev.PubKeyDataChan <- kdtmp
												dev.LdbPubKeyData.WriteMap(strings.ToLower(from), []byte(d.Key))
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
												    kdtmp := dev.KeyData{Key: []byte(strings.ToLower(from)), Data: da2}
												    dev.PubKeyDataChan <- kdtmp
												    dev.LdbPubKeyData.WriteMap(strings.ToLower(from), []byte(da2))
												}
											    }
											}
										    }
										}

									}

									dev.SendMsgToDcrmGroup(ss, reqda.GroupId)
									//fmt.Printf("%v ===============RecivReqAddr,send group accounts to other nodes,msg = %v,key = %v,===========================\n", common.CurrentTime(), ss, d.Key)
									rad.Sigs = sstmp
									if dev.SaveAcceptReqAddrData(rad) != nil { //re-save
									    return
									}
								} else {
									    exsit,da := dev.GetValueFromPubKeyData(strings.ToLower(d.Account))
									    if exsit == false {
										kdtmp := dev.KeyData{Key: []byte(strings.ToLower(d.Account)), Data: d.Key}
										dev.PubKeyDataChan <- kdtmp
										dev.LdbPubKeyData.WriteMap(strings.ToLower(d.Account), []byte(d.Key))
									    } else {
										da2 := string(da.([]byte)) + ":" + d.Key
										kdtmp := dev.KeyData{Key: []byte(strings.ToLower(d.Account)), Data: da2}
										dev.PubKeyDataChan <- kdtmp
										dev.LdbPubKeyData.WriteMap(strings.ToLower(d.Account), []byte(da2))
									    }
								}
								////////////////////////////////////////////////////

								//coin := "ALL"
								//if !types.IsDefaultED25519(msgs[1]) {  //TODO
								//}

								addr, _, err := dev.SendReqDcrmAddr(d.Account, d.Nonce, d.JsonStr, d.Key)
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

	req := dev.TxDataReqAddr{}
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

	Nonce := tx.Nonce()

	////
	nc,_ := dev.GetGroup(groupid)
	if nc != nodecnt {
	    return "","check group node count error",fmt.Errorf("check group node count error")
	}
	////

	key := dev.Keccak256Hash([]byte(strings.ToLower(from.Hex() + ":" + "ALL" + ":" + groupid + ":" + fmt.Sprintf("%v", Nonce) + ":" + threshold + ":" + mode))).Hex()

	data := ReqAddrData{Account: from.Hex(), Nonce: fmt.Sprintf("%v", Nonce), JsonStr:string(tx.Data()), Key: key}
	ReqAddrCh <- data

	fmt.Printf("%v ===============ReqDcrmAddr finish,return,key = %v,raw = %v,mode = %v ================================\n", common.CurrentTime(), key, raw, mode)
	return key, "", nil
}

func AcceptReqAddr(raw string) (string, string, error) {
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

	acceptreq := dev.TxDataAcceptReqAddr{}
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
	exsit,da := dev.GetValueFromPubKeyData(acceptreq.Key)
	if exsit == false {
		return "Failure", "dcrm back-end internal error:get accept data fail from db", fmt.Errorf("dcrm back-end internal error:get accept data fail from db")
	}

	ac,ok := da.(*dev.AcceptReqAddrData)
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
	
	if !dev.CheckAcc(cur_enode,from.Hex(),ac.Sigs) {
	    return "Failure", "invalid accepter", fmt.Errorf("invalid accepter")
	}

	if ac.Mode == "0" {
	    exsit,data := dev.GetValueFromPubKeyData(strings.ToLower(from.Hex()))
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
	ss := enode + dev.Sep + s0 + dev.Sep + s1 + dev.Sep + s2
	dev.SendMsgToDcrmGroup(ss, ac.GroupId)
	
	//////////add decdsa log
	cur_time := fmt.Sprintf("%v",common.CurrentTime())
	log, exist := dev.DecdsaMap.ReadMap(strings.ToLower(acceptreq.Key))
	if exist == false {
	    tmp := make([]dev.SendAcceptResTime,0)
	    rat := dev.SendAcceptResTime{SendTime:cur_time,Reply:ss}
	    tmp = append(tmp,rat)
	    logs := &dev.DecdsaLog{CurEnode:"",GroupEnodes:nil,DcrmCallTime:"",RecivAcceptRes:nil,SendAcceptRes:tmp,RecivDcrm:nil,SendDcrm:nil,FailTime:"",FailInfo:"",No_Reciv:nil}
	    dev.DecdsaMap.WriteMap(strings.ToLower(acceptreq.Key),logs)
	    fmt.Printf("%v ===============AcceptReqAddr,write map success, code is AcceptReqAddrRes,exist is false, msg = %v, key = %v=================\n", common.CurrentTime(),ss,acceptreq.Key)
	} else {
	    logs,ok := log.(*dev.DecdsaLog)
	    if ok == false {
		fmt.Printf("%v ===============AcceptReqAddr,code is AcceptReqAddrRes,ok if false, key = %v=================\n", common.CurrentTime(),acceptreq.Key)
		return "Failure", "get dcrm log fail", fmt.Errorf("get dcrm log fail.")
	    }

	    rats := logs.SendAcceptRes
	    rat := dev.SendAcceptResTime{SendTime:cur_time,Reply:ss}
	    rats = append(rats,rat)
	    logs.SendAcceptRes = rats
	    dev.DecdsaMap.WriteMap(strings.ToLower(acceptreq.Key),logs)
	    fmt.Printf("%v ===============AcceptReqAddr,write map success,code is AcceptReqAddrRes,exist is true,key = %v=================\n", common.CurrentTime(),acceptreq.Key)
	}
	///////////////////////

	dev.DisMsg(ss)
	fmt.Printf("%v ================== AcceptReqAddr, finish send AcceptReqAddrRes to other nodes,key = %v ====================\n", common.CurrentTime(), acceptreq.Key)
	////fix bug: get C1 timeout
	_, enodes := dev.GetGroup(ac.GroupId)
	nodes := strings.Split(enodes, dev.SepSg)
	for _, node := range nodes {
	    node2 := dev.ParseNode(node)
	    c1data := acceptreq.Key + "-" + node2 + dev.Sep + "AcceptReqAddrRes"
	    c1, exist := dev.C1Data.ReadMap(strings.ToLower(c1data))
	    if exist {
		dev.DisMsg(c1.(string))
		go dev.C1Data.DeleteMap(strings.ToLower(c1data))
	    }
	}
	////
	
	w, err := dev.FindWorker(acceptreq.Key)
	if err != nil {
	    return "Failure",err.Error(),err
	}

	id,_ := dev.GetWorkerId(w)
	ars := dev.GetAllReplyFromGroup(id,ac.GroupId,dev.Rpc_REQADDR,ac.Initiator)
	tip, err := dev.AcceptReqAddr(ac.Initiator,ac.Account, ac.Cointype, ac.GroupId, ac.Nonce, ac.LimitNum, ac.Mode, "false", accept, status, "", "", "", ars, ac.WorkId,"")
	if err != nil {
		return "Failure", tip, err
	}

	return "Success", "", nil
}

func AcceptLockOut(raw string) (string, string, error) {
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

	acceptlo := dev.TxDataAcceptLockOut{}
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
	exsit,da := dev.GetValueFromPubKeyData(strings.ToLower(from.Hex()))
	if exsit == false {
		return "Failure", "dcrm back-end internal error:get lockout data from db fail", fmt.Errorf("get lockout data from db fail")
	}

	check := false
	found := false
	keys := strings.Split(string(da.([]byte)),":")
	for _,key := range keys {
	    exsit,data2 := dev.GetValueFromPubKeyData(key)
	    if exsit == false {
		continue
	    }

	    ac,ok := data2.(*dev.AcceptReqAddrData)
	    if ok == false || ac == nil {
		continue
	    }

	    if ac.Mode == "0" && !dev.CheckAcc(cur_enode,from.Hex(),ac.Sigs) {
		continue
	    }

	    dcrmpks, _ := hex.DecodeString(ac.PubKey)
	    exsit,data3 := dev.GetValueFromPubKeyData(string(dcrmpks[:]))
	    if exsit == false || data3 == nil {
		continue
	    }

	    pd,ok := data3.(*dev.PubKeyData)
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
		    exsit,data3 := dev.GetValueFromPubKeyData(lockoutkey)
		    if exsit == false {
			break
		    }

		    ac3,ok := data3.(*dev.AcceptLockOutData)
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
	exsit,da = dev.GetValueFromPubKeyData(acceptlo.Key)
	///////
	if exsit == false {
		return "Failure", "dcrm back-end internal error:get accept result from db fail", fmt.Errorf("get accept result from db fail")
	}

	ac,ok := da.(*dev.AcceptLockOutData)
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
	ss2 := enode + dev.Sep + s0 + dev.Sep + s1 + dev.Sep + s2
	dev.SendMsgToDcrmGroup(ss2, ac.GroupId)
	dev.DisMsg(ss2)
	fmt.Printf("%v ================== AcceptLockOut , finish send AcceptLockOutRes to other nodes ,key = %v ============================\n", common.CurrentTime(), acceptlo.Key)
	////fix bug: get C11 timeout
	_, enodes := dev.GetGroup(ac.GroupId)
	nodes := strings.Split(enodes, dev.SepSg)
	for _, node := range nodes {
	    node2 := dev.ParseNode(node)
	    c1data := acceptlo.Key + "-" + node2 + dev.Sep + "AcceptLockOutRes"
	    c1, exist := dev.C1Data.ReadMap(strings.ToLower(c1data))
	    if exist {
		dev.DisMsg(c1.(string))
		go dev.C1Data.DeleteMap(strings.ToLower(c1data))
	    }
	}
	////

	w, err := dev.FindWorker(acceptlo.Key)
	if err != nil {
	    return "Failure",err.Error(),err
	}

	id,_ := dev.GetWorkerId(w)
	ars := dev.GetAllReplyFromGroup(id,ac.GroupId,dev.Rpc_LOCKOUT,ac.Initiator)
	tip, err := dev.AcceptLockOut(ac.Initiator,ac.Account, ac.GroupId, ac.Nonce, ac.DcrmFrom, ac.LimitNum, "false", accept, status, "", "", "", ars, ac.WorkId)
	if err != nil {
		return "Failure", tip, err
	}

	return "Success", "", nil
}

func AcceptSign(raw string) (string, string, error) {
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

	acceptsig := dev.TxDataAcceptSign{}
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
	exsit,da := dev.GetValueFromPubKeyData(strings.ToLower(from.Hex()))
	if exsit == false {
		return "Failure", "dcrm back-end internal error:get sign data from db fail", fmt.Errorf("get sign data from db fail")
	}

	//key := hash(acc + nonce + pubkey + hash + keytype + groupid + threshold + mode)
	check := false
	found := false
	keys := strings.Split(string(da.([]byte)),":")
	for _,key := range keys {
	    exsit,data2 := dev.GetValueFromPubKeyData(key)
	    if exsit == false {
		continue
	    }

	    ac,ok := data2.(*dev.AcceptReqAddrData)
	    if ok == false || ac == nil {
		continue
	    }

	    if ac.Mode == "0" && !dev.CheckAcc(cur_enode,from.Hex(),ac.Sigs) {
		continue
	    }

	    dcrmpks, _ := hex.DecodeString(ac.PubKey)
	    exsit,data3 := dev.GetValueFromPubKeyData(string(dcrmpks[:]))
	    if exsit == false || data3 == nil {
		continue
	    }

	    pd,ok := data3.(*dev.PubKeyData)
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
		    exsit,data3 := dev.GetValueFromPubKeyData(signkey)
		    if exsit == false {
			break
		    }

		    ac3,ok := data3.(*dev.AcceptSignData)
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
	exsit,da = dev.GetValueFromPubKeyData(acceptsig.Key)
	///////
	if exsit == false {
		return "Failure", "dcrm back-end internal error:get accept result from db fail", fmt.Errorf("get accept result from db fail")
	}

	ac,ok := da.(*dev.AcceptSignData)
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
	ss2 := enode + dev.Sep + s0 + dev.Sep + s1 + dev.Sep + s2
	dev.SendMsgToDcrmGroup(ss2, ac.GroupId)
	dev.DisMsg(ss2)
	fmt.Printf("%v ================== AcceptSign, finish send AcceptSignRes to other nodes ,key = %v ============================\n", common.CurrentTime(), acceptsig.Key)
	////fix bug: get C11 timeout
	_, enodes := dev.GetGroup(ac.GroupId)
	nodes := strings.Split(enodes, dev.SepSg)
	for _, node := range nodes {
	    node2 := dev.ParseNode(node)
	    c1data := acceptsig.Key + "-" + node2 + dev.Sep + "AcceptSignRes"
	    c1, exist := dev.C1Data.ReadMap(strings.ToLower(c1data))
	    if exist {
		dev.DisMsg(c1.(string))
		go dev.C1Data.DeleteMap(strings.ToLower(c1data))
	    }
	}
	////

	w, err := dev.FindWorker(acceptsig.Key)
	if err != nil {
	    return "Failure",err.Error(),err
	}

	id,_ := dev.GetWorkerId(w)
	ars := dev.GetAllReplyFromGroup(id,ac.GroupId,dev.Rpc_SIGN,ac.Initiator)
	
	//ACCEPTSIGN:account:pubkey:msghash:keytype:groupid:nonce:threshold:mode:accept:timestamp
	tip, err := dev.AcceptSign(ac.Initiator,ac.Account, ac.PubKey, ac.MsgHash, ac.Keytype, ac.GroupId, ac.Nonce,ac.LimitNum,ac.Mode,"false", accept, status, "", "", "", ars, ac.WorkId)
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
			exsit,_ := dev.GetValueFromPubKeyData(data.Key)
			if exsit == false {
				lo := dev.TxDataLockOut{}
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
				
				cur_nonce, _, _ := dev.GetLockOutNonce(data.Account)
				cur_nonce_num, _ := new(big.Int).SetString(cur_nonce, 10)
				new_nonce_num, _ := new(big.Int).SetString(data.Nonce, 10)
				if new_nonce_num.Cmp(cur_nonce_num) >= 0 {
					_, err := dev.SetLockOutNonce(data.Account,data.Nonce)
					if err == nil {
						//fmt.Printf("%v ==============================RecivLockOut,SetLockOutNonce, err = %v,account = %v,group id = %v,threshold = %v,mode = %v,nonce = %v,key = %v ============================================\n", common.CurrentTime(), err, data.Account, groupid, threshold, mode, data.Nonce, data.Key)
					    ars := dev.GetAllReplyFromGroup(-1,groupid,dev.Rpc_LOCKOUT,cur_enode)

					    ac := &dev.AcceptLockOutData{Initiator:cur_enode,Account: data.Account, GroupId: groupid, Nonce: data.Nonce, DcrmFrom: dcrmaddr, DcrmTo: dcrmto, Value: value, Cointype: cointype, LimitNum: threshold, Mode: mode, TimeStamp: timestamp, Deal: "false", Accept: "false", Status: "Pending", OutTxHash: "", Tip: "", Error: "", AllReply: ars, WorkId: -1}
						err := dev.SaveAcceptLockOutData(ac)
						if err == nil {
							fmt.Printf("%v ==============================RecivLockOut,finish call SaveAcceptLockOutData, err = %v,account = %v,group id = %v,threshold = %v,mode = %v,nonce = %v,key = %v ============================================\n", common.CurrentTime(), err, data.Account, groupid, threshold, mode, data.Nonce, data.Key)

							/////
							dcrmkey := dev.Keccak256Hash([]byte(strings.ToLower(dcrmaddr))).Hex()
							exsit,da := dev.GetValueFromPubKeyData(dcrmkey)
							if exsit {
							    _,ok := da.(*dev.PubKeyData)
							    if ok == true {
								    dcrmpub := (da.(*dev.PubKeyData)).Pub
								    exsit,da2 := dev.GetValueFromPubKeyData(dcrmpub)
								    if exsit {
									_,ok = da2.(*dev.PubKeyData)
									if ok == true {
									    keys := (da2.(*dev.PubKeyData)).RefLockOutKeys
									    if keys == "" {
										keys = data.Key
									    } else {
										keys = keys + ":" + data.Key
									    }

									    pubs3 := &dev.PubKeyData{Key:(da2.(*dev.PubKeyData)).Key,Account: (da2.(*dev.PubKeyData)).Account, Pub: (da2.(*dev.PubKeyData)).Pub, Save: (da2.(*dev.PubKeyData)).Save, Nonce: (da2.(*dev.PubKeyData)).Nonce, GroupId: (da2.(*dev.PubKeyData)).GroupId, LimitNum: (da2.(*dev.PubKeyData)).LimitNum, Mode: (da2.(*dev.PubKeyData)).Mode,KeyGenTime:(da2.(*dev.PubKeyData)).KeyGenTime,RefLockOutKeys:keys,RefSignKeys:(da2.(*dev.PubKeyData)).RefSignKeys}
									    epubs, err := dev.Encode2(pubs3)
									    if err == nil {
										ss3, err := dev.Compress([]byte(epubs))
										if err == nil {
										    kd := dev.KeyData{Key: []byte(dcrmpub), Data: ss3}
										    dev.PubKeyDataChan <- kd
										    dev.LdbPubKeyData.WriteMap(dcrmpub, pubs3)
										    //fmt.Printf("%v ==============================RecivLockOut,reset PubKeyData success, key = %v ============================================\n", common.CurrentTime(), data.Key)
										    go func(d LockOutData) {
											    for i := 0; i < 1; i++ {
												    txhash, _, err2 := dev.SendLockOut(d.Account, d.Nonce, d.JsonStr,d.Key)
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

	lo := dev.TxDataLockOut{}
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
	memo := lo.Memo
	Nonce := tx.Nonce()

	if from.Hex() == "" || dcrmaddr == "" || dcrmto == "" || cointype == "" || value == "" || groupid == "" || threshold == "" || mode == "" || timestamp == "" || memo == "" {
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

	nc,_ := dev.GetGroup(groupid)
	if nc < limit || nc > nodecnt {
	    return "","check group node count error",fmt.Errorf("check group node count error")
	}
	////

	//check mode
	key2 := dev.Keccak256Hash([]byte(strings.ToLower(dcrmaddr))).Hex()
	exsit,da := dev.GetValueFromPubKeyData(key2)
	if exsit == false {
		return "", "dcrm back-end internal error:get data from db fail in func lockout", fmt.Errorf("dcrm back-end internal error:get data from db fail in lockout")
	}

	pubs,ok := da.(*dev.PubKeyData)
	if pubs == nil || ok == false {
		return "", "dcrm back-end internal error:get data from db fail in func lockout", fmt.Errorf("dcrm back-end internal error:get data from db fail in func lockout")
	}

	if pubs.Mode != mode {
	    return "","can not lockout with different mode in dcrm addr.",fmt.Errorf("can not lockout with different mode in dcrm addr.")
	}

	//

	key := dev.Keccak256Hash([]byte(strings.ToLower(from.Hex() + ":" + groupid + ":" + fmt.Sprintf("%v", Nonce) + ":" + dcrmaddr + ":" + threshold))).Hex()
	data := LockOutData{Account:from.Hex(),Nonce:fmt.Sprintf("%v", Nonce),JsonStr:string(tx.Data()),Key: key}
	LockOutCh <- data

	fmt.Printf("%v =================== LockOut, return, key = %v ===========================\n", common.CurrentTime(), key)
	return key, "", nil
}

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

	sig := dev.TxDataSign{}
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

	nc,_ := dev.GetGroup(groupid)
	if nc < limit || nc > nodecnt {
	    return "","check group node count error",fmt.Errorf("check group node count error")
	}
	////

	//check mode
	dcrmpks, _ := hex.DecodeString(pubkey)
	exsit,da := dev.GetValueFromPubKeyData(string(dcrmpks[:]))
	if exsit == false {
		return "", "dcrm back-end internal error:get data from db fail in func sign", fmt.Errorf("dcrm back-end internal error:get data from db fail in sign")
	}

	pubs,ok := da.(*dev.PubKeyData)
	if pubs == nil || ok == false {
		return "", "dcrm back-end internal error:get data from db fail in func sign", fmt.Errorf("dcrm back-end internal error:get data from db fail in func sign")
	}

	if pubs.Mode != mode {
	    return "","can not sign with different mode in pubkey.",fmt.Errorf("can not sign with different mode in pubkey.")
	}

	//

	//key := hash(acc + nonce + pubkey + hash + keytype + groupid + threshold + mode)
	key := dev.Keccak256Hash([]byte(strings.ToLower(from.Hex() + ":" + fmt.Sprintf("%v", Nonce) + ":" + pubkey + ":" + hash + ":" + keytype + ":" + groupid + ":" + threshold + ":" + mode))).Hex()
	data := SignData{Account: from.Hex(), Nonce: fmt.Sprintf("%v", Nonce), JsonStr:string(tx.Data()), Key: key}
	SignCh <- data

	fmt.Printf("%v =================== Sign, return key = %v ===========================\n", common.CurrentTime(),key)
	return key,"",nil
}

func RecivSign() {
	for {
		select {
		case data := <-SignCh:
			exsit,_ := dev.GetValueFromPubKeyData(data.Key)
			if exsit == false {
				sig := dev.TxDataSign{}
				json.Unmarshal([]byte(data.JsonStr), &sig)
				
				cur_nonce, _, _ := dev.GetSignNonce(data.Account)
				cur_nonce_num, _ := new(big.Int).SetString(cur_nonce, 10)
				new_nonce_num, _ := new(big.Int).SetString(data.Nonce, 10)
				if new_nonce_num.Cmp(cur_nonce_num) >= 0 {
					_, err := dev.SetSignNonce(data.Account,data.Nonce)
					if err == nil {
						fmt.Printf("%v ==============================RecivSign, SetSignNonce, err = %v,pubkey = %v, account = %v,group id = %v,threshold = %v,mode = %v,nonce = %v,key = %v ============================================\n", common.CurrentTime(), err, sig.PubKey, data.Account, sig.GroupId, sig.ThresHold, sig.Mode, data.Nonce, data.Key)
					    ars := dev.GetAllReplyFromGroup(-1,sig.GroupId,dev.Rpc_SIGN,cur_enode)

					    ac := &dev.AcceptSignData{Initiator:cur_enode,Account: data.Account, GroupId: sig.GroupId, Nonce: data.Nonce, PubKey: sig.PubKey, MsgHash: sig.MsgHash, Keytype: sig.Keytype, LimitNum: sig.ThresHold, Mode: sig.Mode, TimeStamp: sig.TimeStamp, Deal: "false", Accept: "false", Status: "Pending", Rsv: "", Tip: "", Error: "", AllReply: ars, WorkId: -1}
						err := dev.SaveAcceptSignData(ac)
						if err == nil {
							fmt.Printf("%v ==============================RecivSign,finish call SaveAcceptSignData, err = %v,account = %v,group id = %v,threshold = %v,mode = %v,nonce = %v,key = %v ============================================\n", common.CurrentTime(), err, data.Account, sig.GroupId, sig.ThresHold, sig.Mode, data.Nonce, data.Key)

							/////
							dcrmpks, _ := hex.DecodeString(ac.PubKey)
							exsit,da := dev.GetValueFromPubKeyData(string(dcrmpks[:]))
							if exsit {
							    _,ok := da.(*dev.PubKeyData)
							    if ok == true {
								    keys := (da.(*dev.PubKeyData)).RefSignKeys
								    if keys == "" {
									keys = data.Key
								    } else {
									keys = keys + ":" + data.Key
								    }

								    pubs3 := &dev.PubKeyData{Key:(da.(*dev.PubKeyData)).Key,Account: (da.(*dev.PubKeyData)).Account, Pub: (da.(*dev.PubKeyData)).Pub, Save: (da.(*dev.PubKeyData)).Save, Nonce: (da.(*dev.PubKeyData)).Nonce, GroupId: (da.(*dev.PubKeyData)).GroupId, LimitNum: (da.(*dev.PubKeyData)).LimitNum, Mode: (da.(*dev.PubKeyData)).Mode,KeyGenTime:(da.(*dev.PubKeyData)).KeyGenTime,RefLockOutKeys:(da.(*dev.PubKeyData)).RefLockOutKeys,RefSignKeys:keys}
								    epubs, err := dev.Encode2(pubs3)
								    if err == nil {
									ss3, err := dev.Compress([]byte(epubs))
									if err == nil {
									    kd := dev.KeyData{Key: dcrmpks[:], Data: ss3}
									    dev.PubKeyDataChan <- kd
									    dev.LdbPubKeyData.WriteMap(string(dcrmpks[:]), pubs3)
									    fmt.Printf("%v ==============================RecivSign,reset PubKeyData success, key = %v ============================================\n", common.CurrentTime(), data.Key)
									    go func(d SignData) {
										    for i := 0; i < 1; i++ {
											    rsv, _, err2 := dev.SendSign(d.Account, d.Nonce, d.JsonStr, d.Key)
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

func GetReqAddrStatus(key string) (string, string, error) {
	return dev.GetReqAddrStatus(key)
}

func GetLockOutStatus(key string) (string, string, error) {
	return dev.GetLockOutStatus(key)
}

func GetSignStatus(key string) (string, string, error) {
	return dev.GetSignStatus(key)
}

func GetAccountsBalance(pubkey string, geter_acc string) (interface{}, string, error) {
	exsit,da := dev.GetValueFromPubKeyData(strings.ToLower(geter_acc))
	if exsit == false {
	    return nil,"",fmt.Errorf("get value from pubkeydata fail.")
	}

	keys := strings.Split(string(da.([]byte)),":")
	for _,key := range keys {
	    exsit,data := dev.GetValueFromPubKeyData(key)
	    if exsit == false {
		continue
	    }

	    ac,ok := data.(*dev.AcceptReqAddrData)
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

	    if ac.Mode == "0" && !dev.CheckAcc(cur_enode,geter_acc,ac.Sigs) {
		continue
	    }

	    dcrmpks, _ := hex.DecodeString(ac.PubKey)
	    exsit,data2 := dev.GetValueFromPubKeyData(string(dcrmpks[:]))
	    if exsit == false || data2 == nil {
		continue
	    }

	    pd,ok := data2.(*dev.PubKeyData)
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

func GetReqAddrNonce(account string) (string, string, error) {
	nonce, tip, err := dev.GetReqAddrNonce(account)
	if err != nil {
		return "", tip, err
	}

	return nonce, "", nil
}

func GetLockOutNonce(account string) (string, string, error) {
	nonce, tip, err := dev.GetLockOutNonce(account)
	if err != nil {
		return "", tip, err
	}

	return nonce, "", nil
}

func GetSignNonce(account string) (string, string, error) {
	nonce, tip, err := dev.GetSignNonce(account)
	if err != nil {
	    return "", tip, err
	}

	return nonce, "", nil
}

type CurNodeReqAddrInfoResult struct {
    Result []*dev.ReqAddrReply
}

func GetCurNodeReqAddrInfo(account string) (*CurNodeReqAddrInfoResult, string, error) {
    res,tip,err := dev.GetCurNodeReqAddrInfo(account)
    ret := &CurNodeReqAddrInfoResult{Result:res}
    return ret,tip,err
}

type CurNodeLockOutInfoResult struct {
    Result []*dev.LockOutCurNodeInfo
}

func GetCurNodeLockOutInfo(account string) (*CurNodeLockOutInfoResult, string, error) {
    res,tip,err := dev.GetCurNodeLockOutInfo(account)
    ret := &CurNodeLockOutInfoResult{Result:res}
    return ret,tip,err
}

func GetCurNodeSignInfo(geter_acc string) ([]string, string, error) {
	reply, tip, err := SendReqToGroup(geter_acc, "rpc_get_cur_node_sign_info")
	if reply == "" || err != nil {
	    return nil, tip, err
	}

	ss := strings.Split(reply, "|")
	return ss, "", nil
}

func init() {
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
	fmt.Println("===========dcrm.Call,msg =%v==============", msg)
	s := msg.(string)
	SetUpMsgList(s)
}

var parts  = common.NewSafeMap(10)

func receiveGroupInfo(msg interface{}) {
	fmt.Println("===========receiveGroupInfo==============", "msg", msg)
	cur_enode = p2pdcrm.GetSelfID()

	m := strings.Split(msg.(string), "|")
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

	if !dev.PutGroup(groupId) {
		out := "=============Init================" + " get group id = " + groupId + ", put group id fail "
		fmt.Println(out)
		return
	}

	if init_times >= 1 {
		return
	}

	init_times = 1
	dev.InitGroupInfo(groupId)
}

func SetUpMsgList(msg string) {

	mm := strings.Split(msg, "dcrmslash")
	if len(mm) >= 2 {
		receiveGroupInfo(msg)
		return
	}
}

func GetAccounts(geter_acc, mode string) (interface{}, string, error) {
	return dev.GetAccounts(geter_acc, mode)
}
