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
	"sort"
	"strconv"
	"strings"
	"time"
	"errors"

	"github.com/fsn-dev/dcrm-walletService/mpcdsa/crypto/ec2"
	"github.com/fsn-dev/dcrm-walletService/mpcdsa/ecdsa/signing"
	"github.com/fsn-dev/dcrm-walletService/mpcdsa/ecdsa/keygen"
	"github.com/fsn-dev/dcrm-walletService/mpcdsa/crypto/ed"
	"github.com/fsn-dev/dcrm-walletService/crypto/secp256k1"
	"github.com/fsn-dev/dcrm-walletService/crypto/sha3"

	"sync"
	"github.com/fsn-dev/cryptoCoins/coins/types"
	"github.com/fsn-dev/dcrm-walletService/internal/common"
	"container/list"
	"github.com/fsn-dev/dcrm-walletService/p2p/discover"
)

var (
	signtodel = list.New()
	delsign    sync.Mutex
	count_to_del_sign = 10 
)

func GetSignNonce(account string) (string, string, error) {
	key := Keccak256Hash([]byte(strings.ToLower(account + ":" + "Sign"))).Hex()
	exsit,da := GetValueFromPubKeyData(key)
	///////
	if !exsit {
	    return "0", "", nil
	}

	nonce, _ := new(big.Int).SetString(string(da.([]byte)), 10)
	one, _ := new(big.Int).SetString("1", 10)
	nonce = new(big.Int).Add(nonce, one)
	return fmt.Sprintf("%v", nonce), "", nil
}

func SetSignNonce(account string,nonce string) (string, error) {
	key := Keccak256Hash([]byte(strings.ToLower(account + ":" + "Sign"))).Hex()
	kd := KeyData{Key: []byte(key), Data: nonce}
	PubKeyDataChan <- kd
	LdbPubKeyData.WriteMap(key, []byte(nonce))
	return "", nil
}

func InitAcceptData2(sbd *SignBrocastData,workid int,sender string,ch chan interface{}) error {
    if sbd == nil || workid < 0 || sender == "" || sbd.Raw == "" || sbd.PickHash == nil {
	res := RpcDcrmRes{Ret: "", Tip: "init accept data fail.", Err: fmt.Errorf("init accept data fail")}
	ch <- res
	return fmt.Errorf("init accept data fail")
    }

    key,from,nonce,txdata,err := CheckRaw(sbd.Raw)
    common.Info("=====================InitAcceptData2,get result from call CheckRaw ================","key",key,"from",from,"err",err,"raw",sbd.Raw,"tx data",txdata)
    if err != nil {
	common.Debug("===============InitAcceptData2,check raw===================","err ",err,"key",key,"from",from,"raw",sbd.Raw)
	res := RpcDcrmRes{Ret: "", Tip: err.Error(), Err: err}
	ch <- res
	return err
    }
    
    sig,ok := txdata.(*TxDataSign)
    if ok {
	    pub := Keccak256Hash([]byte(strings.ToLower(sig.PubKey + ":" + sig.GroupId))).Hex()
	   if !strings.EqualFold(sender,cur_enode) {
		   DtPreSign.Lock()
		/////check pre-sign data
		for _,vv := range sbd.PickHash {
		    common.Debug("===============InitAcceptData2,check pickkey===================","txhash",vv.Hash,"pickkey",vv.PickKey,"key",key)
		   PickPrePubDataByKey(pub,vv.PickKey)
		}
		///////
		DtPreSign.Unlock()
	   }

	   ////////////////////////check pre-sign data
	   /*tmp := make([]string,0)
	    for _,v := range sig.MsgHash {
		txhashs := []rune(v)
		if string(txhashs[0:2]) == "0x" {
			tmp = append(tmp,string(txhashs[2:]))
		} else {
		    tmp = append(tmp,string(txhashs))
		}
	    }

	    for _,vv := range tmp {
		pickkey := ""
		for _,val := range sbd.PickHash {
		    if strings.EqualFold(val.Hash,("0x" + vv)) || strings.EqualFold(val.Hash,vv) {
			    pickkey = val.PickKey
			    break
		    }
		}
		if pickkey == "" {
		    res := RpcDcrmRes{Ret: "", Tip: "check pick key fail", Err: errors.New("check pick key fail")}
		    ch <- res
		    return errors.New("check pick key fail")
		}
		
		pre := GetPrePubDataBak(pub,pickkey)
		if pre == nil {
		    res := RpcDcrmRes{Ret: "", Tip: "get pre-sign data fail", Err: errors.New("get pre-sign data fail")}
		    ch <- res
		    return errors.New("get pre-sign data fail")
		}
	    }*/

	    for _,val := range sbd.PickHash {
		pre := GetPrePubDataBak(pub,val.PickKey)
		if pre == nil {
		    res := RpcDcrmRes{Ret: "", Tip: "get pre-sign data fail", Err: errors.New("get pre-sign data fail")}
		    ch <- res
		    return errors.New("get pre-sign data fail")
		}
	    }
	   ////////////////////////

	common.Debug("===============InitAcceptData2, it is sign txdata and check sign raw success==================","key ",key,"from ",from,"nonce ",nonce)
	exsit,_ := GetValueFromPubKeyData(key)
	if !exsit {
	    cur_nonce, _, _ := GetSignNonce(from)
	    cur_nonce_num, _ := new(big.Int).SetString(cur_nonce, 10)
	    new_nonce_num, _ := new(big.Int).SetString(nonce, 10)
	    common.Debug("===============InitAcceptData2===============","sign cur_nonce_num ",cur_nonce_num,"sign new_nonce_num ",new_nonce_num,"key ",key)
	    //if new_nonce_num.Cmp(cur_nonce_num) >= 0 {
		//_, err := SetSignNonce(from,nonce)
		_, err := SetSignNonce(from,cur_nonce) //bug
		if err == nil {
		    ars := GetAllReplyFromGroup(workid,sig.GroupId,Rpc_SIGN,sender)
		    ac := &AcceptSignData{Initiator:sender,Account: from, GroupId: sig.GroupId, Nonce: nonce, PubKey: sig.PubKey, MsgHash: sig.MsgHash, MsgContext: sig.MsgContext, Keytype: sig.Keytype, LimitNum: sig.ThresHold, Mode: sig.Mode, TimeStamp: sig.TimeStamp, Deal: "false", Accept: "false", Status: "Pending", Rsv: "", Tip: "", Error: "", AllReply: ars, WorkId:workid}
		    err = SaveAcceptSignData(ac)
		    if err == nil {
			common.Info("===============InitAcceptData2,save sign accept data finish===================","ars ",ars,"key ",key,"tx data",sig)
			w := workers[workid]
			w.sid = key 
			w.groupid = sig.GroupId 
			w.limitnum = sig.ThresHold
			gcnt, _ := GetGroup(w.groupid)
			common.Info("=============== InitAcceptData2, ===================","gcnt ",gcnt,"key ",key,"gid",w.groupid)
			w.NodeCnt = gcnt
			w.ThresHold = w.NodeCnt

			nums := strings.Split(w.limitnum, "/")
			if len(nums) == 2 {
			    nodecnt, err := strconv.Atoi(nums[1])
			    if err == nil {
				w.NodeCnt = nodecnt
			    }

			    w.ThresHold = gcnt
			    common.Info("=============== InitAcceptData2 ===================","old w.ThresHold ",w.ThresHold,"key ",key,"gid",w.groupid)
			    //bug
			    if w.ThresHold == 0 {
				th,_ := strconv.Atoi(nums[0])
				w.ThresHold = th
				common.Info("=============== InitAcceptData2 ===================","new w.ThresHold ",w.ThresHold,"key ",key,"gid",w.groupid)
			    }
			}

			w.DcrmFrom = sig.PubKey  // pubkey replace dcrmfrom in sign
			
			if sig.Mode == "0" { // self-group
				////
				pending_err := false

				var reply bool
				var tip string
				timeout := make(chan bool, 1)
				go func(wid int) {
					cur_enode = discover.GetLocalID().String() //GetSelfEnode()
					agreeWaitTime := time.Duration(AgreeWait) * time.Minute
					agreeWaitTimeOut := time.NewTicker(agreeWaitTime)

					wtmp2 := workers[wid]

					for {
						select {
						case account := <-wtmp2.acceptSignChan:
							common.Debug("InitAcceptData,", "account= ", account, "key = ", key)
							ars := GetAllReplyFromGroup(w.id,sig.GroupId,Rpc_SIGN,sender)
							common.Info("================== InitAcceptData2 , get all AcceptSignRes===============","result ",ars,"key ",key)
							
							//bug
							reply = true
							pending := false
							for _,nr := range ars {
							    if strings.EqualFold(nr.Status,"Pending") {
								pending = true
							    }

							    if !strings.EqualFold(nr.Status,"Pending") && !strings.EqualFold(nr.Status,"Agree") {
								reply = false
								break
							    }
							}

							//bug: if status is pending and no someone disagree,must wait for the reply from other nodes
							if reply == true && pending == true {
							    pending_err = true
							    pending = false
							    break
							}
							//

							if !reply {
								tip = "don't accept sign"
								_,err = AcceptSign(sender,from,sig.PubKey,sig.MsgHash,sig.Keytype,sig.GroupId,nonce,sig.ThresHold,sig.Mode,"true", "false", "Failure", "", "don't accept sign", "don't accept sign", ars,wid)
							} else {
							    	common.Debug("=======================InitAcceptData2,11111111111111,set sign pending=============================","key",key)
								tip = ""
								_,err = AcceptSign(sender,from,sig.PubKey,sig.MsgHash,sig.Keytype,sig.GroupId,nonce,sig.ThresHold,sig.Mode,"false", "true", "Pending", "", "", "", ars,wid)
							}

							if err != nil {
							    tip = tip + " and accept sign data fail"
							}

							///////
							timeout <- true
							return
						case <-agreeWaitTimeOut.C:
							ars := GetAllReplyFromGroup(w.id,sig.GroupId,Rpc_SIGN,sender)
							common.Info("================== InitAcceptData2 , agree wait timeout=============","ars",ars,"key ",key)
							_,err = AcceptSign(sender,from,sig.PubKey,sig.MsgHash,sig.Keytype,sig.GroupId,nonce,sig.ThresHold,sig.Mode,"true", "false", "Timeout", "", "get other node accept sign result timeout", "get other node accept sign result timeout", ars,wid)
							reply = false
							tip = "get other node accept sign result timeout"
							if err != nil {
							    tip = tip + " and accept sign data fail"
							}
							//

							timeout <- true
							return
						}
					}
				}(workid)

				if len(workers[workid].acceptWaitSignChan) == 0 {
					workers[workid].acceptWaitSignChan <- "go on"
				}

				//common.Info("===============InitAcceptData2, call DisAcceptMsg begin===================","key ",key)
				DisAcceptMsg(sbd.Raw,workid)
				common.Debug("===============InitAcceptData2, call DisAcceptMsg finish===================","key ",key)
				reqaddrkey := GetReqAddrKeyByOtherKey(key,Rpc_SIGN)
				if reqaddrkey == "" {
					DtPreSign.Lock()
					for _,vv := range sbd.PickHash {
						//SetPrePubDataUseStatus(pub,vv.PickKey,false)
						kd := UpdataPreSignData{Key:[]byte(strings.ToLower(pub)),Del:true,Data:vv.PickKey}
						PrePubKeyDataChan <- kd
					}
					DtPreSign.Unlock()

				    res := RpcDcrmRes{Ret: "", Tip: "dcrm back-end internal error:get req addr key fail", Err: fmt.Errorf("get reqaddr key fail")}
				    ch <- res
				    return fmt.Errorf("get reqaddr key fail") 
				}

				exsit,da := GetValueFromPubKeyData(reqaddrkey)
				if !exsit {
					DtPreSign.Lock()
					for _,vv := range sbd.PickHash {
						//SetPrePubDataUseStatus(pub,vv.PickKey,false)
						kd := UpdataPreSignData{Key:[]byte(strings.ToLower(pub)),Del:true,Data:vv.PickKey}
						PrePubKeyDataChan <- kd
					}
					DtPreSign.Unlock()

					common.Debug("===============InitAcceptData2, get req addr key by other key fail ===================","key ",key)
				    res := RpcDcrmRes{Ret: "", Tip: "dcrm back-end internal error:get reqaddr sigs data fail", Err: fmt.Errorf("get reqaddr sigs data fail")}
				    ch <- res
				    return fmt.Errorf("get reqaddr sigs data fail") 
				}

				acceptreqdata,ok := da.(*AcceptReqAddrData)
				if !ok || acceptreqdata == nil {
					DtPreSign.Lock()
					for _,vv := range sbd.PickHash {
						//SetPrePubDataUseStatus(pub,vv.PickKey,false)
						kd := UpdataPreSignData{Key:[]byte(strings.ToLower(pub)),Del:true,Data:vv.PickKey}
						PrePubKeyDataChan <- kd
					}
					DtPreSign.Unlock()

					common.Debug("===============InitAcceptData2, get req addr key by other key error ===================","key ",key)
				    res := RpcDcrmRes{Ret: "", Tip: "dcrm back-end internal error:get reqaddr sigs data fail", Err: fmt.Errorf("get reqaddr sigs data fail")}
				    ch <- res
				    return fmt.Errorf("get reqaddr sigs data fail") 
				}

				common.Debug("===============InitAcceptData2, start call HandleC1Data===================","reqaddrkey ",reqaddrkey,"key ",key)

				HandleC1Data(acceptreqdata,key,workid)

				<-timeout

				if !reply {
					if tip == "get other node accept sign result timeout" {
						ars := GetAllReplyFromGroup(w.id,sig.GroupId,Rpc_SIGN,sender)
						_,err = AcceptSign(sender,from,sig.PubKey,sig.MsgHash,sig.Keytype,sig.GroupId,nonce,sig.ThresHold,sig.Mode,"true", "", "Timeout", "", "get other node accept sign result timeout", "get other node accept sign result timeout", ars,workid)
					} else {
						//sid-enode:SendSignRes:Success:rsv
						//sid-enode:SendSignRes:Fail:err
						mp := []string{w.sid, cur_enode}
						enode := strings.Join(mp, "-")
						s0 := "SendSignRes"
						s1 := "Fail"
						s2 := "don't accept sign."
						ss := enode + common.Sep + s0 + common.Sep + s1 + common.Sep + s2
						SendMsgToDcrmGroup(ss, w.groupid)
						DisMsg(ss)
						_, _, err := GetChannelValue(waitall, w.bsendsignres)
						ars := GetAllReplyFromGroup(w.id,sig.GroupId,Rpc_SIGN,sender)
						if err != nil {
							tip = "get other node terminal accept sign result timeout" ////bug
							_,err = AcceptSign(sender,from,sig.PubKey,sig.MsgHash,sig.Keytype,sig.GroupId,nonce,sig.ThresHold,sig.Mode,"true", "", "Timeout", "", tip, tip, ars,workid)
							if err != nil {
							    tip = tip + " and accept sign data fail"
							}

						} else if w.msg_sendsignres.Len() != w.ThresHold {
							_,err = AcceptSign(sender,from,sig.PubKey,sig.MsgHash,sig.Keytype,sig.GroupId,nonce,sig.ThresHold,sig.Mode,"true", "", "Failure", "", "get other node sign result fail", "get other node sign result fail", ars,workid)
							if err != nil {
							    tip = tip + " and accept sign data fail"
							}

						} else {
							reply2 := "false"
							lohash := ""
							iter := w.msg_sendsignres.Front()
							for iter != nil {
								mdss := iter.Value.(string)
								common.Info("========================InitAcceptData2,get sign result==================","sign result",mdss)
								ms := strings.Split(mdss, common.Sep)
								if strings.EqualFold(ms[2], "Success") {
									reply2 = "true"
									lohash = ms[3]
									break
								}

								lohash = ms[3]
								iter = iter.Next()
							}

							if reply2 == "true" {
								_,err = AcceptSign(sender,from,sig.PubKey,sig.MsgHash,sig.Keytype,sig.GroupId,nonce,sig.ThresHold,sig.Mode,"true", "true", "Success", lohash, " ", " ", ars,workid)
								if err != nil {
								    tip = tip + " and accept sign data fail"
								}

							} else {
								_,err = AcceptSign(sender,from,sig.PubKey,sig.MsgHash,sig.Keytype,sig.GroupId,nonce,sig.ThresHold,sig.Mode,"true", "", "Failure", "", lohash,lohash, ars,workid)
								if err != nil {
								    tip = tip + " and accept sign data fail"
								}

							}
						}
					}

					DtPreSign.Lock()
					for _,vv := range sbd.PickHash {
						//SetPrePubDataUseStatus(pub,vv.PickKey,false)
						kd := UpdataPreSignData{Key:[]byte(strings.ToLower(pub)),Del:true,Data:vv.PickKey}
						PrePubKeyDataChan <- kd
					}
					DtPreSign.Unlock()

					res := RpcDcrmRes{Ret:"", Tip: tip, Err: fmt.Errorf("don't accept sign.")}
					ch <- res
					return fmt.Errorf("don't accept sign.")
				}
			} else {
				if len(workers[workid].acceptWaitSignChan) == 0 {
					workers[workid].acceptWaitSignChan <- "go on"
				}

				ars := GetAllReplyFromGroup(w.id,sig.GroupId,Rpc_SIGN,sender)
				_,err = AcceptSign(sender,from,sig.PubKey,sig.MsgHash,sig.Keytype,sig.GroupId,nonce,sig.ThresHold,sig.Mode,"false", "true", "Pending", "", "","", ars,workid)
				if err != nil {
					DtPreSign.Lock()
					for _,vv := range sbd.PickHash {
						//SetPrePubDataUseStatus(pub,vv.PickKey,false)
						kd := UpdataPreSignData{Key:[]byte(strings.ToLower(pub)),Del:true,Data:vv.PickKey}
						PrePubKeyDataChan <- kd
					}
					DtPreSign.Unlock()

				    res := RpcDcrmRes{Ret:"", Tip: err.Error(), Err:err}
				    ch <- res
				    return err
				}
			}

			common.Info("===============InitAcceptData2,begin to sign=================","sig.MsgHash ",sig.MsgHash,"sig.Mode ",sig.Mode,"key ",key)
			rch := make(chan interface{}, 1)
			sign(w.sid, from,sig.PubKey,sig.MsgHash,sig.Keytype,nonce,sig.Mode,sbd.PickHash,rch)
			chret, tip, cherr := GetChannelValue(waitallgg20+20, rch)
			common.Info("================== InitAcceptData2,finish sig.================","return sign result ",chret,"err ",cherr,"key ",key)
			if chret != "" {
				//common.Debug("===================InitAcceptData2,DeletePrePubData,11111===============","current total number of the data ",GetTotalCount(sig.PubKey),"key",key)
				DtPreSign.Lock()
				for _,vv := range sbd.PickHash {
					//DeletePrePubDataBak(pub,vv.PickKey)
					kd := UpdataPreSignData{Key:[]byte(strings.ToLower(pub)),Del:true,Data:vv.PickKey}
					PrePubKeyDataChan <- kd
				}
				DtPreSign.Unlock()
				//common.Debug("===================InitAcceptData2,DeletePrePubData,22222===============","current total number of the data ",GetTotalCount(sig.PubKey),"key",key)
				
				res := RpcDcrmRes{Ret: chret, Tip: "", Err: nil}
				ch <- res
				return nil
			}

			ars := GetAllReplyFromGroup(w.id,sig.GroupId,Rpc_SIGN,sender)
			if tip == "get other node accept sign result timeout" {
				_,err = AcceptSign(sender,from,sig.PubKey,sig.MsgHash,sig.Keytype,sig.GroupId,nonce,sig.ThresHold,sig.Mode,"true", "", "Timeout", "", tip,cherr.Error(),ars,workid)
			} else {
				//sid-enode:SendSignRes:Success:rsv
				//sid-enode:SendSignRes:Fail:err
				mp := []string{w.sid, cur_enode}
				enode := strings.Join(mp, "-")
				s0 := "SendSignRes"
				s1 := "Fail"
				s2 := cherr.Error()
				ss := enode + common.Sep + s0 + common.Sep + s1 + common.Sep + s2
				SendMsgToDcrmGroup(ss, w.groupid)
				DisMsg(ss)
				_, _, err := GetChannelValue(waitall, w.bsendsignres)
				if err != nil {
					tip = "get other node terminal accept sign result timeout" ////bug
					_,err = AcceptSign(sender,from,sig.PubKey,sig.MsgHash,sig.Keytype,sig.GroupId,nonce,sig.ThresHold,sig.Mode,"true", "", "Timeout", "", tip, tip, ars, workid)
					if err != nil {
					    tip = tip + " and accept sign data fail"
					}

				} else if w.msg_sendsignres.Len() != w.ThresHold {
					_,err = AcceptSign(sender,from,sig.PubKey,sig.MsgHash,sig.Keytype,sig.GroupId,nonce,sig.ThresHold,sig.Mode,"true", "", "Failure", "", "get other node sign result fail", "get other node sign result fail", ars, workid)
					if err != nil {
					    tip = tip + " and accept sign data fail"
					}

				} else {
					reply2 := "false"
					lohash := ""
					iter := w.msg_sendsignres.Front()
					for iter != nil {
						mdss := iter.Value.(string)
						common.Info("========================InitAcceptData2,get sign result==================","sign result",mdss)
						ms := strings.Split(mdss, common.Sep)
						if strings.EqualFold(ms[2], "Success") {
							reply2 = "true"
							lohash = ms[3]
							break
						}

						lohash = ms[3]
						iter = iter.Next()
					}

					if reply2 == "true" {
						_,err = AcceptSign(sender,from,sig.PubKey,sig.MsgHash,sig.Keytype,sig.GroupId,nonce,sig.ThresHold,sig.Mode,"true", "true", "Success", lohash, " ", " ", ars, workid)
						if err != nil {
						    tip = tip + " and accept sign data fail"
						}
					
						/////bug
						DtPreSign.Lock()
						for _,vv := range sbd.PickHash {
							//DeletePrePubDataBak(pub,vv.PickKey)
							kd := UpdataPreSignData{Key:[]byte(strings.ToLower(pub)),Del:true,Data:vv.PickKey}
							PrePubKeyDataChan <- kd
						}
						DtPreSign.Unlock()

						res := RpcDcrmRes{Ret: lohash, Tip: "", Err: nil}
						ch <- res
						return nil
						////bug

					} else {
						_,err = AcceptSign(sender,from,sig.PubKey,sig.MsgHash,sig.Keytype,sig.GroupId,nonce,sig.ThresHold,sig.Mode,"true", "", "Failure", "", lohash, lohash, ars, workid)
						if err != nil {
						    tip = tip + " and accept sign data fail"
						}
					}
				}
			}

			if cherr != nil {
				DtPreSign.Lock()
				for _,vv := range sbd.PickHash {
					//SetPrePubDataUseStatus(pub,vv.PickKey,false)
					kd := UpdataPreSignData{Key:[]byte(strings.ToLower(pub)),Del:true,Data:vv.PickKey}
					PrePubKeyDataChan <- kd
				}
				DtPreSign.Unlock()

				res := RpcDcrmRes{Ret: "", Tip: tip, Err: cherr}
				ch <- res
				return cherr
			}

			DtPreSign.Lock()
			for _,vv := range sbd.PickHash {
				//SetPrePubDataUseStatus(pub,vv.PickKey,false)
				kd := UpdataPreSignData{Key:[]byte(strings.ToLower(pub)),Del:true,Data:vv.PickKey}
				PrePubKeyDataChan <- kd
			}
			DtPreSign.Unlock()

			res := RpcDcrmRes{Ret: "", Tip: tip, Err: fmt.Errorf("sign fail.")}
			ch <- res
			return fmt.Errorf("sign fail.")
		    } else {
			common.Debug("===============InitAcceptData2, it is sign txdata,but save accept data fail==================","key ",key,"from ",from)
		    }
		} else {
			common.Debug("===============InitAcceptData2, it is sign txdata,but set nonce fail==================","key ",key,"from ",from)
		}
	    //}
	} else {
		common.Info("===============InitAcceptData2, it is sign txdata,but has handled before==================","key ",key,"from ",from)
	}
    }

    common.Debug("===============InitAcceptData2, it is not sign txdata and return fail ==================","key ",key,"from ",from,"nonce ",nonce)
    res := RpcDcrmRes{Ret: "", Tip: "init accept data fail.", Err: fmt.Errorf("init accept data fail")}
    ch <- res
    return fmt.Errorf("init accept data fail")
}

func RpcAcceptSign(raw string) (string, string, error) {
    common.Debug("=====================RpcAcceptSign call CheckRaw ================","raw",raw)
    _,from,_,txdata,err := CheckRaw(raw)
    if err != nil {
	common.Info("=====================RpcAcceptSign,call CheckRaw finish================","raw",raw,"err",err)
	return "Failure",err.Error(),err
    }

    acceptsig,ok := txdata.(*TxDataAcceptSign)
    if !ok {
	return "Failure","check raw fail,it is not *TxDataAcceptSign",fmt.Errorf("check raw fail,it is not *TxDataAcceptSign")
    }

    exsit,da := GetValueFromPubKeyData(acceptsig.Key)
    if exsit {
	ac,ok := da.(*AcceptSignData)
	if ok && ac != nil {
	    common.Info("=====================RpcAcceptSign,call CheckRaw finish ================","key",acceptsig.Key,"from",from,"accept",acceptsig.Accept,"raw",raw)
	    SendMsgToDcrmGroup(raw, ac.GroupId)
	    SetUpMsgList(raw,cur_enode)
	    return "Success", "", nil
	}
    }

    return "Failure","accept fail",fmt.Errorf("accept fail")
}

type TxDataSign struct {
    TxType string
    PubKey string
    MsgHash []string
    MsgContext []string
    Keytype string
    GroupId string
    ThresHold string
    Mode string
    TimeStamp string
}

func Sign(raw string) (string, string, error) {
    common.Debug("=====================Sign call CheckRaw ================","raw",raw)
    key,from,_,txdata,err := CheckRaw(raw)
    if err != nil {
	common.Info("=====================Sign,call CheckRaw finish================","raw",raw,"err",err)
	return "",err.Error(),err
    }

    sig,ok := txdata.(*TxDataSign)
    if !ok {
	return "","check raw fail,it is not *TxDataSign",fmt.Errorf("check raw fail,it is not *TxDataSign")
    }

    common.Debug("=====================Sign================","key",key,"from",from,"raw",raw)

    rsd := &RpcSignData{Raw:raw,PubKey:sig.PubKey,GroupId:sig.GroupId,MsgHash:sig.MsgHash,Key:key}
    SignChan <- rsd
    return key, "", nil
}

func HandleRpcSign() {
	for {
		rsd := <-SignChan
	
		dcrmpks, _ := hex.DecodeString(rsd.PubKey)
		exsit,da := GetPubKeyDataFromLocalDb(string(dcrmpks[:]))
		common.Debug("=========================HandleRpcSign======================","rsd.Pubkey",rsd.PubKey,"key",rsd.Key,"exsit",exsit)
		if exsit {
			_,ok := da.(*PubKeyData)
			common.Debug("=========================HandleRpcSign======================","rsd.Pubkey",rsd.PubKey,"key",rsd.Key,"exsit",exsit,"ok",ok)
			if ok {
				pub := Keccak256Hash([]byte(strings.ToLower(rsd.PubKey + ":" + rsd.GroupId))).Hex()
				bret := false
				pickhash := make([]*PickHashKey,0)
				for _,vv := range rsd.MsgHash {
					pickkey := PickPrePubData(pub)
					if pickkey == "" {
						bret = true
						break
					}

					common.Info("========================HandleRpcSign,choose pickkey==================","txhash",vv,"pickkey",pickkey,"key",rsd.Key)
					ph := &PickHashKey{Hash:vv,PickKey:pickkey}
					pickhash = append(pickhash,ph)

					//check pre sigal
					if GetTotalCount(pub) >= (PrePubDataCount*3/4) && GetTotalCount(pub) <= PrePubDataCount {
						PutPreSigal(pub,false)
					} else {
						PutPreSigal(pub,true)
					}
					//
				}

				if bret {
					continue
				}

				send,err := CompressSignBrocastData(rsd.Raw,pickhash)
				if err != nil {
					common.Info("=========================HandleRpcSign======================","rsd.Pubkey",rsd.PubKey,"key",rsd.Key,"exsit",exsit,"ok",ok,"bret",bret,"err",err)
					DtPreSign.Lock()
					for _,vv := range pickhash {
						//SetPrePubDataUseStatus(pub,vv.PickKey,false)
						kd := UpdataPreSignData{Key:[]byte(strings.ToLower(pub)),Del:true,Data:vv.PickKey}
						PrePubKeyDataChan <- kd
					}
					DtPreSign.Unlock()

					continue
				}

				SendMsgToDcrmGroup(send,rsd.GroupId)
				SetUpMsgList(send,cur_enode)
			}
		}
	}
}

func get_sign_hash(hash []string,keytype string) string {
    var ids sortableIDSSlice
    for _, v := range hash {
	    uid := DoubleHash2(v, keytype)
	    ids = append(ids, uid)
    }
    sort.Sort(ids)

    ret := ""
    for _,v := range ids {
	ret += fmt.Sprintf("%v",v)
	ret += ":"
    }

    ret += "NULL"
    return ret
}

//===================================================================

type SignStatus struct {
	Status    string
	Rsv []string
	Tip       string
	Error     string
	AllReply  []NodeReply 
	TimeStamp string
}

func GetSignStatus(key string) (string, string, error) {
	exsit,da := GetValueFromPubKeyData(key)
	///////
	if !exsit || da == nil {
		common.Info("=================GetSignStatus,get sign accept data fail from db================","key",key)
		return "", "dcrm back-end internal error:get sign accept data fail from db when GetSignStatus", fmt.Errorf("dcrm back-end internal error:get sign accept data fail from db when GetSignStatus")
	}

	ac,ok := da.(*AcceptSignData)
	if !ok {
		common.Info("=================GetSignStatus,get sign accept data error from db================","key",key)
		return "", "dcrm back-end internal error:get sign accept data error from db when GetSignStatus", fmt.Errorf("dcrm back-end internal error:get sign accept data error from db when GetSignStatus")
	}

	rsvs := strings.Split(ac.Rsv,":")
	los := &SignStatus{Status: ac.Status, Rsv: rsvs[:len(rsvs)-1], Tip: ac.Tip, Error: ac.Error, AllReply: ac.AllReply, TimeStamp: ac.TimeStamp}
	ret,_ := json.Marshal(los)
	return string(ret), "",nil 
}

type SignCurNodeInfo struct {
	Key       string
	Account   string
	PubKey   string
	MsgHash   []string
	MsgContext   []string
	KeyType   string
	GroupId   string
	Nonce     string
	ThresHold  string
	Mode      string
	TimeStamp string
}

func GetCurNodeSignInfo(geter_acc string) ([]*SignCurNodeInfo, string, error) {
	var ret []*SignCurNodeInfo
	var wg sync.WaitGroup
	LdbPubKeyData.RLock()
	for k, v := range LdbPubKeyData.Map {
	    wg.Add(1)
	    go func(key string,value interface{}) {
		defer wg.Done()

		vv,ok := value.(*AcceptSignData)
		if vv == nil || !ok {
		    return
		}

		common.Debug("================GetCurNodeSignInfo======================","vv",vv,"vv.Deal",vv.Deal,"vv.Status",vv.Status,"key",key)
		if vv.Deal == "true" || vv.Status == "Success" {
		    return
		}

		if vv.Status != "Pending" {
		    return
		}

		if !CheckAccept(vv.PubKey,vv.Mode,geter_acc) {
			return
		}

		/////bug:no find worker
		w, err := FindWorker(key)
		if w == nil || err != nil {
			//LdbPubKeyData.DeleteMap(key)
			return
		}
		////////
		
		los := &SignCurNodeInfo{Key: key, Account: vv.Account, PubKey:vv.PubKey, MsgHash:vv.MsgHash, MsgContext:vv.MsgContext, KeyType:vv.Keytype, GroupId: vv.GroupId, Nonce: vv.Nonce, ThresHold: vv.LimitNum, Mode: vv.Mode, TimeStamp: vv.TimeStamp}
		ret = append(ret, los)
		common.Debug("================GetCurNodeSignInfo success return=======================","key",key)
	    }(k,v)
	}
	LdbPubKeyData.RUnlock()
	wg.Wait()
	return ret, "", nil
}

func sign(wsid string,account string,pubkey string,unsignhash []string,keytype string,nonce string,mode string,pickhash []*PickHashKey ,ch chan interface{}) {
	dcrmpks, _ := hex.DecodeString(pubkey)
	exsit,da := GetPubKeyDataFromLocalDb(string(dcrmpks[:]))
	if !exsit {
	    time.Sleep(time.Duration(5000000000))
	    exsit,da = GetPubKeyDataFromLocalDb(string(dcrmpks[:]))
	}
	///////
	if !exsit {
	    common.Debug("============================sign,not exist sign data===========================","pubkey",pubkey,"key",wsid)
	    res := RpcDcrmRes{Ret: "", Tip: "dcrm back-end internal error:get sign data from db fail", Err: fmt.Errorf("get sign data from db fail")}
	    ch <- res
	    return
	}

	_,ok := da.(*PubKeyData)
	if !ok {
	    common.Debug("============================sign,sign data error==========================","pubkey",pubkey,"key",wsid)
	    res := RpcDcrmRes{Ret: "", Tip: "dcrm back-end internal error:get sign data from db fail", Err: fmt.Errorf("get sign data from db fail")}
	    ch <- res
	    return
	}

	save := (da.(*PubKeyData)).Save
	dcrmpub := (da.(*PubKeyData)).Pub

	var dcrmpkx *big.Int
	var dcrmpky *big.Int
	if keytype == "ECDSA" {
		dcrmpks := []byte(dcrmpub)
		dcrmpkx, dcrmpky = secp256k1.S256().Unmarshal(dcrmpks[:])
	}

	///sku1
	da2 := GetSkU1FromLocalDb(string(dcrmpks[:]))
	if da2 == nil {
		res := RpcDcrmRes{Ret: "", Tip: "lockout get sku1 fail", Err: fmt.Errorf("lockout get sku1 fail")}
		ch <- res
		return
	}
	sku1 := new(big.Int).SetBytes(da2)
	if sku1 == nil {
		res := RpcDcrmRes{Ret: "", Tip: "lockout get sku1 fail", Err: fmt.Errorf("lockout get sku1 fail")}
		ch <- res
		return
	}
	//

	var result string
	var cherrtmp error
	rch := make(chan interface{}, 1)
	if keytype == "ED25519" {
	    sign_ed(wsid,unsignhash,save,sku1,dcrmpub,keytype,rch)
	    ret, tip, cherr := GetChannelValue(waitall, rch)
	    if cherr != nil {
		    res := RpcDcrmRes{Ret: "", Tip: tip, Err: cherr}
		    ch <- res
		    return
	    }

	    result = ret
	    cherrtmp = cherr
	} else {
	    sign_ec(wsid,unsignhash,save,sku1,dcrmpkx,dcrmpky,keytype,pickhash,rch)
	    ret, tip, cherr := GetChannelValue(waitall,rch)
	    common.Info("=================sign,call sign_ec finish.==============","return result",ret,"err",cherr,"key",wsid)
	    if cherr != nil {
		    res := RpcDcrmRes{Ret: "", Tip: tip, Err: cherr}
		    ch <- res
		    return
	    }

	    result = ret
	    cherrtmp = cherr
	}

	tmps := strings.Split(result, ":")
	for _,rsv := range tmps {

	    if rsv == "NULL" {
		continue
	    }

	    //bug
	    rets := []rune(rsv)
	    if len(rets) != 130 {
		    res := RpcDcrmRes{Ret: "", Tip: "dcrm back-end internal error:wrong rsv size", Err: GetRetErr(ErrDcrmSigWrongSize)}
		    ch <- res
		    return
	    }
	}

	if result != "" {
		w, err := FindWorker(wsid)
		if w == nil || err != nil {
		    common.Debug("==========sign,no find worker============","err",err,"key",wsid)
		    res := RpcDcrmRes{Ret: "", Tip: "dcrm back-end internal error:no find worker", Err: fmt.Errorf("get worker error.")}
		    ch <- res
		    return
		}

		///////TODO tmp
		//sid-enode:SendSignRes:Success:rsv
		//sid-enode:SendSignRes:Fail:err
		mp := []string{w.sid, cur_enode}
		enode := strings.Join(mp, "-")
		s0 := "SendSignRes"
		s1 := "Success"
		s2 := result
		ss := enode + common.Sep + s0 + common.Sep + s1 + common.Sep + s2
		SendMsgToDcrmGroup(ss, w.groupid)
		///////////////

		common.Debug("================sign,success sign and call AcceptSign==============","key",wsid)
		tip,reply := AcceptSign("",account,pubkey,unsignhash,keytype,w.groupid,nonce,w.limitnum,mode,"true", "true", "Success", result,"","",nil,w.id)
		if reply != nil {
			res := RpcDcrmRes{Ret: "", Tip: tip, Err: fmt.Errorf("update sign status error.")}
			ch <- res
			return
		}

		common.Info("================sign,the terminal sign res is success==============","key",wsid)
		res := RpcDcrmRes{Ret: result, Tip: tip, Err: err}
		ch <- res
		return
	}

	if cherrtmp != nil {
		common.Info("================sign,the terminal sign res is failure================","err",cherrtmp,"key",wsid)
		res := RpcDcrmRes{Ret: "", Tip: "dcrm back-end internal error:sign fail", Err: cherrtmp}
		ch <- res
		return
	}

	res := RpcDcrmRes{Ret: "", Tip: "dcrm back-end internal error:sign fail", Err: fmt.Errorf("sign fail.")}
	ch <- res
}

type SignData struct {
    MsgPrex string
    Key string
    Save string
    Sku1 *big.Int
    Txhash string
    GroupId string
    NodeCnt int 
    ThresHold int
    DcrmFrom string
    Keytype string
    Cointype string
    Pkx *big.Int
    Pky *big.Int
    PickKey string
}

func sign_ec(msgprex string, txhash []string, save string, sku1 *big.Int, dcrmpkx *big.Int, dcrmpky *big.Int, keytype string, pickhash []*PickHashKey,ch chan interface{}) string {

    	tmp := make([]string,0)
	for _,v := range txhash {
	    txhashs := []rune(v)
	    if string(txhashs[0:2]) == "0x" {
		    tmp = append(tmp,string(txhashs[2:]))
	    } else {
		tmp = append(tmp,string(txhashs))
	    }
	}

	w, err := FindWorker(msgprex)
	if w == nil || err != nil {
		common.Debug("==========dcrm_sign,no find worker===========","key",msgprex,"err",err)
		res := RpcDcrmRes{Ret: "", Tip: "dcrm back-end internal error:no find worker", Err: fmt.Errorf("no find worker.")}
		ch <- res
		return ""
	}

	cur_enode = GetSelfEnode()

	var wg sync.WaitGroup
	for _,v := range tmp {
	    wg.Add(1)
	    go func(vv string) {
		defer wg.Done()

		//get pickkey
		pickkey := ""
		for _,val := range pickhash {
			if strings.EqualFold(val.Hash,("0x" + vv)) || strings.EqualFold(val.Hash,vv) {
				pickkey = val.PickKey
				break
			}
		}
		if pickkey == "" {
			return
		}
		//

		//tt := fmt.Sprintf("%v",time.Now().UnixNano()/1e6)
		key := Keccak256Hash([]byte(strings.ToLower(msgprex + "-" + vv))).Hex()
		sd := &SignData{MsgPrex:msgprex,Key:key,Save:save,Sku1:sku1,Txhash:vv,GroupId:w.groupid,NodeCnt:w.NodeCnt,ThresHold:w.ThresHold,DcrmFrom:w.DcrmFrom,Keytype:keytype,Cointype:"",Pkx:dcrmpkx,Pky:dcrmpky,PickKey:pickkey}
		common.Info("======================sign_ec=================","unsign txhash",vv,"msgprex",msgprex,"key",key,"pick key",pickkey)

		val,err := Encode2(sd)
		if err != nil {
		    common.Info("======================sign_ec, encode error==================","unsign txhash",vv,"msgprex",msgprex,"key",key,"pick key",pickkey,"err",err)
		    //res := RpcDcrmRes{Ret: "", Tip: "dcrm back-end internal error:marshal sign data error", Err: err}
		    //ch <- res
		    return 
		}
		
		common.Debug("======================sign_ec, encode success=================","vv",vv,"msgprex",msgprex,"key",key)
		rch := make(chan interface{}, 1)
		SetUpMsgList3(val,cur_enode,rch)
		_, _,cherr := GetChannelValue(waitall,rch)
		if cherr != nil {

		    common.Info("======================sign_ec, get finish error====================","vv",vv,"msgprex",msgprex,"key",key,"cherr",cherr)
		    //res := RpcDcrmRes{Ret: "", Tip: "dcrm back-end internal error: sign fail", Err: cherr}
		    //ch <- res
		    return 
		}
		common.Info("======================sign_ec, get finish success===================","vv",vv,"msgprex",msgprex,"key",key)
	    }(v)
	}
	wg.Wait()

	common.Info("======================sign_ec, all sign finish===================","msgprex",msgprex,"w.rsv",w.rsv)

	var ret string
	iter := w.rsv.Front()
	for iter != nil {
	    mdss := iter.Value.(string)
	    ret += mdss 
	    ret += ":"
	    iter = iter.Next()
	}

	ret += "NULL"
	tmps := strings.Split(ret, ":")
	common.Debug("======================sign_ec=====================","return result",ret,"len(tmps)",len(tmps),"len(tmp)",len(tmp),"key",msgprex)
	if len(tmps) == (len(tmp) + 1) {
	    res := RpcDcrmRes{Ret: ret, Tip: "", Err: nil}
	    ch <- res
	    return ""
	}

	res := RpcDcrmRes{Ret: "", Tip: "dcrm back-end internal error: sign fail", Err: fmt.Errorf("sign fail")}
	ch <- res
	return "" 
}

func MapPrivKeyShare(cointype string, w *RPCReqWorker, idSign sortableIDSSlice, privshare string) (*big.Int, *big.Int) {
	if cointype == "" || w == nil || idSign == nil || len(idSign) == 0 || privshare == "" {
		return nil, nil
	}

	// 1. map the share of private key to no-threshold share of private key
	var self *big.Int
	lambda1 := big.NewInt(1)
	for _, uid := range idSign {
		enodes := GetEnodesByUid(uid, cointype, w.groupid)
		if IsCurNode(enodes, cur_enode) {
			self = uid
			break
		}
	}

	if self == nil {
		return nil, nil
	}

	for i, uid := range idSign {
		enodes := GetEnodesByUid(uid, cointype, w.groupid)
		if IsCurNode(enodes, cur_enode) {
			continue
		}

		sub := new(big.Int).Sub(idSign[i], self)
		subInverse := new(big.Int).ModInverse(sub, secp256k1.S256().N)
		times := new(big.Int).Mul(subInverse, idSign[i])
		lambda1 = new(big.Int).Mul(lambda1, times)
		lambda1 = new(big.Int).Mod(lambda1, secp256k1.S256().N)
	}

	skU1 := new(big.Int).SetBytes([]byte(privshare))
	w1 := new(big.Int).Mul(lambda1, skU1)
	w1 = new(big.Int).Mod(w1, secp256k1.S256().N)

	return skU1, w1
}

func DECDSASignRoundOne(msgprex string, w *RPCReqWorker, idSign sortableIDSSlice, ch chan interface{}) (*big.Int, *big.Int, *ec2.Commitment) {
	if msgprex == "" || w == nil || len(idSign) == 0 {
		res := RpcDcrmRes{Ret: "", Err: GetRetErr(ErrGetC11Timeout)}
		ch <- res
		return nil, nil, nil
	}

	u1K, u1Gamma, commitU1GammaG := signing.DECDSA_Sign_RoundOne()
	// 4. Broadcast
	//	commitU1GammaG.C, commitU2GammaG.C, commitU3GammaG.C
	mp := []string{msgprex, cur_enode}
	enode := strings.Join(mp, "-")
	s0 := "C11"
	s1 := string(commitU1GammaG.C.Bytes())
	ss := enode + common.Sep + s0 + common.Sep + s1
	SendMsgToDcrmGroup(ss, w.groupid)
	DisMsg(ss)

	////fix bug: get C11 timeout
	_, enodestmp := GetGroup(w.groupid)
	nodestmp := strings.Split(enodestmp, common.Sep2)
	for _, node := range nodestmp {
	    node2 := ParseNode(node)
	    c1data := msgprex + "-" + node2 + common.Sep + "C11"
	    c1, exist := C1Data.ReadMap(strings.ToLower(c1data))
	    if exist {
		DisMsg(c1.(string))
		go C1Data.DeleteMap(strings.ToLower(c1data))
	    }
	}
	////

	// 1. Receive Broadcast
	//	commitU1GammaG.C, commitU2GammaG.C, commitU3GammaG.C
	common.Debug("===================send C11 finish, ", "prex = ", msgprex, "", "====================")
	_, tip, cherr := GetChannelValue(ch_t, w.bc11)
	common.Debug("===================finish get C11, ", "err = ", cherr, "prex = ", msgprex, "", "====================")
	/////////////////////////request data from dcrm group
	suss := false
	if cherr != nil {
	    suss = ReqDataFromGroup(msgprex,w.id,"C11",reqdata_trytimes,reqdata_timeout)
	} else {
	    suss = true
	}
	///////////////////////////////////

	if !suss {
		res := RpcDcrmRes{Ret: "", Tip: tip, Err: GetRetErr(ErrGetC11Timeout)}
		ch <- res
		return nil, nil, nil
	}

	return u1K, u1Gamma, commitU1GammaG
}

func DECDSASignPaillierEncrypt(cointype string, save string, w *RPCReqWorker, idSign sortableIDSSlice, u1K *big.Int, ch chan interface{}) (map[string]*big.Int, map[string]*big.Int, map[string]*ec2.PublicKey) {
	if cointype == "" || w == nil || len(idSign) == 0 || u1K == nil {
		res := RpcDcrmRes{Ret: "", Err: fmt.Errorf("param error")}
		ch <- res
		return nil, nil, nil
	}

	// 2. MtA(k, gamma) and MtA(k, w)
	// 2.1 encrypt c_k = E_paillier(k)
	var ukc = make(map[string]*big.Int)
	var ukc2 = make(map[string]*big.Int)
	var ukc3 = make(map[string]*ec2.PublicKey)

	for _, id := range idSign {
		enodes := GetEnodesByUid(id, cointype, w.groupid)
		en := strings.Split(string(enodes[8:]), "@")
		if IsCurNode(enodes, cur_enode) {
			u1PaillierPk := signing.GetPaillierPk(save, GetRealByUid(cointype,w,id))
			//u1PaillierPk := GetPaillierPk2(cointype,w,id)
			if u1PaillierPk == nil {
				res := RpcDcrmRes{Ret: "", Err: fmt.Errorf("get save paillier pk fail")}
				ch <- res
				return nil, nil, nil
			}

			u1KCipher, u1R, _ := signing.DECDSA_Sign_Paillier_Encrypt(u1PaillierPk, u1K)
			ukc[en[0]] = u1KCipher
			ukc2[en[0]] = u1R
			ukc3[en[0]] = u1PaillierPk
			break
		}
	}

	return ukc, ukc2, ukc3
}

func DECDSASignRoundTwo(msgprex string, cointype string, save string, w *RPCReqWorker, idSign sortableIDSSlice, ch chan interface{}, u1K *big.Int, ukc2 map[string]*big.Int, ukc3 map[string]*ec2.PublicKey) (map[string]*ec2.MtAZK1Proof_nhh, map[string]*ec2.NtildeH1H2) {
	if msgprex == "" || cointype == "" || save == "" || w == nil || len(idSign) == 0 || u1K == nil || len(ukc2) == 0 || len(ukc3) == 0 {
		res := RpcDcrmRes{Ret: "", Err: fmt.Errorf("param error")}
		ch <- res
		return nil, nil
	}

	// 2.2 calculate zk(k)
	var zk1proof = make(map[string]*ec2.MtAZK1Proof_nhh)
	var zkfactproof = make(map[string]*ec2.NtildeH1H2)
	for _, id := range idSign {
		enodes := GetEnodesByUid(id, cointype, w.groupid)
		en := strings.Split(string(enodes[8:]), "@")

		u1zkFactProof := signing.GetZkFactProof(save, GetRealByUid(cointype,w,id), w.NodeCnt)
		if u1zkFactProof == nil {
			common.Debug("=================Sign_ec2,u1zkFactProof is nil=================","key",msgprex)
			res := RpcDcrmRes{Ret: "", Err: fmt.Errorf("get ntildeh1h2 fail")}
			ch <- res
			return nil, nil
		}

		if len(en) == 0 || en[0] == "" {
			common.Debug("=================Sign_ec2,get enode error================","key",msgprex,"enodes",enodes,"uid",id,"cointype",cointype,"groupid",w.groupid)
			res := RpcDcrmRes{Ret: "", Err: fmt.Errorf("get ntildeh1h2 fail")}
			ch <- res
			return nil, nil
		}

		zkfactproof[en[0]] = u1zkFactProof
		if IsCurNode(enodes, cur_enode) {
			u1u1MtAZK1Proof := signing.DECDSA_Sign_MtAZK1Prove(u1K, ukc2[en[0]], ukc3[en[0]], u1zkFactProof)
			zk1proof[en[0]] = u1u1MtAZK1Proof
		} else {
			u1u1MtAZK1Proof := signing.DECDSA_Sign_MtAZK1Prove(u1K, ukc2[cur_enode], ukc3[cur_enode], u1zkFactProof)
			mp := []string{msgprex, cur_enode}
			enode := strings.Join(mp, "-")
			s0 := "MTAZK1PROOF"
			s1 := string(u1u1MtAZK1Proof.Z.Bytes())
			s2 := string(u1u1MtAZK1Proof.U.Bytes())
			s3 := string(u1u1MtAZK1Proof.W.Bytes())
			s4 := string(u1u1MtAZK1Proof.S.Bytes())
			s5 := string(u1u1MtAZK1Proof.S1.Bytes())
			s6 := string(u1u1MtAZK1Proof.S2.Bytes())
			ss := enode + common.Sep + s0 + common.Sep + s1 + common.Sep + s2 + common.Sep + s3 + common.Sep + s4 + common.Sep + s5 + common.Sep + s6
			SendMsgToPeer(enodes, ss)
		}
	}

	_, tip, cherr := GetChannelValue(ch_t, w.bmtazk1proof)
	/////////////////////////request data from dcrm group
	suss := false
	if cherr != nil {
	    suss = ReqDataFromGroup(msgprex,w.id,"MTAZK1PROOF",reqdata_trytimes,reqdata_timeout)
	} else {
	    suss = true
	}
	///////////////////////////////////

	if !suss {
		res := RpcDcrmRes{Ret: "", Tip: tip, Err: GetRetErr(ErrGetMTAZK1PROOFTimeout)}
		ch <- res
		return nil, nil
	}

	return zk1proof, zkfactproof
}

func DECDSASignRoundThree(msgprex string, cointype string, save string, w *RPCReqWorker, idSign sortableIDSSlice, ch chan interface{}, ukc map[string]*big.Int) bool {
	if msgprex == "" || cointype == "" || save == "" || w == nil || len(idSign) == 0 || len(ukc) == 0 {
		res := RpcDcrmRes{Ret: "", Err: fmt.Errorf("param error")}
		ch <- res
		return false
	}

	// 2.3 Broadcast c_k, zk(k)
	// u1KCipher, u2KCipher, u3KCipher
	mp := []string{msgprex, cur_enode}
	enode := strings.Join(mp, "-")
	s0 := "KC"
	s1 := string(ukc[cur_enode].Bytes())
	ss := enode + common.Sep + s0 + common.Sep + s1
	SendMsgToDcrmGroup(ss, w.groupid)
	DisMsg(ss)

	// 2.4 Receive Broadcast c_k, zk(k)
	// u1KCipher, u2KCipher, u3KCipher
	common.Debug("===================send KC finish, ", "prex = ", msgprex, "", "====================")
	_, tip, cherr := GetChannelValue(ch_t, w.bkc)
	common.Debug("===================finish get KC, ", "err = ", cherr, "prex = ", msgprex, "", "====================")
	/////////////////////////request data from dcrm group
	suss := false
	if cherr != nil {
	    suss = ReqDataFromGroup(msgprex,w.id,"KC",reqdata_trytimes,reqdata_timeout)
	} else {
	    suss = true
	}
	///////////////////////////////////

	if !suss {
		res := RpcDcrmRes{Ret: "", Tip: tip, Err: GetRetErr(ErrGetKCTimeout)}
		ch <- res
		return false
	}

	kcs := make([]string, w.ThresHold)
	if w.msg_kc.Len() != w.ThresHold {
		res := RpcDcrmRes{Ret: "", Err: GetRetErr(ErrGetAllKCFail)}
		ch <- res
		return false
	}

	itmp := 0
	iter := w.msg_kc.Front()
	for iter != nil {
		mdss := iter.Value.(string)
		kcs[itmp] = mdss
		iter = iter.Next()
		itmp++
	}

	for _, id := range idSign {
		enodes := GetEnodesByUid(id, cointype, w.groupid)
		en := strings.Split(string(enodes[8:]), "@")
		if IsCurNode(enodes, cur_enode) {
			continue
		}

		for _, v := range kcs {
			mm := strings.Split(v, common.Sep)
			if len(mm) < 3 {
				res := RpcDcrmRes{Ret: "", Err: fmt.Errorf("get msg_kc fail")}
				ch <- res
				return false
			}

			prex := mm[0]
			prexs := strings.Split(prex, "-")
			if prexs[len(prexs)-1] == en[0] {
				kc := new(big.Int).SetBytes([]byte(mm[2]))
				ukc[en[0]] = kc
				break
			}
		}
	}

	return true
}

func DECDSASignVerifyZKNtilde(msgprex string, cointype string, save string, w *RPCReqWorker, idSign sortableIDSSlice, ch chan interface{}, ukc map[string]*big.Int, ukc3 map[string]*ec2.PublicKey, zk1proof map[string]*ec2.MtAZK1Proof_nhh, zkfactproof map[string]*ec2.NtildeH1H2) bool {
	if msgprex == "" || cointype == "" || save == "" || w == nil || len(idSign) == 0 || len(ukc) == 0 || len(ukc3) == 0 || len(zk1proof) == 0 || len(zkfactproof) == 0 {
		res := RpcDcrmRes{Ret: "", Err: fmt.Errorf("param error")}
		ch <- res
		return false
	}

	// example for u1, receive: u1u1MtAZK1Proof from u1, u2u1MtAZK1Proof from u2, u3u1MtAZK1Proof from u3
	mtazk1s := make([]string, w.ThresHold-1)
	if w.msg_mtazk1proof.Len() != (w.ThresHold - 1) {
		res := RpcDcrmRes{Ret: "", Err: GetRetErr(ErrGetAllMTAZK1PROOFFail)}
		ch <- res
		return false
	}

	itmp := 0
	iter := w.msg_mtazk1proof.Front()
	for iter != nil {
		mdss := iter.Value.(string)
		mtazk1s[itmp] = mdss
		iter = iter.Next()
		itmp++
	}

	for _, id := range idSign {
		enodes := GetEnodesByUid(id, cointype, w.groupid)
		en := strings.Split(string(enodes[8:]), "@")
		if IsCurNode(enodes, cur_enode) {
			continue
		}

		for _, v := range mtazk1s {
			mm := strings.Split(v, common.Sep)
			if len(mm) < 8 {
				res := RpcDcrmRes{Ret: "", Err: fmt.Errorf("get msg_mtazk1proof fail")}
				ch <- res
				return false
			}

			prex := mm[0]
			prexs := strings.Split(prex, "-")
			if prexs[len(prexs)-1] == en[0] {
				z := new(big.Int).SetBytes([]byte(mm[2]))
				u := new(big.Int).SetBytes([]byte(mm[3]))
				w := new(big.Int).SetBytes([]byte(mm[4]))
				s := new(big.Int).SetBytes([]byte(mm[5]))
				s1 := new(big.Int).SetBytes([]byte(mm[6]))
				s2 := new(big.Int).SetBytes([]byte(mm[7]))
				mtAZK1Proof := &ec2.MtAZK1Proof_nhh{Z: z, U: u, W: w, S: s, S1: s1, S2: s2}
				zk1proof[en[0]] = mtAZK1Proof
				break
			}
		}
	}

	// 2.5 verify zk(k)
	for _, id := range idSign {
		enodes := GetEnodesByUid(id, cointype, w.groupid)
		en := strings.Split(string(enodes[8:]), "@")
		if IsCurNode(enodes, cur_enode) {
			if cur_enode == "" || zk1proof[cur_enode] == nil || zkfactproof[cur_enode] == nil || ukc[cur_enode] == nil || ukc3[cur_enode] == nil {
				res := RpcDcrmRes{Ret: "", Err: fmt.Errorf("mtazk1 verification fail")}
				ch <- res
				return false
			}

			//delete zkfactor,add ntilde h1 h2
			u1rlt1 := signing.DECDSA_Sign_MtAZK1Verify(zk1proof[cur_enode], ukc[cur_enode], ukc3[cur_enode], zkfactproof[cur_enode])
			if !u1rlt1 {
				common.Debug("============sign,111111111,verify mtazk1proof fail===================","key",msgprex)
				res := RpcDcrmRes{Ret: "", Err: GetRetErr(ErrVerifyMTAZK1PROOFFail)}
				ch <- res
				return false
			}
		} else {
			if len(en) <= 0 {
				res := RpcDcrmRes{Ret: "", Err: GetRetErr(ErrVerifyMTAZK1PROOFFail)}
				ch <- res
				return false
			}

			_, exsit := zk1proof[en[0]]
			if !exsit {
				res := RpcDcrmRes{Ret: "", Err: GetRetErr(ErrVerifyMTAZK1PROOFFail)}
				ch <- res
				return false
			}

			_, exsit = ukc[en[0]]
			if !exsit {
				res := RpcDcrmRes{Ret: "", Err: GetRetErr(ErrVerifyMTAZK1PROOFFail)}
				ch <- res
				return false
			}

			u1PaillierPk := signing.GetPaillierPk(save, GetRealByUid(cointype,w,id))
			//u1PaillierPk := GetPaillierPk2(cointype,w,id)
			if u1PaillierPk == nil {
				common.Debug("============sign,22222222222,verify mtazk1proof fail===================","key",msgprex)
				res := RpcDcrmRes{Ret: "", Err: GetRetErr(ErrVerifyMTAZK1PROOFFail)}
				ch <- res
				return false
			}

			_, exsit = zkfactproof[cur_enode]
			if !exsit {
				res := RpcDcrmRes{Ret: "", Err: GetRetErr(ErrVerifyMTAZK1PROOFFail)}
				ch <- res
				return false
			}

			if len(en) == 0 || en[0] == "" || zk1proof[en[0]] == nil || zkfactproof[cur_enode] == nil || ukc[en[0]] == nil {
				res := RpcDcrmRes{Ret: "", Err: fmt.Errorf("mtazk1 verification fail")}
				ch <- res
				return false
			}

			u1rlt1 := signing.DECDSA_Sign_MtAZK1Verify(zk1proof[en[0]], ukc[en[0]], u1PaillierPk, zkfactproof[cur_enode])
			if !u1rlt1 {
				common.Debug("============sign,333333333,verify mtazk1proof fail===================","key",msgprex)
				res := RpcDcrmRes{Ret: "", Err: GetRetErr(ErrVerifyMTAZK1PROOFFail)}
				ch <- res
				return false
			}
		}
	}

	return true
}

func DECDSASignRoundFour(msgprex string, cointype string, save string, w *RPCReqWorker, idSign sortableIDSSlice, ukc map[string]*big.Int, ukc3 map[string]*ec2.PublicKey, zkfactproof map[string]*ec2.NtildeH1H2, u1Gamma *big.Int, w1 *big.Int, betaU1Star []*big.Int, vU1Star []*big.Int, ch chan interface{}) (map[string]*big.Int, map[string]*ec2.MtAZK2Proof_nhh, map[string]*big.Int, map[string]*ec2.MtAZK3Proof_nhh, bool) {
	if msgprex == "" || cointype == "" || save == "" || w == nil || len(idSign) == 0 || len(ukc) == 0 || len(ukc3) == 0 || len(zkfactproof) == 0 || len(betaU1Star) == 0 || len(vU1Star) == 0 || u1Gamma == nil || w1 == nil {
		res := RpcDcrmRes{Ret: "", Err: fmt.Errorf("param error")}
		ch <- res
		return nil, nil, nil, nil, false
	}

	// 2.7
	// send c_kGamma to proper node, MtA(k, gamma)   zk
	var mkg = make(map[string]*big.Int)
	var mkg_mtazk2 = make(map[string]*ec2.MtAZK2Proof_nhh)
	for k, id := range idSign {
		enodes := GetEnodesByUid(id, cointype, w.groupid)
		en := strings.Split(string(enodes[8:]), "@")
		if IsCurNode(enodes, cur_enode) {
			//u1PaillierPk := GetPaillierPk2(cointype,w,id)
			u1PaillierPk := signing.GetPaillierPk(save, GetRealByUid(cointype,w,id))
			if u1PaillierPk == nil {
				res := RpcDcrmRes{Ret: "", Err: fmt.Errorf("get paillier pk fail")}
				ch <- res
				return nil, nil, nil, nil, false
			}

			u1KGamma1Cipher := signing.DECDSA_Sign_Paillier_HomoMul(u1PaillierPk, ukc[en[0]], u1Gamma)
			if betaU1Star[k] == nil {
				res := RpcDcrmRes{Ret: "", Err: fmt.Errorf("get betaU1Star fail")}
				ch <- res
				return nil, nil, nil, nil, false
			}

			beta1U1StarCipher, u1BetaR1, _ := signing.DECDSA_Sign_Paillier_Encrypt(u1PaillierPk, betaU1Star[k])
			u1KGamma1Cipher = signing.DECDSA_Sign_Paillier_HomoAdd(u1PaillierPk, u1KGamma1Cipher, beta1U1StarCipher) // send to u1

			u1u1MtAZK2Proof := ec2.MtAZK2Prove_nhh(u1Gamma, betaU1Star[k], u1BetaR1, ukc[cur_enode], ukc3[cur_enode], zkfactproof[cur_enode])
			mkg[en[0]] = u1KGamma1Cipher
			mkg_mtazk2[en[0]] = u1u1MtAZK2Proof
			continue
		}

		u2PaillierPk := signing.GetPaillierPk(save, GetRealByUid(cointype,w,id))
		//u2PaillierPk := GetPaillierPk2(cointype,w,id)
		if u2PaillierPk == nil {
			res := RpcDcrmRes{Ret: "", Err: fmt.Errorf("get paillier pk fail")}
			ch <- res
			return nil, nil, nil, nil, false
		}

		u2KGamma1Cipher := signing.DECDSA_Sign_Paillier_HomoMul(u2PaillierPk, ukc[en[0]], u1Gamma)
		if betaU1Star[k] == nil {
			res := RpcDcrmRes{Ret: "", Err: fmt.Errorf("get betaU1Star fail")}
			ch <- res
			return nil, nil, nil, nil, false
		}

		beta2U1StarCipher, u2BetaR1, _ := signing.DECDSA_Sign_Paillier_Encrypt(u2PaillierPk, betaU1Star[k])
		u2KGamma1Cipher = signing.DECDSA_Sign_Paillier_HomoAdd(u2PaillierPk, u2KGamma1Cipher, beta2U1StarCipher) // send to u2
		u2u1MtAZK2Proof := signing.DECDSA_Sign_MtAZK2Prove(u1Gamma, betaU1Star[k], u2BetaR1, ukc[en[0]], u2PaillierPk, zkfactproof[cur_enode])
		mp := []string{msgprex, cur_enode}
		enode := strings.Join(mp, "-")
		s0 := "MKG"
		s1 := string(u2KGamma1Cipher.Bytes())
		//////
		s2 := string(u2u1MtAZK2Proof.Z.Bytes())
		s3 := string(u2u1MtAZK2Proof.ZBar.Bytes())
		s4 := string(u2u1MtAZK2Proof.T.Bytes())
		s5 := string(u2u1MtAZK2Proof.V.Bytes())
		s6 := string(u2u1MtAZK2Proof.W.Bytes())
		s7 := string(u2u1MtAZK2Proof.S.Bytes())
		s8 := string(u2u1MtAZK2Proof.S1.Bytes())
		s9 := string(u2u1MtAZK2Proof.S2.Bytes())
		s10 := string(u2u1MtAZK2Proof.T1.Bytes())
		s11 := string(u2u1MtAZK2Proof.T2.Bytes())
		///////
		ss := enode + common.Sep + s0 + common.Sep + s1 + common.Sep + s2 + common.Sep + s3 + common.Sep + s4 + common.Sep + s5 + common.Sep + s6 + common.Sep + s7 + common.Sep + s8 + common.Sep + s9 + common.Sep + s10 + common.Sep + s11
		SendMsgToPeer(enodes, ss)
	}

	// 2.8
	// send c_kw to proper node, MtA(k, w)   zk
	var mkw = make(map[string]*big.Int)
	var mkw_mtazk2 = make(map[string]*ec2.MtAZK3Proof_nhh)
	for k, id := range idSign {
		enodes := GetEnodesByUid(id, cointype, w.groupid)
		en := strings.Split(string(enodes[8:]), "@")
		if IsCurNode(enodes, cur_enode) {
			//u1PaillierPk := GetPaillierPk2(cointype,w,id)
			u1PaillierPk := signing.GetPaillierPk(save, GetRealByUid(cointype,w,id))
			if u1PaillierPk == nil {
				res := RpcDcrmRes{Ret: "", Err: fmt.Errorf("get paillier pk fail")}
				ch <- res
				return nil, nil, nil, nil, false
			}

			u1Kw1Cipher := signing.DECDSA_Sign_Paillier_HomoMul(u1PaillierPk, ukc[en[0]], w1)
			if vU1Star[k] == nil {
				res := RpcDcrmRes{Ret: "", Err: fmt.Errorf("get vU1Star fail")}
				ch <- res
				return nil, nil, nil, nil, false
			}

			v1U1StarCipher, u1VR1, _ := signing.DECDSA_Sign_Paillier_Encrypt(u1PaillierPk, vU1Star[k])
			u1Kw1Cipher = signing.DECDSA_Sign_Paillier_HomoAdd(u1PaillierPk, u1Kw1Cipher, v1U1StarCipher)                                       // send to u1
			u1u1MtAZK2Proof2 := signing.DECDSA_Sign_MtAZK3Prove(w1, vU1Star[k], u1VR1, ukc[cur_enode], ukc3[cur_enode], zkfactproof[cur_enode]) //Fusion_dcrm question 8
			mkw[en[0]] = u1Kw1Cipher
			mkw_mtazk2[en[0]] = u1u1MtAZK2Proof2
			continue
		}

		u2PaillierPk := signing.GetPaillierPk(save, GetRealByUid(cointype,w,id))
		//u2PaillierPk := GetPaillierPk2(cointype,w,id)
		if u2PaillierPk == nil {
			res := RpcDcrmRes{Ret: "", Err: fmt.Errorf("get paillier pk fail")}
			ch <- res
			return nil, nil, nil, nil, false
		}

		u2Kw1Cipher := signing.DECDSA_Sign_Paillier_HomoMul(u2PaillierPk, ukc[en[0]], w1)
		if vU1Star[k] == nil {
			res := RpcDcrmRes{Ret: "", Err: fmt.Errorf("get vU1Star fail")}
			ch <- res
			return nil, nil, nil, nil, false
		}

		v2U1StarCipher, u2VR1, _ := signing.DECDSA_Sign_Paillier_Encrypt(u2PaillierPk, vU1Star[k])
		u2Kw1Cipher = signing.DECDSA_Sign_Paillier_HomoAdd(u2PaillierPk, u2Kw1Cipher, v2U1StarCipher) // send to u2
		u2u1MtAZK2Proof2 := signing.DECDSA_Sign_MtAZK3Prove(w1, vU1Star[k], u2VR1, ukc[en[0]], u2PaillierPk, zkfactproof[cur_enode])

		mp := []string{msgprex, cur_enode}
		enode := strings.Join(mp, "-")
		s0 := "MKW"
		s1 := string(u2Kw1Cipher.Bytes())
		//////
		//bug
		s2 := string(u2u1MtAZK2Proof2.Ux.Bytes())
		s3 := string(u2u1MtAZK2Proof2.Uy.Bytes())
		//bug
		s4 := string(u2u1MtAZK2Proof2.Z.Bytes())
		s5 := string(u2u1MtAZK2Proof2.ZBar.Bytes())
		s6 := string(u2u1MtAZK2Proof2.T.Bytes())
		s7 := string(u2u1MtAZK2Proof2.V.Bytes())
		s8 := string(u2u1MtAZK2Proof2.W.Bytes())
		s9 := string(u2u1MtAZK2Proof2.S.Bytes())
		s10 := string(u2u1MtAZK2Proof2.S1.Bytes())
		s11 := string(u2u1MtAZK2Proof2.S2.Bytes())
		s12 := string(u2u1MtAZK2Proof2.T1.Bytes())
		s13 := string(u2u1MtAZK2Proof2.T2.Bytes())
		///////

		ss := enode + common.Sep + s0 + common.Sep + s1 + common.Sep + s2 + common.Sep + s3 + common.Sep + s4 + common.Sep + s5 + common.Sep + s6 + common.Sep + s7 + common.Sep + s8 + common.Sep + s9 + common.Sep + s10 + common.Sep + s11 + common.Sep + s12 + common.Sep + s13
		SendMsgToPeer(enodes, ss)
	}

	return mkg, mkg_mtazk2, mkw, mkw_mtazk2, true
}

func DECDSASignVerifyZKGammaW(msgprex string,cointype string, save string, w *RPCReqWorker, idSign sortableIDSSlice, ukc map[string]*big.Int, ukc3 map[string]*ec2.PublicKey, zkfactproof map[string]*ec2.NtildeH1H2, mkg map[string]*big.Int, mkg_mtazk2 map[string]*ec2.MtAZK2Proof_nhh, mkw map[string]*big.Int, mkw_mtazk2 map[string]*ec2.MtAZK3Proof_nhh, ch chan interface{}) bool {
	if msgprex == "" || cointype == "" || save == "" || w == nil || len(idSign) == 0 || len(ukc) == 0 || len(ukc3) == 0 || len(zkfactproof) == 0 || len(mkg) == 0 || len(mkw) == 0 || len(mkg_mtazk2) == 0 || len(mkw_mtazk2) == 0 {
		res := RpcDcrmRes{Ret: "", Err: fmt.Errorf("param error")}
		ch <- res
		return false
	}

	// 2.9
	// receive c_kGamma from proper node, MtA(k, gamma)   zk
	_, tip, cherr := GetChannelValue(ch_t, w.bmkg)
	/////////////////////////request data from dcrm group
	suss := false
	if cherr != nil {
	    suss = ReqDataFromGroup(msgprex,w.id,"MKG",reqdata_trytimes,reqdata_timeout)
	} else {
	    suss = true
	}
	///////////////////////////////////

	if !suss {
		res := RpcDcrmRes{Ret: "", Tip: tip, Err: GetRetErr(ErrGetMKGTimeout)}
		ch <- res
		return false
	}

	mkgs := make([]string, w.ThresHold-1)
	if w.msg_mkg.Len() != (w.ThresHold-1) {
		res := RpcDcrmRes{Ret: "", Err: GetRetErr(ErrGetAllMKGFail)}
		ch <- res
		return false
	}

	itmp := 0
	iter := w.msg_mkg.Front()
	for iter != nil {
		mdss := iter.Value.(string)
		mkgs[itmp] = mdss
		iter = iter.Next()
		itmp++
	}

	for _, id := range idSign {
		enodes := GetEnodesByUid(id, cointype, w.groupid)
		////////bug
		if len(enodes) < 9 {
			res := RpcDcrmRes{Ret: "", Err: fmt.Errorf("get enodes error")}
			ch <- res
			return false
		}
		////////
		en := strings.Split(string(enodes[8:]), "@")
		if IsCurNode(enodes, cur_enode) {
			continue
		}
		for _, v := range mkgs {
			mm := strings.Split(v, common.Sep)
			if len(mm) < 13 {
				res := RpcDcrmRes{Ret: "", Err: fmt.Errorf("get msg_mkg fail")}
				ch <- res
				return false
			}

			prex := mm[0]
			prexs := strings.Split(prex, "-")
			if prexs[len(prexs)-1] == en[0] {
				kg := new(big.Int).SetBytes([]byte(mm[2]))
				mkg[en[0]] = kg

				z := new(big.Int).SetBytes([]byte(mm[3]))
				zbar := new(big.Int).SetBytes([]byte(mm[4]))
				t := new(big.Int).SetBytes([]byte(mm[5]))
				v := new(big.Int).SetBytes([]byte(mm[6]))
				w := new(big.Int).SetBytes([]byte(mm[7]))
				s := new(big.Int).SetBytes([]byte(mm[8]))
				s1 := new(big.Int).SetBytes([]byte(mm[9]))
				s2 := new(big.Int).SetBytes([]byte(mm[10]))
				t1 := new(big.Int).SetBytes([]byte(mm[11]))
				t2 := new(big.Int).SetBytes([]byte(mm[12]))
				mtAZK2Proof := &ec2.MtAZK2Proof_nhh{Z: z, ZBar: zbar, T: t, V: v, W: w, S: s, S1: s1, S2: s2, T1: t1, T2: t2}
				mkg_mtazk2[en[0]] = mtAZK2Proof
				break
			}
		}
	}

	// 2.10
	// receive c_kw from proper node, MtA(k, w)    zk
	_, tip, cherr = GetChannelValue(ch_t, w.bmkw)
	/////////////////////////request data from dcrm group
	if cherr != nil {
	    suss = ReqDataFromGroup(msgprex,w.id,"MKW",reqdata_trytimes,reqdata_timeout)
	} else {
	    suss = true
	}
	///////////////////////////////////

	if !suss {
		res := RpcDcrmRes{Ret: "", Tip: tip, Err: GetRetErr(ErrGetMKWTimeout)}
		ch <- res
		return false
	}

	mkws := make([]string, w.ThresHold-1)
	if w.msg_mkw.Len() != (w.ThresHold-1) {
		res := RpcDcrmRes{Ret: "", Err: GetRetErr(ErrGetAllMKWFail)}
		ch <- res
		return false
	}

	itmp = 0
	iter = w.msg_mkw.Front()
	for iter != nil {
		mdss := iter.Value.(string)
		mkws[itmp] = mdss
		iter = iter.Next()
		itmp++
	}

	for _, id := range idSign {
		enodes := GetEnodesByUid(id, cointype, w.groupid)
		////////bug
		if len(enodes) < 9 {
			res := RpcDcrmRes{Ret: "", Err: fmt.Errorf("get enodes error")}
			ch <- res
			return false
		}
		////////
		en := strings.Split(string(enodes[8:]), "@")
		if IsCurNode(enodes, cur_enode) {
			continue
		}
		for _, v := range mkws {
			mm := strings.Split(v, common.Sep)
			if len(mm) < 15 {
				res := RpcDcrmRes{Ret: "", Err: fmt.Errorf("get msg_mkw fail")}
				ch <- res
				return false
			}

			prex := mm[0]
			prexs := strings.Split(prex, "-")
			if prexs[len(prexs)-1] == en[0] {
				kw := new(big.Int).SetBytes([]byte(mm[2]))
				mkw[en[0]] = kw

				ux := new(big.Int).SetBytes([]byte(mm[3]))
				uy := new(big.Int).SetBytes([]byte(mm[4]))
				z := new(big.Int).SetBytes([]byte(mm[5]))
				zbar := new(big.Int).SetBytes([]byte(mm[6]))
				t := new(big.Int).SetBytes([]byte(mm[7]))
				v := new(big.Int).SetBytes([]byte(mm[8]))
				w := new(big.Int).SetBytes([]byte(mm[9]))
				s := new(big.Int).SetBytes([]byte(mm[10]))
				s1 := new(big.Int).SetBytes([]byte(mm[11]))
				s2 := new(big.Int).SetBytes([]byte(mm[12]))
				t1 := new(big.Int).SetBytes([]byte(mm[13]))
				t2 := new(big.Int).SetBytes([]byte(mm[14]))
				mtAZK2Proof := &ec2.MtAZK3Proof_nhh{Ux: ux, Uy: uy, Z: z, ZBar: zbar, T: t, V: v, W: w, S: s, S1: s1, S2: s2, T1: t1, T2: t2}
				mkw_mtazk2[en[0]] = mtAZK2Proof
				break
			}
		}
	}

	// 2.11 verify zk
	for _, id := range idSign {
		enodes := GetEnodesByUid(id, cointype, w.groupid)
		////////bug
		if len(enodes) < 9 {
			res := RpcDcrmRes{Ret: "", Err: fmt.Errorf("get enodes error")}
			ch <- res
			return false
		}

		////////
		en := strings.Split(string(enodes[8:]), "@")
		//bug
		if len(en) == 0 || en[0] == "" || mkg_mtazk2[en[0]] == nil || cur_enode == "" || ukc[cur_enode] == nil || mkg[en[0]] == nil || ukc3[cur_enode] == nil || zkfactproof[en[0]] == nil {
			res := RpcDcrmRes{Ret: "", Err: fmt.Errorf("mkw mtazk2 verify fail.")}
			ch <- res
			return false
		}

		//
		rlt111 := signing.DECDSA_Sign_MtAZK2Verify(mkg_mtazk2[en[0]], ukc[cur_enode], mkg[en[0]], ukc3[cur_enode], zkfactproof[en[0]])
		if !rlt111 {
			res := RpcDcrmRes{Ret: "", Err: GetRetErr(ErrVerifyMKGFail)}
			ch <- res
			return false
		}

		if len(en) == 0 || en[0] == "" || mkw_mtazk2[en[0]] == nil || cur_enode == "" || ukc[cur_enode] == nil || mkw[en[0]] == nil || ukc3[cur_enode] == nil || zkfactproof[en[0]] == nil {
			res := RpcDcrmRes{Ret: "", Err: fmt.Errorf("mkw mtazk2 verify fail.")}
			ch <- res
			return false
		}

		rlt112 := signing.DECDSA_Sign_MtAZK3Verify(mkw_mtazk2[en[0]], ukc[cur_enode], mkw[en[0]], ukc3[cur_enode], zkfactproof[en[0]])
		if !rlt112 {
			res := RpcDcrmRes{Ret: "", Err: fmt.Errorf("mkw mtazk2 verify fail.")}
			ch <- res
			return false
		}
	}

	return true
}

func GetSelfPrivKey(cointype string, idSign sortableIDSSlice, w *RPCReqWorker, save string, ch chan interface{}) *ec2.PrivateKey {
	if cointype == "" || len(idSign) == 0 || w == nil || save == "" {
		res := RpcDcrmRes{Ret: "", Err: fmt.Errorf("param error")}
		ch <- res
		return nil
	}

	// 2.12
	// decrypt c_kGamma to get alpha, MtA(k, gamma)
	// MtA(k, gamma)
	var uid *big.Int
	for _, id := range idSign {
		enodes := GetEnodesByUid(id, cointype, w.groupid)
		////////bug
		if len(enodes) < 9 {
			res := RpcDcrmRes{Ret: "", Err: fmt.Errorf("get enodes error")}
			ch <- res
			return nil
		}
		////////
		if IsCurNode(enodes, cur_enode) {
			uid = id
			break
		}
	}

	u1PaillierSk := signing.GetPaillierSk(save,GetRealByUid(cointype,w,uid)) //get self privkey
	if u1PaillierSk == nil {
		res := RpcDcrmRes{Ret: "", Err: fmt.Errorf("get sk fail.")}
		ch <- res
		return nil
	}

	return u1PaillierSk
}

func DecryptCkGamma(cointype string, idSign sortableIDSSlice, w *RPCReqWorker, u1PaillierSk *ec2.PrivateKey, mkg map[string]*big.Int, ch chan interface{}) []*big.Int {
	if cointype == "" || len(idSign) == 0 || w == nil || u1PaillierSk == nil || len(mkg) == 0 {
		res := RpcDcrmRes{Ret: "", Err: fmt.Errorf("param error")}
		ch <- res
		return nil
	}

	alpha1 := make([]*big.Int, w.ThresHold)
	for k, id := range idSign {
		enodes := GetEnodesByUid(id, cointype, w.groupid)
		////////bug
		if len(enodes) < 9 {
			res := RpcDcrmRes{Ret: "", Err: fmt.Errorf("get enodes error")}
			ch <- res
			return nil
		}

		////////
		en := strings.Split(string(enodes[8:]), "@")
		alpha1U1, _ := signing.DECDSA_Sign_Paillier_Decrypt(u1PaillierSk, mkg[en[0]])
		alpha1[k] = alpha1U1
	}

	return alpha1
}

func DecryptCkW(cointype string, idSign sortableIDSSlice, w *RPCReqWorker, u1PaillierSk *ec2.PrivateKey, mkw map[string]*big.Int, ch chan interface{}) []*big.Int {
	if cointype == "" || len(idSign) == 0 || w == nil || u1PaillierSk == nil || len(mkw) == 0 {
		res := RpcDcrmRes{Ret: "", Err: fmt.Errorf("param error")}
		ch <- res
		return nil
	}

	// 2.13
	// decrypt c_kw to get u, MtA(k, w)
	// MtA(k, w)
	uu1 := make([]*big.Int, w.ThresHold)
	for k, id := range idSign {
		enodes := GetEnodesByUid(id, cointype, w.groupid)
		////////bug
		if len(enodes) < 9 {
			res := RpcDcrmRes{Ret: "", Err: fmt.Errorf("get enodes error")}
			ch <- res
			return nil
		}

		////////
		en := strings.Split(string(enodes[8:]), "@")
		u1U1, _ := signing.DECDSA_Sign_Paillier_Decrypt(u1PaillierSk, mkw[en[0]])
		uu1[k] = u1U1
	}

	return uu1
}

func CalcDelta(alpha1 []*big.Int, betaU1 []*big.Int, ch chan interface{}, ThresHold int) *big.Int {
	if len(alpha1) == 0 || len(betaU1) == 0 {
		res := RpcDcrmRes{Ret: "", Err: fmt.Errorf("param error")}
		ch <- res
		return nil
	}

	// 2.14
	// calculate delta, MtA(k, gamma)
	delta1 := alpha1[0]
	for i := 0; i < ThresHold; i++ {
		if i == 0 {
			continue
		}
		delta1 = new(big.Int).Add(delta1, alpha1[i])
	}
	for i := 0; i < ThresHold; i++ {
		delta1 = new(big.Int).Add(delta1, betaU1[i])
	}

	return delta1
}

func CalcSigma(uu1 []*big.Int, vU1 []*big.Int, ch chan interface{}, ThresHold int) *big.Int {
	if len(uu1) == 0 || len(vU1) == 0 {
		res := RpcDcrmRes{Ret: "", Err: fmt.Errorf("param error")}
		ch <- res
		return nil
	}

	// 2.15
	// calculate sigma, MtA(k, w)
	sigma1 := uu1[0]
	for i := 0; i < ThresHold; i++ {
		if i == 0 {
			continue
		}
		sigma1 = new(big.Int).Add(sigma1, uu1[i])
	}
	for i := 0; i < ThresHold; i++ {
		sigma1 = new(big.Int).Add(sigma1, vU1[i])
	}

	return sigma1
}

func DECDSASignRoundFive(msgprex string, cointype string, delta1 *big.Int, idSign sortableIDSSlice, w *RPCReqWorker, ch chan interface{}) *big.Int {
	if cointype == "" || len(idSign) == 0 || w == nil || msgprex == "" || delta1 == nil {
		res := RpcDcrmRes{Ret: "", Err: fmt.Errorf("param error")}
		ch <- res
		return nil
	}

	// 3. Broadcast
	// delta: delta1, delta2, delta3
	var s1 string
	mp := []string{msgprex, cur_enode}
	enode := strings.Join(mp, "-")
	s0 := "DELTA1"
	zero, _ := new(big.Int).SetString("0", 10)
	if delta1.Cmp(zero) < 0 { //bug
		s1 = "0" + common.SepDel + string(delta1.Bytes())
	} else {
		s1 = string(delta1.Bytes())
	}
	ss := enode + common.Sep + s0 + common.Sep + s1
	SendMsgToDcrmGroup(ss, w.groupid)
	DisMsg(ss)

	// 1. Receive Broadcast
	// delta: delta1, delta2, delta3
	common.Debug("===================send DELTA1 finish, ", "prex = ", msgprex, "", "====================")
	_, tip, cherr := GetChannelValue(ch_t, w.bdelta1)
	common.Debug("===================finish get DELTA1, ", "err = ", cherr, "prex = ", msgprex, "", "====================")
	/////////////////////////request data from dcrm group
	suss := false
	if cherr != nil {
	    suss = ReqDataFromGroup(msgprex,w.id,"DELTA1",reqdata_trytimes,reqdata_timeout)
	} else {
	    suss = true
	}
	///////////////////////////////////

	if !suss {
		res := RpcDcrmRes{Ret: "", Tip: tip, Err: fmt.Errorf("get all delta timeout.")}
		ch <- res
		return nil
	}

	var delta1s = make(map[string]*big.Int)
	delta1s[cur_enode] = delta1

	dels := make([]string, w.ThresHold)
	if w.msg_delta1.Len() != w.ThresHold {
		res := RpcDcrmRes{Ret: "", Err: fmt.Errorf("get all delta fail.")}
		ch <- res
		return nil
	}

	itmp := 0
	iter := w.msg_delta1.Front()
	for iter != nil {
		mdss := iter.Value.(string)
		dels[itmp] = mdss
		iter = iter.Next()
		itmp++
	}

	for _, id := range idSign {
		enodes := GetEnodesByUid(id, cointype, w.groupid)
		////////bug
		if len(enodes) < 9 {
			res := RpcDcrmRes{Ret: "", Err: fmt.Errorf("get enodes error")}
			ch <- res
			return nil
		}

		////////
		en := strings.Split(string(enodes[8:]), "@")
		if IsCurNode(enodes, cur_enode) {
			continue
		}

		for _, v := range dels {
			mm := strings.Split(v, common.Sep)
			if len(mm) < 3 {
				res := RpcDcrmRes{Ret: "", Err: fmt.Errorf("get msg_delta1 fail.")}
				ch <- res
				return nil
			}

			prex := mm[0]
			prexs := strings.Split(prex, "-")
			if prexs[len(prexs)-1] == en[0] {
				tmps := strings.Split(mm[2], common.SepDel)
				if len(tmps) == 2 {
					del := new(big.Int).SetBytes([]byte(tmps[1]))
					del = new(big.Int).Sub(zero, del) //bug:-xxxxxxx
					delta1s[en[0]] = del
				} else {
					del := new(big.Int).SetBytes([]byte(mm[2]))
					delta1s[en[0]] = del
				}

				break
			}
		}
	}

	// 2. calculate deltaSum
	var deltaSum *big.Int
	enodes := GetEnodesByUid(idSign[0], cointype, w.groupid)
	////////bug
	if len(enodes) < 9 {
		res := RpcDcrmRes{Ret: "", Err: fmt.Errorf("get enodes error")}
		ch <- res
		return nil
	}
	////////

	en := strings.Split(string(enodes[8:]), "@")
	deltaSum = delta1s[en[0]]

	for k, id := range idSign {
		if k == 0 {
			continue
		}

		enodes := GetEnodesByUid(id, cointype, w.groupid)
		////////bug
		if len(enodes) < 9 {
			res := RpcDcrmRes{Ret: "", Err: fmt.Errorf("get enodes error")}
			ch <- res
			return nil
		}
		////////

		en := strings.Split(string(enodes[8:]), "@")
		//bug
		if deltaSum == nil || len(en) < 1 || en[0] == "" || delta1s[en[0]] == nil {
			var ret2 Err
			ret2.Info = "calc deltaSum error"
			res := RpcDcrmRes{Ret: "", Err: ret2}
			ch <- res
			return nil
		}
		deltaSum = new(big.Int).Add(deltaSum, delta1s[en[0]])
	}
	deltaSum = new(big.Int).Mod(deltaSum, secp256k1.S256().N)

	return deltaSum
}

func DECDSASignRoundSix(msgprex string, u1Gamma *big.Int, commitU1GammaG *ec2.Commitment, w *RPCReqWorker, ch chan interface{}) *ec2.ZkUProof {
	if msgprex == "" || u1Gamma == nil || commitU1GammaG == nil || w == nil {
		res := RpcDcrmRes{Ret: "", Err: fmt.Errorf("param error")}
		ch <- res
		return nil
	}

	u1GammaZKProof := keygen.DECDSA_Key_ZkUProve(u1Gamma)

	// 3. Broadcast
	// commitU1GammaG.D, commitU2GammaG.D, commitU3GammaG.D
	mp := []string{msgprex, cur_enode}
	enode := strings.Join(mp, "-")
	s0 := "D11"
	dlen := len(commitU1GammaG.D)
	s1 := strconv.Itoa(dlen)

	ss := enode + common.Sep + s0 + common.Sep + s1 + common.Sep
	for _, d := range commitU1GammaG.D {
		ss += string(d.Bytes())
		ss += common.Sep
	}
	ss += string(u1GammaZKProof.E.Bytes()) + common.Sep + string(u1GammaZKProof.S.Bytes()) + common.Sep
	ss = ss + "NULL"
	SendMsgToDcrmGroup(ss, w.groupid)
	DisMsg(ss)

	// 1. Receive Broadcast
	// commitU1GammaG.D, commitU2GammaG.D, commitU3GammaG.D
	common.Debug("===================send D11 finish, ", "prex = ", msgprex, "", "====================")
	_, tip, cherr := GetChannelValue(ch_t, w.bd11_1)
	common.Debug("===================finish get D11, ", "err = ", cherr, "prex = ", msgprex, "", "====================")
	/////////////////////////request data from dcrm group
	suss := false
	if cherr != nil {
	    suss = ReqDataFromGroup(msgprex,w.id,"D11",reqdata_trytimes,reqdata_timeout)
	} else {
	    suss = true
	}
	///////////////////////////////////

	if !suss {
		res := RpcDcrmRes{Ret: "", Tip: tip, Err: fmt.Errorf("get all d11 fail.")}
		ch <- res
		return nil
	}

	return u1GammaZKProof
}

func DECDSASignVerifyCommitment(cointype string, w *RPCReqWorker, idSign sortableIDSSlice, commitU1GammaG *ec2.Commitment, u1GammaZKProof *ec2.ZkUProof, ch chan interface{}) map[string][]*big.Int {
	if cointype == "" || w == nil || len(idSign) == 0 || commitU1GammaG == nil || u1GammaZKProof == nil {
		res := RpcDcrmRes{Ret: "", Err: fmt.Errorf("param error")}
		ch <- res
		return nil
	}

	d11s := make([]string, w.ThresHold)
	if w.msg_d11_1.Len() != w.ThresHold {
		res := RpcDcrmRes{Ret: "", Err: fmt.Errorf("get all d11 fail.")}
		ch <- res
		return nil
	}

	itmp := 0
	iter := w.msg_d11_1.Front()
	for iter != nil {
		mdss := iter.Value.(string)
		d11s[itmp] = mdss
		iter = iter.Next()
		itmp++
	}

	c11s := make([]string, w.ThresHold)
	if w.msg_c11.Len() != w.ThresHold {
		res := RpcDcrmRes{Ret: "", Err: fmt.Errorf("get all c11 fail.")}
		ch <- res
		return nil
	}

	itmp = 0
	iter = w.msg_c11.Front()
	for iter != nil {
		mdss := iter.Value.(string)
		c11s[itmp] = mdss
		iter = iter.Next()
		itmp++
	}

	// 2. verify and de-commitment to get GammaG

	// for all nodes, construct the commitment by the receiving C and D
	var udecom = make(map[string]*ec2.Commitment)
	for _, v := range c11s {
		mm := strings.Split(v, common.Sep)
		if len(mm) < 3 {
			res := RpcDcrmRes{Ret: "", Err: fmt.Errorf("get msg_c11 fail.")}
			ch <- res
			return nil
		}

		prex := mm[0]
		prexs := strings.Split(prex, "-")
		for _, vv := range d11s {
			mmm := strings.Split(vv, common.Sep)
			if len(mmm) < 3 {
				res := RpcDcrmRes{Ret: "", Err: fmt.Errorf("get msg_d11 fail.")}
				ch <- res
				return nil
			}

			prex2 := mmm[0]
			prexs2 := strings.Split(prex2, "-")
			if prexs[len(prexs)-1] == prexs2[len(prexs2)-1] {
				dlen, _ := strconv.Atoi(mmm[2])
				var gg = make([]*big.Int, 0)
				l := 0
				for j := 0; j < dlen; j++ {
					l++
					if len(mmm) < (3 + l) {
						res := RpcDcrmRes{Ret: "", Err: fmt.Errorf("get msg_d11 fail.")}
						ch <- res
						return nil
					}

					gg = append(gg, new(big.Int).SetBytes([]byte(mmm[2+l])))
				}

				deCommit := &ec2.Commitment{C: new(big.Int).SetBytes([]byte(mm[2])), D: gg}
				udecom[prexs[len(prexs)-1]] = deCommit
				break
			}
		}
	}

	deCommit_commitU1GammaG := &ec2.Commitment{C: commitU1GammaG.C, D: commitU1GammaG.D}
	udecom[cur_enode] = deCommit_commitU1GammaG

	var zkuproof = make(map[string]*ec2.ZkUProof)
	zkuproof[cur_enode] = u1GammaZKProof
	for _, vv := range d11s {
		mmm := strings.Split(vv, common.Sep)
		prex2 := mmm[0]
		prexs2 := strings.Split(prex2, "-")
		if len(mmm) < 3 { /////bug:crash in signing
			res := RpcDcrmRes{Ret: "", Err: fmt.Errorf("get zkuproof fail.")}
			ch <- res
			return nil
		}

		dlen, err := strconv.Atoi(mmm[2])
		if err != nil || len(mmm) < (5+dlen) {
			res := RpcDcrmRes{Ret: "", Err: fmt.Errorf("get zkuproof fail.")}
			ch <- res
			return nil
		}

		e := new(big.Int).SetBytes([]byte(mmm[3+dlen]))
		s := new(big.Int).SetBytes([]byte(mmm[4+dlen]))
		zkuf := &ec2.ZkUProof{E: e, S: s}
		zkuproof[prexs2[len(prexs2)-1]] = zkuf
	}

	// for all nodes, verify the commitment
	for _, id := range idSign {
		enodes := GetEnodesByUid(id, cointype, w.groupid)
		////////bug
		if len(enodes) < 9 {
			res := RpcDcrmRes{Ret: "", Err: fmt.Errorf("get enodes error")}
			ch <- res
			return nil
		}
		////////
		en := strings.Split(string(enodes[8:]), "@")
		//bug
		if len(en) <= 0 || en[0] == "" {
			res := RpcDcrmRes{Ret: "", Err: fmt.Errorf("verify commit fail.")}
			ch <- res
			return nil
		}

		_, exsit := udecom[en[0]]
		if !exsit {
			res := RpcDcrmRes{Ret: "", Err: fmt.Errorf("verify commit fail.")}
			ch <- res
			return nil
		}
		//

		if udecom[en[0]] == nil {
			res := RpcDcrmRes{Ret: "", Err: fmt.Errorf("verify commit fail.")}
			ch <- res
			return nil
		}

		if !keygen.DECDSA_Key_Commitment_Verify(udecom[en[0]]) {
			res := RpcDcrmRes{Ret: "", Err: fmt.Errorf("verify commit fail.")}
			ch <- res
			return nil
		}
	}

	// for all nodes, de-commitment
	var ug = make(map[string][]*big.Int)
	for _, id := range idSign {
		enodes := GetEnodesByUid(id, cointype, w.groupid)
		////////bug
		if len(enodes) < 9 {
			res := RpcDcrmRes{Ret: "", Err: fmt.Errorf("get enodes error")}
			ch <- res
			return nil
		}
		////////

		en := strings.Split(string(enodes[8:]), "@")
		_, u1GammaG := signing.DECDSA_Key_DeCommit(udecom[en[0]])
		ug[en[0]] = u1GammaG
		if !keygen.DECDSA_Key_ZkUVerify(u1GammaG, zkuproof[en[0]]) {
			res := RpcDcrmRes{Ret: "", Err: fmt.Errorf("verify zkuproof fail.")}
			ch <- res
			return nil
		}
	}

	return ug
}

func Calc_r(cointype string, w *RPCReqWorker, idSign sortableIDSSlice, ug map[string][]*big.Int, deltaSum *big.Int, ch chan interface{}) (*big.Int, *big.Int) {
	if cointype == "" || w == nil || len(idSign) == 0 || len(ug) == 0 {
		res := RpcDcrmRes{Ret: "", Err: fmt.Errorf("param error")}
		ch <- res
		return nil, nil
	}

	// for all nodes, calculate the GammaGSum
	var GammaGSumx *big.Int
	var GammaGSumy *big.Int
	enodes := GetEnodesByUid(idSign[0], cointype, w.groupid)
	////////bug
	if len(enodes) < 9 {
		res := RpcDcrmRes{Ret: "", Err: fmt.Errorf("get enodes error")}
		ch <- res
		return nil, nil
	}
	////////

	en := strings.Split(string(enodes[8:]), "@")
	GammaGSumx = (ug[en[0]])[0]
	GammaGSumy = (ug[en[0]])[1]

	for k, id := range idSign {
		if k == 0 {
			continue
		}

		enodes := GetEnodesByUid(id, cointype, w.groupid)
		////////bug
		if len(enodes) < 9 {
			res := RpcDcrmRes{Ret: "", Err: fmt.Errorf("get enodes error")}
			ch <- res
			return nil, nil
		}
		////////

		en := strings.Split(string(enodes[8:]), "@")
		GammaGSumx, GammaGSumy = secp256k1.S256().Add(GammaGSumx, GammaGSumy, (ug[en[0]])[0], (ug[en[0]])[1])
	}

	r, deltaGammaGy := signing.DECDSA_Sign_Calc_r(deltaSum, GammaGSumx, GammaGSumy)

	zero, _ := new(big.Int).SetString("0", 10)
	if r.Cmp(zero) == 0 {
		res := RpcDcrmRes{Ret: "", Err: fmt.Errorf("r == 0.")}
		ch <- res
		return nil, nil
	}

	return r, deltaGammaGy
}

func DECDSASignRoundSeven(msgprex string, r *big.Int, deltaGammaGy *big.Int, us1 *big.Int, w *RPCReqWorker, ch chan interface{}) (*ec2.Commitment, []string, *big.Int, *big.Int) {
	if msgprex == "" || r == nil || deltaGammaGy == nil || us1 == nil || w == nil {
		res := RpcDcrmRes{Ret: "", Err: fmt.Errorf("param error")}
		ch <- res
		return nil, nil, nil, nil
	}

	commitBigVAB1, rho1, l1 := signing.DECDSA_Sign_Round_Seven(r, deltaGammaGy, us1)

	mp := []string{msgprex, cur_enode}
	enode := strings.Join(mp, "-")
	s0 := "CommitBigVAB"
	s1 := string(commitBigVAB1.C.Bytes())
	ss := enode + common.Sep + s0 + common.Sep + s1
	SendMsgToDcrmGroup(ss, w.groupid)
	DisMsg(ss)

	common.Debug("===================send CommitBigVAB finish, ", "prex = ", msgprex, "", "====================")
	_, tip, cherr := GetChannelValue(ch_t, w.bcommitbigvab)
	common.Debug("===================finish get CommitBigVAB, ", "err = ", cherr, "prex = ", msgprex, "", "====================")
	/////////////////////////request data from dcrm group
	suss := false
	if cherr != nil {
	    suss = ReqDataFromGroup(msgprex,w.id,"CommitBigVAB",reqdata_trytimes,reqdata_timeout)
	} else {
	    suss = true
	}
	///////////////////////////////////

	if !suss {
		res := RpcDcrmRes{Ret: "", Tip: tip, Err: fmt.Errorf("get all CommitBigVAB timeout.")}
		ch <- res
		return nil, nil, nil, nil
	}

	commitbigvabs := make([]string, w.ThresHold)
	if w.msg_commitbigvab.Len() != w.ThresHold {
		res := RpcDcrmRes{Ret: "", Err: fmt.Errorf("get all CommitBigVAB fail.")}
		ch <- res
		return nil, nil, nil, nil
	}

	itmp := 0
	iter := w.msg_commitbigvab.Front()
	for iter != nil {
		mdss := iter.Value.(string)
		commitbigvabs[itmp] = mdss
		iter = iter.Next()
		itmp++
	}

	return commitBigVAB1, commitbigvabs, rho1, l1
}

func DECDSASignRoundEight(msgprex string, r *big.Int, deltaGammaGy *big.Int, us1 *big.Int, l1 *big.Int, rho1 *big.Int, w *RPCReqWorker, ch chan interface{}, commitBigVAB1 *ec2.Commitment) (*ec2.ZkABProof, []string) {
	if msgprex == "" || r == nil || deltaGammaGy == nil || us1 == nil || w == nil || l1 == nil || rho1 == nil {
		res := RpcDcrmRes{Ret: "", Err: fmt.Errorf("param error")}
		ch <- res
		return nil, nil
	}

	// *** Round 5B
	u1zkABProof := signing.DECDSA_Sign_ZkABProve(rho1, l1, us1, []*big.Int{r, deltaGammaGy})

	mp := []string{msgprex, cur_enode}
	enode := strings.Join(mp, "-")
	s0 := "ZKABPROOF"
	dlen := len(commitBigVAB1.D)
	s1 := strconv.Itoa(dlen)

	ss := enode + common.Sep + s0 + common.Sep + s1 + common.Sep
	for _, d := range commitBigVAB1.D {
		ss += string(d.Bytes())
		ss += common.Sep
	}

	dlen = len(u1zkABProof.Alpha)
	s22 := strconv.Itoa(dlen)
	ss += (s22 + common.Sep)
	for _, alp := range u1zkABProof.Alpha {
		ss += string(alp.Bytes())
		ss += common.Sep
	}

	dlen = len(u1zkABProof.Beta)
	s3 := strconv.Itoa(dlen)
	ss += (s3 + common.Sep)
	for _, bet := range u1zkABProof.Beta {
		ss += string(bet.Bytes())
		ss += common.Sep
	}

	//ss = prex-enode:ZKABPROOF:dlen:d1:d2:...:dl:alplen:a1:a2:....aalp:betlen:b1:b2:...bbet:t:u:NULL
	ss += (string(u1zkABProof.T.Bytes()) + common.Sep + string(u1zkABProof.U.Bytes()) + common.Sep)
	ss = ss + "NULL"
	SendMsgToDcrmGroup(ss, w.groupid)
	DisMsg(ss)

	common.Debug("===================send ZKABPROOF finish, ", "prex = ", msgprex, "", "====================")
	_, tip, cherr := GetChannelValue(ch_t, w.bzkabproof)
	common.Debug("===================finish get ZKABPROOF, ", "err = ", cherr, "prex = ", msgprex, "", "====================")
	/////////////////////////request data from dcrm group
	suss := false
	if cherr != nil {
	    suss = ReqDataFromGroup(msgprex,w.id,"ZKABPROOF",reqdata_trytimes,reqdata_timeout)
	} else {
	    suss = true
	}
	///////////////////////////////////

	if !suss {
		res := RpcDcrmRes{Ret: "", Tip: tip, Err: fmt.Errorf("get all ZKABPROOF timeout.")}
		ch <- res
		return nil, nil
	}

	zkabproofs := make([]string, w.ThresHold)
	if w.msg_zkabproof.Len() != w.ThresHold {
		res := RpcDcrmRes{Ret: "", Err: fmt.Errorf("get all ZKABPROOF fail.")}
		ch <- res
		return nil, nil
	}

	itmp := 0
	iter := w.msg_zkabproof.Front()
	for iter != nil {
		mdss := iter.Value.(string)
		zkabproofs[itmp] = mdss
		iter = iter.Next()
		itmp++
	}

	return u1zkABProof, zkabproofs
}

func DECDSASignVerifyBigVAB(cointype string, w *RPCReqWorker, commitbigvabs []string, zkabproofs []string, commitBigVAB1 *ec2.Commitment, u1zkABProof *ec2.ZkABProof, idSign sortableIDSSlice, r *big.Int, deltaGammaGy *big.Int, ch chan interface{}) (map[string]*ec2.Commitment, *big.Int, *big.Int) {
	if len(commitbigvabs) == 0 || len(zkabproofs) == 0 || commitBigVAB1 == nil || u1zkABProof == nil || cointype == "" || w == nil || len(idSign) == 0 || r == nil || deltaGammaGy == nil {
		res := RpcDcrmRes{Ret: "", Err: fmt.Errorf("param error.")}
		ch <- res
		return nil, nil, nil
	}

	var commitbigcom = make(map[string]*ec2.Commitment)
	for _, v := range commitbigvabs {
		mm := strings.Split(v, common.Sep)
		if len(mm) < 3 {
			res := RpcDcrmRes{Ret: "", Err: fmt.Errorf("get msg_commitbigvab fail.")}
			ch <- res
			return nil, nil, nil
		}

		prex := mm[0]
		prexs := strings.Split(prex, "-")
		for _, vv := range zkabproofs {
			mmm := strings.Split(vv, common.Sep)
			if len(mmm) < 3 {
				res := RpcDcrmRes{Ret: "", Err: fmt.Errorf("get msg_zkabproof fail.")}
				ch <- res
				return nil, nil, nil
			}

			prex2 := mmm[0]
			prexs2 := strings.Split(prex2, "-")
			if prexs[len(prexs)-1] == prexs2[len(prexs2)-1] {
				dlen, _ := strconv.Atoi(mmm[2])
				var gg = make([]*big.Int, 0)
				l := 0
				for j := 0; j < dlen; j++ {
					l++
					if len(mmm) < (3 + l) {
						res := RpcDcrmRes{Ret: "", Err: fmt.Errorf("get msg_zkabproof fail.")}
						ch <- res
						return nil, nil, nil
					}

					gg = append(gg, new(big.Int).SetBytes([]byte(mmm[2+l])))
				}

				deCommit := &ec2.Commitment{C: new(big.Int).SetBytes([]byte(mm[2])), D: gg}
				commitbigcom[prexs[len(prexs)-1]] = deCommit
				break
			}
		}
	}

	commitbigcom[cur_enode] = commitBigVAB1

	var zkabproofmap = make(map[string]*ec2.ZkABProof)
	zkabproofmap[cur_enode] = u1zkABProof

	for _, vv := range zkabproofs {
		mmm := strings.Split(vv, common.Sep)
		prex2 := mmm[0]
		prexs2 := strings.Split(prex2, "-")

		//alpha
		dlen, _ := strconv.Atoi(mmm[2])
		alplen, _ := strconv.Atoi(mmm[3+dlen])
		var alp = make([]*big.Int, 0)
		l := 0
		for j := 0; j < alplen; j++ {
			l++
			if len(mmm) < (4 + dlen + l) {
				res := RpcDcrmRes{Ret: "", Err: fmt.Errorf("get msg_zkabproof fail.")}
				ch <- res
				return nil, nil, nil
			}

			alp = append(alp, new(big.Int).SetBytes([]byte(mmm[3+dlen+l])))
		}

		//beta
		betlen, _ := strconv.Atoi(mmm[3+dlen+1+alplen])
		var bet = make([]*big.Int, 0)
		l = 0
		for j := 0; j < betlen; j++ {
			l++
			if len(mmm) < (5 + dlen + alplen + l) {
				res := RpcDcrmRes{Ret: "", Err: fmt.Errorf("get msg_zkabproof fail.")}
				ch <- res
				return nil, nil, nil
			}

			bet = append(bet, new(big.Int).SetBytes([]byte(mmm[3+dlen+1+alplen+l])))
		}

		t := new(big.Int).SetBytes([]byte(mmm[3+dlen+1+alplen+1+betlen]))
		u := new(big.Int).SetBytes([]byte(mmm[3+dlen+1+alplen+1+betlen+1]))

		zkABProof := &ec2.ZkABProof{Alpha: alp, Beta: bet, T: t, U: u}
		zkabproofmap[prexs2[len(prexs2)-1]] = zkABProof
	}

	var BigVx, BigVy *big.Int
	for k, id := range idSign {
		enodes := GetEnodesByUid(id, cointype, w.groupid)
		////////bug
		if len(enodes) < 9 {
			res := RpcDcrmRes{Ret: "", Err: fmt.Errorf("get enodes error")}
			ch <- res
			return nil, nil, nil
		}
		////////

		en := strings.Split(string(enodes[8:]), "@")
		if !keygen.DECDSA_Key_Commitment_Verify(commitbigcom[en[0]]) {
			res := RpcDcrmRes{Ret: "", Err: fmt.Errorf("verify commitbigvab fail.")}
			ch <- res
			return nil, nil, nil
		}

		_, BigVAB1 := signing.DECDSA_Key_DeCommit(commitbigcom[en[0]])
		if !signing.DECDSA_Sign_ZkABVerify([]*big.Int{BigVAB1[2], BigVAB1[3]}, []*big.Int{BigVAB1[4], BigVAB1[5]}, []*big.Int{BigVAB1[0], BigVAB1[1]}, []*big.Int{r, deltaGammaGy}, zkabproofmap[en[0]]) {
			res := RpcDcrmRes{Ret: "", Err: fmt.Errorf("verify zkabproof fail.")}
			ch <- res
			return nil, nil, nil
		}

		if k == 0 {
			BigVx = BigVAB1[0]
			BigVy = BigVAB1[1]
			continue
		}

		BigVx, BigVy = secp256k1.S256().Add(BigVx, BigVy, BigVAB1[0], BigVAB1[1])
	}

	return commitbigcom, BigVx, BigVy
}

func DECDSASignRoundNine(msgprex string, cointype string, w *RPCReqWorker, idSign sortableIDSSlice, mMtA *big.Int, r *big.Int, pkx *big.Int, pky *big.Int, BigVx *big.Int, BigVy *big.Int, rho1 *big.Int, commitbigcom map[string]*ec2.Commitment, l1 *big.Int, ch chan interface{}) ([]string, *ec2.Commitment) {
	//if len(idSign) == 0 || len(commitbigcom) == 0 || msgprex == "" || w == nil || cointype == "" || mMtA == nil || r == nil || pkx == nil || pky == nil || l1 == nil || rho1 == nil {
	//	res := RpcDcrmRes{Ret: "", Err: fmt.Errorf("param error.")}
	//	ch <- res
	//	return nil, nil
	//}

	bigU1x, bigU1y := signing.DECDSA_Sign_Round_Nine(mMtA, r, pkx, pky, BigVx, BigVy, rho1)

	// bigA23 = bigA2 + bigA3
	var bigT1x, bigT1y *big.Int
	var ind int
	for k, id := range idSign {
		enodes := GetEnodesByUid(id, cointype, w.groupid)
		////////bug
		if len(enodes) < 9 {
			res := RpcDcrmRes{Ret: "", Err: fmt.Errorf("get enodes error")}
			ch <- res
			return nil, nil
		}
		////////

		en := strings.Split(string(enodes[8:]), "@")
		if IsCurNode(enodes, cur_enode) {
			continue
		}

		_, BigVAB1 := signing.DECDSA_Key_DeCommit(commitbigcom[en[0]])
		bigT1x = BigVAB1[2]
		bigT1y = BigVAB1[3]
		ind = k
		break
	}

	for k, id := range idSign {
		enodes := GetEnodesByUid(id, cointype, w.groupid)
		////////bug
		if len(enodes) < 9 {
			res := RpcDcrmRes{Ret: "", Err: fmt.Errorf("get enodes error")}
			ch <- res
			return nil, nil
		}
		////////
		en := strings.Split(string(enodes[8:]), "@")
		if IsCurNode(enodes, cur_enode) {
			continue
		}

		if k == ind {
			continue
		}

		_, BigVAB1 := signing.DECDSA_Key_DeCommit(commitbigcom[en[0]])
		bigT1x, bigT1y = secp256k1.S256().Add(bigT1x, bigT1y, BigVAB1[2], BigVAB1[3])
	}

	commitBigUT1 := signing.DECDSA_Sign_Round_Nine_Commitment(bigT1x, bigT1y, l1, bigU1x, bigU1y)

	// Broadcast commitBigUT1.C
	mp := []string{msgprex, cur_enode}
	enode := strings.Join(mp, "-")
	s0 := "CommitBigUT"
	s1 := string(commitBigUT1.C.Bytes())
	ss := enode + common.Sep + s0 + common.Sep + s1
	SendMsgToDcrmGroup(ss, w.groupid)
	DisMsg(ss)

	common.Debug("===================send CommitBigUT finish, ", "prex = ", msgprex, "", "====================")
	_, tip, cherr := GetChannelValue(ch_t, w.bcommitbigut)
	common.Debug("===================finish get CommitBigUT, ", "err = ", cherr, "prex = ", msgprex, "", "====================")
	/////////////////////////request data from dcrm group
	suss := false
	if cherr != nil {
	    suss = ReqDataFromGroup(msgprex,w.id,"CommitBigUT",reqdata_trytimes,reqdata_timeout)
	} else {
	    suss = true
	}
	///////////////////////////////////

	if !suss {
		res := RpcDcrmRes{Ret: "", Tip: tip, Err: fmt.Errorf("get all CommitBigUT timeout.")}
		ch <- res
		return nil, nil
	}

	commitbiguts := make([]string, w.ThresHold)
	if w.msg_commitbigut.Len() != w.ThresHold {
		res := RpcDcrmRes{Ret: "", Err: fmt.Errorf("get all CommitBigUT fail.")}
		ch <- res
		return nil, nil
	}

	itmp := 0
	iter := w.msg_commitbigut.Front()
	for iter != nil {
		mdss := iter.Value.(string)
		commitbiguts[itmp] = mdss
		iter = iter.Next()
		itmp++
	}

	return commitbiguts, commitBigUT1
}

func DECDSASignRoundTen(msgprex string, commitBigUT1 *ec2.Commitment, w *RPCReqWorker, ch chan interface{}) []string {
	if msgprex == "" || commitBigUT1 == nil || w == nil {
		res := RpcDcrmRes{Ret: "", Err: fmt.Errorf("param error.")}
		ch <- res
		return nil
	}

	// *** Round 5D
	// Broadcast
	// commitBigUT1.D,  commitBigUT2.D,  commitBigUT3.D
	mp := []string{msgprex, cur_enode}
	enode := strings.Join(mp, "-")
	s0 := "CommitBigUTD11"
	dlen := len(commitBigUT1.D)
	s1 := strconv.Itoa(dlen)

	ss := enode + common.Sep + s0 + common.Sep + s1 + common.Sep
	for _, d := range commitBigUT1.D {
		ss += string(d.Bytes())
		ss += common.Sep
	}
	ss = ss + "NULL"
	SendMsgToDcrmGroup(ss, w.groupid)
	DisMsg(ss)

	common.Debug("===================send CommitBigUTD11 finish, ", "prex = ", msgprex, "", "====================")
	_, tip, cherr := GetChannelValue(ch_t, w.bcommitbigutd11)
	common.Debug("===================finish get CommitBigUTD11, ", "err = ", cherr, "prex = ", msgprex, "", "====================")
	/////////////////////////request data from dcrm group
	suss := false
	if cherr != nil {
	    suss = ReqDataFromGroup(msgprex,w.id,"CommitBigUTD11",reqdata_trytimes,reqdata_timeout)
	} else {
	    suss = true
	}
	///////////////////////////////////

	if !suss {
		res := RpcDcrmRes{Ret: "", Tip: tip, Err: fmt.Errorf("get all CommitBigUTD11 fail.")}
		ch <- res
		return nil
	}

	commitbigutd11s := make([]string, w.ThresHold)
	if w.msg_commitbigutd11.Len() != w.ThresHold {
		res := RpcDcrmRes{Ret: "", Err: fmt.Errorf("get all CommitBigUTD11 fail.")}
		ch <- res
		return nil
	}

	itmp := 0
	iter := w.msg_commitbigutd11.Front()
	for iter != nil {
		mdss := iter.Value.(string)
		commitbigutd11s[itmp] = mdss
		iter = iter.Next()
		itmp++
	}

	return commitbigutd11s
}

func DECDSASignVerifyBigUTCommitment(msgprex string,cointype string, commitbiguts []string, commitbigutd11s []string, commitBigUT1 *ec2.Commitment, w *RPCReqWorker, idSign sortableIDSSlice, ch chan interface{}, commitbigcom map[string]*ec2.Commitment) bool {
	if msgprex == "" || cointype == "" || len(commitbiguts) == 0 || len(commitbigutd11s) == 0 || commitBigUT1 == nil || w == nil || len(idSign) == 0 || commitbigcom == nil {
		res := RpcDcrmRes{Ret: "", Err: fmt.Errorf("param error.")}
		ch <- res
		return false
	}

	var commitbigutmap = make(map[string]*ec2.Commitment)
	for _, v := range commitbiguts {
		mm := strings.Split(v, common.Sep)
		if len(mm) < 3 {
			res := RpcDcrmRes{Ret: "", Err: fmt.Errorf("get msg_commitbigut fail.")}
			ch <- res
			return false
		}

		prex := mm[0]
		prexs := strings.Split(prex, "-")
		for _, vv := range commitbigutd11s {
			mmm := strings.Split(vv, common.Sep)
			if len(mmm) < 3 {
				res := RpcDcrmRes{Ret: "", Err: fmt.Errorf("get msg_commitbigutd11 fail.")}
				ch <- res
				return false
			}

			prex2 := mmm[0]
			prexs2 := strings.Split(prex2, "-")
			if prexs[len(prexs)-1] == prexs2[len(prexs2)-1] {
				dlen, _ := strconv.Atoi(mmm[2])
				var gg = make([]*big.Int, 0)
				l := 0
				for j := 0; j < dlen; j++ {
					l++
					if len(mmm) < (3 + l) {
						res := RpcDcrmRes{Ret: "", Err: fmt.Errorf("get msg_commitbigutd11 fail.")}
						ch <- res
						return false
					}

					gg = append(gg, new(big.Int).SetBytes([]byte(mmm[2+l])))
				}

				deCommit := &ec2.Commitment{C: new(big.Int).SetBytes([]byte(mm[2])), D: gg}
				commitbigutmap[prexs[len(prexs)-1]] = deCommit
				break
			}
		}
	}

	commitbigutmap[cur_enode] = commitBigUT1

	var bigTBx, bigTBy *big.Int
	var bigUx, bigUy *big.Int
	for k, id := range idSign {
		enodes := GetEnodesByUid(id, cointype, w.groupid)
		////////bug
		if len(enodes) < 9 {
			res := RpcDcrmRes{Ret: "", Err: fmt.Errorf("get enodes error")}
			ch <- res
			return false
		}
		////////

		en := strings.Split(string(enodes[8:]), "@")
		if !keygen.DECDSA_Key_Commitment_Verify(commitbigutmap[en[0]]) {
			res := RpcDcrmRes{Ret: "", Err: fmt.Errorf("verify commit big ut fail.")}
			ch <- res
			return false
		}

		_, BigUT1 := signing.DECDSA_Key_DeCommit(commitbigutmap[en[0]])
		_, BigVAB1 := signing.DECDSA_Key_DeCommit(commitbigcom[en[0]])
		if k == 0 {
			bigTBx = BigUT1[2]
			bigTBy = BigUT1[3]
			bigUx = BigUT1[0]
			bigUy = BigUT1[1]
			bigTBx, bigTBy = secp256k1.S256().Add(bigTBx, bigTBy, BigVAB1[4], BigVAB1[5])
			continue
		}

		bigTBx, bigTBy = secp256k1.S256().Add(bigTBx, bigTBy, BigUT1[2], BigUT1[3])
		bigTBx, bigTBy = secp256k1.S256().Add(bigTBx, bigTBy, BigVAB1[4], BigVAB1[5])
		bigUx, bigUy = secp256k1.S256().Add(bigUx, bigUy, BigUT1[0], BigUT1[1])
	}

	if bigTBx.Cmp(bigUx) != 0 || bigTBy.Cmp(bigUy) != 0 {
		common.Debug("==============verify bigTB = BigU fails.=================","key",msgprex)
		res := RpcDcrmRes{Ret: "", Err: fmt.Errorf("verify bigTB = BigU fails.")}
		ch <- res
		return false
	}

	return true
}

func DECDSASignRoundEleven(msgprex string, cointype string, w *RPCReqWorker, idSign sortableIDSSlice, ch chan interface{}, us1 *big.Int) map[string]*big.Int {
	if cointype == "" || msgprex == "" || w == nil || len(idSign) == 0 || us1 == nil {
		res := RpcDcrmRes{Ret: "", Err: fmt.Errorf("param error.")}
		ch <- res
		return nil
	}

	// 4. Broadcast
	// s: s1, s2, s3
	mp := []string{msgprex, cur_enode}
	enode := strings.Join(mp, "-")
	s0 := "SS1"
	s1 := string(us1.Bytes())
	ss := enode + common.Sep + s0 + common.Sep + s1
	SendMsgToDcrmGroup(ss, w.groupid)
	DisMsg(ss)

	// 1. Receive Broadcast
	// s: s1, s2, s3
	common.Info("===================send SS1 finish, ", "prex = ", msgprex, "", "====================")
	_, tip, cherr := GetChannelValue(WaitMsgTimeGG20, w.bss1)
	common.Info("===================finish get SS1, ", "err = ", cherr, "prex = ", msgprex, "", "====================")
	/////////////////////////request data from dcrm group
	suss := false
	if cherr != nil {
	    suss = ReqDataFromGroup(msgprex,w.id,"SS1",reqdata_trytimes,reqdata_timeout)
	} else {
	    suss = true
	}
	///////////////////////////////////

	if !suss {
		res := RpcDcrmRes{Ret: "", Tip: tip, Err: fmt.Errorf("get ss1 timeout.")}
		ch <- res
		return nil
	}

	var ss1s = make(map[string]*big.Int)
	ss1s[cur_enode] = us1

	uss1s := make([]string, w.ThresHold)
	if w.msg_ss1.Len() != w.ThresHold {
		res := RpcDcrmRes{Ret: "", Err: fmt.Errorf("get ss1 fail.")}
		ch <- res
		return nil
	}

	itmp := 0
	iter := w.msg_ss1.Front()
	for iter != nil {
		mdss := iter.Value.(string)
		uss1s[itmp] = mdss
		iter = iter.Next()
		itmp++
	}

	for _, id := range idSign {
		enodes := GetEnodesByUid(id, cointype, w.groupid)
		////////bug
		if len(enodes) < 9 {
			res := RpcDcrmRes{Ret: "", Err: fmt.Errorf("get enodes error")}
			ch <- res
			return nil
		}
		////////
		en := strings.Split(string(enodes[8:]), "@")
		if IsCurNode(enodes, cur_enode) {
			continue
		}

		for _, v := range uss1s {
			mm := strings.Split(v, common.Sep)
			if len(mm) < 3 {
				res := RpcDcrmRes{Ret: "", Err: fmt.Errorf("get ss1 fail.")}
				ch <- res
				return nil
			}

			prex := mm[0]
			prexs := strings.Split(prex, "-")
			if prexs[len(prexs)-1] == en[0] {
				tmp := new(big.Int).SetBytes([]byte(mm[2]))
				ss1s[en[0]] = tmp
				break
			}
		}
	}

	return ss1s
}

func Calc_s(msgprex string,cointype string, w *RPCReqWorker, idSign sortableIDSSlice, ss1s map[string]*big.Int, ch chan interface{}) *big.Int {
	if msgprex == "" || cointype == "" || len(idSign) == 0 || w == nil || len(ss1s) == 0 {
		res := RpcDcrmRes{Ret: "", Err: fmt.Errorf("param error.")}
		ch <- res
		return nil
	}

	// 2. calculate s
	var s *big.Int
	enodes := GetEnodesByUid(idSign[0], cointype, w.groupid)
	////////bug
	if len(enodes) < 9 {
		res := RpcDcrmRes{Ret: "", Err: fmt.Errorf("get enodes error")}
		ch <- res
		return nil
	}
	////////

	en := strings.Split(string(enodes[8:]), "@")
	s = ss1s[en[0]]

	for k, id := range idSign {
		if k == 0 {
			continue
		}

		enodes := GetEnodesByUid(id, cointype, w.groupid)
		////////bug
		if len(enodes) < 9 {
			res := RpcDcrmRes{Ret: "", Err: fmt.Errorf("get enodes error")}
			ch <- res
			return nil
		}
		////////
		en := strings.Split(string(enodes[8:]), "@")

		//bug
		if s == nil || len(en) == 0 || en[0] == "" || len(ss1s) == 0 || ss1s[en[0]] == nil {
			common.Debug("=================================== !!!Sign_ec2,calc s error. !!!====================","key",msgprex)
			res := RpcDcrmRes{Ret: "", Err: fmt.Errorf("calculate s error.")}
			ch <- res
			return nil
		}
		//
		s = new(big.Int).Add(s, ss1s[en[0]])
	}

	s = new(big.Int).Mod(s, secp256k1.S256().N)

	return s
}

func GetPaillierPk2(cointype string,w *RPCReqWorker,uid *big.Int) *ec2.PublicKey {
	if cointype == "" || w == nil || uid == nil {
		return nil
	}

	key := Keccak256Hash([]byte(strings.ToLower(w.DcrmFrom))).Hex()
	exsit,da := GetValueFromPubKeyData(key)
	if !exsit {
	    return nil 
	}

	pubs,ok := da.(*PubKeyData)
	if !ok {
	    return nil
	}

	_, nodes := GetGroup(pubs.GroupId)
	others := strings.Split(nodes, common.Sep2)
	for _, v := range others {
		node2 := ParseNode(v) //bug??
		uid2 := DoubleHash(node2, cointype)
		if uid2.Cmp(uid) == 0 {
		    iter := w.msg_paillierkey.Front() //////by type
		    for iter != nil {
			if iter.Value == nil {
			    iter = iter.Next()
			    continue
			}

			mdss,ok := iter.Value.(string)
			if !ok {
			    iter = iter.Next()
			    continue
			}

			ms := strings.Split(mdss, common.Sep)
			prexs := strings.Split(ms[0], "-")
			if len(prexs) < 2 {
			    iter = iter.Next()
			    continue
			}

			node3 := prexs[1]
			if strings.EqualFold(node3,node2) {
			    l := ms[2]
			    n := new(big.Int).SetBytes([]byte(ms[3]))
			    g := new(big.Int).SetBytes([]byte(ms[4]))
			    n2 := new(big.Int).SetBytes([]byte(ms[5]))
			    publicKey := &ec2.PublicKey{Length: l, N: n, G: g, N2: n2}
			    return publicKey
			}

			iter = iter.Next()
		    }

		    break
		}
	}

	return nil
}

func GetRealByUid(cointype string,w *RPCReqWorker,uid *big.Int) int {
    if cointype == "ED25519" || cointype == "ECDSA" {
	return GetRealByUid2(cointype,w,uid)
    }

    if cointype == "" || w == nil || w.DcrmFrom == "" || uid == nil {
	return -1
    }

    key := Keccak256Hash([]byte(strings.ToLower(w.DcrmFrom))).Hex()
    exsit,da := GetValueFromPubKeyData(key)
    if !exsit {
	return -1
    }

    pubs,ok := da.(*PubKeyData)
    if !ok {
	return -1
    }

    ids := GetIds(cointype, pubs.GroupId)
    for k,v := range ids {
	if v.Cmp(uid) == 0 {
	    return k
	}
    }

    return -1
}

func GetRealByUid2(keytype string,w *RPCReqWorker,uid *big.Int) int {
    if keytype == "" || w == nil || w.DcrmFrom == "" || uid == nil {
	return -1
    }

    dcrmpks, _ := hex.DecodeString(w.DcrmFrom)
    exsit,da := GetValueFromPubKeyData(string(dcrmpks[:]))
    if !exsit {
	return -1
    }

    pubs,ok := da.(*PubKeyData)
    if !ok {
	return -1
    }

    ids := GetIds2(keytype, pubs.GroupId)
    for k,v := range ids {
	if v.Cmp(uid) == 0 {
	    return k
	}
    }

    return -1
}

//msgprex = hash
//return value is the backup for the dcrm sig
func PreSign_ec3(msgprex string, save string, sku1 *big.Int, cointype string, ch chan interface{},id int)  *PrePubData {
	if id < 0 || id >= len(workers) {
		res := RpcDcrmRes{Ret: "", Err: fmt.Errorf("no find worker.")}
		ch <- res
		return nil
	}
	w := workers[id]
	if w.groupid == "" {
		res := RpcDcrmRes{Ret: "", Err: fmt.Errorf("get group id fail.")}
		ch <- res
		return nil
	}

	mm := strings.Split(save, common.SepSave)
	if len(mm) == 0 {
		res := RpcDcrmRes{Ret: "", Err: fmt.Errorf("get save data fail")}
		ch <- res
		return nil
	}

	// [Notes]
	// 1. assume the nodes who take part in the signature generation as follows
	ids := GetIds(cointype, w.groupid)
	idSign := ids[:w.ThresHold]

	//common.Info("===================PreSign_ec3 start=================","index",index,"w.groupid",w.groupid,"key",msgprex)
	//*******************!!!Distributed ECDSA Sign Start!!!**********************************

	skU1, w1 := MapPrivKeyShare(cointype, w, idSign, string(sku1.Bytes()))
	if skU1 == nil || w1 == nil {
	    return nil
	}

	u1K, u1Gamma, commitU1GammaG := DECDSASignRoundOne(msgprex, w, idSign, ch)
	if u1K == nil || u1Gamma == nil || commitU1GammaG == nil {
		return nil 
	}
	common.Debug("===================,PreSign_ec3,round one finish=================","key",msgprex)

	ukc, ukc2, ukc3 := DECDSASignPaillierEncrypt(cointype, save, w, idSign, u1K, ch)
	if ukc == nil || ukc2 == nil || ukc3 == nil {
		return nil
	}
	common.Debug("===================PreSign_ec3,paillier encrypt finish=================","key",msgprex)

	zk1proof, zkfactproof := DECDSASignRoundTwo(msgprex, cointype, save, w, idSign, ch, u1K, ukc2, ukc3)
	if zk1proof == nil || zkfactproof == nil {
		return nil
	}
	common.Debug("===================PreSign_ec3,round two finish================","key",msgprex)

	if !DECDSASignRoundThree(msgprex, cointype, save, w, idSign, ch, ukc) {
		return nil
	}
	common.Debug("===================PreSign_ec3,round three finish================","key",msgprex)

	if !DECDSASignVerifyZKNtilde(msgprex, cointype, save, w, idSign, ch, ukc, ukc3, zk1proof, zkfactproof) {
		return nil
	}
	common.Debug("===================PreSign_ec3,verify zk ntilde finish==================","key",msgprex)

	betaU1Star, betaU1, vU1Star, vU1 := signing.GetRandomBetaV(PaillierKeyLength, w.ThresHold)
	common.Debug("===================PreSign_ec3,get random betaU1Star/vU1Star finish================","key",msgprex)

	mkg, mkg_mtazk2, mkw, mkw_mtazk2, status := DECDSASignRoundFour(msgprex, cointype, save, w, idSign, ukc, ukc3, zkfactproof, u1Gamma, w1, betaU1Star, vU1Star,ch)
	if !status {
		return nil
	}
	common.Debug("===================PreSign_ec3,round four finish================","key",msgprex)

	if !DECDSASignVerifyZKGammaW(msgprex,cointype, save, w, idSign, ukc, ukc3, zkfactproof, mkg, mkg_mtazk2, mkw, mkw_mtazk2, ch) {
		return nil
	} 
	common.Debug("===================PreSign_ec3,verify zk gamma/w finish===================","key",msgprex)

	u1PaillierSk := GetSelfPrivKey(cointype, idSign, w, save, ch)
	if u1PaillierSk == nil {
		return nil
	}
	common.Debug("===================PreSign_ec3,get self privkey finish====================","key",msgprex)

	alpha1 := DecryptCkGamma(cointype, idSign, w, u1PaillierSk, mkg, ch)
	if alpha1 == nil {
		return nil
	}
	common.Debug("=====================PreSign_ec3,decrypt paillier(k)XGamma finish=================","key",msgprex)

	uu1 := DecryptCkW(cointype, idSign, w, u1PaillierSk, mkw, ch)
	if uu1 == nil {
		return nil
	}
	common.Debug("=====================PreSign_ec3, decrypt paillier(k)Xw1 finish=================","key",msgprex)

	delta1 := CalcDelta(alpha1, betaU1, ch, w.ThresHold)
	if delta1 == nil {
		return nil
	}
	common.Debug("=====================PreSign_ec3, calc delta finish=================","key",msgprex)

	sigma1 := CalcSigma(uu1, vU1, ch, w.ThresHold)
	if sigma1 == nil {
		return nil
	}
	common.Debug("=====================PreSign_ec3, calc sigma finish=================","key",msgprex)

	deltaSum := DECDSASignRoundFive(msgprex, cointype, delta1, idSign, w, ch)
	if deltaSum == nil {
		return nil
	}
	common.Debug("=====================PreSign_ec3, round five finish=================","key",msgprex)

	u1GammaZKProof := DECDSASignRoundSix(msgprex, u1Gamma, commitU1GammaG, w, ch)
	if u1GammaZKProof == nil {
		return nil
	}
	common.Debug("=====================PreSign_ec3, round six finish=================","key",msgprex)

	ug := DECDSASignVerifyCommitment(cointype, w, idSign, commitU1GammaG, u1GammaZKProof, ch)
	if ug == nil {
		return nil
	}
	common.Debug("=====================PreSign_ec3, verify commitment finish=================","key",msgprex)

	r, deltaGammaGy := Calc_r(cointype, w, idSign, ug, deltaSum, ch)
	if r == nil || deltaGammaGy == nil {
		return nil
	}
	//common.Info("=====================PreSign_ec3, calc r finish=================","key",msgprex)
	ret := &PrePubData{Key:msgprex,K1:u1K,R:r,Ry:deltaGammaGy,Sigma1:sigma1,Gid:w.groupid,Used:false}
	return ret
}

//msgprex = hash
//return value is the backup for the dcrm sig
func Sign_ec3(msgprex string, message string, cointype string, pkx *big.Int, pky *big.Int, ch chan interface{}, id int,pre *PrePubData) string {
	if id < 0 || id >= len(workers) {
		res := RpcDcrmRes{Ret: "", Err: fmt.Errorf("no find worker.")}
		ch <- res
		return ""
	}
	w := workers[id]
	if w.groupid == "" {
		res := RpcDcrmRes{Ret: "", Err: fmt.Errorf("get group id fail.")}
		ch <- res
		return ""
	}

	hashBytes, err2 := hex.DecodeString(message)
	if err2 != nil {
		res := RpcDcrmRes{Ret: "", Err: err2}
		ch <- res
		return ""
	}

	// [Notes]
	// 1. assume the nodes who take part in the signature generation as follows
	ids := GetIds(cointype, w.groupid)
	idSign := ids[:w.ThresHold]
	
	mMtA, _ := new(big.Int).SetString(message, 16)
	common.Info("=============Sign_ec3 start=============","w.ThresHold",w.ThresHold,"w.groupid",w.groupid,"key",msgprex)

	//*******************!!!Distributed ECDSA Sign Start!!!**********************************

	// 5. calculate s
	us1 := signing.CalcUs(mMtA, pre.K1, pre.R, pre.Sigma1)

	/*commitBigVAB1, commitbigvabs, rho1, l1 := DECDSASignRoundSeven(msgprex, pre.R, pre.Ry, us1, w, ch)
	if commitBigVAB1 == nil || commitbigvabs == nil || rho1 == nil || l1 == nil {
		return ""
	}
	common.Debug("=====================Sign_ec3, round seven finish=================","key",msgprex)

	u1zkABProof, zkabproofs := DECDSASignRoundEight(msgprex, pre.R, pre.Ry, us1, l1, rho1, w, ch, commitBigVAB1)
	if u1zkABProof == nil || zkabproofs == nil {
		return ""
	}
	common.Debug("=====================Sign_ec3, round eight finish=================","key",msgprex)

	commitbigcom, BigVx, BigVy := DECDSASignVerifyBigVAB(cointype, w, commitbigvabs, zkabproofs, commitBigVAB1, u1zkABProof, idSign, pre.R, pre.Ry, ch)
	if commitbigcom == nil || BigVx == nil || BigVy == nil {
		return ""
	}
	common.Debug("=====================Sign_ec3, verify BigVAB finish=================","key",msgprex)

	commitbiguts, commitBigUT1 := DECDSASignRoundNine(msgprex, cointype, w, idSign, mMtA, pre.R, pkx, pky, BigVx, BigVy, rho1, commitbigcom, l1, ch)
	if commitbiguts == nil || commitBigUT1 == nil {
		return ""
	}
	common.Debug("=====================Sign_ec3, round nine finish=================","key",msgprex)

	commitbigutd11s := DECDSASignRoundTen(msgprex, commitBigUT1, w, ch)
	if commitbigutd11s == nil {
		return ""
	}
	common.Debug("=====================Sign_ec3, round ten finish=================","key",msgprex)

	if !DECDSASignVerifyBigUTCommitment(msgprex,cointype, commitbiguts, commitbigutd11s, commitBigUT1, w, idSign, ch, commitbigcom) {
		return ""
	}
	common.Debug("=====================Sign_ec3, verify BigUT commitment finish=================","key",msgprex)
*/
	ss1s := DECDSASignRoundEleven(msgprex, cointype, w, idSign, ch, us1)
	if ss1s == nil {
		return ""
	}
	common.Debug("=====================Sign_ec3,round eleven finish=================","key",msgprex)

	s := Calc_s(msgprex,cointype, w, idSign, ss1s, ch)
	if s == nil {
		return ""
	}
	common.Debug("=====================Sign_ec3,calc s finish=================","key",msgprex)

	// 3. justify the s
	bb := false
	halfN := new(big.Int).Div(secp256k1.S256().N, big.NewInt(2))
	if s.Cmp(halfN) > 0 {
		bb = true
		s = new(big.Int).Sub(secp256k1.S256().N, s)
	}

	zero, _ := new(big.Int).SetString("0", 10)
	if s.Cmp(zero) == 0 {
		res := RpcDcrmRes{Ret: "", Err: fmt.Errorf("s == 0.")}
		ch <- res
		return ""
	}
	common.Debug("=====================Sign_ec3,justify s finish=================","key",msgprex)

	// **[End-Test]  verify signature with MtA
	signature := new(ECDSASignature)
	signature.New()
	signature.SetR(pre.R)
	signature.SetS(s)

	invert := false
	if cointype == "ETH" && bb {
		//recid ^=1
		invert = true
	}
	if cointype == "BTC" && bb {
		//recid ^= 1
		invert = true
	}

	recid := signing.DECDSA_Sign_Calc_v(pre.R, pre.Ry, pkx, pky, signature.GetR(), signature.GetS(), hashBytes, invert)
	////check v
	ys := secp256k1.S256().Marshal(pkx,pky)
	pubkeyhex := hex.EncodeToString(ys)
	pbhs := []rune(pubkeyhex)
	if string(pbhs[0:2]) == "0x" {
	    pubkeyhex = string(pbhs[2:])
	}

	rsvBytes1 := append(signature.GetR().Bytes(), signature.GetS().Bytes()...)
	for j := 0; j < 4; j++ {
	    rsvBytes2 := append(rsvBytes1, byte(j))
	    pkr, e := secp256k1.RecoverPubkey(hashBytes,rsvBytes2)
	    pkr2 := hex.EncodeToString(pkr)
	    pbhs2 := []rune(pkr2)
	    if string(pbhs2[0:2]) == "0x" {
		pkr2 = string(pbhs2[2:])
	    }
	    if e == nil && strings.EqualFold(pkr2,pubkeyhex) {
		recid = j
		break
	    }
	}
	/////
	signature.SetRecoveryParam(int32(recid))

	if !DECDSA_Sign_Verify_RSV(signature.GetR(), signature.GetS(), signature.GetRecoveryParam(), message, pkx, pky) {
		common.Debug("=================Sign_ec3,verify is false==============","key",msgprex)
		res := RpcDcrmRes{Ret: "", Err: fmt.Errorf("sign verify fail.")}
		ch <- res
		return ""
	}
	common.Debug("=================Sign_ec3,verify (r,s) pass==============","key",msgprex)

	signature2 := GetSignString(signature.GetR(), signature.GetS(), signature.GetRecoveryParam(), int(signature.GetRecoveryParam()))
	rstring := "========================== r = " + fmt.Sprintf("%v", signature.GetR()) + " ========================="
	sstring := "========================== s = " + fmt.Sprintf("%v", signature.GetS()) + " =========================="
	fmt.Println(rstring)
	fmt.Println(sstring)
	common.Debug("=================Sign_ec3==============","rsv str",signature2,"key",msgprex)
	res := RpcDcrmRes{Ret: signature2, Err: nil}
	ch <- res

	common.Debug("=================Sign_ec3, rsv pass==============","key",msgprex)
	//*******************!!!Distributed ECDSA Sign End!!!**********************************

	return ""
}

func DoubleHash(id string, cointype string) *big.Int {
	
    	if cointype == "ED25519" || cointype == "ECDSA" {
	    return DoubleHash2(id,cointype)
	}

    	// Generate the random num

	// First, hash with the keccak256
	keccak256 := sha3.NewKeccak256()
	_,err := keccak256.Write([]byte(id))
	if err != nil {
	    return nil
	}

	digestKeccak256 := keccak256.Sum(nil)

	//second, hash with the SHA3-256
	sha3256 := sha3.New256()

	_,err = sha3256.Write(digestKeccak256)
	if err != nil {
	    return nil
	}

	if types.IsDefaultED25519(cointype) {
		var digest [32]byte
		copy(digest[:], sha3256.Sum(nil))

		//////
		var zero [32]byte
		var one [32]byte
		one[0] = 1
		ed.ScMulAdd(&digest, &digest, &one, &zero)
		//////
		digestBigInt := new(big.Int).SetBytes(digest[:])
		return digestBigInt
	}

	digest := sha3256.Sum(nil)
	// convert the hash ([]byte) to big.Int
	digestBigInt := new(big.Int).SetBytes(digest)
	return digestBigInt
}

type ECDSASignature struct {
	r               *big.Int
	s               *big.Int
	recoveryParam   int32
	roudFiveAborted bool
}

func (this *ECDSASignature) New() {
}

func (this *ECDSASignature) New2(r *big.Int, s *big.Int) {
	this.r = r
	this.s = s
}

func (this *ECDSASignature) New3(r *big.Int, s *big.Int, recoveryParam int32) {
	this.r = r
	this.s = s
	this.recoveryParam = recoveryParam
}

func (this *ECDSASignature) GetRoudFiveAborted() bool {
	return this.roudFiveAborted
}

func (this *ECDSASignature) SetRoudFiveAborted(roudFiveAborted bool) {
	this.roudFiveAborted = roudFiveAborted
}

func (this *ECDSASignature) GetR() *big.Int {
	return this.r
}

func (this *ECDSASignature) SetR(r *big.Int) {
	this.r = r
}

func (this *ECDSASignature) GetS() *big.Int {
	return this.s
}

func (this *ECDSASignature) SetS(s *big.Int) {
	this.s = s
}

func (this *ECDSASignature) GetRecoveryParam() int32 {
	return this.recoveryParam
}

func (this *ECDSASignature) SetRecoveryParam(recoveryParam int32) {
	this.recoveryParam = recoveryParam
}

func Tool_DecimalByteSlice2HexString(DecimalSlice []byte) string {
	var sa = make([]string, 0)
	for _, v := range DecimalSlice {
		sa = append(sa, fmt.Sprintf("%02X", v))
	}
	ss := strings.Join(sa, "")
	return ss
}

func GetSignString(r *big.Int, s *big.Int, v int32, i int) string {
	rr := r.Bytes()
	sss := s.Bytes()

	//bug
	if len(rr) == 31 && len(sss) == 32 {
		sigs := make([]byte, 65)
		sigs[0] = byte(0)
		signing.ReadBits(r, sigs[1:32])
		signing.ReadBits(s, sigs[32:64])
		sigs[64] = byte(i)
		ret := Tool_DecimalByteSlice2HexString(sigs)
		return ret
	}
	if len(rr) == 31 && len(sss) == 31 {
		sigs := make([]byte, 65)
		sigs[0] = byte(0)
		sigs[32] = byte(0)
		signing.ReadBits(r, sigs[1:32])
		signing.ReadBits(s, sigs[33:64])
		sigs[64] = byte(i)
		ret := Tool_DecimalByteSlice2HexString(sigs)
		return ret
	}
	if len(rr) == 32 && len(sss) == 31 {
		sigs := make([]byte, 65)
		sigs[32] = byte(0)
		signing.ReadBits(r, sigs[0:32])
		signing.ReadBits(s, sigs[33:64])
		sigs[64] = byte(i)
		ret := Tool_DecimalByteSlice2HexString(sigs)
		return ret
	}
	//

	n := len(rr) + len(sss) + 1
	sigs := make([]byte, n)
	signing.ReadBits(r, sigs[0:len(rr)])
	signing.ReadBits(s, sigs[len(rr):len(rr)+len(sss)])

	sigs[len(rr)+len(sss)] = byte(i)
	ret := Tool_DecimalByteSlice2HexString(sigs)

	return ret
}

func DECDSA_Sign_Verify_RSV(r *big.Int, s *big.Int, v int32, message string, pkx *big.Int, pky *big.Int) bool {
	return signing.Verify2(r, s, v, message, pkx, pky)
}

