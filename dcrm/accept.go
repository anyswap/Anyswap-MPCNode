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
    "github.com/fsn-dev/dcrm-walletService/internal/common"
    "strings"
    "fmt"
)

type TxDataAcceptReqAddr struct {
    TxType string
    Key string
    Accept string
    TimeStamp string
}

func AcceptReqAddr(initiator string,account string, cointype string, groupid string, nonce string, threshold string, mode string, deal string, accept string, status string, pubkey string, tip string, errinfo string, allreply []NodeReply, workid int,sigs string) (string, error) {
	key := Keccak256Hash([]byte(strings.ToLower(account + ":" + cointype + ":" + groupid + ":" + nonce + ":" + threshold + ":" + mode))).Hex()
	exsit,da := GetPubKeyData([]byte(key))
	if !exsit {
		common.Info("=====================AcceptReqAddr,no exist key=======================","key",key)
		return "dcrm back-end internal error:get accept data fail from db", fmt.Errorf("dcrm back-end internal error:get accept data fail from db")
	}

	ac,ok := da.(*AcceptReqAddrData)
	if !ok {
		return "dcrm back-end internal error:get accept data fail from db", fmt.Errorf("dcrm back-end internal error:get accept data fail from db")
	}

	in := ac.Initiator
	if initiator != "" {
	    in = initiator
	}

	de := ac.Deal
	if deal != "" {
	    de = deal
	}

	acp := ac.Accept
	if accept != "" {
		acp = accept
	}

	pk := ac.PubKey
	if pubkey != "" {
		pk = pubkey
	}

	ttip := ac.Tip
	if tip != "" {
		ttip = tip
	}

	eif := ac.Error
	if errinfo != "" {
		eif = errinfo
	}

	sts := ac.Status
	if status != "" {
		sts = status
	}

	arl := ac.AllReply
	if allreply != nil {
		arl = allreply
	}

	wid := ac.WorkId
	if workid >= 0 {
		wid = workid
	}

	gs := ac.Sigs
	if sigs != "" {
	    gs = sigs
	}

	ac2 := &AcceptReqAddrData{Initiator:in,Account: ac.Account, Cointype: ac.Cointype, GroupId: ac.GroupId, Nonce: ac.Nonce, LimitNum: ac.LimitNum, Mode: ac.Mode, TimeStamp: ac.TimeStamp, Deal: de, Accept: acp, Status: sts, PubKey: pk, Tip: ttip, Error: eif, AllReply: arl, WorkId: wid,Sigs:gs}

	e, err := Encode2(ac2)
	if err != nil {
		common.Debug("=====================AcceptReqAddr,encode fail=======================","err",err,"key",key)
		return "dcrm back-end internal error:encode accept data fail", err
	}

	es, err := Compress([]byte(e))
	if err != nil {
		common.Debug("=====================AcceptReqAddr,compress fail=======================","err",err,"key",key)
		return "dcrm back-end internal error:compress accept data fail", err
	}

	err = PutPubKeyData([]byte(key),[]byte(es))
	if err != nil {
	    common.Error("===================================AcceptReqAddr,put pubkey data fail===========================","err",err,"key",key)
	    return err.Error(),err
	}

	common.Debug("=====================AcceptReqAddr,write map success====================","status",ac2.Status,"key",key)
	return "", nil
}

type TxDataAcceptSign struct {
    TxType string
    Key string
    MsgHash []string
    MsgContext []string
    Accept string
    TimeStamp string
}

func AcceptSign(initiator string,account string, pubkey string,msghash []string,keytype string,groupid string, nonce string,threshold string,mode string, deal string, accept string, status string, rsv string, tip string, errinfo string, allreply []NodeReply, workid int) (string, error) {
	key := Keccak256Hash([]byte(strings.ToLower(account + ":" + nonce + ":" + pubkey + ":" + get_sign_hash(msghash,keytype) + ":" + keytype + ":" + groupid + ":" + threshold + ":" + mode))).Hex()
	exsit,da := GetPubKeyData([]byte(key))
	if !exsit {
		common.Info("=====================AcceptSign,no exist key=======================","key",key)
		return "dcrm back-end internal error:get accept data fail from db", fmt.Errorf("dcrm back-end internal error:get accept data fail from db")
	}

	ac,ok := da.(*AcceptSignData)

	if !ok {
		return "dcrm back-end internal error:get accept data fail from db", fmt.Errorf("dcrm back-end internal error:get accept data fail from db")
	}

	in := ac.Initiator
	if initiator != "" {
	    in = initiator
	}

	de := ac.Deal
	if deal != "" {
	    de = deal
	}

	acp := ac.Accept
	if accept != "" {
		acp = accept
	}

	ah := ac.Rsv
	if rsv != "" {
		ah = rsv
	}

	ttip := ac.Tip
	if tip != "" {
		ttip = tip
	}

	eif := ac.Error
	if errinfo != "" {
		eif = errinfo
	}

	sts := ac.Status
	if status != "" {
		sts = status
	}

	arl := ac.AllReply
	if allreply != nil {
		arl = allreply
	}

	wid := ac.WorkId
	if workid >= 0 {
		wid = workid
	}

	ac2 := &AcceptSignData{Initiator:in,Account: ac.Account, GroupId: ac.GroupId, Nonce: ac.Nonce, PubKey: ac.PubKey, MsgHash: ac.MsgHash, MsgContext:ac.MsgContext, Keytype: ac.Keytype, LimitNum: ac.LimitNum, Mode: ac.Mode, TimeStamp: ac.TimeStamp, Deal: de, Accept: acp, Status: sts, Rsv: ah, Tip: ttip, Error: eif, AllReply: arl, WorkId: wid}

	e, err := Encode2(ac2)
	if err != nil {
		common.Debug("=====================AcceptSign,encode fail=======================","err",err,"key",key)
		return "dcrm back-end internal error:encode accept data fail", err
	}

	es, err := Compress([]byte(e))
	if err != nil {
		common.Debug("=====================AcceptSign,compress fail=======================","err",err,"key",key)
		return "dcrm back-end internal error:compress accept data fail", err
	}

	exsit,da = GetPubKeyData([]byte(key))
	if exsit {
		ac,ok = da.(*AcceptSignData)
		if ok {
			if ac.Status != "Pending" || ac.Rsv != "" {
				common.Info("=====================AcceptSign,already in ldb=======================","key",key)
				return "",nil
			}
		}
	}

	err = PutPubKeyData([]byte(key),[]byte(es))
	if err != nil {
	    common.Error("========================AcceptSign,put accept sign data fail.=======================","key",key,"err",err)
	    return err.Error(),err
	}

	common.Debug("=====================AcceptSign,finish.========================","key",key)
	return "", nil
}

type AcceptReqAddrData struct {
        Initiator string //enode
	Account   string
	Cointype  string
	GroupId   string
	Nonce     string
	LimitNum  string
	Mode      string
	TimeStamp string

	Deal   string 
	Accept string

	Status string
	PubKey string
	Tip    string
	Error  string

	AllReply []NodeReply

	WorkId int

	Sigs string //5:eid1:acc1:eid2:acc2:eid3:acc3:eid4:acc4:eid5:acc5
}

func SaveAcceptReqAddrData(ac *AcceptReqAddrData) error {
	if ac == nil {
		return fmt.Errorf("no accept data.")
	}

	key := Keccak256Hash([]byte(strings.ToLower(ac.Account + ":" + ac.Cointype + ":" + ac.GroupId + ":" + ac.Nonce + ":" + ac.LimitNum + ":" + ac.Mode))).Hex()

	alos, err := Encode2(ac)
	if err != nil {
		return err
	}

	ss, err := Compress([]byte(alos))
	if err != nil {
		return err
	}

	err = PutPubKeyData([]byte(key),[]byte(ss))
	if err != nil {
	    common.Error("===============================SaveAcceptReqAddrData,put accept reqaddr data to db fail===========================","key",key,"err",err)
	    return err
	}
	
	return nil
}

type AcceptSignData struct {
        Initiator string //enode
	Account   string
	GroupId   string
	Nonce     string
	PubKey  string
	MsgHash    []string
	MsgContext    []string
	Keytype  string
	LimitNum  string
	Mode      string
	TimeStamp string

	Deal   string 
	Accept string

	Status    string
	Rsv string   //rsv1:rsv2:....:rsvn:NULL
	Tip       string
	Error     string

	AllReply []NodeReply
	WorkId   int
}

type SignBak struct {
	Key string
	Ac *AcceptSignData
}

func SaveAcceptSignData(ac *AcceptSignData) error {
	if ac == nil {
	    return fmt.Errorf("no accept data.")
	}

	//key := hash(acc + nonce + pubkey + hash + keytype + groupid + threshold + mode)
	key := Keccak256Hash([]byte(strings.ToLower(ac.Account + ":" + ac.Nonce + ":" + ac.PubKey + ":" + get_sign_hash(ac.MsgHash,ac.Keytype) + ":" + ac.Keytype + ":" + ac.GroupId + ":" + ac.LimitNum + ":" + ac.Mode))).Hex()

	alos, err := Encode2(ac)
	if err != nil {
	    common.Debug("========================SaveAcceptSignData======================","enode err",err,"key",key)
	    return err
	}

	ss, err := Compress([]byte(alos))
	if err != nil {
		common.Debug("========================SaveAcceptSignData======================","compress err",err,"key",key)
		return err
	}

	err = PutPubKeyData([]byte(key),[]byte(ss))
	if err != nil {
	    common.Error("========================SaveAcceptSignData,put accept sign data to db fail======================","err",err,"key",key)
	    return err
	}

	return nil
}

type AcceptReShareData struct {
        Initiator string //enode
	Account   string
	GroupId   string
	TSGroupId   string
	PubKey  string
	LimitNum  string
	PubAccount string
	Mode string
	Sigs string
	TimeStamp string

	Deal   string 
	Accept string

	Status    string
	NewSk string //TODO 
	Tip       string
	Error     string

	AllReply []NodeReply
	WorkId   int
}

func SaveAcceptReShareData(ac *AcceptReShareData) error {
	if ac == nil {
		return fmt.Errorf("no accept data.")
	}

	key := Keccak256Hash([]byte(strings.ToLower(ac.Account + ":" + ac.GroupId + ":" + ac.TSGroupId + ":" + ac.PubKey + ":" + ac.LimitNum + ":" + ac.Mode))).Hex()

	alos, err := Encode2(ac)
	if err != nil {
		common.Debug("========================SaveAcceptReShareData======================","enode err",err,"key",key)
		return err
	}

	ss, err := Compress([]byte(alos))
	if err != nil {
		common.Debug("========================SaveAcceptReShareData======================","compress err",err,"key",key)
		return err
	}

	err = PutPubKeyData([]byte(key),[]byte(ss))
	if err != nil {
	    return err
	}
	
	return nil
}

type TxDataAcceptReShare struct {
    TxType string
    Key string
    Accept string
    TimeStamp string
}

func AcceptReShare(initiator string,account string, groupid string, tsgroupid string,pubkey string, threshold string,mode string,deal string, accept string, status string, newsk string, tip string, errinfo string, allreply []NodeReply, workid int) (string, error) {
    key := Keccak256Hash([]byte(strings.ToLower(account + ":" + groupid + ":" + tsgroupid + ":" + pubkey + ":" + threshold + ":" + mode))).Hex()
	exsit,da := GetPubKeyData([]byte(key))
	if !exsit {
		common.Debug("=====================AcceptReShare, no exist======================","key",key)
		return "dcrm back-end internal error:get accept data fail from db", fmt.Errorf("dcrm back-end internal error:get accept data fail from db")
	}

	ac,ok := da.(*AcceptReShareData)

	if !ok {
		return "dcrm back-end internal error:get accept data fail from db", fmt.Errorf("dcrm back-end internal error:get accept data fail from db")
	}

	in := ac.Initiator
	if initiator != "" {
	    in = initiator
	}

	de := ac.Deal
	if deal != "" {
	    de = deal
	}

	acp := ac.Accept
	if accept != "" {
		acp = accept
	}

	ah := ac.NewSk
	if newsk != "" {
		ah = newsk
	}

	ttip := ac.Tip
	if tip != "" {
		ttip = tip
	}

	eif := ac.Error
	if errinfo != "" {
		eif = errinfo
	}

	sts := ac.Status
	if status != "" {
		sts = status
	}

	arl := ac.AllReply
	if allreply != nil {
		arl = allreply
	}

	wid := ac.WorkId
	if workid >= 0 {
		wid = workid
	}

	ac2 := &AcceptReShareData{Initiator:in,Account: ac.Account, GroupId: ac.GroupId, TSGroupId:ac.TSGroupId, PubKey: ac.PubKey,LimitNum: ac.LimitNum, PubAccount:ac.PubAccount, Mode:ac.Mode,Sigs:ac.Sigs,TimeStamp: ac.TimeStamp, Deal: de, Accept: acp, Status: sts, NewSk: ah, Tip: ttip, Error: eif, AllReply: arl, WorkId: wid}

	e, err := Encode2(ac2)
	if err != nil {
		common.Debug("=====================AcceptReShare, encode fail======================","err",err,"key",key)
		return "dcrm back-end internal error:encode accept data fail", err
	}

	es, err := Compress([]byte(e))
	if err != nil {
		common.Debug("=====================AcceptReShare, compress fail======================","err",err,"key",key)
		return "dcrm back-end internal error:compress accept data fail", err
	}

	err = PutPubKeyData([]byte(key),[]byte(es))
	if err != nil {
	    return err.Error(),err
	}
	
	return "", nil
}

