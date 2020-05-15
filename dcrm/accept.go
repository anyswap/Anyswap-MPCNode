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

func GetAcceptReqAddrRes(account string, cointype string, groupid string, nonce string, threshold string, mode string) (string, bool) {
	key := Keccak256Hash([]byte(strings.ToLower(account + ":" + cointype + ":" + groupid + ":" + nonce + ":" + threshold + ":" + mode))).Hex()
	fmt.Printf("%v ===================!!!!GetAcceptReqAddrRes,acc =%v,cointype =%v,groupid =%v,nonce =%v,threshold =%v,mode =%v,key =%v !!!!============================\n", common.CurrentTime(), account, cointype, groupid, nonce, threshold, mode, key)
	exsit,da := GetValueFromPubKeyData(key)
	///////
	if exsit == false {
		fmt.Printf("%v ===================!!!!GetAcceptReqAddrRes,no exsit key =%v !!!!============================\n", common.CurrentTime(), key)
		return "dcrm back-end internal error:get accept result from db fail", false
	}

	ac,ok := da.(*AcceptReqAddrData)
	if ok == false {
		return "dcrm back-end internal error:get accept result from db fail", false
	}

	fmt.Printf("%v ===================!!!! GetAcceptReqAddrRes,ac.Accept =%v,key =%v !!!!============================\n", common.CurrentTime(),ac.Accept, key)

	var rp bool
	if strings.EqualFold(ac.Accept, "false") {
		rp = false
	} else {
		rp = true
	}

	return "", rp
}

func GetAcceptLockOutRes(account string, groupid string, nonce string, dcrmfrom string, threshold string) (string, bool) {
	key := Keccak256Hash([]byte(strings.ToLower(account + ":" + groupid + ":" + nonce + ":" + dcrmfrom + ":" + threshold))).Hex()
	fmt.Printf("%v ===================!!!! GetAcceptLockOutRes,acc =%v,groupid =%v,nonce =%v,dcrmfrom =%v,threshold =%v,key =%v !!!!============================\n", common.CurrentTime(), account, groupid, nonce, dcrmfrom, threshold, key)
	exsit,da := GetValueFromPubKeyData(key)
	///////
	if exsit == false {
		fmt.Printf("%v ===================!!!! GetAcceptLockOutRes,no exsit key =%v !!!!============================\n", common.CurrentTime(), key)
		return "dcrm back-end internal error:get accept result from db fail", false
	}

	ac,ok := da.(*AcceptLockOutData)
	if ok == false {
		return "dcrm back-end internal error:get accept result from db fail", false
	}

	fmt.Printf("%v ===================!!!! GetAcceptLockOutRes,ac.Accept =%v, key =%v !!!!============================\n", common.CurrentTime(), ac.Accept, key)

	var rp bool
	if strings.EqualFold(ac.Accept, "false") {
		rp = false
	} else {
		rp = true
	}

	return "", rp
}

type TxDataAcceptReqAddr struct {
    TxType string
    Key string
    Accept string
    TimeStamp string
}

func AcceptReqAddr(initiator string,account string, cointype string, groupid string, nonce string, threshold string, mode string, deal string, accept string, status string, pubkey string, tip string, errinfo string, allreply []NodeReply, workid int,sigs string) (string, error) {
	key := Keccak256Hash([]byte(strings.ToLower(account + ":" + cointype + ":" + groupid + ":" + nonce + ":" + threshold + ":" + mode))).Hex()
	exsit,da := GetValueFromPubKeyData(key)
	///////
	if exsit == false {
		fmt.Printf("%v =====================AcceptReqAddr,no exist key, key = %v ======================\n", common.CurrentTime(), key)
		return "dcrm back-end internal error:get accept data fail from db", fmt.Errorf("dcrm back-end internal error:get accept data fail from db")
	}

	ac,ok := da.(*AcceptReqAddrData)
	if ok == false {
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
	if allreply != nil && len(allreply) != 0 {
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
		fmt.Printf("%v =====================AcceptReqAddr,encode fail,err = %v,key = %v ======================\n", common.CurrentTime(), err, key)
		return "dcrm back-end internal error:encode accept data fail", err
	}

	es, err := Compress([]byte(e))
	if err != nil {
		fmt.Printf("%v =====================AcceptReqAddr,compress fail,err = %v,key = %v ======================\n", common.CurrentTime(), err, key)
		return "dcrm back-end internal error:compress accept data fail", err
	}

	kdtmp := KeyData{Key: []byte(key), Data: es}
	PubKeyDataChan <- kdtmp

	LdbPubKeyData.WriteMap(key, ac2)
	fmt.Printf("%v =====================AcceptReqAddr,write map success, status = %v,key = %v ======================\n", common.CurrentTime(), ac2.Status, key)
	return "", nil
}

type TxDataAcceptLockOut struct {
    TxType string
    Key string
    DcrmTo string
    Value string
    Cointype string
    Mode string
    Accept string
    TimeStamp string
}

func AcceptLockOut(initiator string,account string, groupid string, nonce string, dcrmfrom string, threshold string, deal string, accept string, status string, outhash string, tip string, errinfo string, allreply []NodeReply, workid int) (string, error) {
	key := Keccak256Hash([]byte(strings.ToLower(account + ":" + groupid + ":" + nonce + ":" + dcrmfrom + ":" + threshold))).Hex()
	exsit,da := GetValueFromPubKeyData(key)
	///////
	if exsit == false {
		fmt.Printf("%v =====================AcceptLockOut, no exist key = %v =================================\n", common.CurrentTime(), key)
		return "dcrm back-end internal error:get accept data fail from db", fmt.Errorf("dcrm back-end internal error:get accept data fail from db")
	}

	ac,ok := da.(*AcceptLockOutData)

	if ok == false {
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

	ah := ac.OutTxHash
	if outhash != "" {
		ah = outhash
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
	if allreply != nil && len(allreply) != 0 {
		arl = allreply
	}

	wid := ac.WorkId
	if workid >= 0 {
		wid = workid
	}

	ac2 := &AcceptLockOutData{Initiator:in,Account: ac.Account, GroupId: ac.GroupId, Nonce: ac.Nonce, DcrmFrom: ac.DcrmFrom, DcrmTo: ac.DcrmTo, Value: ac.Value, Cointype: ac.Cointype, LimitNum: ac.LimitNum, Mode: ac.Mode, TimeStamp: ac.TimeStamp, Deal: de, Accept: acp, Status: sts, OutTxHash: ah, Tip: ttip, Error: eif, AllReply: arl, WorkId: wid}

	e, err := Encode2(ac2)
	if err != nil {
		fmt.Printf("%v =====================AcceptLockOut, encode fail,err = %v, key = %v =================================\n", common.CurrentTime(), err, key)
		return "dcrm back-end internal error:encode accept data fail", err
	}

	es, err := Compress([]byte(e))
	if err != nil {
		fmt.Printf("%v =====================AcceptLockOut, compress fail,err = %v, key = %v =================================\n", common.CurrentTime(), err, key)
		return "dcrm back-end internal error:compress accept data fail", err
	}

	kdtmp := KeyData{Key: []byte(key), Data: es}
	PubKeyDataChan <- kdtmp

	LdbPubKeyData.WriteMap(key, ac2)
	return "", nil
}

type TxDataAcceptSign struct {
    TxType string
    Key string
    Accept string
    TimeStamp string
}

func AcceptSign(initiator string,account string, pubkey string,msghash string,keytype string,groupid string, nonce string,threshold string,mode string, deal string, accept string, status string, rsv string, tip string, errinfo string, allreply []NodeReply, workid int) (string, error) {
	key := Keccak256Hash([]byte(strings.ToLower(account + ":" + nonce + ":" + pubkey + ":" + msghash + ":" + keytype + ":" + groupid + ":" + threshold + ":" + mode))).Hex()
	exsit,da := GetValueFromPubKeyData(key)
	///////
	if exsit == false {
		fmt.Printf("%v =====================AcceptSign, no exist key = %v =================================\n", common.CurrentTime(), key)
		return "dcrm back-end internal error:get accept data fail from db", fmt.Errorf("dcrm back-end internal error:get accept data fail from db")
	}

	ac,ok := da.(*AcceptSignData)

	if ok == false {
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
	if allreply != nil && len(allreply) != 0 {
		arl = allreply
	}

	wid := ac.WorkId
	if workid >= 0 {
		wid = workid
	}

	ac2 := &AcceptSignData{Initiator:in,Account: ac.Account, GroupId: ac.GroupId, Nonce: ac.Nonce, PubKey: ac.PubKey, MsgHash: ac.MsgHash, MsgContext:ac.MsgContext, Keytype: ac.Keytype, LimitNum: ac.LimitNum, Mode: ac.Mode, TimeStamp: ac.TimeStamp, Deal: de, Accept: acp, Status: sts, Rsv: ah, Tip: ttip, Error: eif, AllReply: arl, WorkId: wid}

	e, err := Encode2(ac2)
	if err != nil {
		fmt.Printf("%v =====================AcceptSign, encode fail,err = %v, key = %v =================================\n", common.CurrentTime(), err, key)
		return "dcrm back-end internal error:encode accept data fail", err
	}

	es, err := Compress([]byte(e))
	if err != nil {
		fmt.Printf("%v =====================AcceptSign, compress fail,err = %v, key = %v =================================\n", common.CurrentTime(), err, key)
		return "dcrm back-end internal error:compress accept data fail", err
	}

	kdtmp := KeyData{Key: []byte(key), Data: es}
	PubKeyDataChan <- kdtmp

	LdbPubKeyData.WriteMap(key, ac2)
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

	kdtmp := KeyData{Key: []byte(key), Data: ss}
	PubKeyDataChan <- kdtmp

	LdbPubKeyData.WriteMap(key, ac)
	return nil
}

type AcceptLockOutData struct {
        Initiator string //enode
	Account   string
	GroupId   string
	Nonce     string
	DcrmFrom  string
	DcrmTo    string
	Value     string
	Cointype  string
	LimitNum  string
	Mode      string
	TimeStamp string

	Deal   string 
	Accept string

	Status    string
	OutTxHash string
	Tip       string
	Error     string

	AllReply []NodeReply
	WorkId   int
}

func SaveAcceptLockOutData(ac *AcceptLockOutData) error {
	if ac == nil {
		return fmt.Errorf("no accept data.")
	}

	key := Keccak256Hash([]byte(strings.ToLower(ac.Account + ":" + ac.GroupId + ":" + ac.Nonce + ":" + ac.DcrmFrom + ":" + ac.LimitNum))).Hex()

	alos, err := Encode2(ac)
	if err != nil {
		return err
	}

	ss, err := Compress([]byte(alos))
	if err != nil {
		return err
	}

	kdtmp := KeyData{Key: []byte(key), Data: ss}
	PubKeyDataChan <- kdtmp

	LdbPubKeyData.WriteMap(key, ac)
	return nil
}

type AcceptSignData struct {
        Initiator string //enode
	Account   string
	GroupId   string
	Nonce     string
	PubKey  string
	MsgHash    string
	MsgContext    string
	Keytype  string
	LimitNum  string
	Mode      string
	TimeStamp string

	Deal   string 
	Accept string

	Status    string
	Rsv string
	Tip       string
	Error     string

	AllReply []NodeReply
	WorkId   int
}

func SaveAcceptSignData(ac *AcceptSignData) error {
	if ac == nil {
	    return fmt.Errorf("no accept data.")
	}

	//key := hash(acc + nonce + pubkey + hash + keytype + groupid + threshold + mode)
	key := Keccak256Hash([]byte(strings.ToLower(ac.Account + ":" + ac.Nonce + ":" + ac.PubKey + ":" + ac.MsgHash + ":" + ac.Keytype + ":" + ac.GroupId + ":" + ac.LimitNum + ":" + ac.Mode))).Hex()

	alos, err := Encode2(ac)
	if err != nil {
	    fmt.Printf("%v========================SaveAcceptSignData,enode err = %v ================================\n",common.CurrentTime(),err)
	    return err
	}

	ss, err := Compress([]byte(alos))
	if err != nil {
	    fmt.Printf("%v========================SaveAcceptSignData,compress err = %v ================================\n",common.CurrentTime(),err)
		return err
	}

	kdtmp := KeyData{Key: []byte(key), Data: ss}
	PubKeyDataChan <- kdtmp

	LdbPubKeyData.WriteMap(key, ac)
	return nil
}

type AcceptReShareData struct {
        Initiator string //enode
	Account   string
	GroupId   string
	Nonce     string
	PubKey  string
	LimitNum  string
	Mode      string
	TimeStamp string

	Deal   string 
	Accept string

	Status    string
	NewSk string
	Tip       string
	Error     string

	AllReply []NodeReply
	WorkId   int
}

func SaveAcceptReShareData(ac *AcceptReShareData) error {
	if ac == nil {
		return fmt.Errorf("no accept data.")
	}

	key := Keccak256Hash([]byte(strings.ToLower(ac.Account + ":" + ac.GroupId + ":" + ac.Nonce + ":" + ac.PubKey + ":" + ac.LimitNum))).Hex()

	alos, err := Encode2(ac)
	if err != nil {
		return err
	}

	ss, err := Compress([]byte(alos))
	if err != nil {
		return err
	}

	kdtmp := KeyData{Key: []byte(key), Data: ss}
	PubKeyDataChan <- kdtmp

	LdbPubKeyData.WriteMap(key, ac)
	return nil
}

type TxDataAcceptReShare struct {
    TxType string
    Key string
    Mode string
    Accept string
    TimeStamp string
}

func AcceptReShare(initiator string,account string, groupid string, nonce string, pubkey string, threshold string, deal string, accept string, status string, newsk string, tip string, errinfo string, allreply []NodeReply, workid int) (string, error) {
	key := Keccak256Hash([]byte(strings.ToLower(account + ":" + groupid + ":" + nonce + ":" + pubkey + ":" + threshold))).Hex()
	exsit,da := GetValueFromPubKeyData(key)
	///////
	if exsit == false {
		fmt.Printf("%v =====================AcceptReShare, no exist key = %v =================================\n", common.CurrentTime(), key)
		return "dcrm back-end internal error:get accept data fail from db", fmt.Errorf("dcrm back-end internal error:get accept data fail from db")
	}

	ac,ok := da.(*AcceptReShareData)

	if ok == false {
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
	if allreply != nil && len(allreply) != 0 {
		arl = allreply
	}

	wid := ac.WorkId
	if workid >= 0 {
		wid = workid
	}

	ac2 := &AcceptReShareData{Initiator:in,Account: ac.Account, GroupId: ac.GroupId, Nonce: ac.Nonce, PubKey: ac.PubKey,LimitNum: ac.LimitNum, Mode: ac.Mode, TimeStamp: ac.TimeStamp, Deal: de, Accept: acp, Status: sts, NewSk: ah, Tip: ttip, Error: eif, AllReply: arl, WorkId: wid}

	e, err := Encode2(ac2)
	if err != nil {
		fmt.Printf("%v =====================AcceptReShare, encode fail,err = %v, key = %v =================================\n", common.CurrentTime(), err, key)
		return "dcrm back-end internal error:encode accept data fail", err
	}

	es, err := Compress([]byte(e))
	if err != nil {
		fmt.Printf("%v =====================AcceptReShare, compress fail,err = %v, key = %v =================================\n", common.CurrentTime(), err, key)
		return "dcrm back-end internal error:compress accept data fail", err
	}

	kdtmp := KeyData{Key: []byte(key), Data: es}
	PubKeyDataChan <- kdtmp

	LdbPubKeyData.WriteMap(key, ac2)
	return "", nil
}

