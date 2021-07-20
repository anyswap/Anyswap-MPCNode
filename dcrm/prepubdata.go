
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
	"math/big"
	"github.com/fsn-dev/dcrm-walletService/ethdb"
	"time"
	"fmt"
	"errors"
	"sync"
	"strconv"
	"encoding/json"
)

var (
	predb *ethdb.LDBDatabase
	PrePubDataCount = 2000
	PreSigal  = common.NewSafeMap(10) //make(map[string][]byte)
)

//------------------------------------------------

type PreSign struct {
	Pub string
	Gid string
	Nonce string
	Index int //pre-sign data index
}

func (ps *PreSign) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Pub string `json:"Pub"`
		Gid string `json:"Gid"`
		Nonce string `json:"Nonce"`
		Index string `json:"Index"`
	}{
		Pub: ps.Pub,
		Gid: ps.Gid,
		Nonce: ps.Nonce,
		Index: strconv.Itoa(ps.Index),
	})
}

func (ps *PreSign) UnmarshalJSON(raw []byte) error {
	var pre struct {
		Pub string `json:"Pub"`
		Gid string `json:"Gid"`
		Nonce string `json:"Nonce"`
		Index string `json:"Index"`
	}
	if err := json.Unmarshal(raw, &pre); err != nil {
		return err
	}

	ps.Pub = pre.Pub
	ps.Gid = pre.Gid
	ps.Nonce = pre.Nonce
	ps.Index,_ = strconv.Atoi(pre.Index)
	return nil
}

//-------------------------------------------

type PreSignData struct {
	Key string
	K1 *big.Int
	R *big.Int
	Ry *big.Int
	Sigma1 *big.Int
	Gid string
	Used bool //useless? TODO
	Index int
}

func (psd *PreSignData) MarshalJSON() ([]byte, error) {
    used := "false"
    if psd.Used == true {
	used = "true"
    }

    return json.Marshal(struct {
	    Key string `json:"Key"`
	    K1 string `json:"K1"`
	    R string `json:"R"`
	    Ry string `json:"Ry"`
	    Sigma1 string `json:"Sigma1"`
	    Gid string `json:"Gid"`
	    Used string `json:"Used"`
	    Index string `json:"Index"`
    }{
	    Key: psd.Key,
	    K1: fmt.Sprintf("%v",psd.K1),
	    R: fmt.Sprintf("%v",psd.R),
	    Ry: fmt.Sprintf("%v",psd.Ry),
	    Sigma1: fmt.Sprintf("%v",psd.Sigma1),
	    Gid: psd.Gid,
	    Used: used,
	    Index: strconv.Itoa(psd.Index),
    })
}

func (psd *PreSignData) UnmarshalJSON(raw []byte) error {
	var pre struct {
	    Key string `json:"Key"`
	    K1 string `json:"K1"`
	    R string `json:"R"`
	    Ry string `json:"Ry"`
	    Sigma1 string `json:"Sigma1"`
	    Gid string `json:"Gid"`
	    Used string `json:"Used"`
	    Index string `json:"Index"`
	}
	if err := json.Unmarshal(raw, &pre); err != nil {
		return err
	}

	psd.Key = pre.Key
	psd.K1,_ = new(big.Int).SetString(pre.K1,10)
	psd.R,_ = new(big.Int).SetString(pre.R,10)
	psd.Ry,_ = new(big.Int).SetString(pre.Ry,10)
	psd.Sigma1,_ = new(big.Int).SetString(pre.Sigma1,10)
	psd.Gid = pre.Gid
	if pre.Used == "true" {
	    psd.Used = true
	} else {
	    psd.Used = false
	}
	psd.Index,_ = strconv.Atoi(pre.Index)

	return nil
}

//---------------------------------------

type PickHashData struct {
	Hash string
	Pre *PreSignData
}

func (Phd *PickHashData) MarshalJSON() ([]byte, error) {
    if Phd.Pre == nil {
	return nil,errors.New("get pre-sign data fail.")
    }

    s,err := Phd.Pre.MarshalJSON()
    if err != nil {
	return nil,err
    }

    return json.Marshal(struct {
	    Hash string `json:"Hash"`
	    PickData string `json:"PickData"`
    }{
	    Hash: Phd.Hash,
	    PickData: string(s),
    })
}

func (Phd *PickHashData) UnmarshalJSON(raw []byte) error {
	var phd struct {
		Hash string `json:"Hash"`
		PickData string `json:"PickData"`
	}
	if err := json.Unmarshal(raw, &phd); err != nil {
		return err
	}

	Phd.Hash = phd.Hash

	pre := &PreSignData{}
	err := pre.UnmarshalJSON([]byte(phd.PickData))
	if err != nil {
	    return err
	}

	Phd.Pre = pre

	return nil
}

//--------------------------------------------------

type PickHashKey struct {
	Hash string
	PickKey string
}

func (Phk *PickHashKey) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Hash string `json:"Hash"`
		PickKey string `json:"PickKey"`
	}{
		Hash: Phk.Hash,
		PickKey: Phk.PickKey,
	})
}

func (Phk *PickHashKey) UnmarshalJSON(raw []byte) error {
	var phk struct {
		Hash string `json:"Hash"`
		PickKey string `json:"PickKey"`
	}
	if err := json.Unmarshal(raw, &phk); err != nil {
		return err
	}

	Phk.Hash = phk.Hash
	Phk.PickKey = phk.PickKey

	return nil
}

//----------------------------------------------------------------

type SignBrocastData struct {
	Raw string
	PickHash []*PickHashKey
}

func (Sbd *SignBrocastData) MarshalJSON() ([]byte, error) {
    ph := make([]string,0)
    for _,v := range Sbd.PickHash {
	s,err := v.MarshalJSON()
	if err != nil {
	    return nil,err
	}

	ph = append(ph,string(s))
    }
    phs := strings.Join(ph,"|")

    return json.Marshal(struct {
	    Raw string `json:"Raw"`
	    PickHash string `json:"PickHash"`
    }{
	    Raw: Sbd.Raw,
	    PickHash: phs,
    })
}

func (Sbd *SignBrocastData) UnmarshalJSON(raw []byte) error {
	var sbd struct {
		Raw string `json:"Raw"`
		PickHash string `json:"PickHash"`
	}
	if err := json.Unmarshal(raw, &sbd); err != nil {
		return err
	}

	Sbd.Raw = sbd.Raw
	phs := strings.Split(sbd.PickHash,"|")
	pickhash := make([]*PickHashKey,0)
	for _,v := range phs {
	    vv := &PickHashKey{}
	    if err := vv.UnmarshalJSON([]byte(v));err != nil {
		return err
	    }

	    pickhash = append(pickhash,vv)
	}

	Sbd.PickHash = pickhash

	return nil
}

//-------------------------------------------------------

type SignPickData struct {
	Raw string
	PickData []*PickHashData
}

func (Spd *SignPickData) MarshalJSON() ([]byte, error) {
    ph := make([]string,0)
    for _,v := range Spd.PickData {
	s,err := v.MarshalJSON()
 	if err != nil {
	    return nil,err
	}

	ph = append(ph,string(s))
    }
    phs := strings.Join(ph,"|")

    return json.Marshal(struct {
	    Raw string `json:"Raw"`
	    PickData string `json:"PickData"`
    }{
	    Raw: Spd.Raw,
	    PickData: phs,
    })
}

func (Spd *SignPickData) UnmarshalJSON(raw []byte) error {
	var spd struct {
		Raw string `json:"Raw"`
		PickData string `json:"PickData"`
	}
	if err := json.Unmarshal(raw, &spd); err != nil {
		return err
	}

	Spd.Raw = spd.Raw

	phs := strings.Split(spd.PickData,"|")
	pickdata := make([]*PickHashData,0)
	for _,v := range phs {
	    vv := &PickHashData{}
	    if err := vv.UnmarshalJSON([]byte(v));err != nil {
		return err
	    }

	    pickdata = append(pickdata,vv)
	}

	Spd.PickData = pickdata

	return nil
}

//-------------------------------------------------------------

func CompressSignData(raw string,pickdata []*PickHashData) (string,error) {
	if raw == "" || pickdata == nil {
		return "",fmt.Errorf("sign data error")
	}

	s := &SignPickData{Raw:raw,PickData:pickdata}
	data,err := s.MarshalJSON()
 	if err != nil {
	    return "",err
	}

	return string(data),nil
}

func UnCompressSignData(data string) (*SignPickData,error) {
	if data == "" {
		return nil,fmt.Errorf("Sign Data error")
	}

	s := &SignPickData{}
	if err := s.UnmarshalJSON([]byte(data));err != nil {
	    return nil,err
 	}

	return s,nil
 }

//---------------------------------------------------------------

func CompressSignBrocastData(raw string,pickhash []*PickHashKey) (string,error) {
	if raw == "" || pickhash == nil {
		return "",fmt.Errorf("sign brocast data error")
	}

	s := &SignBrocastData{Raw:raw,PickHash:pickhash}
	data,err := s.MarshalJSON()
	if err != nil {
		return "",err
	}

	return string(data),nil
}

func UnCompressSignBrocastData(data string) (*SignBrocastData,error) {
	if data == "" {
		return nil,fmt.Errorf("Sign Brocast Data error")
	}

	s := &SignBrocastData{}
	if err := s.UnmarshalJSON([]byte(data));err != nil {
	    return nil,err
	}

	return s,nil
}

//-----------------------------------------------------------------------

func GetPreSignKey(pubkey string,gid string,index int) (string,error) {
    if pubkey == "" || gid == "" || index < 0 {
	return "",fmt.Errorf("get pre-sign key fail,param error.")
    }

    key := strings.ToLower(Keccak256Hash([]byte(strings.ToLower(pubkey + ":" + gid + ":" + strconv.Itoa(index)))).Hex())
    return key,nil
}

func NeedPreSign(pubkey string,gid string) (int,bool) {

    if predb == nil || pubkey == "" || gid == "" {
	return -1,false
    }

    idx := make(chan int, 1)

    for i:=0;i<PrePubDataCount;i++ {
	go func(index int) {

	    key,err := GetPreSignKey(pubkey,gid,index)
	    if err != nil {
		return
	    }

	    exsit, err := predb.Has([]byte(key))
	    if !exsit || err != nil {
		if len(idx) == 0 {
		    idx <- index
		}
	    }
	}(i)
    }

    WaitTime := 30 * time.Second
    getIndexTimeOut := time.NewTicker(WaitTime)
    
    select {
	case ret := <-idx:
	    return ret,true
	case <-getIndexTimeOut.C:
	    common.Errorf("=====================NeedPreSign,get index timeout.==========================","pubkey",pubkey,"gid",gid)
	    return -1,false
    }

    return -1,false
}

func GetTotalCount(pubkey string,gid string) int {
    if predb == nil || pubkey == "" || gid == "" {
	return 0
    }

    count := 0

     var wg sync.WaitGroup
    for i:=0;i<PrePubDataCount;i++ {
	wg.Add(1)
	go func(index int) {
	    defer wg.Done()

	    key,err := GetPreSignKey(pubkey,gid,index)
	    if err != nil {
		return
	    }

	    exsit, err := predb.Has([]byte(key))
	    if exsit && err == nil {
		count++
	    }
	}(i)
    }
    wg.Wait()

    return count
}

func PutPreSignData(pubkey string,gid string,index int,val *PreSignData) error {
    if predb == nil || val == nil || index < 0 {
	return fmt.Errorf("put pre-sign data fail,param error.") 
    }

    key,err := GetPreSignKey(pubkey,gid,index)
    if err != nil {
	return err
    }

    exsit, err := predb.Has([]byte(key))
    if !exsit || err != nil {
	value,err := val.MarshalJSON()
	if err != nil {
	    common.Errorf("====================PutPreSignData,marshal pre-sign data error ======================","pubkey",pubkey,"gid",gid,"index",index,"val",val,"err",err)
	    return err
 	}

	err = predb.Put([]byte(key),value)
	if err != nil {
	    common.Errorf("====================PutPreSignData,put pre-sign data to db fail ======================","pubkey",pubkey,"gid",gid,"index",index,"val",val,"err",err)
	}

 	return err
    }

    return fmt.Errorf("pre-sign data on the key already exsit.")
}

func GetPreSignData(pubkey string,gid string,datakey string) *PreSignData {
    if predb == nil || pubkey == "" || gid == "" || datakey == "" {
	return nil
    }

    data := make(chan *PreSignData, 1)

    for i:=0;i<PrePubDataCount;i++ {
	go func(index int) {

	    key,err := GetPreSignKey(pubkey,gid,index)
	    if err != nil {
 		return
	    }

	    da,err := predb.Get([]byte(key))
	    if da != nil && err == nil {
		psd := &PreSignData{}
		if err = psd.UnmarshalJSON(da);err == nil {
		    if strings.EqualFold(psd.Key,datakey) {
			data <- psd
			return
		    }
		}
	    }
	}(i)
    }

    WaitTime := 30 * time.Second
    checkKeyTimeOut := time.NewTicker(WaitTime)
    
    select {
	case ret := <-data:
	    return ret
	case <-checkKeyTimeOut.C:
	    common.Errorf("=====================GetPreSignData,get pre-sign data timeout.==========================","pubkey",pubkey,"gid",gid)
	    return nil
    }

    return nil
}

func DeletePreSignData(pubkey string,gid string,datakey string) error {
    if predb == nil || pubkey == "" || gid == "" || datakey == "" {
	common.Errorf("=======================DeletePreSignData,delete pre-sign data from db fail========================","pubkey",pubkey,"gid",gid,"datakey",datakey)
	return fmt.Errorf("delete pre-sign data from db error.")
    }

    data := make(chan string, 1)

    for i:=0;i<PrePubDataCount;i++ {
	go func(index int) {

	    key,err := GetPreSignKey(pubkey,gid,index)
	    if err != nil {
		return
	    }

	    da, err := predb.Get([]byte(key))
	    if da != nil && err == nil {
		psd := &PreSignData{}
		if err = psd.UnmarshalJSON(da);err == nil {
		    if strings.EqualFold(psd.Key,datakey) {
			data <- key
			return
		    }
		}
	    }
	}(i)
    }
    
    WaitTime := 30 * time.Second
    checkKeyTimeOut := time.NewTicker(WaitTime)
    
    select {
	case ret := <-data:
	    err := predb.Delete([]byte(ret))
	    if err != nil {
		common.Errorf("=====================DeletePreSignData,delete pre-sign data from db fail.==========================","pubkey",pubkey,"gid",gid,"err",err)
	    }

	    return err
	case <-checkKeyTimeOut.C:
	    common.Errorf("=====================DeletePreSignData,delete pre-sign data from db timeout.==========================","pubkey",pubkey,"gid",gid)
	    return fmt.Errorf("delete pre-sign data from db timeout.")
    }

    return fmt.Errorf("delete pre-sign data from db fail.")
}

func PickPreSignData(pubkey string,gid string) *PreSignData {
    if predb == nil || pubkey == "" || gid == "" {
	common.Errorf("=======================PickPreSignData,pick pre-sign data from db fail========================","pubkey",pubkey,"gid",gid)
	return nil
    }

    data := make(chan string, 1)

    for i:=0;i<PrePubDataCount;i++ {
	go func(index int) {

	    key,err := GetPreSignKey(pubkey,gid,index)
	    if err != nil {
		return
	    }

	    da, err := predb.Get([]byte(key))
	    if da != nil && err == nil {
		psd := &PreSignData{}
		if err = psd.UnmarshalJSON(da);err == nil {
		    if len(data) == 0 {
			data <- key
			return
		    }
		}
	    }
	}(i)
    }

    WaitTime := 30 * time.Second
    pickTimeOut := time.NewTicker(WaitTime)
    
    select {
	case ret := <-data:
	    da, err := predb.Get([]byte(ret))
	    if da != nil && err == nil {
		psd := &PreSignData{}
		if err = psd.UnmarshalJSON(da);err == nil {
		    err := predb.Delete([]byte(ret))
		    if err != nil {
			common.Errorf("=====================PickPreSignData,pick pre-sign data from db fail.==========================","pubkey",pubkey,"gid",gid,"err",err)
			return nil
		    }

		    return psd
		}
	    }

	case <-pickTimeOut.C:
	    common.Errorf("=====================PickPreSignData,pick pre-sign data from db timeout.==========================","pubkey",pubkey,"gid",gid)
	    return nil
    }
    
    return nil
}

//-----------------------------------------------------------------------

type TxDataPreSignData struct {
    TxType string
    PubKey string
    SubGid []string
}

func PreGenSignData(raw string) (string, error) {
    common.Debug("=====================PreGenSignData call CheckRaw ================","raw",raw)
    _,from,_,txdata,err := CheckRaw(raw)
    if err != nil {
	common.Errorf("=====================PreGenSignData,call CheckRaw finish================","raw",raw,"err",err)
	return err.Error(),err
    }

    pre,ok := txdata.(*TxDataPreSignData)
    if !ok {
	return "check raw fail,it is not *TxDataPreSignData",fmt.Errorf("check raw fail,it is not *TxDataPreSignData")
    }

    common.Debug("=====================PreGenSignData================","from",from,"raw",raw)
    ExcutePreSignData(pre)
    return "", nil
}

func ExcutePreSignData(pre *TxDataPreSignData) {
    if pre == nil {
	return
    }
    
    for _,gid := range pre.SubGid {
	go func(gg string) {
	    pub := Keccak256Hash([]byte(strings.ToLower(pre.PubKey + ":" + gg))).Hex()

	    PutPreSigal(pub,true)

	    common.Info("===================ExcutePreSignData,before generate pre-sign data===============","current total number of the data ",GetTotalCount(pre.PubKey,gg),"the number of remaining pre-sign data",(PrePubDataCount-GetTotalCount(pre.PubKey,gg)),"pubkey",pre.PubKey,"sub-groupid",gg)
	    for {
		    index,need := NeedPreSign(pre.PubKey,gg)
		    if need && index != -1 && GetPreSigal(pub) {
			    tt := fmt.Sprintf("%v",time.Now().UnixNano()/1e6)
			    nonce := Keccak256Hash([]byte(strings.ToLower(pub + tt + strconv.Itoa(index)))).Hex()
			    ps := &PreSign{Pub:pre.PubKey,Gid:gg,Nonce:nonce,Index:index}

			    m := make(map[string]string)
			    psjson,err := ps.MarshalJSON()
			    if err == nil {
				m["PreSign"] = string(psjson) 
			    }
			    m["Type"] = "PreSign"
			    val,err := json.Marshal(m)
			    if err != nil {
				time.Sleep(time.Duration(10000000))
				continue 
			    }
			    SendMsgToDcrmGroup(string(val),gg)

			    rch := make(chan interface{}, 1)
			    SetUpMsgList3(string(val),cur_enode,rch)
			    _, _,cherr := GetChannelValue(waitall+10,rch)
			    if cherr != nil {
				common.Errorf("=====================ExcutePreSignData in genkey fail========================","pubkey",pre.PubKey,"cherr",cherr,"Index",index)
			    }
			    
			    common.Info("===================ExcutePreSignData,after generate pre-sign data===============","current total number of the data ",GetTotalCount(pre.PubKey,gg),"the number of remaining pre-sign data",(PrePubDataCount-GetTotalCount(pre.PubKey,gg)),"pubkey",pre.PubKey,"sub-groupid",gg,"Index",index)
		    } 

		    time.Sleep(time.Duration(1000000))
	    }
	}(gid)
    }
}

//--------------------------------------------------------------

//pub = hash256(pubkey + gid)
func GetPreSigal(pub string) bool {
	data,exsit := PreSigal.ReadMap(strings.ToLower(pub)) 
	if exsit {
		sigal := data.(string)
		if sigal == "false" {
			return false
		}
	}

	return true
}

func PutPreSigal(pub string,val bool) {
	if val {
		PreSigal.WriteMap(strings.ToLower(pub),"true")
		return
	}

	PreSigal.WriteMap(strings.ToLower(pub),"false")
}

//-------------------------------------------------------------------------


