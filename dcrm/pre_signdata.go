
/*
 *  Copyright (C) 2018-2019  Fusion Foundation Ltd. All rights reserved.
 *  Copyright (C) 2018-2019  haijun.cai@fusion.org
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
	"time"
	"fmt"
	"errors"
	"sync"
	"strconv"
	"encoding/json"
	dberrors "github.com/syndtr/goleveldb/leveldb/errors"
)

var (
	PrePubDataCount = 2000
	PreBip32DataCount = 4
	PreSigal  = common.NewSafeMap(10) //make(map[string][]byte)
	PrePubGids  = common.NewSafeMap(10)
)

//------------------------------------------------

type PreSign struct {
	Pub string
	InputCode string //for bip32
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

func GetPreSignKey(pubkey string,inputcode string,gid string,index int) (string,error) {
    if pubkey == "" || gid == "" || index < 0 {
	return "",fmt.Errorf("get pre-sign key fail,param error.")
    }

    if inputcode != "" {
	key := strings.ToLower(Keccak256Hash([]byte(strings.ToLower(pubkey + ":" + inputcode + ":" + gid + ":" + strconv.Itoa(index)))).Hex())
	return key,nil
    }

    key := strings.ToLower(Keccak256Hash([]byte(strings.ToLower(pubkey + ":" + gid + ":" + strconv.Itoa(index)))).Hex())
    return key,nil
}

//[start,end]
//mid = (end + 1 - start)/2
//left = [start,start - 1 + mid]
//right = [start + mid,end]
func BinarySearchVacancy(pubkey string,inputcode string,gid string,start int,end int) int {
    if predb == nil || pubkey == "" || gid == "" {
	return -1
    }

    if start < 0 || end < 0 || start > end {
	return -1
    }

    if start == end {
	key,err := GetPreSignKey(pubkey,inputcode,gid,start)
	if err != nil {
	    return -1
	}
	_,err = predb.Get([]byte(key))
	if IsNotFoundErr(err) {
	    return start
	}

	return -1
    }

    mid := (end + 1 - start)/2
    left := BinarySearchVacancy(pubkey,inputcode,gid,start,start + mid - 1)
    if left >= 0 {
	return left
    }
    right := BinarySearchVacancy(pubkey,inputcode,gid,start + mid,end)
    return right
}

func NeedPreSign(pubkey string,inputcode string,gid string) (int,bool) {

    if predb == nil || pubkey == "" || gid == "" || PrePubDataCount < 1 {
	return -1,false
    }

    index := BinarySearchVacancy(pubkey,inputcode,gid,0,PrePubDataCount - 1)
    if index < 0 {
	return index,false
    }

    return index,true
}

func GetTotalCount(pubkey string,inputcode string,gid string) int {
    if predb == nil || pubkey == "" || gid == "" || PrePubDataCount < 1 {
	return 0
    }

    index := BinarySearchVacancy(pubkey,inputcode,gid,0,PrePubDataCount - 1)
    if index < 0 {
	count := 0
	 var wg sync.WaitGroup
	for i:=0;i<PrePubDataCount;i++ {
	    wg.Add(1)
	    go func(index int) {
		defer wg.Done()

		key,err := GetPreSignKey(pubkey,inputcode,gid,index)
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

    return index
}

func PutPreSignData(pubkey string,inputcode string,gid string,index int,val *PreSignData,force bool) error {
    if predb == nil || val == nil || index < 0 {
	return fmt.Errorf("put pre-sign data fail,param error.") 
    }

    key,err := GetPreSignKey(pubkey,inputcode,gid,index)
    if err != nil {
	return err
    }

    _,err = predb.Get([]byte(key))
    if IsNotFoundErr(err) {
	value,err := val.MarshalJSON()
	if err != nil {
	    common.Error("====================PutPreSignData,marshal pre-sign data error ======================","pubkey",pubkey,"gid",gid,"index",index,"val",val,"err",err)
	    return err
 	}

	err = predb.Put([]byte(key),value)
	if err != nil {
	    common.Error("====================PutPreSignData,put pre-sign data to db fail ======================","pubkey",pubkey,"gid",gid,"index",index,"datakey",val.Key,"err",err)
	}

	//common.Debug("====================PutPreSignData,put pre-sign data to db success ======================","pubkey",pubkey,"gid",gid,"index",index,"datakey",val.Key)
 	return err
    }
    
    if force {
	value,err := val.MarshalJSON()
	if err != nil {
	    common.Error("====================PutPreSignData,force update,marshal pre-sign data error ======================","pubkey",pubkey,"gid",gid,"index",index,"val",val,"err",err)
	    return nil //force update fail,but still return nil
 	}

	err = predb.Put([]byte(key),value)
	if err != nil {
	    common.Error("====================PutPreSignData,force update,put pre-sign data to db fail ======================","pubkey",pubkey,"gid",gid,"index",index,"datakey",val.Key,"err",err)
	    return nil //force update fail,but still return nil
	}

	//common.Debug("====================PutPreSignData,force update,put pre-sign data to db success ======================","pubkey",pubkey,"gid",gid,"index",index,"datakey",val.Key)
	return nil
    }

    return fmt.Errorf(" The pre-sign data of the key has been put to db before.")
}

//[start,end]
//mid = (end + 1 - start)/2
//left = [start,start - 1 + mid]
//right = [start + mid,end]
func BinarySearchPreSignData(pubkey string,inputcode string,gid string,datakey string,start int,end int) (int,*PreSignData) {
    if predb == nil || pubkey == "" || gid == "" {
	return -1,nil
    }

    if start < 0 || end < 0 || start > end {
	return -1,nil
    }

    if start == end {
	key,err := GetPreSignKey(pubkey,inputcode,gid,start)
	if err != nil {
	    return -1,nil
	}
	da,err := predb.Get([]byte(key))
	if da != nil && err == nil {
	    psd := &PreSignData{}
	    if err = psd.UnmarshalJSON(da);err == nil {
		if strings.EqualFold(psd.Key,datakey) {
		    return start,psd
		}
	    }
	}

	return -1,nil
    }

    mid := (end + 1 - start)/2
    left,data := BinarySearchPreSignData(pubkey,inputcode,gid,datakey,start,start + mid - 1)
    if left >= 0 {
	return left,data
    }
    right,data := BinarySearchPreSignData(pubkey,inputcode,gid,datakey,start + mid,end)
    return right,data
}

func GetPreSignData(pubkey string,inputcode string,gid string,datakey string) *PreSignData {
    if predb == nil || pubkey == "" || gid == "" || datakey == "" || PrePubDataCount < 1 {
	return nil
    }

    _,data := BinarySearchPreSignData(pubkey,inputcode,gid,datakey,0,PrePubDataCount - 1)
    return data
}

func DeletePreSignData(pubkey string,inputcode string,gid string,datakey string) error {
    if predb == nil || pubkey == "" || gid == "" || datakey == "" || PrePubDataCount < 1 {
	common.Error("=======================DeletePreSignData,delete pre-sign data from db fail========================","pubkey",pubkey,"gid",gid,"datakey",datakey)
	return fmt.Errorf("delete pre-sign data from db error.")
    }

    index,data := BinarySearchPreSignData(pubkey,inputcode,gid,datakey,0,PrePubDataCount - 1)
    if data == nil || index < 0 {
	return fmt.Errorf("pre-sign data was not found.")
    }
    
    key,err := GetPreSignKey(pubkey,inputcode,gid,index)
    if err != nil {
	return err 
    }

    err = predb.Delete([]byte(key))
    if err != nil {
	common.Error("======================DeletePreSignData,delete pre-sign data from db fail.==========================","pubkey",pubkey,"gid",gid,"index",index,"datakey",datakey,"err",err)
    }

    return err
}

//[start,end]
//mid = (end + 1 - start)/2
//left = [start,start - 1 + mid]
//right = [start + mid,end]
func BinarySearchPick(pubkey string,inputcode string,gid string,start int,end int) (int,*PreSignData) {
    if predb == nil || pubkey == "" || gid == "" {
	return -1,nil
    }

    if start < 0 || end < 0 || start > end {
	return -1,nil
    }

    if start == end {
	key,err := GetPreSignKey(pubkey,inputcode,gid,start)
	if err != nil {
	    return -1,nil
	}
	da, err := predb.Get([]byte(key))
	if da != nil && err == nil {
	    psd := &PreSignData{}
	    if err = psd.UnmarshalJSON(da);err == nil {
		return start,psd
	    }
	}

	return -1,nil
    }

    mid := (end + 1 - start)/2
    left,data := BinarySearchPick(pubkey,inputcode,gid,start,start + mid - 1)
    if left >= 0 {
	return left,data
    }
    right,data := BinarySearchPick(pubkey,inputcode,gid,start + mid,end)
    return right,data
}

func PickPreSignData(pubkey string,inputcode string,gid string) *PreSignData {
    if predb == nil || pubkey == "" || gid == "" || PrePubDataCount < 1 {
	common.Error("=======================PickPreSignData,param error.========================","pubkey",pubkey,"gid",gid)
	return nil
    }

    index,data := BinarySearchPick(pubkey,inputcode,gid,0,PrePubDataCount - 1)
    if index < 0 || data == nil {
	return nil
    }

    key,err := GetPreSignKey(pubkey,inputcode,gid,index)
    if err != nil {
	return nil 
    }
    
    err = predb.Delete([]byte(key))
    if err != nil {
	common.Error("=====================PickPreSignData,delete pre-sign data from db fail.==========================","pubkey",pubkey,"gid",gid,"err",err)
	return nil
    }

    return data
}

//-----------------------------------------------------------------------

type TxDataPreSignData struct {
    TxType string
    PubKey string
    SubGid []string
}

func PreGenSignData(raw string) (string, error) {
    _,from,_,txdata,err := CheckRaw(raw)
    if err != nil {
	common.Error("=====================PreGenSignData,check raw data error================","raw",raw,"from",from,"err",err)
	return err.Error(),err
    }

    pre,ok := txdata.(*TxDataPreSignData)
    if !ok {
	common.Error("=====================PreGenSignData, get tx data error================","raw",raw,"from",from)
	return "",fmt.Errorf("get tx data error.")
    }

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
	    err := SavePrekeyToDb(pre.PubKey,"",gg)
	    if err != nil {
		common.Error("=========================ExcutePreSignData,save (pubkey,gid) to db fail.=======================","pubkey",pre.PubKey,"gid",gg,"err",err)
		return
	    }

	    common.Info("================================ExcutePreSignData,before pre-generation of sign data ==================================","current total number of the data ",GetTotalCount(pre.PubKey,"",gg),"pubkey",pre.PubKey,"sub-groupid",gg)
	    for {
		    b := GetPreSigal(pub)
		    if b {
			index,need := NeedPreSign(pre.PubKey,"",gg)

			if need && index != -1 {
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

			    reply := false
			    timeout := make(chan bool, 1)
			    go func() {
				syncWaitTime := 40 * time.Second
				syncWaitTimeOut := time.NewTicker(syncWaitTime)
				
				for {
				    select {
					case <-rch:
					    reply = true
					    timeout <-false
					    return
					case <-syncWaitTimeOut.C:
					    reply = false
					    timeout <-true
					    return
				    }
				}
			    }()
			    <-timeout

			    if !reply {
				common.Error("=====================ExcutePreSignData, failed to pre-generate sign data.========================","pubkey",pre.PubKey,"sub-groupid",gg,"Index",index)
				continue
			    }
			    
			    common.Info("================================ExcutePreSignData,after pre-generation of sign data==================================","current total number of the data ",GetTotalCount(pre.PubKey,"",gg),"pubkey",pre.PubKey,"sub-groupid",gg,"Index",index)
			}
		    }

		    time.Sleep(time.Duration(1000000))
	    }
	}(gid)
    }
}

func AutoPreGenSignData() {
    if prekey == nil {
	return
    }

    iter := prekey.NewIterator()
    for iter.Next() {
	value := []byte(string(iter.Value()))
	if len(value) == 0 {
	    continue
	}

	go func(val string) {
	    common.Debug("======================AutoPreGenSignData=========================","val",val)
	    tmp := strings.Split(val,":") // val = pubkey:gid
	    if len(tmp) < 2 || tmp[0] == "" || tmp[1] == "" {
		return
	    }
	    
	    subgid := make([]string,0)
	    subgid = append(subgid,tmp[1])
	    pre := &TxDataPreSignData{TxType:"PRESIGNDATA",PubKey:tmp[0],SubGid:subgid}
	    ExcutePreSignData(pre)
	}(string(value))
    }
    
    iter.Release()
}

func SavePrekeyToDb(pubkey string,inputcode string,gid string) error {
    if prekey == nil {
	return fmt.Errorf("db open fail.")
    }

    var pub string
    var val string
    if inputcode != "" {
	pub = strings.ToLower(Keccak256Hash([]byte(strings.ToLower(pubkey + ":" + inputcode + ":" + gid))).Hex())
	val = pubkey + ":" + inputcode + ":" + gid
    } else {
	pub = strings.ToLower(Keccak256Hash([]byte(strings.ToLower(pubkey + ":" + gid))).Hex())
	val = pubkey + ":" + gid
    }

    _,err := prekey.Get([]byte(pub))
    if IsNotFoundErr(err) {
	common.Debug("==================SavePrekeyToDb, Not Found pub.=====================","pub",pub,"pubkey",pubkey,"gid",gid)
	err = prekey.Put([]byte(pub),[]byte(val))
	if err != nil {
	    common.Error("==================SavePrekeyToDb, put prekey to db fail.=====================","pub",pub,"pubkey",pubkey,"gid",gid,"err",err)
	    return err
	}
    }

    return nil
}

func IsNotFoundErr(err error) bool {
    return errors.Is(err, dberrors.ErrNotFound)
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

func NeedToStartPreBip32(pub string) bool {
    _,exsit := PreSigal.ReadMap(strings.ToLower(pub))
    return !exsit
}

func NeedPreSignForBip32(pubkey string,inputcode string,gid string) (int,bool) {

    if predb == nil || pubkey == "" || inputcode == "" || gid == "" {
	return -1,false
    }

    idx := make(chan int, 1)

    for i:=0;i<PreBip32DataCount;i++ {
	go func(index int) {

	    key,err := GetPreSignKey(pubkey,inputcode,gid,index)
	    if err != nil {
		return
	    }

	    _,err = predb.Get([]byte(key))
	    if IsNotFoundErr(err) {
		if len(idx) == 0 {
		    idx <- index
		}
	    }
	}(i)
    }

    WaitTime := 60 * time.Second
    getIndexTimeOut := time.NewTicker(WaitTime)
    
    select {
	case ret := <-idx:
	    return ret,true
	case <-getIndexTimeOut.C:
	    return -1,false
    }

    return -1,false
}


func GetPrePubGids(pub string) []string {
	data,exsit := PrePubGids.ReadMap(strings.ToLower(pub)) 
	if exsit {
		gids := data.([]string)
		return gids
	}

	return nil
}

func PutPrePubGids(pub string,gids []string) {
    old := GetPrePubGids(pub)
    if old == nil {
	old = make([]string,0)
	old = append(old,gids...)
	PrePubGids.WriteMap(strings.ToLower(pub),old)
	return
    }

    old = append(old,gids...)
    PrePubGids.WriteMap(strings.ToLower(pub),gids)
}

//-----------------------------------------------------------

