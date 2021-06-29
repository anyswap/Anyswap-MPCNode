
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
	"encoding/json"
	"strconv"
)

var (
	predb *ethdb.LDBDatabase
	PrePubDataCount = 2000
	PreSigal  = common.NewSafeMap(10) //make(map[string][]byte)
)

//------------------------------------
type PreSign struct {
	Pub string
	Gid string
	Nonce string // == data pocket KEY
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

//----------------------------------
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
//presignkey
// (k,v) in db,  k == PreSignKey.MarshalJSON,  v == PreSignData.MarshalJSON
type PreSignKey struct {
	PubKey string
	Gid string
	Index int
}

func (Psk *PreSignKey) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		PubKey string `json:"PubKey"`
		Gid string `json:"Gid"`
		Index string `json:"Index"`
	}{
		PubKey: Psk.PubKey,
		Gid: Psk.Gid,
		Index: strconv.Itoa(Psk.Index),
	})
}

func (Psk *PreSignKey) UnmarshalJSON(raw []byte) error {
	var psk struct {
		PubKey string `json:"PubKey"`
		Gid string `json:"Gid"`
		Index string `json:"Index"`
	}
	if err := json.Unmarshal(raw, &psk); err != nil {
		return err
	}

	Psk.PubKey = psk.PubKey
	Psk.Gid = psk.Gid

	var err error
	Psk.Index,err = strconv.Atoi(psk.Index)
	if err != nil {
	    return err
	}

	return nil
}

//-------------------------------------

func NeedPreSign(pubkey string,gid string) (int,bool) {

    if predb == nil {
	return -1,false
    }

    idx := make(chan int, PrePubDataCount)

    var wg sync.WaitGroup
    for i:=0;i<PrePubDataCount;i++ {
	wg.Add(1)
	go func(index int) {
	    defer wg.Done()
	    
	    key := &PreSignKey{PubKey:pubkey,Gid:gid,Index:index}
	    s,err := key.MarshalJSON()
	    if err != nil {
		fmt.Printf("==================NeedPreSign,marshal pre-sign data err = %v ====================\n",err)
		return
	    }
	    
	    _, err = predb.Get(s)
	    if err != nil {
		//if len(idx) == 0 {
		    //fmt.Printf("==================NeedPreSign,write index = %v to idx channel ====================\n",index)
		    idx <- index
		//}
	    }
	}(i)
    }
    wg.Wait()

    if len(idx) == 0 {
	return -1,false
    }

    ret := <- idx
    return ret,true
}

func GetTotalCount(pubkey string,gid string) int {
    if predb == nil {
	return 0
    }

    count := 0

    var wg sync.WaitGroup
    for i:=0;i<PrePubDataCount;i++ {
	wg.Add(1)
	go func(index int) {
	    defer wg.Done()
	    
	    key := &PreSignKey{PubKey:pubkey,Gid:gid,Index:index}
	    s,err := key.MarshalJSON()
	    if err != nil {
		return
	    }
	    
	    _, err = predb.Get(s)
	    if err == nil {
		count++
	    }
	}(i)
    }
    wg.Wait()

    return count
}

func PutPreSignData(pubkey string,gid string,index int,val *PreSignData) error {
    if predb == nil || val == nil || index < 0 {
	return errors.New("param error.")
    }

    key := &PreSignKey{PubKey:pubkey,Gid:gid,Index:index}
    s,err := key.MarshalJSON()
    if err != nil {
	common.Info("======================PutPreSignData,marshal presign key error.=================","pubkey",pubkey,"gid",gid,"index",index,"err",err)
	return err
    }
    
    //da, err = predb.Get(s)
    //if err != nil || da == nil {
	value,err := val.MarshalJSON()
	if err != nil {
	    common.Info("======================PutPreSignData,marshal presign data error.=================","pubkey",pubkey,"gid",gid,"index",index,"err",err)
	    return err
	}

	/*err = predb.Put(s, value)
	if err == nil {
	    common.Debug("===============PutPreSignData, put pre-sign data into db success.=================","pubkey",pubkey,"gid",gid,"index",index,"key",val.Key)
	} else {
	    common.Debug("===============PutPreSignData, put pre-sign data into db fail.=================","pubkey",pubkey,"gid",gid,"index",index,"key",val.Key,"err",err)
	}*/

	//retry
	for i:=0;i<10;i++ {
	    err = predb.Put(s, value)
	    if err == nil {
		common.Debug("===============PutPreSignData, put pre-sign data into db success.=================","pubkey",pubkey,"gid",gid,"index",index,"key",val.Key)
		return nil	
	    }
	    
	    time.Sleep(time.Duration(1) * time.Second) //1000 == 1s
	}
	
	common.Debug("===============PutPreSignData, put pre-sign data into db fail.=================","pubkey",pubkey,"gid",gid,"index",index,"key",val.Key)
	return errors.New("put pre-sign data into db fail.")
	//
	
	//return nil
    //}

    //return errors.New("pre-sign data on the key already exsit.")
}

func GetPreSignData(pubkey string,gid string,key string) *PreSignData {
    if predb == nil {
	return nil
    }
    
    data := make(chan *PreSignData, 1)

    var wg sync.WaitGroup
    for i:=0;i<PrePubDataCount;i++ {
	wg.Add(1)
	go func(index int) {
	    defer wg.Done()
	    
	    key2 := &PreSignKey{PubKey:pubkey,Gid:gid,Index:index}
	    s,err := key2.MarshalJSON()
	    if err != nil {
		common.Info("====================GetPreSignData,marshal presign key fail=================","pubkey",pubkey,"gid",gid,"pick key",key,"err",err)
		return
	    }
	    
	    da, err := predb.Get(s)
	    if err == nil {
		psd := &PreSignData{}
		if err = psd.UnmarshalJSON(da);err == nil {
		    //common.Info("====================GetPreSignData,unmarshal presign data fail=================","pubkey",pubkey,"gid",gid,"pick key",key,"err",err)
		    if strings.EqualFold(psd.Key,key) {
			common.Info("====================GetPreSignData, get presign data success=================","pubkey",pubkey,"gid",gid,"pick key",key)
			data <- psd
			return
		    }
		} else {
		    common.Info("====================GetPreSignData,unmarshal presign data fail=================","pubkey",pubkey,"gid",gid,"pick key",key,"err",err)
		}
	    } 
	}(i)
    }
    wg.Wait()

    if len(data) == 0 {
	common.Info("====================GetPreSignData, get presign data fail=================","pubkey",pubkey,"gid",gid,"pick key",key)
	return nil
    }

    ret := <- data
    return ret
}

func DeletePreSignData(pubkey string,gid string,key string) {
    if predb == nil {
	return
    }
    
    var wg sync.WaitGroup
    for i:=0;i<PrePubDataCount;i++ {
	wg.Add(1)
	go func(index int) {
	    defer wg.Done()
	    
	    key2 := &PreSignKey{PubKey:pubkey,Gid:gid,Index:index}
	    s,err := key2.MarshalJSON()
	    if err != nil {
		return
	    }
	    
	    da, err := predb.Get(s)
	    if err == nil {
		psd := &PreSignData{}
		if err = psd.UnmarshalJSON(da);err == nil {
		    if strings.EqualFold(psd.Key,key) {
			/*err = predb.Delete(s)
			if err == nil {
			    common.Debug("===============DeletePreSignData, del pre-sign data from db success.=================","pubkey",pubkey,"gid",gid,"index",index,"key",key)
			} else {
			    common.Debug("===============DeletePreSignData, del pre-sign data from db fail.=================","pubkey",pubkey,"gid",gid,"index",index,"key",key,"err",err)
			}
			
			return*/
			for i:=0;i<10;i++ {
			    err = predb.Delete(s)
			    if err == nil {
				common.Debug("===============DeletePreSignData, del pre-sign data from db success.=================","pubkey",pubkey,"gid",gid,"index",index,"key",key)
				return
			    }

			    time.Sleep(time.Duration(1) * time.Second) //1000 == 1s
			}
			
			common.Debug("===============DeletePreSignData, del pre-sign data from db fail.=================","pubkey",pubkey,"gid",gid,"index",index,"key",key)
			return
		    }
		}
	    }
	}(i)
    }
    wg.Wait()
}

func PickPreSignData(pubkey string,gid string) *PreSignData {
    if predb == nil {
	return nil
    }
    
    data := make(chan *PreSignData,1)
    
    var wg sync.WaitGroup
    for i:=0;i<PrePubDataCount;i++ {
	wg.Add(1)
	go func(index int) {
	    defer wg.Done()
	    
	    key2 := &PreSignKey{PubKey:pubkey,Gid:gid,Index:index}
	    s,err := key2.MarshalJSON()
	    if err != nil {
		common.Info("=========================PickPreSignData,marshal presign key error.=========================","err",err,"pubkey",pubkey,"gid",gid,"index",index)
		return
	    }
	    
	    da, err := predb.Get(s)
	    //common.Info("=========================PickPreSignData,get presign data from localdb.=========================","err",err,"pubkey",pubkey,"gid",gid,"index",index)
	    if err == nil {
		psd := &PreSignData{}
		if err = psd.UnmarshalJSON(da);err == nil {
		    if len(data) == 0 {
			//err := predb.Delete(s)
			//if err == nil {
			    data <- psd
			    common.Info("=========================PickPreSignData,pick success.=========================","pubkey",pubkey,"gid",gid,"index",index)
			    return
			//}
		    }
		}

		//common.Info("=========================PickPreSignData,unmarshal presign data error.=========================","err",err,"pubkey",pubkey,"gid",gid,"index",index)
	    }
	}(i)
    }
    wg.Wait()

    if len(data) == 0 {
	common.Info("=========================PickPreSignData,pick fail.=========================","pubkey",pubkey,"gid",gid)
	return nil
    }

    ret := <- data

    //we also remove it from the local db.
    key2 := &PreSignKey{PubKey:pubkey,Gid:gid,Index:ret.Index}
    s,err := key2.MarshalJSON()
    if err != nil {
	common.Info("=========================PickPreSignData,remove presign data from localdb. marshal presign key error.=========================","err",err,"pubkey",pubkey,"gid",gid,"index",ret.Index)
	return nil
    }

    /*err = predb.Delete(s)
    if err != nil {
	common.Debug("===============PickPreSignData, pick pre-sign data fail.=================","pubkey",pubkey,"gid",gid,"index",ret.Index,"key",ret.Key,"err",err)
	return nil
    }

    common.Debug("===============PickPreSignData, pick pre-sign data success.=================","pubkey",pubkey,"gid",gid,"index",ret.Index,"key",ret.Key,"err",err)*/

    for i:=0;i<10;i++ {
	err = predb.Delete(s)
	if err == nil {
	    common.Debug("===============PickPreSignData, remove presign data from localdb success.=================","pubkey",pubkey,"gid",gid,"index",ret.Index,"key",ret.Key)
	    return ret
	}

	time.Sleep(time.Duration(1) * time.Second) //1000 == 1s
    }

    common.Debug("===============PickPreSignData, remove presign data from localdb fail.=================","pubkey",pubkey,"gid",gid,"index",ret.Index,"key",ret.Key,"err",err)
    return nil 
}

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

//-------------------------------------------
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

//--------------------------------------------

//the data brocast to all nodes in group,include sign data and Pick Key Of PreSignData.
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

//--------------------------------------------
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

//-------------------------------------------------

//the data prepare for signing,include sign data and PreSignData 
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

//---------------------------------------------------

//the path save the pre-sign data
func GetPreDbDir() string {
	dir := common.DefaultDataDir()
	//dir += "/dcrmdata/dcrmpredb" + cur_enode  //old path
	dir += "/smpc-data/pre-sign-db" + cur_enode //new path
	return dir
}

//----------------------------------------------------

//the data broacast to all nodes in group for checking the status of writing pre-sign data to local db
type PreSignDataStatus struct {
    MsgPrex string
    Status string
    Gid string
    ThresHold int 
}

func (psds *PreSignDataStatus) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		MsgPrex string `json:"MsgPrex"`
		Status string `json:"Status"`
		Gid string `json:"Gid"`
		ThresHold string `json:"ThresHold"`
	}{
		MsgPrex: psds.MsgPrex,
		Status: psds.Status,
		Gid: psds.Gid,
		ThresHold: strconv.Itoa(psds.ThresHold),
	})
}

func (psds *PreSignDataStatus) UnmarshalJSON(raw []byte) error {
	var psd struct {
		MsgPrex string `json:"MsgPrex"`
		Status string `json:"Status"`
		Gid string `json:"Gid"`
		ThresHold string `json:"ThresHold"`
	}
	if err := json.Unmarshal(raw, &psd); err != nil {
		return err
	}

	psds.MsgPrex = psd.MsgPrex
	psds.Status = psd.Status
	psds.Gid = psd.Gid
	psds.ThresHold,_ = strconv.Atoi(psd.ThresHold)
	return nil
}

//--------------------------------------------------------------------------

func CheckAllSignNodesPreSignDataStatus(msgprex string, ch chan interface{},w *RPCReqWorker) bool {
    if msgprex == "" || w == nil {
	res := RpcDcrmRes{Ret: "", Err: fmt.Errorf("param error")}
	ch <- res
	return false
    }

    mp := []string{msgprex, cur_enode}
    enode := strings.Join(mp, "-")
    s0 := "CHECKPRESIGNDATASTATUS"
    s1 := "true" 
    ss := enode + common.Sep + s0 + common.Sep + s1
    SendMsgToDcrmGroup(ss, w.groupid)
    DisMsg(ss)

    _, tip, cherr := GetChannelValue(ch_t, w.bcheckpresigndatastatus)

    if cherr != nil {
	fmt.Printf("==========================CheckAllSignNodesPreSignDataStatus, cherr = %v ================================\n",cherr)
	res := RpcDcrmRes{Ret: "", Tip: tip, Err: fmt.Errorf("check pre-sign data status fail.")}
	ch <- res
	return false
    }

    fmt.Printf("==========================CheckAllSignNodesPreSignDataStatus, success.================================\n")
    res := RpcDcrmRes{Ret: "success", Tip: "", Err: nil}
    ch <- res
    return true
}

//--------------------------------------------------------------------------------

//the data for pre-generating pre-sign data pockets
type TxDataPreSignData struct {
    TxType string
    PubKey string
    SubGid []string
}

//-------------------------------------------------------------------------------------

func PreGenSignData(raw string) (string, error) {
    common.Debug("=====================PreGenSignData call CheckRaw ================","raw",raw)
    _,from,_,txdata,err := CheckRaw(raw)
    if err != nil {
	common.Info("=====================PreGenSignData,call CheckRaw finish================","raw",raw,"err",err)
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

	    //common.Info("===================ExcutePreSignData,before generate pre-sign data===============","current total number of the data ",GetTotalCount(pre.PubKey,gg),"the number of remaining pre-sign data",(PrePubDataCount-GetTotalCount(pre.PubKey,gg)),"pubkey",pre.PubKey,"sub-groupid",gg)
	    common.Info("===================ExcutePreSignData,before generate pre-sign data===============")
	    common.Info("","current total number of the data",GetTotalCount(pre.PubKey,gg))
	    common.Info("","the number of remaining pre-sign data",(PrePubDataCount-GetTotalCount(pre.PubKey,gg)))
	    common.Info("","pubkey",pre.PubKey,"sub-gid",gg)
	    for {
		    index,need := NeedPreSign(pre.PubKey,gg)
		    if need && index != -1 && GetPreSigal(pub) {
			    //tt := fmt.Sprintf("%v",time.Now().UnixNano()/1e6)
			    tt := fmt.Sprintf("%v",time.Now().UnixNano())
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
				common.Info("=====================ExcutePreSignData in genkey fail========================","pubkey",pre.PubKey,"cherr",cherr,"Index",index)
			    } else {
				//common.Info("===================ExcutePreSignData,after generate pre-sign data===============","current total number of the data ",GetTotalCount(pre.PubKey,gg),"the number of remaining pre-sign data",(PrePubDataCount-GetTotalCount(pre.PubKey,gg)),"pubkey",pre.PubKey,"sub-groupid",gg,"Index",index)
				common.Info("===================ExcutePreSignData,after generate pre-sign data===============")
				common.Info("","current total number of the data",GetTotalCount(pre.PubKey,gg))
				common.Info("","the number of remaining pre-sign data",(PrePubDataCount-GetTotalCount(pre.PubKey,gg)))
				common.Info("","pubkey",pre.PubKey,"sub-gid",gg,"Index",index)
			    }
		    } 

		    time.Sleep(time.Duration(1000000))
	    }
	}(gid)
    }
}

func AutoPreGenSignData() {
    if predb == nil {
	return
    }

    var allpresign sync.Map

    iter := predb.NewIterator()
    for iter.Next() {

	key := []byte(string(iter.Key())) //must be deep copy,or show me the error: "panic: JSON decoder out of sync - data changing underfoot?"
	//common.Debug("====================AutoPreGenSignData===================","key",string(iter.Key()))
	if len(key) == 0 {
	    continue
	}

	go func(kd []byte) {
	    psk := &PreSignKey{}
	    if err := psk.UnmarshalJSON(kd);err != nil {
		common.Debug("====================AutoPreGenSignData,unmarshal presign key err===================","key",string(iter.Key()),"err",err)
	       return 
	    }

	    pub := Keccak256Hash([]byte(strings.ToLower(psk.PubKey + ":" + psk.Gid))).Hex()
	    if _, ok := allpresign.Load(strings.ToLower(pub)); ok {
		//common.Debug("====================AutoPreGenSignData,load presign key fail===================","key",string(iter.Key()),"pubkey",psk.PubKey,"gid",psk.Gid)
		return	
	    }
	    allpresign.Store(strings.ToLower(pub), true)

	    common.Debug("====================AutoPreGenSignData,bagin to auto gen presign data.===================","key",string(iter.Key()),"pubkey",psk.PubKey,"gid",psk.Gid)

	    subgid := make([]string,0)
	    subgid = append(subgid,psk.Gid)
	    pre := &TxDataPreSignData{TxType:"PRESIGNDATA",PubKey:psk.PubKey,SubGid:subgid}
	    ExcutePreSignData(pre)
	}(key)
    }
    
    iter.Release()
}


