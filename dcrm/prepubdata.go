
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

    idx := make(chan int, 1)

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
	    
	    _, err = predb.Get([]byte(strings.ToLower(string(s))))
	    if err != nil {
		if len(idx) == 0 {
		    idx <- index
		}
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
	    
	    _, err = predb.Get([]byte(strings.ToLower(string(s))))
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
	return err
    }
    
    _, err = predb.Get([]byte(strings.ToLower(string(s))))
    if err != nil {
	value,err := val.MarshalJSON()
	if err != nil {
	    return err
	}

	predb.Put([]byte(strings.ToLower(string(s))), value)
	return nil
    }

    return errors.New("pre-sign data on the key already exsit.")
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
		return
	    }
	    
	    da, err := predb.Get([]byte(strings.ToLower(string(s))))
	    if err == nil {
		psd := &PreSignData{}
		if err = psd.UnmarshalJSON(da);err == nil {
		    if strings.EqualFold(psd.Key,key) {
			data <- psd
			return
		    }
		}
	    }
	}(i)
    }
    wg.Wait()

    if len(data) == 0 {
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
	    
	    da, err := predb.Get([]byte(strings.ToLower(string(s))))
	    if err == nil {
		psd := &PreSignData{}
		if err = psd.UnmarshalJSON(da);err == nil {
		    if strings.EqualFold(psd.Key,key) {
			predb.Delete([]byte(strings.ToLower(string(s))))
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
    
    data := make(chan *PreSignData, 1)
    
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
	    
	    da, err := predb.Get([]byte(strings.ToLower(string(s))))
	    if err == nil {
		psd := &PreSignData{}
		if err = psd.UnmarshalJSON(da);err == nil {
		    if len(data) == 0 {
			err := predb.Delete([]byte(strings.ToLower(string(s))))
			if err == nil {
			    data <- psd
			    return
			}
		    }
		}
	    }
	}(i)
    }
    wg.Wait()

    if len(data) == 0 {
	return nil
    }

    ret := <- data
    return ret
}

/////////
/*type PreSignHashPair struct {
	PubKey string
	Gid string
}

func (PsHp *PreSignHashPair) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		PubKey string `json:"PubKey"`
		Gid string `json:"Gid"`
	}{
		PubKey: PsHp.PubKey,
		Gid: PsHp.Gid,
	})
}

func (PsHp *PreSignHashPair) UnmarshalJSON(raw []byte) error {
	var pshp struct {
		PubKey string `json:"PubKey"`
		Gid string `json:"Gid"`
	}
	if err := json.Unmarshal(raw, &pshp); err != nil {
		return err
	}

	PsHp.PubKey = pshp.PubKey
	PsHp.Gid = pshp.Gid
	return nil
}

func GetPreSignHashPair(pub string) *PreSignHashPair {
	data,exsit := PreSignHashPairMap.ReadMap(strings.ToLower(pub)) 
	if exsit {
		pshp := data.(*PreSignHashPair)
		if pshp != nil {
			return pshp
		}
	}

	return nil
}

func PutPreSignHashPair(pub string,val *PreSignHashPair) {
	if val == nil {
		return
	}

	PreSignHashPairMap.WriteMap(strings.ToLower(pub),val)
}
*/
////////

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

/*func GetTotalCount(pub string) int {
	data,exsit := PreSignData.ReadMap(strings.ToLower(pub)) 
	if exsit {
		datas := data.([]*PrePubData)

		if len(datas) == 0 {
			return 0
		} else {
			if datas[0].Used == true {
				return 0
			}
		}

		return len(datas)
	}

	return 0
}

func GetTotalCount2(pub string) int {
	data,exsit := PreSignDataBak.ReadMap(strings.ToLower(pub)) 
	if exsit {
		datas := data.([]*PrePubData)
		if len(datas) == 0 {
			return 0
		} else {
			if datas[0].Used == true {
				return 0
			}
		}

		return len(datas)
	}

	return 0
}

func NeedPreSignBak(pub string) bool {
	if GetTotalCount2(pub) >= PrePubDataCount {
		return false
	}

	return true
}

func PutPreSignBak(pub string,val *PrePubData) {
	if val == nil {
		return
	}

	data,exsit := PreSignDataBak.ReadMap(strings.ToLower(pub)) 
	if exsit {
		datas := data.([]*PrePubData)
		datas = append(datas,val)
		PreSignDataBak.WriteMap(strings.ToLower(pub),datas)
		return
	}

	datas := make([]*PrePubData,0)
	datas = append(datas,val)
	PreSignDataBak.WriteMap(strings.ToLower(pub),datas)
}

func NeedPreSign(pub string) bool {
	
	if GetTotalCount(pub) >= PrePubDataCount {
		return false
	}

	return true
}

func GetPrePubData(pub string,key string) *PrePubData {
	if pub == "" || key == "" {
		return nil
	}

	data,exsit := PreSignData.ReadMap(strings.ToLower(pub)) 
	if exsit {
		datas := data.([]*PrePubData)
		for _,v := range datas {
			if v != nil && strings.EqualFold(v.Key,key) {
				return v
			}
		}
		return nil
	}

	return nil
}

func GetPrePubDataBak(pub string,key string) *PrePubData {
	if pub == "" || key == "" {
		return nil
	}

	data,exsit := PreSignDataBak.ReadMap(strings.ToLower(pub)) 
	if exsit {
		datas := data.([]*PrePubData)
		for _,v := range datas {
			if v != nil && strings.EqualFold(v.Key,key) {
				return v
			}
		}
		return nil
	}

	return nil
}

func PutPreSign(pub string,val *PrePubData) {
	if val == nil {
		return
	}

	data,exsit := PreSignData.ReadMap(strings.ToLower(pub)) 
	if exsit {
		datas := data.([]*PrePubData)
		////check same 
		for _,v := range datas {
			if v != nil && strings.EqualFold(v.Key,val.Key) {
				common.Debug("========================PutPreSign,already have this key==================","pub",pub,"key",v.Key)
				return
			}
		}
		///

		datas = append(datas,val)
		PreSignData.WriteMap(strings.ToLower(pub),datas)
		return
	}

	datas := make([]*PrePubData,0)
	datas = append(datas,val)
	PreSignData.WriteMap(strings.ToLower(pub),datas)
}

func DeletePrePubDataBak(pub string,key string) {
	if pub == "" || key == "" {
		return
	}

	data,exsit := PreSignDataBak.ReadMap(strings.ToLower(pub))
	if !exsit {
		return
	}

	tmp := make([]*PrePubData,0)
	datas := data.([]*PrePubData)
	for _,v := range datas {
		if strings.EqualFold(v.Key,key) {
			continue
		}

		tmp = append(tmp,v)
	}

	PreSignDataBak.WriteMap(strings.ToLower(pub),tmp)
}

func DeletePrePubData(pub string,key string) {
	if pub == "" || key == "" {
		return
	}

	data,exsit := PreSignData.ReadMap(strings.ToLower(pub))
	if !exsit {
		return
	}

	tmp := make([]*PrePubData,0)
	datas := data.([]*PrePubData)
	for _,v := range datas {
		if strings.EqualFold(v.Key,key) {
			continue
		}

		tmp = append(tmp,v)
	}

	PreSignData.WriteMap(strings.ToLower(pub),tmp)
}

func PickPrePubData(pub string) string {
	data,exsit := PreSignData.ReadMap(strings.ToLower(pub)) 
	if exsit {
		key := ""
		var val *PrePubData
		datas := data.([]*PrePubData)
		for _,v := range datas {
			if v != nil && v.Used == false {
				key = v.Key
				val = v
				break
			}
		}

		if key != "" {
			tmp := make([]*PrePubData,0)
			for _,v := range datas {
				if strings.EqualFold(v.Key,key) {
					continue
				}

				tmp = append(tmp,v)
			}

			PreSignData.WriteMap(strings.ToLower(pub),tmp)
			PutPreSignBak(pub,val)
			return key
		}
	}

	return ""
}

func PickPrePubDataByKey(pub string,key string) {
	if pub == "" || key == "" {
		return
	}
	
	data,exsit := PreSignData.ReadMap(strings.ToLower(pub)) 
	if !exsit {
		return
	}

	var val *PrePubData
	tmp := make([]*PrePubData,0)
	datas := data.([]*PrePubData)
	for _,v := range datas {
		if v != nil && strings.EqualFold(v.Key,key) {
			val = v
			break
		}
	}

	for _,v := range datas {
		if strings.EqualFold(v.Key,key) {
			continue
		}

		tmp = append(tmp,v)
	}

	PreSignData.WriteMap(strings.ToLower(pub),tmp)
	PutPreSignBak(pub,val)
}

func SetPrePubDataUseStatus(pub string,key string,used bool ) {

	if !used {
		val := GetPrePubDataBak(pub,key)
		if val != nil {
			//PutPreSign(pub,val) //don't put into queue again??
			DeletePrePubDataBak(pub,key)
		}
	}
}
*/

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

func GetPreDbDir() string {
	dir := common.DefaultDataDir()
	//dir += "/dcrmdata/dcrmpredb" + cur_enode  //old path
	dir += "/smpcdata/presigndb" + cur_enode //new path
	return dir
}

/*func UpdatePrePubKeyDataForDb() {
    for {
	kd := <-PrePubKeyDataChan
	if predb != nil {
	    if !kd.Del {
		val,err := Decode2(kd.Data,"PrePubData")
		if err != nil {
		    time.Sleep(time.Duration(1000000)) //na, 1 s = 10e9 na
		   continue 
		}

		da, err := predb.Get([]byte(kd.Key))
		if err != nil {
		    datas := make([]*PrePubData,0)
		    datas = append(datas,val.(*PrePubData))
		    es,err := EncodePreSignDataValue(datas)
		    if err != nil {
			time.Sleep(time.Duration(1000000)) //na, 1 s = 10e9 na
			continue
		    }
		    err = predb.Put(kd.Key, []byte(es))
		    common.Info("=====================UpdatePrePubKeyDataForDb,no key,put pre-sign data into db========================","pick key",val.(*PrePubData).Key,"pub",string(kd.Key),"err",err)
		    if err != nil {
			time.Sleep(time.Duration(1000000)) //na, 1 s = 10e9 na
			continue
		    }

		    ///////////check all sign nodes pre-sign data status
		    psds := &PreSignDataStatus{MsgPrex:string(kd.Key),Status:"true",Gid:(val.(*PrePubData)).Gid,ThresHold:kd.ThresHold}
		    m := make(map[string]string)
		    psdsjson,err := psds.MarshalJSON()
		    if err == nil {
			m["PreSignDataStatus"] = string(psdsjson) 
		    }
		    m["Type"] = "PreSignDataStatus"
		    psdstmp,err := json.Marshal(m)
		    if err != nil {
			predb.Delete(kd.Key)
			time.Sleep(time.Duration(1000000)) //na, 1 s = 10e9 na
			continue
		    }
		
		    rch := make(chan interface{}, 1)
		    SetUpMsgList3(string(psdstmp),cur_enode,rch)
		    _, _,cherr := GetChannelValue(waitall,rch)
		    if cherr != nil {
			predb.Delete(kd.Key)
			time.Sleep(time.Duration(1000000)) //na, 1 s = 10e9 na
			continue
		    }
		    ///////////
		    
		    //PutPreSign(string(kd.Key),val.(*PrePubData))
		    time.Sleep(time.Duration(1000000)) //na, 1 s = 10e9 na
		    continue
		}

		ps,err := DecodePreSignDataValue(string(da))
		if err != nil {
		    datas := make([]*PrePubData,0)
		    datas = append(datas,val.(*PrePubData))
		    es,err := EncodePreSignDataValue(datas)
		    if err != nil {
			time.Sleep(time.Duration(1000000)) //na, 1 s = 10e9 na
			continue
		    }
		    err = predb.Put(kd.Key, []byte(es))
		    common.Info("=====================UpdatePrePubKeyDataForDb,put pre-sign data into db========================","pick key",val.(*PrePubData).Key,"pub",string(kd.Key),"err",err)
		    if err != nil {
			time.Sleep(time.Duration(1000000)) //na, 1 s = 10e9 na
			continue
		    }

		    ///////////check all sign nodes pre-sign data status
		    psds := &PreSignDataStatus{MsgPrex:string(kd.Key),Status:"true",Gid:(val.(*PrePubData)).Gid,ThresHold:kd.ThresHold}
		    m := make(map[string]string)
		    psdsjson,err := psds.MarshalJSON()
		    if err == nil {
			m["PreSignDataStatus"] = string(psdsjson) 
		    }
		    m["Type"] = "PreSignDataStatus"
		    psdstmp,err := json.Marshal(m)
		    if err != nil {
			predb.Delete(kd.Key)
			time.Sleep(time.Duration(1000000)) //na, 1 s = 10e9 na
			continue
		    }
		
		    rch := make(chan interface{}, 1)
		    SetUpMsgList3(string(psdstmp),cur_enode,rch)
		    _, _,cherr := GetChannelValue(waitall,rch)
		    if cherr != nil {
			predb.Delete(kd.Key)
			time.Sleep(time.Duration(1000000)) //na, 1 s = 10e9 na
			continue
		    }
		    ///////////
		    
		    //PutPreSign(string(kd.Key),val.(*PrePubData))
		    time.Sleep(time.Duration(1000000)) //na, 1 s = 10e9 na
		    continue
		}

		ps.Data = append(ps.Data,val.(*PrePubData))
		es,err := EncodePreSignDataValue(ps.Data)
		if err != nil {
		    time.Sleep(time.Duration(1000000)) //na, 1 s = 10e9 na
		    continue
		}
		err = predb.Put(kd.Key, []byte(es))
		common.Info("=====================UpdatePrePubKeyDataForDb,put pre-sign data into db========================","pick key",val.(*PrePubData).Key,"pub",string(kd.Key),"err",err)
		if err != nil {
		    time.Sleep(time.Duration(1000000)) //na, 1 s = 10e9 na
		    continue
		}
		
		///////////check all sign nodes pre-sign data status
		psds := &PreSignDataStatus{MsgPrex:string(kd.Key),Status:"true",Gid:(val.(*PrePubData)).Gid,ThresHold:kd.ThresHold}
		m := make(map[string]string)
		psdsjson,err := psds.MarshalJSON()
		if err == nil {
		    m["PreSignDataStatus"] = string(psdsjson) 
		}
		m["Type"] = "PreSignDataStatus"
		psdstmp,err := json.Marshal(m)
		if err != nil {
		    predb.Put(kd.Key, da)
		    time.Sleep(time.Duration(1000000)) //na, 1 s = 10e9 na
		    continue
		}
	    
		rch := make(chan interface{}, 1)
		SetUpMsgList3(string(psdstmp),cur_enode,rch)
		_, _,cherr := GetChannelValue(waitall,rch)
		if cherr != nil {
		    predb.Put(kd.Key, da)
		    time.Sleep(time.Duration(1000000)) //na, 1 s = 10e9 na
		    continue
		}
		///////////
		    
		//PutPreSign(string(kd.Key),val.(*PrePubData))
		time.Sleep(time.Duration(1000000)) //na, 1 s = 10e9 na
		continue
	    }

	    ////////////
	    da, err := predb.Get([]byte(kd.Key))
	    if err != nil {
		time.Sleep(time.Duration(1000000)) //na, 1 s = 10e9 na
		continue	
	    }
	    ps,err := DecodePreSignDataValue(string(da))
	    if err != nil {
		time.Sleep(time.Duration(1000000)) //na, 1 s = 10e9 na
		continue
	    }

	    tmp := make([]*PrePubData,0)
	    for _,v := range ps.Data {
		    if v != nil && strings.EqualFold(v.Key,kd.Data) {
			   continue 
		    }
		    
		    tmp = append(tmp,v)
	    }
	    
	    es,err := EncodePreSignDataValue(tmp)
	    if err != nil {
		time.Sleep(time.Duration(1000000)) //na, 1 s = 10e9 na
		continue
	    }
	    err = predb.Put(kd.Key, []byte(es))
	    common.Info("=================UpdatePrePubKeyDataForDb, delete pre-sign data from db ===============","key",string(kd.Key),"pick key",kd.Data,"err",err)
	    if err != nil {
		time.Sleep(time.Duration(1000000)) //na, 1 s = 10e9 na
		continue
	    }

	    ///////////check all sign nodes pre-sign data status
	    psds := &PreSignDataStatus{MsgPrex:string(kd.Key),Status:"true",Gid:((ps.Data)[0]).Gid,ThresHold:kd.ThresHold}
	    m := make(map[string]string)
	    psdsjson,err := psds.MarshalJSON()
	    if err == nil {
		m["PreSignDataStatus"] = string(psdsjson) 
	    }
	    m["Type"] = "PreSignDataStatus"
	    val,err := json.Marshal(m)
	    if err != nil {
		predb.Put(kd.Key, da)
		time.Sleep(time.Duration(1000000)) //na, 1 s = 10e9 na
		continue
	    }
	
	    rch := make(chan interface{}, 1)
	    SetUpMsgList3(string(val),cur_enode,rch)
	    _, _,cherr := GetChannelValue(waitall,rch)
	    if cherr != nil {
		predb.Put(kd.Key, da)
		time.Sleep(time.Duration(1000000)) //na, 1 s = 10e9 na
		continue
	    }
	    ///////////
		
	    //SetPrePubDataUseStatus(string(kd.Key),kd.Data,false)
	    common.Info("=================UpdatePrePubKeyDataForDb, delete pre-sign data from db success ===============","pub",string(kd.Key),"pick key",kd.Data)
	    /////////////

	} else {
	    common.Info("=================UpdatePrePubKeyDataForDb, save to db fail ,db is nil ===============","pub",string(kd.Key))
	}

	time.Sleep(time.Duration(1000000)) //na, 1 s = 10e9 na
    }
}
*/

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
	res := RpcDcrmRes{Ret: "", Tip: tip, Err: fmt.Errorf("check pre-sign data status fail.")}
	ch <- res
	return false
    }

    res := RpcDcrmRes{Ret: "", Tip: "", Err: nil}
    ch <- res
    return true
}

type TxDataPreSignData struct {
    TxType string
    PubKey string
    SubGid []string
}

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
				common.Info("=====================ExcutePreSignData in genkey fail========================","pubkey",pre.PubKey,"cherr",cherr,"Index",index)
			    }
			    common.Info("===================ExcutePreSignData,after generate pre-sign data===============","current total number of the data ",GetTotalCount(pre.PubKey,gg),"the number of remaining pre-sign data",(PrePubDataCount-GetTotalCount(pre.PubKey,gg)),"pubkey",pre.PubKey,"sub-groupid",gg,"Index",index)
		    } 

		    time.Sleep(time.Duration(1000000))
	    }
	}(gid)
    }
}

