
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
	"github.com/anyswap/Anyswap-MPCNode/internal/common"
	"strings"
	"math/big"
	"github.com/anyswap/Anyswap-MPCNode/ethdb"
	"time"
	"fmt"
	"sync"
	dberrors "github.com/syndtr/goleveldb/leveldb/errors"
	"errors"
	"encoding/json"
	"github.com/anyswap/Anyswap-MPCNode/log"
)

var (
	PreSignData  = common.NewSafeMap(10) //make(map[string][]byte)
	PreSignDataBak  = common.NewSafeMap(10) //make(map[string][]byte)
	predb *ethdb.LDBDatabase
	PrePubDataCount = 2000
	SignChan = make(chan *RpcSignData, 10000)
	DtPreSign sync.Mutex
	PreSigal  = common.NewSafeMap(10) //make(map[string][]byte)
)

type RpcSignData struct {
	Raw string
	PubKey string
	GroupId string
	MsgHash []string
	Key string
	TimeStamp string
}

//--------------------------------------------------------------------------

type PreSign struct {
	Pub string
	Gid string
	Nonce string
}

func (ps *PreSign) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Pub string `json:"Pub"`
		Gid string `json:"Gid"`
		Nonce string `json:"Nonce"`
	}{
		Pub: ps.Pub,
		Gid: ps.Gid,
		Nonce: ps.Nonce,
	})
}

func (ps *PreSign) UnmarshalJSON(raw []byte) error {
	var pre struct {
		Pub string `json:"Pub"`
		Gid string `json:"Gid"`
		Nonce string `json:"Nonce"`
	}
	if err := json.Unmarshal(raw, &pre); err != nil {
		return err
	}

	ps.Pub = pre.Pub
	ps.Gid = pre.Gid
	ps.Nonce = pre.Nonce
	return nil
}

//-------------------------------------------------------------------

type PrePubData struct {
	Key string
	K1 *big.Int
	R *big.Int
	Ry *big.Int
	Sigma1 *big.Int
	Gid string
	Used bool //useless? TODO
}

type PickHashKey struct {
	Hash string
	PickKey string
}

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

func GetTotalCount(pub string) int {
	data,exsit := PreSignData.ReadMap(strings.ToLower(pub)) 
	if exsit {
		datas := data.([]*PrePubData)
		return len(datas)
	}

	return 0
}

func GetTotalCount2(pub string) int {
	data,exsit := PreSignDataBak.ReadMap(strings.ToLower(pub)) 
	if exsit {
		datas := data.([]*PrePubData)
		return len(datas)
	}

	return 0
}

func NeedPreSignBak(pub string) bool {
	data,exsit := PreSignDataBak.ReadMap(strings.ToLower(pub)) 
	if exsit {
		datas := data.([]*PrePubData)
		if len(datas) >= PrePubDataCount {
			return false
		}
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
	data,exsit := PreSignData.ReadMap(strings.ToLower(pub)) 
	if exsit {
		datas := data.([]*PrePubData)
		if len(datas) >= PrePubDataCount {
			return false
		}
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
				log.Info("[PRESIGN] the pre-sign data key already exist","key",v.Key)
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
			if v != nil {
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

func PickPrePubDataByKey(pub string,key string) error {
	if pub == "" || key == "" {
		return fmt.Errorf("param error.")
	}
	
	data,exsit := PreSignData.ReadMap(strings.ToLower(pub)) 
	if !exsit {
		return fmt.Errorf(" Key does not exist.")
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
	return nil
}

func SetPrePubDataUseStatus(pub string,key string,used bool ) {
	if !used {
		val := GetPrePubDataBak(pub,key)
		if val != nil {
			DeletePrePubDataBak(pub,key)
		}
	}
}

func IsNotFoundErr(err error) bool {
    return errors.Is(err, dberrors.ErrNotFound)
}

func PutPreSignDataIntoDb(key string,val *PrePubData) error {
    if predb == nil {
	return fmt.Errorf("open db fail.")
     }
 
    da,err := predb.Get([]byte(key))
    if err != nil && !IsNotFoundErr(err) {
	return err
     }

    if IsNotFoundErr(err) {
 	datas := make([]*PrePubData,0)
 	datas = append(datas,val)
 	es,err := EncodePreSignDataValue(datas)
 	if err != nil {
	    log.Error("[PRESIGN] encode pre-sign data fail","pre-sign data key",val.Key,"err",err)
 	    return err
 	}
 
 	err = predb.Put([]byte(key), []byte(es))
 	if err != nil {
	    log.Error("[PRESIGN] failed to save pre-sign data to database","pre-sign data key",val.Key,"err",err)
 	    return err
 	}

	return nil
    }

    ps,err := DecodePreSignDataValue(string(da))
    if err != nil {
	log.Error("[PRESIGN] decode pre-sign data fail","pre-sign data key",val.Key,"err",err)
	return err
    }

    ps.Data = append(ps.Data,val)
    es,err := EncodePreSignDataValue(ps.Data)
    if err != nil {
	log.Error("[PRESIGN] encode pre-sign data fail","pre-sign data key",val.Key,"err",err)
	return err
    }

    err = predb.Put([]byte(key), []byte(es))
    if err != nil {
	log.Error("[PRESIGN] failed to save pre-sign data to database","pre-sign data key",val.Key,"err",err)
	return err
     }

     return nil
}

func DeletePreSignDataFromDb(pub string,key string) error {
    if pub == "" || key == "" {
	return fmt.Errorf("invalid parameter")
    }

    da, err := predb.Get([]byte(pub))
    if err != nil {
	log.Error("[PRESIGN] delete pre-sign data from db fail","err",err,"pre-sign data key",key)
	return err
    }

    ps,err := DecodePreSignDataValue(string(da))
    if err != nil {
	log.Error("[PRESIGN] delete pre-sign data from db fail","err",err,"pre-sign data key",key)
	return err
    }

    tmp := make([]*PrePubData,0)
    for _,v := range ps.Data {
	    if v != nil && strings.EqualFold(v.Key,key) {
		   continue 
	    }

	    tmp = append(tmp,v)
    }

    es,err := EncodePreSignDataValue(tmp)
    if err != nil {
	log.Error("[PRESIGN] delete pre-sign data from db fail","err",err,"pre-sign data key",key)
	return err
    }

    err = predb.Put([]byte(pub), []byte(es))
    if err != nil {
	log.Error("[PRESIGN] delete pre-sign data from db fail","err",err,"pre-sign data key",key)
	return err
    }

    return nil
}

type SignBrocastData struct {
	Raw string
	PickHash []*PickHashKey
	TimeStamp string // receive time of the sign cmd at current node
}

func CompressSignBrocastData(raw string,pickhash []*PickHashKey,timestamp string) (string,error) {
	if raw == "" || pickhash == nil || timestamp == "" {
		return "",fmt.Errorf("sign brocast data error")
	}

	s := &SignBrocastData{Raw:raw,PickHash:pickhash,TimeStamp:timestamp}
	send,err := Encode2(s)
	if err != nil {
		return "",err
	}

	return send,nil
}

func UnCompressSignBrocastData(data string) (*SignBrocastData,error) {
	if data == "" {
		return nil,fmt.Errorf("Sign Brocast Data error")
	}

	s := data

	ret,err := Decode2(s,"SignBrocastData")
	if err != nil {
		return nil,err
	}

	return ret.(*SignBrocastData),nil
}

func GetPreDbDir() string {
	dir := common.DefaultDataDir()
	dir += "/dcrmdata/dcrmpredb" + cur_enode
	return dir
}

type TxDataPreSignData struct {
    TxType string
    PubKey string
    SubGid []string
}

func PreGenSignData(raw string) (string, error) {
    _,_,_,txdata,err := CheckRaw(raw)
    if err != nil {
	hash := Keccak256Hash([]byte(raw)).Hex()
	log.Error("[PRESIGN] check raw data fail","raw data hash",hash,"err",err)
	return err.Error(),err
    }

    pre,ok := txdata.(*TxDataPreSignData)
    if !ok {
	return "check raw data fail",fmt.Errorf("check raw data fail")
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

	    err := SavePrekeyToDb(pre.PubKey,gg)
	    if err != nil {
		    log.Error("[PRESIGN] save (pubkey,gid) to db fail", "pubkey", pre.PubKey, "gid", gg, "err", err)
		    return
	    }

	    for {
		    if NeedPreSign(pub) && GetPreSigal(pub) {
			    tt := fmt.Sprintf("%v",time.Now().UnixNano()/1e6)
			    nonce := Keccak256Hash([]byte(strings.ToLower(pub + tt))).Hex()
			    ps := &PreSign{Pub:pre.PubKey,Gid:gg,Nonce:nonce}

			    psjson,err := ps.MarshalJSON()
			    if err != nil {
				time.Sleep(time.Duration(10000000))
				continue 
			    }
			    
			    m := make(map[string]string)
			    m["PreSign"] = string(psjson) 
			    m["Type"] = "PreSign"
			    val,err := json.Marshal(m)
			    if err != nil {
				time.Sleep(time.Duration(10000000))
				continue 
			    }
			    
			    hash := Keccak256Hash(val).Hex()
			    log.Info("[PRESIGN] broadcasting pre-sign cmd data to group","data hash",hash,"gid",gg,"group nodes",getGroupNodes(gg))
			    SendMsgToDcrmGroup(string(val),gg)

			    rch := make(chan interface{}, 1)
			    SetUpMsgList3(string(val),cur_enode,rch)
			    _, _,cherr := GetChannelValue(waitall+10,rch)
			    if cherr == nil {
				log.Info("[PRESIGN] pre-generated sign data succeeded","current total number of the data ",GetTotalCount(pub),"pubkey",pre.PubKey,"groupid",gg)
			    }
		    }

		    time.Sleep(time.Duration(1000000))
	    }
	}(gid)
    }
}

// AutoPreGenSignData Automatically generate pre-sign data based on database that saving public key group information. 
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
			tmp := strings.Split(val, ":") // val = pubkey:gid
			if len(tmp) < 2 || tmp[0] == "" || tmp[1] == "" {
				return
			}

			log.Info("[PRESIGN] start automatic pre-generated sign data","pubkey",tmp[0],"sub gid",tmp[1])
			subgid := make([]string, 0)
			subgid = append(subgid, tmp[1])
			pre := &TxDataPreSignData{TxType: "PRESIGNDATA", PubKey: tmp[0], SubGid: subgid}
			ExcutePreSignData(pre)
		}(string(value))
	}

	iter.Release()
}

// SavePrekeyToDb save pubkey gid information to the specified batabase
func SavePrekeyToDb(pubkey string,gid string) error {
	if prekey == nil {
		return fmt.Errorf("db open fail")
	}

	pub := strings.ToLower(Keccak256Hash([]byte(strings.ToLower(pubkey + ":" + gid))).Hex())
	val := pubkey + ":" + gid

	_, err := prekey.Get([]byte(pub))
	if IsNotFoundErr(err) {
		err = prekey.Put([]byte(pub), []byte(val))
		if err != nil {
		    log.Error("[PRESIGN] failed to save (pubkey:gid) data to db", "pubkey", pubkey, "gid", gid, "err", err)
			return err
		}
	}

	return nil
}

type PreSignDataValue struct {
    Data []*PrePubData
}

func EncodePreSignDataValue(data []*PrePubData) (string,error) {
	if data == nil {
		return "",fmt.Errorf("invalid parameter")
	}

	s := &PreSignDataValue{Data:data}
	cs,err := Encode2(s)
	if err != nil {
		return "",err
	}

	return cs,nil
}

func DecodePreSignDataValue(s string) (*PreSignDataValue,error) {
	if s == "" {
		return nil,fmt.Errorf("invalid parameter")
	}

	ret,err := Decode2(s,"PreSignDataValue")
	if err != nil {
		return nil,err
	}

	return ret.(*PreSignDataValue),nil
}

func GetPreSign(pub string) []*PrePubData {
	if pub == "" {
	    return nil
	}

	data,exsit := PreSignData.ReadMap(strings.ToLower(pub)) 
	if exsit {
	    return data.([]*PrePubData)
	}

	return nil
}

func GetAllPreSignFromDb() {
    if predb == nil {
	return
    }

    iter := predb.NewIterator()
    for iter.Next() {
	key := string(iter.Key())
	value := string(iter.Value())

	ps, err := DecodePreSignDataValue(value)
	if err != nil {
	    log.Error("[PRESIGN] failed to decode pre-sign data at startup","err",err) 
	    continue
	}

	for k,v := range ps.Data {
	    log.Info("[PRESIGN] read pre-sign data from db","index",k,"pre-sign data key",v.Key) 
	    PutPreSign(key,v)
	}
    }
    
    iter.Release()
}

