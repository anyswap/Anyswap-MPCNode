
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
	"sync"
	dberrors "github.com/syndtr/goleveldb/leveldb/errors"
	"errors"
)

var (
	PreSignData  = common.NewSafeMap(10) //make(map[string][]byte)
	PreSignDataBak  = common.NewSafeMap(10) //make(map[string][]byte)
	predb *ethdb.LDBDatabase
	PrePubDataCount = 2000
	SignChan = make(chan *RpcSignData, 10000)
	//DelSignChan = make(chan *DelSignData, 10000)
	DtPreSign sync.Mutex
	PreSigal  = common.NewSafeMap(10) //make(map[string][]byte)
)

type RpcSignData struct {
	Raw string
	PubKey string
	GroupId string
	MsgHash []string
	Key string
}

type PreSign struct {
	Pub string
	Gid string
	Nonce string
}

type PrePubData struct {
	Key string
	K1 *big.Int
	R *big.Int
	Ry *big.Int
	Sigma1 *big.Int
	Gid string
	Used bool //useless? TODO
}

/*type DelSignData struct {
	PubKey string
	PickKey string

	Pbd *PrePubData //for PutPreSign
}
*/

type PickHashKey struct {
	Hash string
	PickKey string
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

/*func PickPrePubData(pub string) string {
	data,exsit := PreSignData.ReadMap(strings.ToLower(pub)) 
	if exsit {
		datas := data.([]*PrePubData)
		for _,v := range datas {
			if v != nil && !v.Used {
				v.Used = true //bug
				return v.Key
			}
		}
	}

	return ""
}*/

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
	/*data,exsit := PreSignData.ReadMap(strings.ToLower(pub))
	if !exsit {
		return
	}

	datas := data.([]*PrePubData)
	for _,v := range datas {
		if v != nil && strings.EqualFold(v.Key,key) {
			v.Used = used
			//PreSignData.WriteMap(strings.ToLower(pub),datas)
			return
		}
	}*/

	if !used {
		val := GetPrePubDataBak(pub,key)
		if val != nil {
			//PutPreSign(pub,val) //don't put into queue again??
			DeletePrePubDataBak(pub,key)
		}
	}
}

func IsNotFoundErr(err error) bool {
    return errors.Is(err, dberrors.ErrNotFound)
}

func PutPreSignDataIntoDb(key string,val *PrePubData) error {
    if predb == nil {
	common.Error("=====================PutPreSignDataIntoDb,open db fail.========================")
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
	    common.Error("=====================PutPreSignDataIntoDb,encode pre-sign data fail.========================","pre-sign data key",val.Key,"key",key,"err",err)
 	    return err
 	}
 
 	err = predb.Put([]byte(key), []byte(es))
 	if err != nil {
	    common.Error("=====================PutPreSignDataIntoDb,put pre-sign data into db fail.========================","pre-sign data key",val.Key,"key",key,"err",err)
 	    return err
 	}

	return nil
    }

    ps,err := DecodePreSignDataValue(string(da))
    if err != nil {
	common.Error("=====================PutPreSignDataIntoDb,decode pre-sign data from db fail.========================","pre-sign data key",val.Key,"key",key,"err",err)
	return err
    }

    ps.Data = append(ps.Data,val)
    es,err := EncodePreSignDataValue(ps.Data)
    if err != nil {
	common.Error("=====================PutPreSignDataIntoDb,encode pre-sign data fail.========================","pick key",val.Key,"key",key,"err",err)
	return err
    }

    err = predb.Put([]byte(key), []byte(es))
    if err != nil {
	common.Error("=================PutPreSignDataIntoDb, put pre-sign data to db fail. ===============","key",key,"pick key",val.Key,"err",err)
	return err
     }

     return nil
}

func DeletePreSignDataFromDb(pub string,key string) error {
    if pub == "" || key == "" {
	return fmt.Errorf("param error.")
    }

    da, err := predb.Get([]byte(pub))
    if err != nil {
	return err
    }

    ps,err := DecodePreSignDataValue(string(da))
    if err != nil {
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
	return err
    }

    err = predb.Put([]byte(pub), []byte(es))
    if err != nil {
	common.Errorf("=================DeletePreSignDataFromDb, delete pre-sign data from db fail. ===============","key",pub,"pick key",key,"err",err)
	return err
    }

    common.Debug("=================DeletePreSignDataFromDb, delete pre-sign data from db success ===============","pub",pub,"pick key",key)
    return nil
}

type SignBrocastData struct {
	Raw string
	PickHash []*PickHashKey
}

func CompressSignBrocastData(raw string,pickhash []*PickHashKey) (string,error) {
	if raw == "" || pickhash == nil {
		return "",fmt.Errorf("sign brocast data error")
	}

	s := &SignBrocastData{Raw:raw,PickHash:pickhash}
	send,err := Encode2(s)
	if err != nil {
		return "",err
	}

	return send,nil

	/*ret,err := Compress([]byte(send))
	if err != nil {
		return "",err
	}

	return ret,nil*/
}

func UnCompressSignBrocastData(data string) (*SignBrocastData,error) {
	if data == "" {
		return nil,fmt.Errorf("Sign Brocast Data error")
	}

	/*s,err := UnCompress(data)
	if err != nil {
		return nil,err
	}*/

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
	    common.Info("===================before generate pre-sign data===============","current total number of the data ",GetTotalCount(pub),"pub",pub,"pubkey",pre.PubKey,"groupid",gg)
	    for {
		    if NeedPreSign(pub) && GetPreSigal(pub) {
			    tt := fmt.Sprintf("%v",time.Now().UnixNano()/1e6)
			    nonce := Keccak256Hash([]byte(strings.ToLower(pub + tt))).Hex()
			    ps := &PreSign{Pub:pre.PubKey,Gid:gg,Nonce:nonce}

			    val,err := Encode2(ps)
			    if err != nil {
				common.Error("=====================ExcutePreSignData,encode pre-sign data error.========================","pub",pub,"pubkey",pre.PubKey,"gid",gg,"err",err)
				time.Sleep(time.Duration(10000000))
				continue 
			    }
			    SendMsgToDcrmGroup(val,gg)

			    rch := make(chan interface{}, 1)
			    SetUpMsgList3(val,cur_enode,rch)
			    _, _,cherr := GetChannelValue(waitall+10,rch)
			    if cherr != nil {
				common.Error("=====================ExcutePreSignData, pre-sign fail========================","pub",pub,"pubkey",pre.PubKey,"gid",gg,"cherr",cherr)
			    }

			    common.Info("===================generate pre-sign data===============","current total number of the data ",GetTotalCount(pub),"pub",pub,"pubkey",pre.PubKey,"groupid",gg)
		    } 

		    time.Sleep(time.Duration(1000000))
	    }
	}(gid)
    }
}

type PreSignDataValue struct {
    Data []*PrePubData
}

func EncodePreSignDataValue(data []*PrePubData) (string,error) {
	if data == nil {
		return "",fmt.Errorf("pre-sign data error")
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
		return nil,fmt.Errorf("pre-sign data error")
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
	    common.Info("=================GetAllPreSignFromDb=================\n","err",err) 
	    continue
	}

	common.Info("=================GetAllPreSignFromDb=================\n","data count",len(ps.Data)) 
	for _,v := range ps.Data {
	    //common.Info("=================GetAllPreSignFromDb=================\n","pub",key,"pick key",v.Key) 
	    PutPreSign(key,v)
	}
    }
    
    iter.Release()
}

