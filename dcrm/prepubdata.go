
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
)

var (
	PrePubKeyDataChan = make(chan KeyData, 2000)
	//PrePubKeyDataQueueChan = make(chan *PrePubData, 1000)
	PreSignData  = common.NewSafeMap(10) //make(map[string][]byte)
	PreSignDataBak  = common.NewSafeMap(10) //make(map[string][]byte)
	predb *ethdb.LDBDatabase
	PrePubDataCount = 2000
	SignChan = make(chan *RpcSignData, 10000)
	//DelSignChan = make(chan *DelSignData, 10000)
	DelPreSign                     sync.Mutex
	PreSigal  = common.NewSafeMap(10) //make(map[string][]byte)
)

type RpcSignData struct {
	Raw string
	PubKey string
	MsgHash []string
	Key string
}

type PreSign struct {
	Pub string
	Gid string
	Nonce string
	Index int
}

type PrePubData struct {
	Key string
	K1 *big.Int
	R *big.Int
	Ry *big.Int
	Sigma1 *big.Int
	Gid string
	Index int
	Used bool
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
				common.Debug("========================PutPreSign,already have this key==================","key",v.Key)
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
			PutPreSign(pub,val)
			DeletePrePubDataBak(pub,key)
		}
	}
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

	ret,err := Compress([]byte(send))
	if err != nil {
		return "",err
	}

	return ret,nil
}

func UnCompressSignBrocastData(data string) (*SignBrocastData,error) {
	if data == "" {
		return nil,fmt.Errorf("Sign Brocast Data error")
	}

	s,err := UnCompress(data)
	if err != nil {
		return nil,err
	}

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

/*func GetAllPrePubkeyDataFromDb() {
	if predb != nil {
	    iter := predb.NewIterator()
	    for iter.Next() {
		//key := string(iter.Key())
		value := string(iter.Value())

		ss, err := UnCompress(value)
		if err == nil {
		    pubs, err := Decode2(ss, "PrePubKeyData")
		    if err == nil {
			pd,ok := pubs.(*PrePubData)
			if ok {
				if len(PrePubKeyDataQueueChan) < 1000 {
					PrePubKeyDataQueueChan <-pd
				}
			}
		    }
		}
	    }
	    
	    iter.Release()
	}
}
*/

func SavePrePubKeyDataToDb() {
	for {
		kd := <-PrePubKeyDataChan
		if predb != nil {
			//common.Debug("=================SavePubKeyDataToDb, db is not nil ===============","key",kd.Key)
		    if kd.Data == "CLEAN" {
			err := predb.Delete(kd.Key)
			if err != nil {
				common.Info("=================SavePubKeyDataToDb, db is not nil and delete fail ===============","key",kd.Key)
			    //PubKeyDataChan <- kd
			}
		    } else {
			err := predb.Put(kd.Key, []byte(kd.Data))
			if err != nil {
				common.Info("=================SavePubKeyDataToDb, db is not nil and save fail ===============","key",kd.Key)
			    dir := GetPreDbDir()
			    predbtmp, err := ethdb.NewLDBDatabase(dir, cache, handles)
			    //bug
			    if err != nil {
				    for i := 0; i < 100; i++ {
					    predbtmp, err = ethdb.NewLDBDatabase(dir, cache, handles)
					    if err == nil {
						    break
					    }

					    time.Sleep(time.Duration(1000000))
				    }
			    }
			    if err != nil {
				common.Info("=================SavePubKeyDataToDb, re-get db fail and save fail ===============","key",kd.Key)
				//dbsk = nil
			    } else {
				predb = predbtmp
				err = predb.Put(kd.Key, []byte(kd.Data))
				if err != nil {
					common.Info("=================SavePubKeyDataToDb, re-get db success and save fail ===============","key",kd.Key)
				    //PubKeyDataChan <- kd
				}
			    }

			}
			//db.Close()
		    }
		} else {
			common.Info("=================SavePubKeyDataToDb, save to db fail ,db is nil ===============","key",kd.Key)
			//PubKeyDataChan <- kd
		}

		time.Sleep(time.Duration(1000000)) //na, 1 s = 10e9 na
	    }
}

