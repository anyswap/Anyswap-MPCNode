
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
	"encoding/json"
	"strconv"
)

var (
	PrePubKeyDataChan = make(chan UpdataPreSignData, 20000)
	//PrePubKeyDataQueueChan = make(chan *PrePubData, 1000)
	PreSignData  = common.NewSafeMap(10) //make(map[string][]byte)
	PreSignDataBak  = common.NewSafeMap(10) //make(map[string][]byte)
	predb *ethdb.LDBDatabase
	presignhashpairdb *ethdb.LDBDatabase
	PrePubDataCount = 2000
	SignChan = make(chan *RpcSignData, 10000)
	//DelSignChan = make(chan *DelSignData, 10000)
	DtPreSign sync.Mutex
	PreSigal  = common.NewSafeMap(10) //make(map[string][]byte)
	PreSignHashPairMap  = common.NewSafeMap(10) //make(map[string][]byte)
	PreSignHashPairChan = make(chan UpdataPreSignHashPair, 20000)
)

/////////
type PreSignHashPair struct {
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

////////

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

type RpcSignData struct {
	Raw string
	PubKey string
	GroupId string
	MsgHash []string
	Key string
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

	/*data,exsit := PreSignDataBak.ReadMap(strings.ToLower(pub)) 
	if exsit {
		datas := data.([]*PrePubData)
		if len(datas) >= PrePubDataCount {
			return false
		}
	}

	return true 
	*/
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

	/*data,exsit := PreSignData.ReadMap(strings.ToLower(pub)) 
	if exsit {
		datas := data.([]*PrePubData)
		if len(datas) >= PrePubDataCount {
			return false
		}
	}

	return true 
	*/
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

func UpdatePrePubKeyDataForDb() {
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
    ExcutePreSignData(pre,true)
    return "", nil
}

func ExcutePreSignData(pre *TxDataPreSignData,over bool) {
    if pre == nil {
	return
    }
    
    for _,gid := range pre.SubGid {
	go func(gg string) {
	    pub := Keccak256Hash([]byte(strings.ToLower(pre.PubKey + ":" + gg))).Hex()

	    PutPreSigal(pub,true)

	    //////////
	    if over {
		    pshp := &PreSignHashPair{PubKey:pre.PubKey,Gid:gg}
		    PutPreSignHashPair(pub,pshp)
		    databyte,err := pshp.MarshalJSON()
		    if err == nil {
			    kd := UpdataPreSignHashPair{Key: []byte(strings.ToLower(pub)), Del:false,Data: string(databyte)}
			    PreSignHashPairChan <- kd
		    }
	    }
	    //////////

	    common.Info("===================ExcutePreSignData,before generate pre-sign data===============","current total number of the data ",GetTotalCount(pub),"the number of remaining pre-sign data",(PrePubDataCount-GetTotalCount(pub)),"pub",pub,"pubkey",pre.PubKey,"sub-groupid",gg)
	    for {
		    if NeedPreSign(pub) && GetPreSigal(pub) {
			    tt := fmt.Sprintf("%v",time.Now().UnixNano()/1e6)
			    nonce := Keccak256Hash([]byte(strings.ToLower(pub + tt))).Hex()
			    ps := &PreSign{Pub:pre.PubKey,Gid:gg,Nonce:nonce}

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
				common.Info("=====================ExcutePreSignData in genkey fail========================","pub",pub,"cherr",cherr)
			    }
			    common.Info("===================ExcutePreSignData,after generate pre-sign data===============","current total number of the data ",GetTotalCount(pub),"the number of remaining pre-sign data",(PrePubDataCount-GetTotalCount(pub)),"pub",pub,"pubkey",pre.PubKey,"sub-groupid",gg)
		    } 

		    time.Sleep(time.Duration(1000000))
	    }
	}(gid)
    }
}

type UpdataPreSignData struct {
    Key []byte
    Del bool 
    Data string //pickkey or pre-sign-data
    ThresHold int 
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

	subgid := make([]string,0)
	pshp := GetPreSignHashPair(key)
	if pshp != nil {
		subgid = append(subgid,pshp.Gid)
		pre := &TxDataPreSignData{TxType:"PRESIGNDATA",PubKey:pshp.PubKey,SubGid:subgid}
		common.Info("================= GetAllPreSignFromDb, call ExcutePreSignData to generate pre-sign data =================\n")
		ExcutePreSignData(pre,false)
	}
    }
    
    iter.Release()
}

func GetPreSignHashPairDbDir() string {
	dir := common.DefaultDataDir()
	dir += "/dcrmdata/presignhashpair" + cur_enode
	return dir
}

type UpdataPreSignHashPair struct {
    Key []byte
    Del bool 
    Data string
}

func UpdatePreSignHashPairForDb() {
    for {
	kd := <-PreSignHashPairChan
	if presignhashpairdb != nil {
	    if !kd.Del {
		    err := presignhashpairdb.Put(kd.Key, []byte(kd.Data))
		    common.Info("=====================UpdatePreSignHashPairForDb,put pre-sign hash pair into db========================","pub",string(kd.Key),"err",err)

		    time.Sleep(time.Duration(1000000)) //na, 1 s = 10e9 na
		    continue
	    }

	    ////////////
	    err := presignhashpairdb.Delete(kd.Key)
	    if err != nil {
		    common.Info("=====================UpdatePreSignHashPairForDb,delete pre-sign hash pair from db========================","pub",string(kd.Key),"err",err)
	    }
	    /////////////

	} else {
	    common.Info("=================UpdatePreSignHashPairForDb, save to db fail ,db is nil ===============","key",string(kd.Key))
	}

	time.Sleep(time.Duration(1000000)) //na, 1 s = 10e9 na
    }
}

func GetAllPreSignHashPairFromDb() {
    if presignhashpairdb == nil {
	return
    }

    iter := presignhashpairdb.NewIterator()
    for iter.Next() {
	key := string(iter.Key())
	value := string(iter.Value())

	pshp := &PreSignHashPair{}
	if err := pshp.UnmarshalJSON([]byte(value));err != nil {
	    common.Info("=================GetAllPreSignHashPairFromDb=================\n","pub",key,"err",err) 
	    continue 
	}

	common.Info("=================GetAllPreSignHashPairFromDb=================\n","pub",key,"PubKey",pshp.PubKey,"Gid",pshp.Gid) 
	PutPreSignHashPair(key,pshp)
    }
    
    iter.Release()
}


