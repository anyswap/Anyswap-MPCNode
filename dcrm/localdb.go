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
    "github.com/fsn-dev/dcrm-walletService/internal/common/fdlimit"
    "github.com/fsn-dev/dcrm-walletService/ethdb"
    "time"
    "sync"
    "fmt"
    "github.com/fsn-dev/dcrm-walletService/p2p/discover"
)

var (
	LdbPubKeyData  = common.NewSafeMap(10) //make(map[string][]byte)
	PubKeyDataChan = make(chan KeyData, 2000)
	SkU1Chan = make(chan KeyData, 2000)
	cache = (75*1024)/1000 
	handles = makeDatabaseHandles()
	
	lock                     sync.Mutex
	db *ethdb.LDBDatabase
	dbsk *ethdb.LDBDatabase

	reqaddrinfodb *ethdb.LDBDatabase
	signinfodb *ethdb.LDBDatabase
	reshareinfodb *ethdb.LDBDatabase
)

func makeDatabaseHandles() int {
     limit, err := fdlimit.Current()
     if err != nil {
	     //Fatalf("Failed to retrieve file descriptor allowance: %v", err)
	     common.Info("Failed to retrieve file descriptor allowance: " + err.Error())
	     return 0
     }
     if limit < 2048 {
	     if err := fdlimit.Raise(2048); err != nil {
		     //Fatalf("Failed to raise file descriptor allowance: %v", err)
		     common.Info("Failed to raise file descriptor allowance: " + err.Error())
	     }
     }
     if limit > 2048 { // cap database file descriptors even if more is available
	     limit = 2048
     }
     return limit / 2 // Leave half for networking and other stuff
}

func GetSkU1FromLocalDb(key string) []byte {
	lock.Lock()
	if dbsk == nil {
	    common.Debug("=====================GetSkU1FromLocalDb, dbsk is nil =====================")
	    dir := GetSkU1Dir()
	    ////////
	    dbsktmp, err := ethdb.NewLDBDatabase(dir, cache, handles)
	    //bug
	    if err != nil {
		    for i := 0; i < 100; i++ {
			    dbsktmp, err = ethdb.NewLDBDatabase(dir, cache, handles)
			    if err == nil {
				    break
			    }

			    time.Sleep(time.Duration(1000000))
		    }
	    }
	    if err != nil {
		dbsk = nil
	    } else {
		dbsk = dbsktmp
	    }

		lock.Unlock()
		return nil
	}

	da, err := dbsk.Get([]byte(key))
	if err != nil {
	    dir := GetSkU1Dir()
	    ////////
	    dbsktmp, err := ethdb.NewLDBDatabase(dir, cache, handles)
	    //bug
	    if err != nil {
		    for i := 0; i < 100; i++ {
			    dbsktmp, err = ethdb.NewLDBDatabase(dir, cache, handles)
			    if err == nil {
				    break
			    }

			    time.Sleep(time.Duration(1000000))
		    }
	    }
	    if err != nil {
		//dbsk = nil
	    } else {
		dbsk = dbsktmp
	    }

	    da, err = dbsk.Get([]byte(key))
	    if err != nil {
		lock.Unlock()
		return nil
	    }
	    
	    sk,err := DecryptMsg(string(da))
	    if err != nil {
		lock.Unlock()
		return da //TODO ,tmp code 
		//return nil
	    }

	    lock.Unlock()
	    return []byte(sk)
	}

	sk,err := DecryptMsg(string(da))
	if err != nil {
	    lock.Unlock()
	    return da //TODO ,tmp code 
	    //return nil
	}

	lock.Unlock()
	return []byte(sk)
}

func GetPubKeyDataValueFromDb(key string) []byte {
	if db == nil {
	    return nil
 	}

	da, err := db.Get([]byte(key))
	if err != nil {
	    common.Info("===================GetPubKeyDataValueFromDb,get data fail===================","err",err,"key",key)
	    return nil
	}

	return da
}

type KeyData struct {
	Key  []byte
	Data string
}

func SavePubKeyDataToDb() {
	for {
		kd := <-PubKeyDataChan
		if db != nil {
		    if kd.Data == "CLEAN" {
			err := db.Delete(kd.Key)
			if err != nil {
				common.Info("=================SavePubKeyDataToDb, db is not nil and delete fail ===============","key",kd.Key)
			}
		    } else {
			err := db.Put(kd.Key, []byte(kd.Data))
			if err != nil {
				common.Info("=================SavePubKeyDataToDb, db is not nil and save fail ===============","key",string(kd.Key))
			    dir := GetDbDir()
			    dbtmp, err := ethdb.NewLDBDatabase(dir, cache, handles)
			    //bug
			    if err != nil {
				    for i := 0; i < 100; i++ {
					    dbtmp, err = ethdb.NewLDBDatabase(dir, cache, handles)
					    if err == nil {
						    break
					    }

					    time.Sleep(time.Duration(1000000))
				    }
			    }
			    if err != nil {
				common.Debug("=================SavePubKeyDataToDb, re-get db fail and save fail ===============","key",kd.Key)
			    } else {
				db = dbtmp
				err = db.Put(kd.Key, []byte(kd.Data))
				if err != nil {
					common.Debug("=================SavePubKeyDataToDb, re-get db success and save fail ===============","key",kd.Key)
				}
			    }

			}
		    }
		} else {
			common.Debug("=================SavePubKeyDataToDb, save to db fail ,db is nil ===============","key",kd.Key)
		}

		time.Sleep(time.Duration(1000000)) //na, 1 s = 10e9 na
	    }
}

func SaveSkU1ToDb() {
	for {
		kd := <-SkU1Chan
		if dbsk != nil {
		    cm,err := EncryptMsg(kd.Data,cur_enode)
		    if err != nil {
			SkU1Chan <- kd
			continue	
		    }

		    err = dbsk.Put(kd.Key, []byte(cm))
		    if err != nil {
			dir := GetSkU1Dir()
			dbsktmp, err := ethdb.NewLDBDatabase(dir, cache, handles)
			//bug
			if err != nil {
				for i := 0; i < 100; i++ {
					dbsktmp, err = ethdb.NewLDBDatabase(dir, cache, handles)
					if err == nil {
						break
					}

					time.Sleep(time.Duration(1000000))
				}
			}
			if err != nil {
			    //dbsk = nil
			} else {
			    dbsk = dbsktmp
			    err = dbsk.Put(kd.Key, []byte(cm))
			    if err != nil {
				SkU1Chan <- kd
				continue
			    }
			}

		    }
		//	db.Close()
		} else {
			SkU1Chan <- kd
		}

		time.Sleep(time.Duration(1000000)) //na, 1 s = 10e9 na
	    }
}

func GetAllPubKeyDataFromDb() *common.SafeMap {
    kd := common.NewSafeMap(10)
    if db != nil {
	var wg sync.WaitGroup
	iter := db.NewIterator()
	for iter.Next() {
	    key := string(iter.Key())
	    value := string(iter.Value())

	    wg.Add(1)
	    go func(key2 string,value2 string) {
		defer wg.Done()
		ss, err := UnCompress(value2)
		if err == nil {
		    pubs3, err := Decode2(ss, "PubKeyData")
		    if err == nil {
			pd,ok := pubs3.(*PubKeyData)
			if ok {
			    kd.WriteMap(key2, pd)
			    return
			}
		    }
		}
	    }(key,value)
	}
	
	iter.Release()
	wg.Wait()
    }

    return kd
}

func GetValueFromPubKeyData(key string) (bool,interface{}) {
    if key == "" {
	    common.Debug("========================GetValueFromPubKeyData, param err=======================","key",key)
	return false,nil
    }

    datmp, exsit := LdbPubKeyData.ReadMap(key)
    if !exsit {
	    common.Info("========================GetValueFromPubKeyData, get value from memory fail =======================","key",key)
	da := GetPubKeyDataValueFromDb(key)
	if da == nil {
	    common.Info("========================GetValueFromPubKeyData, get value from local db fail =======================","key",key)
	    return false,nil
	}

	ss, err := UnCompress(string(da))
	if err != nil {
	    common.Info("========================GetValueFromPubKeyData, uncompress err=======================","err",err,"key",key)
	    return true,da
	}

	pubs3, err := Decode2(ss, "PubKeyData")
	if err == nil {
	    pd,ok := pubs3.(*PubKeyData)
	    if ok {
		return true,pd
	    }
	}
	
	pubs, err := Decode2(ss, "AcceptReqAddrData")
	if err == nil {
	    pd,ok := pubs.(*AcceptReqAddrData)
	    if ok {
		return true,pd
	    }
	}
	
	pubs2, err := Decode2(ss, "AcceptLockOutData")
	if err == nil {
	    pd,ok := pubs2.(*AcceptLockOutData)
	    if ok {
		return true,pd
	    }
	}

	pubs4, err := Decode2(ss, "AcceptSignData")
	if err == nil {
	    pd,ok := pubs4.(*AcceptSignData)
	    if ok {
		return true,pd
	    }
	}
	
	pubs5, err := Decode2(ss, "AcceptReShareData")
	if err == nil {
	    pd,ok := pubs5.(*AcceptReShareData)
	    if ok {
		return true,pd
	    }
	}
	
	return true,da
    }

    return exsit,datmp
}

func GetPubKeyDataValueFromDb2(key string) (bool,interface{}) {
    if key == "" {
	common.Debug("========================GetPubKeyDataValueFromDb2, param err=======================","key",key)
	return false,nil
    }

    da := GetPubKeyDataValueFromDb(key)
    if da == nil {
	common.Debug("========================GetPubKeyDataValueFromDb2, get value from local db fail =======================","key",key)
	return false,nil
    }

    ss, err := UnCompress(string(da))
    if err != nil {
	common.Debug("========================GetPubKeyDataValueFromDb2, uncompress err=======================","err",err,"key",key)
	return true,da
    }

    pubs3, err := Decode2(ss, "PubKeyData")
    if err == nil {
	common.Debug("========================GetPubKeyDataValueFromDb2, get PubKeyData success=======================","key",key)
	pd,ok := pubs3.(*PubKeyData)
	if ok && pd != nil && pd.Key != "" && pd.Save != "" {
	    return true,pd
	}
    }
    
    pubs4, err := Decode2(ss, "AcceptSignData")
    if err == nil {
	common.Debug("========================GetPubKeyDataValueFromDb2, get AcceptSignData success=======================","key",key)
	pd,ok := pubs4.(*AcceptSignData)
	if ok && pd != nil && pd.Keytype != "" {
	    return true,pd
	}
    }
    
    pubs5, err := Decode2(ss, "AcceptReShareData")
    if err == nil {
	common.Debug("========================GetPubKeyDataValueFromDb2, get AcceptReShareData success=======================","key",key)
	pd,ok := pubs5.(*AcceptReShareData)
	if ok && pd != nil && pd.TSGroupId != "" {
	    return true,pd
	}
    }
    
    pubs, err := Decode2(ss, "AcceptReqAddrData")
    if err == nil {
	common.Debug("========================GetPubKeyDataValueFromDb2, get AcceptReqAddrData success=======================","key",key)
	pd,ok := pubs.(*AcceptReqAddrData)
	if ok && pd != nil && pd.Account != "" {
	    return true,pd
	}
    }
    
    common.Debug("========================GetPubKeyDataValueFromDb2, get []byte success=======================","key",key)
    return true,da
}

func GetPubKeyDataFromLocalDb(key string) (bool,interface{}) {
    if key == "" {
	return false,nil
    }

    da := GetPubKeyDataValueFromDb(key)
    if da == nil {
	common.Debug("========================GetPubKeyDataFromLocalDb, get pubkey data from db fail =======================","key",key)
	return false,nil
    }

    ss, err := UnCompress(string(da))
    if err != nil {
	common.Debug("========================GetPubKeyDataFromLocalDb, uncompress err=======================","err",err,"key",key)
	return false,nil
    }

    pubs, err := Decode2(ss, "PubKeyData")
    if err != nil {
	common.Debug("========================GetPubKeyDataFromLocalDb, decode err=======================","err",err,"key",key)
	return false,nil
    }

    pd,ok := pubs.(*PubKeyData)
    if !ok {
	common.Debug("========================GetPubKeyDataFromLocalDb, it is not pubkey data ========================")
	return false,nil
    }

    return true,pd 
}

func GetReqAddrInfoData(key []byte) (bool,interface{}) {
    if key == nil || reqaddrinfodb == nil {
	    common.Error("========================GetReqAddrInfoData, param err=======================","key",string(key))
	return false,nil
    }
	
    da, err := reqaddrinfodb.Get(key)
    if da == nil || err != nil {
	common.Error("========================GetReqAddrInfoData, get reqaddr info from local db fail =======================","key",string(key))
	return false,nil
    }
 
    ss, err := UnCompress(string(da))
    if err != nil {
	common.Error("========================GetReqAddrInfoData, uncompress err=======================","err",err,"key",string(key))
	return true,da
    }
 
    pubs, err := Decode2(ss, "AcceptReqAddrData")
    if err == nil {
	pd,ok := pubs.(*AcceptReqAddrData)
	if ok {
	    return true,pd
 	}
    }
    
    return false,nil
}

//----------------------------------------------------------------

func PutReqAddrInfoData(key []byte,value []byte) error {
    if reqaddrinfodb == nil || key == nil || value == nil {
	return fmt.Errorf("put reqaddr info to db fail")
    }
 
    err := reqaddrinfodb.Put(key,value)
    if err == nil {
	common.Debug("===============PutReqAddrInfoData, put reqaddr info into db success.=================","key",string(key))
	return nil	
    }
	
    common.Error("===============PutReqAddrInfoData, put reqaddr info into db fail.=================","key",string(key),"err",err)
    return err
}

//----------------------------------------------------------------

func DeleteReqAddrInfoData(key []byte) error {
    if key == nil || reqaddrinfodb == nil {
	return fmt.Errorf("delete reqaddr info from db fail.")
    }
 
    err := reqaddrinfodb.Delete(key)
    if err == nil {
	common.Debug("===============DeleteReqAddrInfoData, del reqaddr info from db success.=================","key",string(key))
	return nil
    }
 
    common.Error("===============DeleteReqAddrInfoData, delete reqaddr info from db fail.=================","key",string(key),"err",err)
    return err
}

//--------------------------------------------------------------

func GetSignInfoData(key []byte) (bool,interface{}) {
    if key == nil || signinfodb == nil {
	    common.Error("========================GetSignInfoData, param err=======================","key",string(key))
	return false,nil
    }
	
    da, err := signinfodb.Get(key)
    if da == nil || err != nil {
	common.Error("========================GetSignInfoData, get sign info from local db fail =======================","key",string(key))
	return false,nil
    }
 
    ss, err := UnCompress(string(da))
    if err != nil {
	common.Error("========================GetSignInfoData, uncompress err=======================","err",err,"key",string(key))
	return true,da
    }
 
    pubs, err := Decode2(ss, "AcceptSignData")
    if err == nil {
	pd,ok := pubs.(*AcceptSignData)
	if ok && pd.Keytype != "" {
	    return true,pd
 	}
    }
    
    return false,nil
}

//-------------------------------------------------------

func PutSignInfoData(key []byte,value []byte) error {
    if signinfodb == nil || key == nil || value == nil {
	return fmt.Errorf("put sign info to db fail")
    }
 
    err := signinfodb.Put(key,value)
    if err == nil {
	common.Debug("===============PutSignInfoData, put sign info into db success.=================","key",string(key))
	return nil	
    }
	
    common.Error("===============PutSignInfoData, put sign info into db fail.=================","key",string(key),"err",err)
    return err
}

//-----------------------------------------------------------

func DeleteSignInfoData(key []byte) error {
    if key == nil || signinfodb == nil {
	return fmt.Errorf("delete sign info from db fail.")
    }
 
    err := signinfodb.Delete(key)
    if err == nil {
	common.Debug("===============DeleteSignInfoData, del sign info from db success.=================","key",string(key))
	return nil
    }
 
    common.Error("===============DeleteSignInfoData, delete sign info from db fail.=================","key",string(key),"err",err)
    return err
}

//------------------------------------------------------

func GetReShareInfoData(key []byte) (bool,interface{}) {
    if key == nil || reshareinfodb == nil {
	    common.Error("========================GetReShareInfoData, param err=======================","key",string(key))
	return false,nil
    }
	
    da, err := reshareinfodb.Get(key)
    if da == nil || err != nil {
	common.Error("========================GetReShareInfoData, get reshare info from local db fail =======================","key",string(key))
	return false,nil
    }
 
    ss, err := UnCompress(string(da))
    if err != nil {
	common.Error("========================GetReShareInfoData, uncompress err=======================","err",err,"key",string(key))
	return true,da
    }
 
    pubs, err := Decode2(ss, "AcceptReShareData")
    if err == nil {
	pd,ok := pubs.(*AcceptReShareData)
	if ok && pd.TSGroupId != "" {
	    return true,pd
 	}
    }
    
    return false,nil
}

//-------------------------------------------------------

func PutReShareInfoData(key []byte,value []byte) error {
    if reshareinfodb == nil || key == nil || value == nil {
	return fmt.Errorf("put reshare info to db fail")
    }
 
    err := reshareinfodb.Put(key,value)
    if err == nil {
	common.Debug("===============PutReShareInfoData, put reshare info into db success.=================","key",string(key))
	return nil	
    }
	
    common.Error("===============PutReShareInfoData, put reshare info into db fail.=================","key",string(key),"err",err)
    return err
}

//-------------------------------------------------------

func DeleteReShareInfoData(key []byte) error {
    if key == nil || reshareinfodb == nil {
	return fmt.Errorf("delete reshare info from db fail.")
    }
 
    err := reshareinfodb.Delete(key)
    if err == nil {
	common.Debug("===============DeleteReShareInfoData, del reshare info from db success.=================","key",string(key))
	return nil
    }
 
    common.Error("===============DeleteReShareInfoData, delete reshare info from db fail.=================","key",string(key),"err",err)
    return err
}

func GetGroupDir() string { //TODO
	dir := common.DefaultDataDir()
	dir += "/dcrmdata/dcrmdb" + discover.GetLocalID().String() + "group"
	return dir
}

func GetDbDir() string {
	dir := common.DefaultDataDir()
	dir += "/dcrmdata/dcrmdb" + cur_enode
	return dir
}

func GetSkU1Dir() string {
	dir := common.DefaultDataDir()
	dir += "/dcrmdata/sk" + cur_enode
	return dir
}

func GetAllAccountsDir() string {
	dir := common.DefaultDataDir()
	dir += "/dcrmdata/allaccounts" + cur_enode
	return dir
}

func GetAcceptLockOutDir() string {
	dir := common.DefaultDataDir()
	dir += "/dcrmdata/dcrmdb/acceptlockout" + cur_enode
	return dir
}

func GetAcceptReqAddrDir() string {
	dir := common.DefaultDataDir()
	dir += "/dcrmdata/dcrmdb/acceptreqaddr" + cur_enode
	return dir
}

func GetGAccsDir() string {
	dir := common.DefaultDataDir()
	dir += "/dcrmdata/dcrmdb/gaccs" + cur_enode
	return dir
}

func GetReqAddrInfoDir() string {
         dir := common.DefaultDataDir()
         dir += "/dcrmdata/dcrmreqaddrinfo" + cur_enode
         return dir
} 


func GetDcrmReqAddrInfoDb() *ethdb.LDBDatabase {
    dir := GetReqAddrInfoDir()
    reqaddrinfodb, err := ethdb.NewLDBDatabase(dir, cache, handles)
    if err != nil {
	common.Error("======================dcrm.Start,open reqaddrinfodb fail======================","err",err,"dir",dir)
	return nil
    }

    return reqaddrinfodb
}

//--------------------------------------------------------------

func GetSignInfoDir() string {
         dir := common.DefaultDataDir()
         dir += "/dcrmdata/dcrmsigninfo" + cur_enode
         return dir
} 

func GetDcrmSignInfoDb() *ethdb.LDBDatabase {
    dir := GetSignInfoDir()
    signinfodb, err := ethdb.NewLDBDatabase(dir, cache, handles)
    if err != nil {
	common.Error("======================dcrm.Start,open signinfodb fail======================","err",err,"dir",dir)
	return nil
    }

    return signinfodb
}

//--------------------------------------------------------------

func GetReShareInfoDir() string {
         dir := common.DefaultDataDir()
         dir += "/dcrmdata/dcrmreshareinfo" + cur_enode
         return dir
} 

func GetDcrmReShareInfoDb() *ethdb.LDBDatabase {
    dir := GetReShareInfoDir()
    reshareinfodb, err := ethdb.NewLDBDatabase(dir, cache, handles)
    if err != nil {
	common.Error("======================dcrm.Start,open reshareinfodb fail======================","err",err,"dir",dir)
	return nil
    }

    return reshareinfodb
}

//-----------------------------------------------------------

func CleanUpAllReqAddrInfo() {
    if reqaddrinfodb == nil {
	return
    }

    iter := reqaddrinfodb.NewIterator()
    for iter.Next() {
	key := []byte(string(iter.Key())) //must be deep copy, Otherwise, an error will be reported: "panic: JSON decoder out of sync - data changing underfoot?"
	if len(key) == 0 {
	    continue
	}

	exsit,da := GetReqAddrInfoData(key) 
	if !exsit || da == nil {
	    continue
	}
	    
	vv,ok := da.(*AcceptReqAddrData)
	if vv == nil || !ok {
	    continue
	}

	vv.Status = "Timeout"
	
	e, err := Encode2(vv)
	if err != nil {
	    continue
	}

	es, err := Compress([]byte(e))
	if err != nil {
	    continue
	}
	
	DeleteReqAddrInfoData(key)
	kdtmp := KeyData{Key: key, Data: es}
	PubKeyDataChan <- kdtmp
    }
    iter.Release()
}

func CleanUpAllSignInfo() {
    if signinfodb == nil {
	return
    }

    iter := signinfodb.NewIterator()
    for iter.Next() {
	key := []byte(string(iter.Key())) //must be deep copy, Otherwise, an error will be reported: "panic: JSON decoder out of sync - data changing underfoot?"
	if len(key) == 0 {
	    continue
	}

	exsit,da := GetSignInfoData(key) 
	if !exsit || da == nil {
	    continue
	}
	    
	vv,ok := da.(*AcceptSignData)
	if vv == nil || !ok {
	    continue
	}

	vv.Status = "Timeout"
	
	e, err := Encode2(vv)
	if err != nil {
	    continue
	}

	es, err := Compress([]byte(e))
	if err != nil {
	    continue
	}
	
	DeleteSignInfoData(key)
	kdtmp := KeyData{Key: key, Data: es}
	PubKeyDataChan <- kdtmp
    }
    iter.Release()
}
	
func CleanUpAllReshareInfo() {
    if reshareinfodb == nil {
	return
    }

    iter := reshareinfodb.NewIterator()
    for iter.Next() {
	key := []byte(string(iter.Key())) //must be deep copy, Otherwise, an error will be reported: "panic: JSON decoder out of sync - data changing underfoot?"
	if len(key) == 0 {
	    continue
	}

	exsit,da := GetReShareInfoData(key) 
	if !exsit || da == nil {
	    continue
	}
	    
	vv,ok := da.(*AcceptReShareData)
	if vv == nil || !ok {
	    continue
	}

	vv.Status = "Timeout"
	
	e, err := Encode2(vv)
	if err != nil {
	    continue
	}

	es, err := Compress([]byte(e))
	if err != nil {
	    continue
	}
	
	DeleteReShareInfoData(key)
	kdtmp := KeyData{Key: key, Data: es}
	PubKeyDataChan <- kdtmp
    }
    iter.Release()
}

