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
    "encoding/hex"
)

var (
	SkU1Chan = make(chan KeyData, 2000)
	cache = (75*1024)/1000 
	handles = makeDatabaseHandles()
	
	lock                     sync.Mutex
	db *ethdb.LDBDatabase
	dbsk *ethdb.LDBDatabase

	reqaddrinfodb *ethdb.LDBDatabase
	signinfodb *ethdb.LDBDatabase
	reshareinfodb *ethdb.LDBDatabase
	accountsdb *ethdb.LDBDatabase
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

type KeyData struct {
    Key []byte
    Data string
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

//---------------------------------------------------------------------------------------

//db:
//--------compress--------------
// reqaddr key:AcceptReqAddrData
// sign key:AcceptSignData
// reshare key:AcceptReshareData
// pubkey bytes:PubKeyData
// dcrmaddr1:PubKeyData
// dcrmaddrn:PubKeyData
//--------no compress------------
// account:reqaddr nonce
// account+sign:sign nonce
// account+reshare:reshare nonce
// tolower(account1):   pubkey1:pubkey2:.....
// tolower(accountn):   pubkey1:pubkey2:.....
func GetValueFromDb(key string) (bool,interface{}) {
    if key == "" || db == nil {
	return false,nil
    }

    da, err := db.Get([]byte(key))
    if err != nil || da == nil {
	common.Debug("===================GetValueFromDb,get data fail===================","err",err,"key",key)
	return false,nil
    }

    ss, err := UnCompress(string(da))
    if err != nil {
	common.Error("========================GetValueFromDb, uncompress err=======================","err",err,"key",key)
	return true,da
    }

    pubs3, err := Decode2(ss, "PubKeyData")
    if err == nil {
	common.Debug("========================GetValueFromDb, get PubKeyData success=======================","key",key)
	pd,ok := pubs3.(*PubKeyData)
	if ok && pd != nil && pd.Key != "" && pd.Save != "" {
	    return true,pd
	}
    }
    
    pubs4, err := Decode2(ss, "AcceptSignData")
    if err == nil {
	common.Debug("========================GetValueFromDb, get AcceptSignData success=======================","key",key)
	pd,ok := pubs4.(*AcceptSignData)
	if ok && pd != nil && pd.Keytype != "" {
	    return true,pd
	}
    }
    
    pubs5, err := Decode2(ss, "AcceptReShareData")
    if err == nil {
	common.Debug("========================GetValueFromDb, get AcceptReShareData success=======================","key",key)
	pd,ok := pubs5.(*AcceptReShareData)
	if ok && pd != nil && pd.TSGroupId != "" {
	    return true,pd
	}
    }
    
    pubs, err := Decode2(ss, "AcceptReqAddrData")
    if err == nil {
	common.Debug("========================GetValueFromDb, get AcceptReqAddrData success=======================","key",key)
	pd,ok := pubs.(*AcceptReqAddrData)
	if ok && pd != nil && pd.Account != "" {
	    return true,pd
	}
    }
    
    common.Debug("========================GetValueFromDb, get []byte success=======================","key",key)
    return true,da
}

func PutValueToDb(key []byte,value []byte) error {
    if db == nil || key == nil || value == nil {
	return fmt.Errorf("put pubkey data to db fail")
    }
 
    err := db.Put(key,value)
    if err == nil {
	common.Debug("===============PutValueToDb, put pubkey data into db success.=================","key",string(key))
	return nil	
    }
	
    common.Error("===============PutValueToDb, put pubkey data into db fail.=================","key",string(key),"err",err)
    return err
}

//----------------------------------------------------------------------------------------------

func DeleteValueFromDb(key []byte) error {
    if key == nil || db == nil {
	return fmt.Errorf("delete pubkey data from db fail.")
    }
 
    err := db.Delete(key)
    if err == nil {
	common.Debug("===============DeleteValueFromDb, del pubkey data from db success.=================","key",string(key))
	return nil
    }
 
    common.Error("===============DeleteValueFromDb, delete pubkey data from db fail.=================","key",string(key),"err",err)
    return err
}

//-----------------------------------------------------------------------------------------------

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
	PutValueToDb(key,[]byte(es))
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
	PutValueToDb(key,[]byte(es))
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
	PutValueToDb(key,[]byte(es))
    }
    iter.Release()
}

//----------------------------------------------------------

func GetAccountsDir() string {
         dir := common.DefaultDataDir()
         dir += "/dcrmdata/dcrmaccounts" + cur_enode
         return dir
} 

func AccountLoaded() bool {
    dir := GetAccountsDir()
    return common.FileExist(dir)
}

func GetDcrmAccountsDirDb() *ethdb.LDBDatabase {
    dir := GetAccountsDir()
    accountsdb, err := ethdb.NewLDBDatabase(dir, cache, handles)
    if err != nil {
	common.Error("======================dcrm.Start,open accountsdb fail======================","err",err,"dir",dir)
	return nil
    }

    return accountsdb
}

func CopyAllAccountsFromDb() {
    if db == nil {
	return
    }

    iter := db.NewIterator()
    for iter.Next() {
	key := string(iter.Key())
	value := string(iter.Value())

	ss, err := UnCompress(value)
	if err != nil {
	    continue
	}

	pubs, err := Decode2(ss, "PubKeyData")
	if err != nil {
	    continue
	}

	pd,ok := pubs.(*PubKeyData)
	if !ok {
	    continue
	}

	if pd.Pub == "" {
	    continue
	}

	pubkey := hex.EncodeToString([]byte(pd.Pub))

	//key: ys (marshal(pkx,pky)) 
	//key: []byte(hash256(tolower(dcrmaddr))) 
	//value: []byte(pubkey)
	PutAccountDataToDb([]byte(key),[]byte(pubkey))
    }
    
    iter.Release()
}

func GetAccountFromDb(key []byte) (bool,interface{}) {
    if key == nil || accountsdb == nil {
	    common.Error("========================GetAccountFromDb, param err=======================","key",string(key))
	return false,nil
    }
	
    da, err := accountsdb.Get(key)
    if da == nil || err != nil {
	common.Error("========================GetAccountFromDb, get account from local db fail =======================","key",string(key))
	return false,nil
    }
 
    return true,string(da) 
}

//----------------------------------------------------------------

func PutAccountDataToDb(key []byte,value []byte) error {
    if accountsdb == nil || key == nil || value == nil {
	return fmt.Errorf("put account data to db fail")
    }
 
    err := accountsdb.Put(key,value)
    if err == nil {
	common.Debug("===============PutAccountDataToDb, put account data into db success.=================","key",string(key))
	return nil	
    }
	
    common.Error("===============PutAccountDataToDb, put account data into db fail.=================","key",string(key),"err",err)
    return err
}

//----------------------------------------------------------------

func DeleteAccountDataFromDb(key []byte) error {
    if key == nil || accountsdb == nil {
	return fmt.Errorf("delete account data from db fail.")
    }
 
    err := accountsdb.Delete(key)
    if err == nil {
	common.Debug("===============DeleteAccountDataFromDb, del account data from db success.=================","key",string(key))
	return nil
    }
 
    common.Error("===============DeleteAccountDataFromDb, delete account data from db fail.=================","key",string(key),"err",err)
    return err
}



