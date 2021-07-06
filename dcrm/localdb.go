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
    //"sync"
    "fmt"
    "github.com/fsn-dev/dcrm-walletService/p2p/discover"
)

var (
	//LdbPubKeyData  = common.NewSafeMap(10) //make(map[string][]byte)
	//PubKeyDataChan = make(chan KeyData, 2000)
	//SkU1Chan = make(chan KeyData, 2000)
	
	cache = (75*1024)/1000 
	handles = makeDatabaseHandles()
	
	//lock                     sync.Mutex
	db *ethdb.LDBDatabase
	dbsk *ethdb.LDBDatabase
)

//----------------------------------------------------------------

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

//--------------------------------------------------------------

func GetPubKeyData(key []byte) (bool,interface{}) {
    if key == nil || db == nil {
	    common.Debug("========================GetPubKeyData, param err=======================","key",string(key))
	return false,nil
    }
	
    da, err := db.Get(key)
    if da == nil || err != nil {
	common.Info("========================GetPubKeyData, get pubkey data from local db fail =======================","key",string(key))
	return false,nil
    }

    ss, err := UnCompress(string(da))
    if err != nil {
	common.Debug("========================GetPubKeyData, uncompress err=======================","err",err,"key",string(key))
	return true,da
    }

    pubs3, err := Decode2(ss, "PubKeyData")
    //common.Debug("========================GetPubKeyData, decode PubKeyData finish 11111=======================","key",string(key),"err",err)
    if err == nil {
	pd,ok := pubs3.(*PubKeyData)
	if ok && pd.Key != "" && pd.Save != "" {  
	    //common.Debug("========================GetPubKeyData, the type is *PubKeyData,decode PubKeyData success=======================","key",string(key),"data",pubs3)
	    return true,pd
	}
    }
    
    pubs4, err := Decode2(ss, "AcceptSignData")
    //common.Debug("========================GetPubKeyData, decode PubKeyData finish 222222=======================","key",string(key),"err",err)
    if err == nil {
	pd,ok := pubs4.(*AcceptSignData)
	if ok && pd.Keytype != "" {
	    //common.Debug("========================GetPubKeyData, decode AcceptSignData success,the type is *AcceptSignData=======================","key",string(key),"data",pubs4)
	    return true,pd
	}
    }
    
    pubs5, err := Decode2(ss, "AcceptReShareData")
    if err == nil {
	pd,ok := pubs5.(*AcceptReShareData)
	if ok && pd.TSGroupId != "" {
	    //common.Debug("========================GetPubKeyData, decode AcceptReShareData success,the type is *AcceptReShareData=======================","key",string(key),"data",pubs5)
	    return true,pd
	}
    }
    
    pubs, err := Decode2(ss, "AcceptReqAddrData")
    if err == nil {
	pd,ok := pubs.(*AcceptReqAddrData)
	if ok {
	    //common.Debug("========================GetPubKeyData, decode AcceptReqAddrData success, the type is *AcceptReqAddrData=======================","key",string(key),"data",pubs)
	    return true,pd
	}
    }
    
    /*pubs2, err := Decode2(ss, "AcceptLockOutData")
    if err == nil {
	pd,ok := pubs2.(*AcceptLockOutData)
	if ok {
	    return true,pd
	}
    }*/

    return false,nil
}

//-------------------------------------------------------------------

func PutPubKeyData(key []byte,value []byte) error {
    if db == nil || key == nil || value == nil {
	return fmt.Errorf("put pubkey data fail")
    }

    for i:=0;i<10;i++ {
	err := db.Put(key,value)
	if err == nil {
	    common.Debug("===============PutPubKeyData, put pubkey data into db success.=================","key",string(key))
	    return nil	
	}
	
	time.Sleep(time.Duration(1) * time.Second) //1000 == 1s
    }

    common.Debug("===============PutPubKeyData, put pubkey data into db fail.=================","key",string(key))
    return fmt.Errorf("put pubkey data into db fail")
}

//--------------------------------------------------------------------------

func DeletePubKeyData(key []byte) {
    if key == nil || db == nil {
	return
    }

    for i:=0;i<10;i++ {
	err := db.Delete(key)
	if err == nil {
	    common.Debug("===============DeletePubKeyData, del pubkey data from db success.=================","key",string(key))
	    return
	}

	time.Sleep(time.Duration(1) * time.Second) //1000 == 1s
    }
    
    common.Debug("===============DeletePubKeyData, del pubkey data from db fail.=================","key",string(key))
}

//-------------------------------------------------------------------------------

func getSkU1FromLocalDb(key []byte) []byte {
    if key == nil || dbsk == nil {
	return nil
    }

    da, err := dbsk.Get(key)
    if err != nil || da == nil {
	common.Info("========================getSkU1FromLocalDb,get sku1 from local db error.=========================","err",err,"key",string(key))
	return nil
    }

    sk,err := DecryptMsg(string(da))
    if err != nil {
	common.Info("========================getSkU1FromLocalDb,decrypt sku1 data error.=========================","err",err,"key",string(key))
	return da //TODO ,tmp code 
    }

    return []byte(sk)
}

func putSkU1ToLocalDb(key []byte,value []byte)  error {
    if dbsk == nil || key == nil || value == nil {
	return fmt.Errorf("put sku1 data fail")
    }

    cm,err := EncryptMsg(string(value),cur_enode)
    if err != nil {
	common.Debug("===============putSkU1ToLocalDb, encrypt sku1 data fail.=================","err",err,"key",string(key))
	return err
    }

    for i:=0;i<10;i++ {
	err = dbsk.Put(key, []byte(cm))
	if err == nil {
	    common.Debug("===============putSkU1ToLocalDb, put sku1 data into db success.=================","key",string(key))
	    return nil	
	}
	
	time.Sleep(time.Duration(1) * time.Second) //1000 == 1s
    }

    common.Debug("===============putSkU1ToLocalDb, put sku1 data into db fail.=================","key",string(key))
    return fmt.Errorf("put sku1 data into db fail")
}

//--------------------------------------------------------------------------

func deleteSkU1FromLocalDb(key []byte) {
    if key == nil || dbsk == nil {
	return
    }

    for i:=0;i<10;i++ {
	err := dbsk.Delete(key)
	if err == nil {
	    common.Debug("===============deleteSkU1FromLocalDb, del sku1 data from db success.=================","key",string(key))
	    return
	}

	time.Sleep(time.Duration(1) * time.Second) //1000 == 1s
    }
    
    common.Debug("===============deleteSkU1FromLocalDb, del sku1 data from db fail.=================","key",string(key))
}

//------------------------------------------------------------------------------

/*type KeyData struct {
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
			    common.Info("=================SavePubKeyDataToDb, db is not nil and save fail ===============","key",kd.Key)
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
	    common.Debug("========================GetAllPubKeyDataFromDb,db is not nil =================================")
	    iter := db.NewIterator()
	    for iter.Next() {
		key := string(iter.Key())
		value := string(iter.Value())

		ss, err := UnCompress(value)
		if err == nil {
		    pubs3, err := Decode2(ss, "PubKeyData")
		    if err == nil {
			pd,ok := pubs3.(*PubKeyData)
			if ok {
			    kd.WriteMap(key, pd)
			    continue
			}
		    }
		    
		    pubs, err := Decode2(ss, "AcceptReqAddrData")
		    if err == nil {
			pd,ok := pubs.(*AcceptReqAddrData)
			if ok {
			    kd.WriteMap(key, pd)

			    continue
			}
		    }
		    
		    continue
		}

		kd.WriteMap(key, []byte(value))
	    }
	    
	    iter.Release()
    //	db.Close()
	}

	return kd
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
*/

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

