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
    "github.com/anyswap/Anyswap-MPCNode/internal/common/fdlimit"
    "github.com/anyswap/Anyswap-MPCNode/ethdb"
    "time"
    "fmt"
    "runtime/debug"
    "sync"
    "github.com/anyswap/Anyswap-MPCNode/p2p/discover"
    "github.com/anyswap/Anyswap-MPCNode/log"
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
	prekey  *ethdb.LDBDatabase
)

func makeDatabaseHandles() int {
     limit, err := fdlimit.Current()
     if err != nil {
	 //Fatalf("Failed to retrieve file descriptor allowance: %v", err)
	 log.Info("Failed to retrieve file descriptor allowance: " + err.Error())
	 return 0
     }
     if limit < 2048 {
	     if err := fdlimit.Raise(2048); err != nil {
		     //Fatalf("Failed to raise file descriptor allowance: %v", err)
		     log.Info("Failed to raise file descriptor allowance: " + err.Error())
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
	    dir := GetSkU1Dir()
	    dbsktmp, err := ethdb.NewLDBDatabase(dir, cache, handles)
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
	    dbsktmp, err := ethdb.NewLDBDatabase(dir, cache, handles)
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
	lock.Lock()
	if db == nil {
	    lock.Unlock()
	    return nil
 	}

	da, err := db.Get([]byte(key))
	if err != nil {
	    lock.Unlock()
	    return nil
	}

	lock.Unlock()
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
				log.Error("=================SavePubKeyDataToDb, delete data from local db fail ===============","key",kd.Key,"err",err)
			}
		    } else {
			err := db.Put(kd.Key, []byte(kd.Data))
			if err != nil {
			    log.Error("=================SavePubKeyDataToDb,save data to local db fail ===============","key",kd.Key,"err",err)
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
				log.Error("=================SavePubKeyDataToDb, re-get db fail and save data to local db fail ===============","key",kd.Key,"err",err)
			    } else {
				db = dbtmp
				err = db.Put(kd.Key, []byte(kd.Data))
				if err != nil {
					log.Error("=================SavePubKeyDataToDb, re-get db success and save data to local db fail ===============","key",kd.Key,"err",err)
				}
			    }
			}
		    }
		} else {
			log.Error("=================SavePubKeyDataToDb, save to db fail ,db is nil ===============","key",kd.Key)
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
	}

	return kd
}

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

    defer func() {
             if r := recover(); r != nil {
                     fmt.Errorf("GetValueFromDb error: %v\n%v", r, string(debug.Stack()))
                     return
             }
     }()
    
     da, err := db.Get([]byte(key))
    if err != nil || da == nil {
	return false,nil
    }

    ss, err := UnCompress(string(da))
    if err != nil {
	return true,da
    }

    pubs3, err := Decode2(ss, "PubKeyData")
    if err == nil {
	pd,ok := pubs3.(*PubKeyData)
	if ok && pd != nil && pd.Key != "" && pd.Save != "" {
	    return true,pd
	}
    }
    
    pubs4, err := Decode2(ss, "AcceptSignData")
    if err == nil {
	pd,ok := pubs4.(*AcceptSignData)
	if ok && pd != nil && pd.Keytype != "" {
	    return true,pd
	}
    }
    
    pubs5, err := Decode2(ss, "AcceptReShareData")
    if err == nil {
	pd,ok := pubs5.(*AcceptReShareData)
	if ok && pd != nil && pd.TSGroupId != "" {
	    return true,pd
	}
    }
    
    pubs, err := Decode2(ss, "AcceptReqAddrData")
    if err == nil {
	pd,ok := pubs.(*AcceptReqAddrData)
	if ok && pd != nil && pd.Account != "" {
	    return true,pd
	}
    }
    
    return true,da
}

func GetValueFromPubKeyData(key string) (bool,interface{}) {
    if key == "" {
	return false,nil
    }

    datmp, exsit := LdbPubKeyData.ReadMap(key)
    if !exsit {
	return GetValueFromDb(key)
    }

    return exsit,datmp
}

func GetPubKeyDataFromLocalDb(key string) (bool,interface{}) {
    if key == "" {
	return false,nil
    }

    da := GetPubKeyDataValueFromDb(key)
    if da == nil {
	return false,nil
    }

    ss, err := UnCompress(string(da))
    if err != nil {
	return false,nil
    }

    pubs, err := Decode2(ss, "PubKeyData")
    if err != nil {
	return false,nil
    }

    pd,ok := pubs.(*PubKeyData)
    if !ok {
	return false,nil
    }

    return true,pd 
}

//----------------------------------------------------------------------------------

// GetPreKeyDir get public key group information database dir
func GetPreKeyDir() string {
	dir := common.DefaultDataDir()
	dir += "/smpcdata/smpcprekey" + cur_enode
	return dir
}

// GetSmpcPreKeyDb open public key group information database
func GetSmpcPreKeyDb() *ethdb.LDBDatabase {
	dir := GetPreKeyDir()
	prekey, err := ethdb.NewLDBDatabase(dir, cache, handles)
	if err != nil {
		return nil
	}

	return prekey
}

//----------------------------------------------------------------------------------

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

