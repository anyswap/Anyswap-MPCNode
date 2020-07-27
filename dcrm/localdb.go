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
    "github.com/fsn-dev/dcrm-walletService/ethdb"
    "time"
    //"fmt"
    "github.com/fsn-dev/dcrm-walletService/p2p/discover"
)

var (
	LdbPubKeyData  = common.NewSafeMap(10) //make(map[string][]byte)
	PubKeyDataChan = make(chan KeyData, 10000)
	SkU1Chan = make(chan KeyData, 10000)
	cache = 0 
	handles = 0
)

func GetSkU1FromLocalDb(key string) []byte {
	lock.Lock()
	/*dir := GetSkU1Dir()
	////////
	db, err := ethdb.NewLDBDatabase(dir, cache, handles)
	//bug
	if err != nil {
		for i := 0; i < 100; i++ {
			db, err = ethdb.NewLDBDatabase(dir, cache, handles)
			if err == nil {
				break
			}

			time.Sleep(time.Duration(1000000))
		}
	}*/
	//
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
	lock.Lock()
	if db == nil {
	    common.Debug("===================GetPubKeyDataValueFromDb, db is nil ===================")
	    dir := GetDbDir()
	    ////////
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
		lock.Unlock()
		return nil
	    } else {
		db = dbtmp
		da, err := db.Get([]byte(key))
		if err != nil {
		    lock.Unlock()
		    return nil
		}

		lock.Unlock()
		return da
	    }
	}

	da, err := db.Get([]byte(key))
	if err != nil {
	    dir := GetDbDir()
	    ////////
	    dbtmp, err := ethdb.NewLDBDatabase(dir, cache, handles)
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
		lock.Unlock()
		return nil
	    } else {
		db = dbtmp
		da, err := db.Get([]byte(key))
		if err != nil {
		    lock.Unlock()
		    return nil
		}

		lock.Unlock()
		return da
	    }
	}

	lock.Unlock()
	return da
}

type KeyData struct {
	Key  []byte
	Data string
}

func SavePubKeyDataToDb() {
	/*for {
		select {
		case kd := <-PubKeyDataChan:
			if db != nil {
			    if kd.Data == "CLEAN" {
				err := db.Delete(kd.Key)
				if err != nil {
				    PubKeyDataChan <- kd
				    return
				}
			    } else {
				err := db.Put(kd.Key, []byte(kd.Data))
				if err != nil {
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
					//dbsk = nil
				    } else {
					db = dbtmp
					err = db.Put(kd.Key, []byte(kd.Data))
					if err != nil {
					    PubKeyDataChan <- kd
					    return
					}
				    }

				}
				//db.Close()
			    }
			} else {
				PubKeyDataChan <- kd
			}

			time.Sleep(time.Duration(1000000)) //na, 1 s = 10e9 na
		}
	}
	*/
	for {
		kd := <-PubKeyDataChan
		if db != nil {
		    if kd.Data == "CLEAN" {
			err := db.Delete(kd.Key)
			if err != nil {
			    //PubKeyDataChan <- kd
			}
		    } else {
			err := db.Put(kd.Key, []byte(kd.Data))
			if err != nil {
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
				//dbsk = nil
			    } else {
				db = dbtmp
				err = db.Put(kd.Key, []byte(kd.Data))
				if err != nil {
				    //PubKeyDataChan <- kd
				}
			    }

			}
			//db.Close()
		    }
		} else {
			//PubKeyDataChan <- kd
		}

		time.Sleep(time.Duration(1000000)) //na, 1 s = 10e9 na
	    }
}

func SaveSkU1ToDb() {
	/*
	for {
		select {
		case kd := <-SkU1Chan:
			if dbsk != nil {
			    cm,err := EncryptMsg(kd.Data,cur_enode)
			    if err != nil {
				SkU1Chan <- kd
				break
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
					return
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
	*/
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
			    //fmt.Printf("%v ==============GetAllPubKeyDataFromDb,success read PubKeyData. key = %v,pd = %v ===============\n", common.CurrentTime(), key,pd)
			    continue
			}
		    }
		    
		    pubs, err := Decode2(ss, "AcceptReqAddrData")
		    if err == nil {
			pd,ok := pubs.(*AcceptReqAddrData)
			if ok {
			    kd.WriteMap(key, pd)
			    //fmt.Printf("%v ==============GetAllPubKeyDataFromDb,success read AcceptReqAddrData. key = %v,pd = %v ===============\n", common.CurrentTime(), key,pd)
			    continue
			}
		    }
		    
		    pubs2, err := Decode2(ss, "AcceptLockOutData")
		    if err == nil {
			pd,ok := pubs2.(*AcceptLockOutData)
			if ok {
			    kd.WriteMap(key, pd)
			    //fmt.Printf("%v ==============GetAllPubKeyDataFromDb,success read AcceptLockOutData. key = %v,pd = %v ===============\n", common.CurrentTime(), key,pd)
			    continue
			}
		    }

		    pubs4, err := Decode2(ss, "AcceptSignData")
		    if err == nil {
			pd,ok := pubs4.(*AcceptSignData)
			if ok {
			    kd.WriteMap(key, pd)
			    //fmt.Printf("%v ==============GetAllPubKeyDataFromDb,success read AcceptReqAddrData. key = %v,pd = %v ===============\n", common.CurrentTime(), key,pd)
			    continue
			}
		    }
		    
		    pubs5, err := Decode2(ss, "AcceptReShareData")
		    if err == nil {
			pd,ok := pubs5.(*AcceptReShareData)
			if ok {
			    kd.WriteMap(key, pd)
			    //fmt.Printf("%v ==============GetAllPubKeyDataFromDb,success read AcceptReqAddrData. key = %v,pd = %v ===============\n", common.CurrentTime(), key,pd)
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

func GetValueFromPubKeyData(key string) (bool,interface{}) {
    if key == "" {
	return false,nil
    }

    datmp, exsit := LdbPubKeyData.ReadMap(key)
    if !exsit {
	da := GetPubKeyDataValueFromDb(key)
	if da == nil {
	    return false,nil
	}

	ss, err := UnCompress(string(da))
	if err != nil {
	    common.Debug("========================GetValueFromPubKeyData, uncompress err=======================","err",err,"key",key)
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

func GetGroupDir() string { //TODO
	dir := common.DefaultDataDir()
	//dir += "/dcrmdata/dcrmdb" + GetSelfEnode() + "group"
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

