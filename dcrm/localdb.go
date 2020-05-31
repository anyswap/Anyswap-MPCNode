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
    "fmt"
    "github.com/fsn-dev/dcrm-walletService/p2p/discover"
)

var (
	LdbPubKeyData  = common.NewSafeMap(10) //make(map[string][]byte)
	PubKeyDataChan = make(chan KeyData, 1000)
	SkU1Chan = make(chan KeyData, 1000)
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
	    fmt.Printf("=====================GetSkU1FromLocalDb, dbsk is nil =====================\n")
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
	///////
	if err != nil {
		//db.Close()
		lock.Unlock()
		return nil
	}

	//db.Close()
	lock.Unlock()
	return da
}

func GetPubKeyDataValueFromDb(key string) []byte {
	lock.Lock()
	/*dir := GetDbDir()
	////////
	db, err := ethdb.NewLDBDatabase(dir, cache, handles)
	//bug
	if err != nil {
	    fmt.Printf("===================GetPubKeyDataValueFromDb, err = %v ===================\n",err)
		for i := 0; i < 100; i++ {
			db, err = ethdb.NewLDBDatabase(dir, cache, handles)
			if err == nil {
				break
			}

			time.Sleep(time.Duration(1000000))
		}
	}*/
	//
	if db == nil {
	    fmt.Printf("===================GetPubKeyDataValueFromDb, db is nil ===================\n")
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
		db = nil
	    } else {
		db = dbtmp
	    }

		lock.Unlock()
		return nil
	}

	da, err := db.Get([]byte(key))
	///////
	if err != nil {
	    fmt.Printf("===================GetPubKeyDataValueFromDb, 222222, err = %v ===================\n",err)
	//	db.Close()
		lock.Unlock()
		return nil
	}

	//db.Close()
	lock.Unlock()
	return da
}

type KeyData struct {
	Key  []byte
	Data string
}

func SavePubKeyDataToDb() {
	for {
		select {
		case kd := <-PubKeyDataChan:
			/*dir := GetDbDir()
			db, err := ethdb.NewLDBDatabase(dir, cache, handles)
			//bug
			if err != nil {
				for i := 0; i < 100; i++ {
					db, err = ethdb.NewLDBDatabase(dir, cache, handles)
					if err == nil && db != nil {
						break
					}

					time.Sleep(time.Duration(1000000))
				}
			}*/
			//
			if db != nil {
			    if kd.Data == "CLEAN" {
				db.Delete(kd.Key)
			    } else {
				err := db.Put(kd.Key, []byte(kd.Data))
				if err != nil {
				    dir := GetSkU1Dir()
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
					db.Put(kd.Key, []byte(kd.Data))
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
}

func SaveSkU1ToDb() {
	for {
		select {
		case kd := <-SkU1Chan:
			/*dir := GetSkU1Dir()
			db, err := ethdb.NewLDBDatabase(dir, cache, handles)
			//bug
			if err != nil {
				for i := 0; i < 100; i++ {
					db, err = ethdb.NewLDBDatabase(dir, cache, handles)
					if err == nil && db != nil {
						break
					}

					time.Sleep(time.Duration(1000000))
				}
			}*/
			//
			if dbsk != nil {
			    err := dbsk.Put(kd.Key, []byte(kd.Data))
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
				    dbsk.Put(kd.Key, []byte(kd.Data))
				}

			    }
			//	db.Close()
			} else {
				SkU1Chan <- kd
			}

			time.Sleep(time.Duration(1000000)) //na, 1 s = 10e9 na
		}
	}
}

func GetAllPubKeyDataFromDb() *common.SafeMap {
	kd := common.NewSafeMap(10)
	/*dir := GetDbDir()
	//fmt.Printf("%v ==============GetAllPubKeyDataFromDb,start read from db,dir = %v ===============\n", common.CurrentTime(), dir)
	db, err := ethdb.NewLDBDatabase(dir, cache, handles)
	//bug
	if err != nil {
		for i := 0; i < 100; i++ {
			db, err = ethdb.NewLDBDatabase(dir, cache, handles)
			if err == nil && db != nil {
				break
			}

			time.Sleep(time.Duration(1000000))
		}
	}*/
	//
	if db != nil {
		//fmt.Printf("%v ==============GetAllPubKeyDataFromDb,open db success.dir = %v ===============\n", common.CurrentTime(), dir)
		iter := db.NewIterator()
		for iter.Next() {
			key := string(iter.Key())
			value := string(iter.Value())

			ss, err := UnCompress(value)
			if err == nil {
			    pubs3, err := Decode2(ss, "PubKeyData")
			    if err == nil {
				pd,ok := pubs3.(*PubKeyData)
				if ok == true {
				    kd.WriteMap(key, pd)
				    //fmt.Printf("%v ==============GetAllPubKeyDataFromDb,success read PubKeyData. key = %v,pd = %v ===============\n", common.CurrentTime(), key,pd)
				    continue
				}
			    }
			    
			    pubs, err := Decode2(ss, "AcceptReqAddrData")
			    if err == nil {
				pd,ok := pubs.(*AcceptReqAddrData)
				if ok == true {
				    kd.WriteMap(key, pd)
				    //fmt.Printf("%v ==============GetAllPubKeyDataFromDb,success read AcceptReqAddrData. key = %v,pd = %v ===============\n", common.CurrentTime(), key,pd)
				    continue
				}
			    }
			    
			    pubs2, err := Decode2(ss, "AcceptLockOutData")
			    if err == nil {
				pd,ok := pubs2.(*AcceptLockOutData)
				if ok == true {
				    kd.WriteMap(key, pd)
				    //fmt.Printf("%v ==============GetAllPubKeyDataFromDb,success read AcceptLockOutData. key = %v,pd = %v ===============\n", common.CurrentTime(), key,pd)
				    continue
				}
			    }
			    
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

    //var data []byte
    datmp, exsit := LdbPubKeyData.ReadMap(key)
    if exsit == false {
	    /*da := GetPubKeyDataValueFromDb(key)
	    if da == nil {
		    exsit = false
	    } else {
		    exsit = true
		    data = da
		    //fmt.Printf("%v==============GetValueFromPubKeyData,get data from db = %v================\n",common.CurrentTime(),string(data))
	    }*/
    } else {
	    //data = []byte(fmt.Sprintf("%v", datmp))
	    //data = datmp.([]byte)
	    //fmt.Printf("%v==============GetValueFromPubKeyData,get data from memory = %v================\n",common.CurrentTime(),string(data))
	    exsit = true
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
	fmt.Printf("========================GetPubKeyDataFromLocalDb, uncompress err = %v ========================\n",err)
	return false,nil
    }

    pubs, err := Decode2(ss, "PubKeyData")
    if err != nil {
	fmt.Printf("========================GetPubKeyDataFromLocalDb, decode err = %v ========================\n",err)
	return false,nil
    }

    pd,ok := pubs.(*PubKeyData)
    if ok == false {
	fmt.Printf("========================GetPubKeyDataFromLocalDb, it is not pubkey data ========================\n")
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

