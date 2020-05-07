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
    "github.com/fsn-dev/dcrm-walletService/p2p/discover"
)

var (
	LdbPubKeyData  = common.NewSafeMap(10) //make(map[string][]byte)
	PubKeyDataChan = make(chan KeyData, 1000)
)

func GetPubKeyDataValueFromDb(key string) []byte {
	lock.Lock()
	dir := GetDbDir()
	////////
	db, err := ethdb.NewLDBDatabase(dir, 0, 0)
	//bug
	if err != nil {
		for i := 0; i < 100; i++ {
			db, err = ethdb.NewLDBDatabase(dir, 0, 0)
			if err == nil {
				break
			}

			time.Sleep(time.Duration(1000000))
		}
	}
	//
	if db == nil {
		common.Info("==============GetPubKeyDataValueFromDb,db is nil=================", "account hash = ", key)
		lock.Unlock()
		return nil
	}

	da, err := db.Get([]byte(key))
	///////
	if err != nil {
		common.Info("==============GetPubKeyDataValueFromDb,read from db error=================", "err = ", err, "account hash = ", key)
		db.Close()
		lock.Unlock()
		return nil
	}

	db.Close()
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
			dir := GetDbDir()
			db, err := ethdb.NewLDBDatabase(dir, 0, 0)
			//bug
			if err != nil {
				for i := 0; i < 100; i++ {
					db, err = ethdb.NewLDBDatabase(dir, 0, 0)
					if err == nil && db != nil {
						break
					}

					time.Sleep(time.Duration(1000000))
				}
			}
			//
			if db != nil {
				db.Put(kd.Key, []byte(kd.Data))
				db.Close()
			} else {
				PubKeyDataChan <- kd
			}

			time.Sleep(time.Duration(1000000)) //na, 1 s = 10e9 na
		}
	}
}

func GetAllPubKeyDataFromDb() *common.SafeMap {
	kd := common.NewSafeMap(10)
	dir := GetDbDir()
	//fmt.Printf("%v ==============GetAllPubKeyDataFromDb,start read from db,dir = %v ===============\n", common.CurrentTime(), dir)
	db, err := ethdb.NewLDBDatabase(dir, 0, 0)
	//bug
	if err != nil {
		for i := 0; i < 100; i++ {
			db, err = ethdb.NewLDBDatabase(dir, 0, 0)
			if err == nil && db != nil {
				break
			}

			time.Sleep(time.Duration(1000000))
		}
	}
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
		db.Close()
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

