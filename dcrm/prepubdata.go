
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
	"math/big"
	"github.com/fsn-dev/dcrm-walletService/ethdb"
	"time"
)

var (
	PrePubKeyDataChan = make(chan KeyData, 2000)
	PrePubKeyDataQueueChan = make(chan *PrePubData, 1000)
	predb *ethdb.LDBDatabase
)

type PreSign struct {
	Pub string
	Gid string
	Nonce string
	Index int
}

type PrePubData struct {
	K1 *big.Int
	R *big.Int
	Ry *big.Int
	Sigma1 *big.Int
	Gid string
	Index int
}

func GetPreDbDir() string {
	dir := common.DefaultDataDir()
	dir += "/dcrmdata/dcrmpredb" + cur_enode
	return dir
}

func GetAllPrePubkeyDataFromDb() {
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

func SavePrePubKeyDataToDb() {
	for {
		kd := <-PrePubKeyDataChan
		if predb != nil {
			//common.Debug("=================SavePubKeyDataToDb, db is not nil ===============","key",kd.Key)
		    if kd.Data == "CLEAN" {
			err := predb.Delete(kd.Key)
			if err != nil {
				common.Debug("=================SavePubKeyDataToDb, db is not nil and delete fail ===============","key",kd.Key)
			    //PubKeyDataChan <- kd
			}
		    } else {
			err := predb.Put(kd.Key, []byte(kd.Data))
			if err != nil {
				common.Debug("=================SavePubKeyDataToDb, db is not nil and save fail ===============","key",kd.Key)
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
				common.Debug("=================SavePubKeyDataToDb, re-get db fail and save fail ===============","key",kd.Key)
				//dbsk = nil
			    } else {
				predb = predbtmp
				err = predb.Put(kd.Key, []byte(kd.Data))
				if err != nil {
					common.Debug("=================SavePubKeyDataToDb, re-get db success and save fail ===============","key",kd.Key)
				    //PubKeyDataChan <- kd
				}
			    }

			}
			//db.Close()
		    }
		} else {
			common.Debug("=================SavePubKeyDataToDb, save to db fail ,db is nil ===============","key",kd.Key)
			//PubKeyDataChan <- kd
		}

		time.Sleep(time.Duration(1000000)) //na, 1 s = 10e9 na
	    }
}

