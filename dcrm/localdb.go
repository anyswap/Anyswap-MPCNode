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
    "fmt"
    "github.com/fsn-dev/dcrm-walletService/p2p/discover"
)

var (
	cache = (75*1024)/1000 
	handles = makeDatabaseHandles()
	
	db *ethdb.LDBDatabase
	dbsk *ethdb.LDBDatabase
	predb *ethdb.LDBDatabase
	prekey *ethdb.LDBDatabase
)

func makeDatabaseHandles() int {
     limit, err := fdlimit.Current()
     if err != nil {
	     common.Info("Failed to retrieve file descriptor allowance: " + err.Error())
	     return 0
     }
     if limit < 2048 {
	     if err := fdlimit.Raise(2048); err != nil {
		     common.Info("Failed to raise file descriptor allowance: " + err.Error())
	     }
     }
     if limit > 2048 { // cap database file descriptors even if more is available
	     limit = 2048
     }
     return limit / 2 // Leave half for networking and other stuff
}

func GetPubKeyData(key []byte) (bool,interface{}) {
    if key == nil || db == nil {
	    common.Error("========================GetPubKeyData, param err=======================","key",string(key))
	return false,nil
    }
	
    da, err := db.Get(key)
    if da == nil || err != nil {
	common.Error("========================GetPubKeyData, get pubkey data from local db fail =======================","key",string(key))
	return false,nil
    }

    ss, err := UnCompress(string(da))
    if err != nil {
	common.Error("========================GetPubKeyData, uncompress err=======================","err",err,"key",string(key))
	return true,da
    }
 
    pubs3, err := Decode2(ss, "PubKeyData")
    if err == nil {
	pd,ok := pubs3.(*PubKeyData)
	if ok && pd.Key != "" && pd.Save != "" {  
	    return true,pd
 	}
    }
    
    pubs4, err := Decode2(ss, "AcceptSignData")
    if err == nil {
	pd,ok := pubs4.(*AcceptSignData)
	if ok && pd.Keytype != "" {
	    return true,pd
	}
    }
    
    pubs5, err := Decode2(ss, "AcceptReShareData")
    if err == nil {
	pd,ok := pubs5.(*AcceptReShareData)
	if ok && pd.TSGroupId != "" {
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
    
    return false,nil
}

func PutPubKeyData(key []byte,value []byte) error {
    if db == nil || key == nil || value == nil {
	return fmt.Errorf("put pubkey data to db fail")
    }
 
    err := db.Put(key,value)
    if err == nil {
	common.Debug("===============PutPubKeyData, put pubkey data into db success.=================","key",string(key))
	return nil	
    }
	
    common.Error("===============PutPubKeyData, put pubkey data into db fail.=================","key",string(key),"err",err)
    return err
}

//--------------------------------------------------------------------------

func DeletePubKeyData(key []byte) error {
    if key == nil || db == nil {
	return fmt.Errorf("delete pubkey data from db fail.")
    }

    err := db.Delete(key)
    if err == nil {
	common.Debug("===============DeletePubKeyData, del pubkey data from db success.=================","key",string(key))
	return nil
    }

    common.Error("===============DeletePubKeyData, delete pubkey data from db fail.=================","key",string(key),"err",err)
    return err
}

//-------------------------------------------------------------------------------

func getSkU1FromLocalDb(key []byte) []byte {
    if key == nil || dbsk == nil {
	return nil
    }

    da, err := dbsk.Get(key)
    if err != nil || da == nil {
	common.Error("========================getSkU1FromLocalDb,get sku1 from local db error.=========================","err",err)
	return nil
    }

    sk,err := DecryptMsg(string(da))
    if err != nil {
	common.Error("========================getSkU1FromLocalDb,decrypt sku1 data error.=========================","err",err)
	return da
   }

    return []byte(sk)
}

func putSkU1ToLocalDb(key []byte,value []byte)  error {
    if dbsk == nil || key == nil || value == nil {
	return fmt.Errorf("put sku1 data to db fail")
    }

    cm,err := EncryptMsg(string(value),cur_enode)
    if err != nil {
	common.Error("===============putSkU1ToLocalDb, encrypt sku1 data fail.=================","err",err)
	return err
    }
 
    err = dbsk.Put(key,[]byte(cm))
    if err == nil {
	common.Debug("===============putSkU1ToLocalDb, put sku1 data into db success.=================")
	return nil	
    }
	
    common.Error("===============putSkU1ToLocalDb, put sku1 data to db fail.=================","err",err)
    return err
 }

func deleteSkU1FromLocalDb(key []byte) error {
    if key == nil || dbsk == nil {
	return fmt.Errorf("delete sku1 from db fail,param error.")
    }
 
    err := dbsk.Delete(key)
    if err == nil {
	common.Debug("===============deleteSkU1FromLocalDb, delete sku1 data from db success.=================")
	return nil
    }
 
    common.Error("===============deleteSkU1FromLocalDb, delete sku1 data from db fail.=================","err",err)
    return err
}

//-----------------------------------------------------------------------

// key = hash(pubkey:gid)
//value = pubkey:gid
func GetPreKeyDir() string {
	dir := common.DefaultDataDir()
	dir += "/dcrmdata/dcrmprekey" + cur_enode
	return dir
}

//key = tolower(hash(pubkey:gid:index))
//value = PreSignData.Marshal
func GetPreDbDir() string {
	dir := common.DefaultDataDir()
	dir += "/dcrmdata/dcrmpredb" + cur_enode
	return dir
}

//save the group info
func GetGroupDir() string { //TODO
	dir := common.DefaultDataDir()
	dir += "/dcrmdata/dcrmdb" + discover.GetLocalID().String() + "group"
	return dir
}

//save the pubkey/paillier
func GetDbDir() string {
	dir := common.DefaultDataDir()
	dir += "/dcrmdata/dcrmdb" + cur_enode
	return dir
}

//save sku1
func GetSkU1Dir() string {
	dir := common.DefaultDataDir()
	dir += "/dcrmdata/sk" + cur_enode
	return dir
}

