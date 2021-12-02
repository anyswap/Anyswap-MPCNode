
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
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"strconv"
	"strings"
	"sync"
	"time"
	"bytes"
	"os"

	"github.com/fsn-dev/cryptoCoins/coins"
	cryptocoinsconfig "github.com/fsn-dev/cryptoCoins/coins/config"
	"github.com/fsn-dev/cryptoCoins/coins/eos"
	"github.com/fsn-dev/cryptoCoins/coins/types"
	"github.com/fsn-dev/dcrm-walletService/internal/common"
	p2pdcrm "github.com/fsn-dev/dcrm-walletService/p2p/layer2"
	"github.com/fsn-dev/cryptoCoins/tools/rlp"
	"github.com/fsn-dev/dcrm-walletService/ethdb"
	"github.com/fsn-dev/dcrm-walletService/mpcdsa/crypto/ec2"
	"github.com/fsn-dev/dcrm-walletService/p2p/discover"
	"encoding/gob"
	"sort"
	"compress/zlib"
	"github.com/fsn-dev/dcrm-walletService/crypto/sha3"
	"io"
	"github.com/fsn-dev/dcrm-walletService/internal/common/hexutil"
	"github.com/fsn-dev/dcrm-walletService/mpcdsa/crypto/ed"
)

var (
	cur_enode  string
	init_times = 0
	recalc_times = 1 
	KeyFile    string
	signer = types.NewEIP155Signer(big.NewInt(30400))
)

type NodeReply struct {
    Enode string
    Status string
    TimeStamp string
    Initiator string // "1"/"0"
}

func Start(waitmsg uint64,trytimes uint64,presignnum uint64,waitagree uint64) {
	cryptocoinsconfig.Init()
	coins.Init()
	
	InitDev(KeyFile)
	cur_enode = p2pdcrm.GetSelfID()
	accloaded := AccountLoaded()
	
	common.Info("======================dcrm.Start======================","accounts loaded",accloaded,"cache",cache,"handles",handles,"cur enode",cur_enode)
	
	dir := GetDbDir()
	dbtmp, err := ethdb.NewLDBDatabase(dir, cache, handles)
	//bug
	if err != nil {
	    common.Info("======================dcrm.Start,open db fail======================","err",err,"dir",dir)
		for i := 0; i < 80; i++ {
			dbtmp2, err2 := ethdb.NewLDBDatabase(dir, cache, handles)
			if err2 == nil && dbtmp2 != nil {
				dbtmp = dbtmp2
				err = err2
				break
			} else {
			    common.Info("======================dcrm.Start,open db fail======================","i",i,"err",err2,"dir",dir)
			}

			//time.Sleep(time.Duration(1000000000))
			time.Sleep(time.Duration(2) * time.Second)
		}
	}
	if err != nil {
	    db = nil
	} else {
	    db = dbtmp
	}

	if db == nil {
	    common.Info("======================dcrm.Start,open db fail and gdcrm panic======================")
	    os.Exit(1)
	    return
	}

	time.Sleep(time.Duration(10) * time.Second)
	
	//
	dbsktmp, err := ethdb.NewLDBDatabase(GetSkU1Dir(), cache, handles)
	//bug
	if err != nil {
	    common.Info("======================dcrm.Start,open dbsk fail======================","err",err,"dir",GetSkU1Dir())
		for i := 0; i < 80; i++ {
			dbsktmp, err = ethdb.NewLDBDatabase(GetSkU1Dir(), cache, handles)
			if err == nil && dbsktmp != nil {
				break
			} else {
			    common.Info("======================dcrm.Start,open dbsk fail======================","i",i,"err",err,"dir",GetSkU1Dir())
			}

			//time.Sleep(time.Duration(1000000))
			time.Sleep(time.Duration(2) * time.Second)
		}
	}
	if err != nil {
	    dbsk = nil
	} else {
	    dbsk = dbsktmp
	}

	if dbsk == nil {
	    common.Info("======================dcrm.Start,open dbsk fail and gdcrm panic======================")
	    os.Exit(1)
	    return
	}

	time.Sleep(time.Duration(10) * time.Second)

	//
	predbtmp, err := ethdb.NewLDBDatabase(GetPreDbDir(), cache, handles)
	//bug
	if err != nil {
	    common.Info("======================dcrm.Start,open predb fail======================","err",err,"dir",GetPreDbDir())
		for i := 0; i < 80; i++ {
			predbtmp, err = ethdb.NewLDBDatabase(GetPreDbDir(), cache, handles)
			if err == nil && predbtmp != nil {
				break
			} else {
			    common.Info("======================dcrm.Start,open predb fail======================","i",i,"err",err,"dir",GetPreDbDir())
			}

			//time.Sleep(time.Duration(1000000))
			time.Sleep(time.Duration(2) * time.Second)
		}
	}
	if err != nil {
	    predb = nil
	} else {
	    predb = predbtmp
	}
	   
	if predb == nil {
	    common.Info("======================dcrm.Start,open predb fail and gdcrm panic======================")
	    os.Exit(1)
	    return
	}

	//////////////////
	pairdbtmp, err := ethdb.NewLDBDatabase(GetPreSignHashPairDbDir(), cache, handles)
	//bug
	if err != nil {
	    common.Info("======================dcrm.Start,open pairdb fail======================","err",err,"dir",GetPreSignHashPairDbDir())
		for i := 0; i < 80; i++ {
			pairdbtmp, err = ethdb.NewLDBDatabase(GetPreSignHashPairDbDir(), cache, handles)
			if err == nil && pairdbtmp != nil {
				break
			} else {
			    common.Info("======================dcrm.Start,open predb fail======================","i",i,"err",err,"dir",GetPreSignHashPairDbDir())
			}

			time.Sleep(time.Duration(2) * time.Second)
		}
	}
	if err != nil {
	    presignhashpairdb = nil
	} else {
	    presignhashpairdb = pairdbtmp
	}
	   
	if presignhashpairdb == nil {
	    common.Info("======================dcrm.Start,open presignhashpairdb fail and gdcrm panic======================")
	    os.Exit(1)
	    return
	}

	reqaddrinfodb = GetDcrmReqAddrInfoDb()
        if reqaddrinfodb == nil {
	    common.Error("======================Start,open reqaddrinfodb fail=====================")
	    return
        }
    
        signinfodb = GetDcrmSignInfoDb()
        if signinfodb == nil {
	    common.Error("======================Start,open signinfodb fail=====================")
	    return
        }
    
        reshareinfodb = GetDcrmReShareInfoDb()
        if reshareinfodb == nil {
	    common.Error("======================Start,open reshareinfodb fail=====================")
	    return
        }

        accountsdb = GetDcrmAccountsDirDb()
        if accountsdb == nil {
	    common.Error("======================Start,open accountsdb fail=====================")
	    return
        }

	common.Info("======================dcrm.Start,open all db success======================","cur_enode",cur_enode)
	
	PrePubDataCount = int(presignnum)
	WaitMsgTimeGG20 = int(waitmsg)
	recalc_times = int(trytimes)
	waitallgg20 = WaitMsgTimeGG20 * recalc_times
	AgreeWait = int(waitagree)
	
	GetAllPreSignHashPairFromDb()
	go UpdatePreSignHashPairForDb()
	
	//do this must after openning accounts db success,but get accloaded must before it
	if !accloaded {
	    go CopyAllAccountsFromDb()
	}

	GetAllPreSignFromDb()
	CleanUpAllReqAddrInfo()
	CleanUpAllSignInfo()
	CleanUpAllReshareInfo()

	common.Info("================================dcrm.Start,init finish.========================","cur_enode",cur_enode,"waitmsg",WaitMsgTimeGG20,"trytimes",recalc_times,"presignnum",PrePubDataCount)
}

func InitDev(keyfile string) {
	cur_enode = discover.GetLocalID().String()

	go SavePubKeyDataToDb()
	go SaveSkU1ToDb()
	go ec2.GenRandomInt(2048)
	go ec2.GenRandomSafePrime(2048)
}

func InitGroupInfo(groupId string) {
	cur_enode = discover.GetLocalID().String()
}

type RpcDcrmRes struct {
	Ret string
	Tip string
	Err error
}

type DcrmAccountsBalanceRes struct {
	PubKey   string
	Balances []SubAddressBalance
}

type SubAddressBalance struct {
	Cointype string
	DcrmAddr string
	Balance  string
}

type DcrmAddrRes struct {
	Account  string
	PubKey   string
	DcrmAddr string
	Cointype string
}

type DcrmPubkeyRes struct {
	Account     string
	PubKey      string
	DcrmAddress map[string]string
}

func GetPubKeyData(key string, account string, cointype string) (string, string, error) {
	if key == "" || cointype == "" {
		return "", "dcrm back-end internal error:parameter error in func GetPubKeyData", fmt.Errorf("get pubkey data param error.")
	}

	exsit,da := GetValueFromPubKeyData(key)
	///////
	if !exsit {
		return "", "dcrm back-end internal error:get data from db fail in func GetPubKeyData", fmt.Errorf("dcrm back-end internal error:get data from db fail in func GetPubKeyData")
	}

	pubs,ok := da.(*PubKeyData)
	if !ok {
		return "", "dcrm back-end internal error:get data from db fail in func GetPubKeyData", fmt.Errorf("dcrm back-end internal error:get data from db fail in func GetPubKeyData")
	}

	pubkey := hex.EncodeToString([]byte(pubs.Pub))
	///////////
	var m interface{}
	if !strings.EqualFold(cointype, "ALL") {

		h := coins.NewCryptocoinHandler(cointype)
		if h == nil {
			return "", "cointype is not supported", fmt.Errorf("req addr fail.cointype is not supported.")
		}

		ctaddr, err := h.PublicKeyToAddress(pubkey)
		if err != nil {
			return "", "dcrm back-end internal error:get dcrm addr fail from pubkey:" + pubkey, fmt.Errorf("req addr fail.")
		}

		m = &DcrmAddrRes{Account: account, PubKey: pubkey, DcrmAddr: ctaddr, Cointype: cointype}
		b, _ := json.Marshal(m)
		return string(b), "", nil
	}

	addrmp := make(map[string]string)
	for _, ct := range coins.Cointypes {
		if strings.EqualFold(ct, "ALL") {
			continue
		}

		h := coins.NewCryptocoinHandler(ct)
		if h == nil {
			continue
		}
		ctaddr, err := h.PublicKeyToAddress(pubkey)
		if err != nil {
			continue
		}

		addrmp[ct] = ctaddr
	}

	m = &DcrmPubkeyRes{Account: account, PubKey: pubkey, DcrmAddress: addrmp}
	b, _ := json.Marshal(m)
	return string(b), "", nil
}

func CheckAccept(pubkey string,mode string,account string) bool {
    if pubkey == "" || mode == "" || account == "" {
	return false
    }

    dcrmpks, _ := hex.DecodeString(pubkey)
    exsit,da := GetValueFromPubKeyData(string(dcrmpks[:]))
    if exsit {
	pd,ok := da.(*PubKeyData)
	if ok {
	    exsit,da2 := GetValueFromPubKeyData(pd.Key)
	    if exsit {
		ac,ok := da2.(*AcceptReqAddrData)
		if ok {
		    if ac != nil {
			if ac.Mode != mode {
			    return false
			}
			if mode == "1" && strings.EqualFold(account,ac.Account) {
			    return true
			}

			if mode == "0" && CheckAcc(cur_enode,account,ac.Sigs) {
			    return true
			}
		    }
		}
	    }
	}
    }

    return false
}

func CheckRaw(raw string) (string,string,string,interface{},error) {
    if raw == "" {
	return "","","",nil,fmt.Errorf("raw data empty")
    }
    
    tx := new(types.Transaction)
    raws := common.FromHex(raw)
    if err := rlp.DecodeBytes(raws, tx); err != nil {
	    return "","","",nil,err
    }

    from, err := types.Sender(signer, tx)
    if err != nil {
	return "", "","",nil,err
    }

    req := TxDataReqAddr{}
    err = json.Unmarshal(tx.Data(), &req)
    if err == nil && req.TxType == "REQDCRMADDR" {
	groupid := req.GroupId 
	if groupid == "" {
		return "","","",nil,fmt.Errorf("get group id fail.")
	}

	threshold := req.ThresHold
	if threshold == "" {
		return "","","",nil,fmt.Errorf("get threshold fail.")
	}

	mode := req.Mode
	if mode == "" {
		return "","","", nil,fmt.Errorf("get mode fail.")
	}

	timestamp := req.TimeStamp
	if timestamp == "" {
		return "","","", nil,fmt.Errorf("get timestamp fail.")
	}

	nums := strings.Split(threshold, "/")
	if len(nums) != 2 {
		return "","","", nil,fmt.Errorf("tx.data error.")
	}

	nodecnt, err := strconv.Atoi(nums[1])
	if err != nil {
		return "","","", nil,err
	}

	ts, err := strconv.Atoi(nums[0])
	if err != nil {
		return "","","", nil,err
	}

	if nodecnt < ts || ts < 2 {
	    return "","","",nil,fmt.Errorf("threshold format error")
	}

	Nonce := tx.Nonce()

	nc,_ := GetGroup(groupid)
	if nc != nodecnt {
	    return "","","",nil,fmt.Errorf("check group node count error")
	}

	if !CheckGroupEnode(groupid) {
	    return "","","",nil,fmt.Errorf("there is same enodeID in group")
	}
	
	key := Keccak256Hash([]byte(strings.ToLower(from.Hex() + ":" + "ALL" + ":" + groupid + ":" + fmt.Sprintf("%v", Nonce) + ":" + threshold + ":" + mode))).Hex()

	return key,from.Hex(),fmt.Sprintf("%v", Nonce),&req,nil
    }
    
    lo := TxDataLockOut{}
    err = json.Unmarshal(tx.Data(), &lo)
    if err == nil && lo.TxType == "LOCKOUT" {
	dcrmaddr := lo.DcrmAddr
	dcrmto := lo.DcrmTo
	value := lo.Value
	cointype := lo.Cointype
	groupid := lo.GroupId
	threshold := lo.ThresHold
	mode := lo.Mode
	timestamp := lo.TimeStamp
	Nonce := tx.Nonce()

	if from.Hex() == "" || dcrmaddr == "" || dcrmto == "" || cointype == "" || value == "" || groupid == "" || threshold == "" || mode == "" || timestamp == "" {
		return "","","",nil,fmt.Errorf("param error.")
	}

	////
	nums := strings.Split(threshold, "/")
	if len(nums) != 2 {
		return "","","",nil,fmt.Errorf("tx.data error.")
	}
	nodecnt, err := strconv.Atoi(nums[1])
	if err != nil {
		return "","","",nil,err
	}
	limit, err := strconv.Atoi(nums[0])
	if err != nil {
		return "","","",nil,err
	}
	if nodecnt < limit || limit < 2 {
	    return "","","",nil,fmt.Errorf("threshold format error")
	}

	nc,_ := GetGroup(groupid)
	if nc < limit || nc > nodecnt {
	    return "","","",nil,fmt.Errorf("check group node count error")
	}
	
	if !CheckGroupEnode(groupid) {
	    return "","","",nil,fmt.Errorf("there is same enodeID in group")
	}
	
	////

	//check mode
	key2 := Keccak256Hash([]byte(strings.ToLower(dcrmaddr))).Hex()
	exsit,da := GetValueFromPubKeyData(key2)
	if !exsit {
		return "","","",nil,fmt.Errorf("dcrm back-end internal error:get data from db fail in lockout")
	}

	pubs,ok := da.(*PubKeyData)
	if pubs == nil || !ok {
		return "","","",nil,fmt.Errorf("dcrm back-end internal error:get data from db fail in func lockout")
	}

	if pubs.Key != "" && pubs.Mode != mode {
	    return "","","",nil,fmt.Errorf("can not lockout with different mode in dcrm addr.")
	}

	////bug:check accout
	if pubs.Key != "" && pubs.Mode == "1" && !strings.EqualFold(pubs.Account,from.Hex()) {
	    return "","","",nil,fmt.Errorf("invalid lockout account")
	}

	if pubs.Key != "" {
	    exsit,da = GetValueFromPubKeyData(pubs.Key)
	    if !exsit {
		return "","","",nil,fmt.Errorf("no exist dcrm addr pubkey data")
	    }

	    if da == nil {
		return "","","",nil,fmt.Errorf("no exist dcrm addr pubkey data")
	    }

	    ac,ok := da.(*AcceptReqAddrData)
	    if !ok {
		return "","","",nil,fmt.Errorf("no exist dcrm addr pubkey data")
	    }

	    if ac == nil {
		return "","","",nil,fmt.Errorf("no exist dcrm addr pubkey data")
	    }

//	    common.Debug("================CheckRaw=============","cur_enode ",cur_enode,"from ",from.Hex(),"ac.Sigs ",ac.Sigs)
	    if pubs.Mode == "0" && !CheckAcc(cur_enode,from.Hex(),ac.Sigs) {
		return "","","",nil,fmt.Errorf("invalid lockout account")
	    }
	}

	//check to addr
	validator := coins.NewDcrmAddressValidator(cointype)
	if validator == nil {
	    return "","","",nil,fmt.Errorf("unsupported cointype")
	}
	if !validator.IsValidAddress(dcrmto) {
	    return "","","",nil,fmt.Errorf("invalid to addr")
	}
	//

	key := Keccak256Hash([]byte(strings.ToLower(from.Hex() + ":" + groupid + ":" + fmt.Sprintf("%v", Nonce) + ":" + dcrmaddr + ":" + threshold))).Hex()

	return key,from.Hex(),fmt.Sprintf("%v", Nonce),&lo,nil
    }

    sig := TxDataSign{}
    err = json.Unmarshal(tx.Data(), &sig)
    if err == nil && sig.TxType == "SIGN" {
	pubkey := sig.PubKey
	hash := sig.MsgHash
	keytype := sig.Keytype
	groupid := sig.GroupId
	threshold := sig.ThresHold
	mode := sig.Mode
	timestamp := sig.TimeStamp
	Nonce := tx.Nonce()

	if from.Hex() == "" || pubkey == "" || hash == nil || keytype == "" || groupid == "" || threshold == "" || mode == "" || timestamp == "" {
		return "","","",nil,fmt.Errorf("param error from raw data.")
	}

	nums := strings.Split(threshold, "/")
	if len(nums) != 2 {
		return "","","",nil,fmt.Errorf("threshold is not right.")
	}
	nodecnt, err := strconv.Atoi(nums[1])
	if err != nil {
		return "", "","",nil,err
	}
	limit, err := strconv.Atoi(nums[0])
	if err != nil {
		return "", "","",nil,err
	}
	if nodecnt < limit || limit < 2 {
	    return "","","",nil,fmt.Errorf("threshold format error.")
	}

	nc,_ := GetGroup(groupid)
	if nc < limit || nc > nodecnt {
	    common.Info("==============CheckRaw, sign,check group node count error============","limit ",limit,"nodecnt ",nodecnt,"nc ",nc,"groupid ",groupid)
	    return "","","",nil,fmt.Errorf("check group node count error")
	}

	if !CheckGroupEnode(groupid) {
	    return "","","",nil,fmt.Errorf("there is same enodeID in group")
	}
	
	//check mode
	dcrmpks, _ := hex.DecodeString(pubkey)
	exsit,da := GetValueFromPubKeyData(string(dcrmpks[:]))
	if !exsit {
	    return "","","",nil,fmt.Errorf("get data from db fail in func sign")
	}

	pubs,ok := da.(*PubKeyData)
	if pubs == nil || !ok {
	    return "","","",nil,fmt.Errorf("get data from db fail in func sign")
	}

	if pubs.Mode != mode {
	    return "","","",nil,fmt.Errorf("can not sign with different mode in pubkey.")
	}

	if len(sig.MsgContext) > 16 {
	    return "","","",nil,fmt.Errorf("msgcontext counts must <= 16")
	}
	for _,item := range sig.MsgContext {
	    if len(item) > 1024*1024 {
		return "","","",nil,fmt.Errorf("msgcontext item size must <= 1M")
	    }
	}

	key := Keccak256Hash([]byte(strings.ToLower(from.Hex() + ":" + fmt.Sprintf("%v", Nonce) + ":" + pubkey + ":" + get_sign_hash(hash,keytype) + ":" + keytype + ":" + groupid + ":" + threshold + ":" + mode))).Hex()
	return key,from.Hex(),fmt.Sprintf("%v", Nonce),&sig,nil
    }

    //******************//////////TODO
    pre := TxDataPreSignData{}
    err = json.Unmarshal(tx.Data(), &pre)
    if err == nil && pre.TxType == "PRESIGNDATA" {
	pubkey := pre.PubKey
	subgids := pre.SubGid
	Nonce := tx.Nonce()

	if from.Hex() == "" || pubkey == "" || subgids == nil {
		return "","","",nil,fmt.Errorf("param error from raw data.")
	}

	dcrmpks, _ := hex.DecodeString(pubkey)
	exsit,_ := GetPubKeyDataFromLocalDb(string(dcrmpks[:]))
	if !exsit {
	    time.Sleep(time.Duration(5000000000))
	    exsit,_ = GetPubKeyDataFromLocalDb(string(dcrmpks[:])) //try again
	}
	if !exsit {
		return "","","",nil,fmt.Errorf("invalid pubkey")
	}

	return "",from.Hex(),fmt.Sprintf("%v", Nonce),&pre,nil
    }

    //************************/////////////

    rh := TxDataReShare{}
    err = json.Unmarshal(tx.Data(), &rh)
    if err == nil && rh.TxType == "RESHARE" {
	if !IsValidReShareAccept(from.Hex(),rh.GroupId) {
	    return "","","",nil,fmt.Errorf("check current enode account fail from raw data")
	}

	if from.Hex() == "" || rh.PubKey == "" || rh.TSGroupId == "" || rh.ThresHold == "" || rh.Account == "" || rh.Mode == "" || rh.TimeStamp == "" {
	    return "","","",nil,fmt.Errorf("param error.")
	}

	////
	nums := strings.Split(rh.ThresHold, "/")
	if len(nums) != 2 {
	    return "","","",nil,fmt.Errorf("transacion data format error,threshold is not right")
	}
	nodecnt, err := strconv.Atoi(nums[1])
	if err != nil {
	    return "","","",nil,err
	}
	limit, err := strconv.Atoi(nums[0])
	if err != nil {
	    return "","","",nil,err
	}
	if nodecnt < limit || limit < 2 {
	    return "","","",nil,fmt.Errorf("threshold format error")
	}

	nc,_ := GetGroup(rh.GroupId)
	if nc < limit || nc > nodecnt {
	    return "","","",nil,fmt.Errorf("check group node count error")
	}
	
	key := Keccak256Hash([]byte(strings.ToLower(from.Hex() + ":" + rh.GroupId + ":" + rh.TSGroupId + ":" + rh.PubKey + ":" + rh.ThresHold + ":" + rh.Mode))).Hex()
	Nonce := tx.Nonce()
	
	return key,from.Hex(),fmt.Sprintf("%v", Nonce),&rh,nil
    }

    acceptreq := TxDataAcceptReqAddr{}
    err = json.Unmarshal(tx.Data(), &acceptreq)
    if err == nil && acceptreq.TxType == "ACCEPTREQADDR" {
	if acceptreq.Accept != "AGREE" && acceptreq.Accept != "DISAGREE" {
	    return "","","",nil,fmt.Errorf("transaction data format error,the lastest segment is not AGREE or DISAGREE")
	}

	//bug: accept data was not put into list
        w, err := FindWorker(acceptreq.Key)
        if err != nil || w == nil {
		c1data := acceptreq.Key + "-" + from.Hex()
		C1Data.WriteMap(strings.ToLower(c1data),raw)
		return "","","",nil,fmt.Errorf("Not Found Worker,Pre-save the accept data.")
         }
         time.Sleep(time.Duration(5000000000)) // the time to wait for finishing to write reqaddr cmd data to localdb.
         //

	exsit,da := GetReqAddrInfoData([]byte(acceptreq.Key))
	if !exsit {
	    return "","","",nil,fmt.Errorf("get accept data fail from db in checking raw reqaddr accept data")
	}

	ac,ok := da.(*AcceptReqAddrData)
	if !ok || ac == nil {
	    return "","","",nil,fmt.Errorf("decode accept data fail")
	}

	///////
	if ac.Mode == "1" {
	    return "","","",nil,fmt.Errorf("mode = 1,do not need to accept")
	}
	
	if !CheckAcc(cur_enode,from.Hex(),ac.Sigs) {
	    return "","","",nil,fmt.Errorf("invalid accept account")
	}

	return acceptreq.Key,from.Hex(),"",&acceptreq,nil
    }

    acceptlo := TxDataAcceptLockOut{}
    err = json.Unmarshal(tx.Data(), &acceptlo)
    if err == nil && acceptlo.TxType == "ACCEPTLOCKOUT" {

	if acceptlo.Accept != "AGREE" && acceptlo.Accept != "DISAGREE" {
	    return "","","",nil,fmt.Errorf("transaction data format error,the lastest segment is not AGREE or DISAGREE")
	}

	exsit,da := GetValueFromPubKeyData(acceptlo.Key)
	if !exsit {
	    return "","","",nil,fmt.Errorf("get accept data fail from db in checking raw lockout accept data")
	}

	ac,ok := da.(*AcceptLockOutData)
	if !ok || ac == nil {
	    return "","","",nil,fmt.Errorf("decode accept data fail")
	}

	if ac.Mode == "1" {
	    return "","","",nil,fmt.Errorf("mode = 1,do not need to accept")
	}
	
	if !CheckAccept(ac.PubKey,ac.Mode,from.Hex()) {
	    return "","","",nil,fmt.Errorf("invalid accept account")
	}

	return acceptlo.Key,from.Hex(),"",&acceptlo,nil
    }

    acceptsig := TxDataAcceptSign{}
    err = json.Unmarshal(tx.Data(), &acceptsig)
    if err == nil && acceptsig.TxType == "ACCEPTSIGN" {

	if acceptsig.MsgHash == nil {
	    return "","","",nil,fmt.Errorf("accept data error.")
	}

	if len(acceptsig.MsgContext) > 16 {
	    return "","","",nil,fmt.Errorf("msgcontext counts must <= 16")
	}
	for _,item := range acceptsig.MsgContext {
	    if len(item) > 1024*1024 {
		return "","","",nil,fmt.Errorf("msgcontext item size must <= 1M")
	    }
	}

	if acceptsig.Accept != "AGREE" && acceptsig.Accept != "DISAGREE" {
	    return "","","",nil,fmt.Errorf("transaction data format error,the lastest segment is not AGREE or DISAGREE")
	}

	//bug: accept data was not put into list
         w, err := FindWorker(acceptsig.Key)
         if err != nil || w == nil {
             common.Info("===============CheckRaw, it is accept sign tx and Not Found Worker=====================","key ",acceptsig.Key,"from ",from)
             c1data := acceptsig.Key + "-" + from.Hex()
             C1Data.WriteMap(strings.ToLower(c1data),raw)
             return "","","",nil,fmt.Errorf("Not Found Worker,Pre-save the accept data.")
         }
         time.Sleep(time.Duration(5000000000)) // the time to wait for finishing to write sign cmd data to localdb.
         //
	
	 exsit,da := GetSignInfoData([]byte(acceptsig.Key))
	if !exsit {
	    return "","","",nil,fmt.Errorf("get accept result from db fail")
	}

	ac,ok := da.(*AcceptSignData)
	if !ok || ac == nil {
	    return "","","",nil,fmt.Errorf("get accept result from db fail")
	}

	if ac.Mode == "1" {
	    return "","","",nil,fmt.Errorf("mode = 1,do not need to accept")
	}
	
	if !CheckAccept(ac.PubKey,ac.Mode,from.Hex()) {
	    return "","","",nil,fmt.Errorf("invalid accepter")
	}
	
	return acceptsig.Key,from.Hex(),"",&acceptsig,nil
    }

    acceptrh := TxDataAcceptReShare{}
    err = json.Unmarshal(tx.Data(), &acceptrh)
    if err == nil && acceptrh.TxType == "ACCEPTRESHARE" {
	if acceptrh.Accept != "AGREE" && acceptrh.Accept != "DISAGREE" {
	    return "","","",nil,fmt.Errorf("transaction data format error,the lastest segment is not AGREE or DISAGREE")
	}

	//bug: accept data was not put into list
         w, err := FindWorker(acceptrh.Key)
         if err != nil || w == nil {
             c1data := acceptrh.Key + "-" + from.Hex()
             C1Data.WriteMap(strings.ToLower(c1data),raw)
             return "","","",nil,fmt.Errorf("Not Found Worker,Pre-save the accept data.")
         }
         time.Sleep(time.Duration(5000000000)) // the time to wait for finishing to write reshare cmd data to localdb.

         //
	
	 exsit,da := GetReShareInfoData([]byte(acceptrh.Key))
	if !exsit {
	    return "","","",nil,fmt.Errorf("get accept result from db fail")
	}

	ac,ok := da.(*AcceptReShareData)
	if !ok || ac == nil {
	    return "","","",nil,fmt.Errorf("get accept result from db fail")
	}

	if ac.Mode == "1" {
	    return "","","",nil,fmt.Errorf("mode = 1,do not need to accept")
	}
	
	if !IsValidReShareAccept(from.Hex(),ac.GroupId) {
	    return "","","",nil,fmt.Errorf("check current enode account fail from raw data")
	}

	return acceptrh.Key,from.Hex(),"",&acceptrh,nil
    }

    return "","","",nil,fmt.Errorf("check fail")
}

func GetAccountsBalance(pubkey string, geter_acc string) (interface{}, string, error) {
	keytmp, err2 := hex.DecodeString(pubkey)
	if err2 != nil {
		return nil, "decode pubkey fail", err2
	}

	ret, tip, err := GetPubKeyData(string(keytmp), pubkey, "ALL")
	var m interface{}
	if err == nil {
		dp := DcrmPubkeyRes{}
		_ = json.Unmarshal([]byte(ret), &dp)
		balances := make([]SubAddressBalance, 0)
		var wg sync.WaitGroup
		ret  := common.NewSafeMap(10)
		for cointype, subaddr := range dp.DcrmAddress {
			wg.Add(1)
			go func(cointype, subaddr string) {
				defer wg.Done()
				balance, _, err := GetBalance(pubkey, cointype, subaddr)
				if err != nil {
					balance = "0"
				}
				ret.WriteMap(strings.ToLower(cointype),&SubAddressBalance{Cointype: cointype, DcrmAddr: subaddr, Balance: balance})
			}(cointype, subaddr)
		}
		wg.Wait()
		for _, cointype := range coins.Cointypes {
			subaddrbal,exist := ret.ReadMap(strings.ToLower(cointype))
			if exist && subaddrbal != nil {
			    subbal,ok := subaddrbal.(*SubAddressBalance)
			    if ok && subbal != nil {
				balances = append(balances, *subbal)
				ret.DeleteMap(strings.ToLower(cointype))
			    }
			}
		}
		m = &DcrmAccountsBalanceRes{PubKey: pubkey, Balances: balances}
	}

	return m, tip, err
}

func GetBalance(account string, cointype string, dcrmaddr string) (string, string, error) {

	if strings.EqualFold(cointype, "EVT1") || strings.EqualFold(cointype, "EVT") { ///tmp code
		return "0","",nil  //TODO
	}

	if strings.EqualFold(cointype, "EOS") {
		return "0", "", nil //TODO
	}

	if strings.EqualFold(cointype, "BEP2GZX_754") {
		return "0", "", nil //TODO
	}

	h := coins.NewCryptocoinHandler(cointype)
	if h == nil {
		return "", "coin type is not supported", fmt.Errorf("coin type is not supported")
	}

	ba, err := h.GetAddressBalance(dcrmaddr, "")
	if err != nil {
		return "0","dcrm back-end internal error:get dcrm addr balance fail,but return 0",nil
	}

	if h.IsToken() {
	    if ba.TokenBalance.Val == nil {
		return "0", "token balance is nil,but return 0", nil
	    }

	    ret := fmt.Sprintf("%v", ba.TokenBalance.Val)
	    return ret, "", nil
	}

	if ba.CoinBalance.Val == nil {
	    return "0", "coin balance is nil,but return 0", nil
	}

	ret := fmt.Sprintf("%v", ba.CoinBalance.Val)
	return ret, "", nil
}

func init() {
	p2pdcrm.RegisterRecvCallback(Call2)
	p2pdcrm.SdkProtocol_registerBroadcastInGroupCallback(Call)
	p2pdcrm.RegisterCallback(Call)

	RegP2pGetGroupCallBack(p2pdcrm.SdkProtocol_getGroup)
	RegP2pSendToGroupAllNodesCallBack(p2pdcrm.SdkProtocol_SendToGroupAllNodes)
	RegP2pGetSelfEnodeCallBack(p2pdcrm.GetSelfID)
	RegP2pBroadcastInGroupOthersCallBack(p2pdcrm.SdkProtocol_broadcastInGroupOthers)
	RegP2pSendMsgToPeerCallBack(p2pdcrm.SendMsgToPeer)
	RegP2pParseNodeCallBack(p2pdcrm.ParseNodeID)
	RegDcrmGetEosAccountCallBack(eos.GetEosAccount)
	InitChan()
}

func Call2(msg interface{}) {
	s := msg.(string)
	SetUpMsgList2(s)
}

var parts  = common.NewSafeMap(10)

func receiveGroupInfo(msg interface{}) {
	cur_enode = p2pdcrm.GetSelfID()

	m := strings.Split(msg.(string), "|")
	if len(m) != 2 {
		return
	}

	splitkey := m[1]

	head := strings.Split(splitkey, ":")[0]
	body := strings.Split(splitkey, ":")[1]
	if a := strings.Split(body, "#"); len(a) > 1 {
		body = a[1]
	}
	p, _ := strconv.Atoi(strings.Split(head, "dcrmslash")[0])
	total, _ := strconv.Atoi(strings.Split(head, "dcrmslash")[1])
	//parts[p] = body
	parts.WriteMap(strconv.Itoa(p),body)

	if parts.MapLength() == total {
		var c string = ""
		for i := 1; i <= total; i++ {
			da,exist := parts.ReadMap(strconv.Itoa(i))
			if exist {
			    datmp,ok := da.(string)
			    if ok {
				c += datmp
			    }
			}
		}

		time.Sleep(time.Duration(2) * time.Second) //1000 == 1s
		////
		Init(m[0])
	}
}

func Init(groupId string) {
	common.Debug("======================Init==========================","get group id",groupId,"init_times",strconv.Itoa(init_times))

	if init_times >= 1 {
		return
	}

	init_times = 1
	InitGroupInfo(groupId)
}

func SetUpMsgList2(msg string) {

	mm := strings.Split(msg, "dcrmslash")
	if len(mm) >= 2 {
		receiveGroupInfo(msg)
		return
	}
}

func GetAddr(pubkey string,cointype string) (string,string,error) {
    if pubkey == "" || cointype == "" {
	return "","param error",fmt.Errorf("param error")
    }

     h := coins.NewCryptocoinHandler(cointype)
     if h == nil {
	     return "", "cointype is not supported", fmt.Errorf("req addr fail.cointype is not supported.")
     }

     ctaddr, err := h.PublicKeyToAddress(pubkey)
     if err != nil {
	     return "", "dcrm back-end internal error:get dcrm addr fail from pubkey:" + pubkey, fmt.Errorf("get dcrm  addr fail.")
     }

     return ctaddr, "", nil
}

func Encode2(obj interface{}) (string, error) {
    switch ch := obj.(type) {
	case *SendMsg:
		/*ch := obj.(*SendMsg)
		ret,err := json.Marshal(ch)
		if err != nil {
		    return "",err
		}
		return string(ret),nil*/

		var buff bytes.Buffer
		enc := gob.NewEncoder(&buff)

		err1 := enc.Encode(ch)
		if err1 != nil {
			return "", err1
		}
		return buff.String(), nil
	case *SignBrocastData:

		/*var buff bytes.Buffer
		enc := gob.NewEncoder(&buff)

		err1 := enc.Encode(ch)
		if err1 != nil {
			return "", err1
		}
		return buff.String(), nil*/

		ch2 := obj.(*SignBrocastData)
		ret,err := json.Marshal(ch2)
		if err != nil {
		    return "",err
		}
		return string(ret),nil

	case *PubKeyData:

		var buff bytes.Buffer
		enc := gob.NewEncoder(&buff)

		err1 := enc.Encode(ch)
		if err1 != nil {
			return "", err1
		}
		return buff.String(), nil
	case *PrePubData:

		var buff bytes.Buffer
		enc := gob.NewEncoder(&buff)

		err1 := enc.Encode(ch)
		if err1 != nil {
			return "", err1
		}
		return buff.String(), nil
	case *AcceptLockOutData:

		var buff bytes.Buffer
		enc := gob.NewEncoder(&buff)

		err1 := enc.Encode(ch)
		if err1 != nil {
			return "", err1
		}
		return buff.String(), nil
	case *AcceptReqAddrData:
		ret,err := json.Marshal(ch)
		if err != nil {
		    return "",err
		}
		return string(ret),nil
		/*ch := obj.(*AcceptReqAddrData)

		var buff bytes.Buffer
		enc := gob.NewEncoder(&buff)

		err1 := enc.Encode(ch)
		if err1 != nil {
			return "", err1
		}
		return buff.String(), nil*/
	case *AcceptSignData:

		var buff bytes.Buffer
		enc := gob.NewEncoder(&buff)

		err1 := enc.Encode(ch)
		if err1 != nil {
		    return "", err1
		}
		return buff.String(), nil
	case *AcceptReShareData:

		var buff bytes.Buffer
		enc := gob.NewEncoder(&buff)

		err1 := enc.Encode(ch)
		if err1 != nil {
		    return "", err1
		}
		return buff.String(), nil
	case *SignData:

		var buff bytes.Buffer
		enc := gob.NewEncoder(&buff)

		err1 := enc.Encode(ch)
		if err1 != nil {
			return "", err1
		}
		return buff.String(), nil
	case *PreSign:

		var buff bytes.Buffer
		enc := gob.NewEncoder(&buff)

		err1 := enc.Encode(ch)
		if err1 != nil {
			return "", err1
		}
		return buff.String(), nil
	case *PreSignDataValue:
		ch2 := obj.(*PreSignDataValue)
		ret,err := json.Marshal(ch2)
		if err != nil {
		    return "",err
		}
		return string(ret),nil
	default:
		return "", fmt.Errorf("encode obj fail.")
	}
}

func Decode2(s string, datatype string) (interface{}, error) {

	if datatype == "SendMsg" {
		/*var m SendMsg
		err := json.Unmarshal([]byte(s), &m)
		if err != nil {
		    fmt.Println("================Decode2,json Unmarshal err =%v===================",err)
		    return nil,err
		}

		return &m,nil*/
		var data bytes.Buffer
		data.Write([]byte(s))

		dec := gob.NewDecoder(&data)

		var res SendMsg
		err := dec.Decode(&res)
		if err != nil {
			return nil, err
		}

		return &res, nil
	}

	if datatype == "SignBrocastData" {
		/*var data bytes.Buffer
		data.Write([]byte(s))

		dec := gob.NewDecoder(&data)

		var res SignBrocastData
		err := dec.Decode(&res)
		if err != nil {
			return nil, err
		}

		return &res, nil*/

		var m SignBrocastData 
		err := json.Unmarshal([]byte(s), &m)
		if err != nil {
		    return nil,err
		}

		return &m,nil
	}

	if datatype == "PubKeyData" {
		var data bytes.Buffer
		data.Write([]byte(s))

		dec := gob.NewDecoder(&data)

		var res PubKeyData
		err := dec.Decode(&res)
		if err != nil {
			return nil, err
		}

		return &res, nil
	}

	if datatype == "PrePubData" {
		var data bytes.Buffer
		data.Write([]byte(s))

		dec := gob.NewDecoder(&data)

		var res PrePubData
		err := dec.Decode(&res)
		if err != nil {
			return nil, err
		}

		return &res, nil
	}

	if datatype == "AcceptLockOutData" {
		var data bytes.Buffer
		data.Write([]byte(s))

		dec := gob.NewDecoder(&data)

		var res AcceptLockOutData
		err := dec.Decode(&res)
		if err != nil {
			return nil, err
		}

		return &res, nil
	}

	if datatype == "AcceptReqAddrData" {
		var m AcceptReqAddrData
		err := json.Unmarshal([]byte(s), &m)
		if err != nil {
		    return nil,err
		}

		return &m,nil
		/*var data bytes.Buffer
		data.Write([]byte(s))

		dec := gob.NewDecoder(&data)

		var res AcceptReqAddrData
		err := dec.Decode(&res)
		if err != nil {
			return nil, err
		}

		return &res, nil*/
	}

	if datatype == "AcceptSignData" {
		var data bytes.Buffer
		data.Write([]byte(s))

		dec := gob.NewDecoder(&data)

		var res AcceptSignData
		err := dec.Decode(&res)
		if err != nil {
			return nil, err
		}

		return &res, nil
	}

	if datatype == "AcceptReShareData" {
		var data bytes.Buffer
		data.Write([]byte(s))

		dec := gob.NewDecoder(&data)

		var res AcceptReShareData
		err := dec.Decode(&res)
		if err != nil {
			return nil, err
		}

		return &res, nil
	}

	if datatype == "SignData" {
		var data bytes.Buffer
		data.Write([]byte(s))

		dec := gob.NewDecoder(&data)

		var res SignData
		err := dec.Decode(&res)
		if err != nil {
			return nil, err
		}

		return &res, nil
	}

	if datatype == "PreSign" {
		var data bytes.Buffer
		data.Write([]byte(s))

		dec := gob.NewDecoder(&data)

		var res PreSign
		err := dec.Decode(&res)
		if err != nil {
			return nil, err
		}

		return &res, nil
	}

	if datatype == "PreSignDataValue" {
		var m PreSignDataValue 
		err := json.Unmarshal([]byte(s), &m)
		if err != nil {
		    return nil,err
		}

		return &m,nil
	}

	return nil, fmt.Errorf("decode obj fail.")
}

///////

func Compress(c []byte) (string, error) {
	if c == nil {
		return "", fmt.Errorf("compress fail.")
	}

	var in bytes.Buffer
	w, err := zlib.NewWriterLevel(&in, zlib.BestCompression-1)
	if err != nil {
		return "", err
	}

	_,err = w.Write(c)
	if err != nil {
	    return "",err
	}

	w.Close()

	s := in.String()
	return s, nil
}

func UnCompress(s string) (string, error) {

	if s == "" {
		return "", fmt.Errorf("param error.")
	}

	var data bytes.Buffer
	data.Write([]byte(s))

	r, err := zlib.NewReader(&data)
	if err != nil {
		return "", err
	}

	var out bytes.Buffer
	_,err = io.Copy(&out, r)
	if err != nil {
	    return "",err
	}

	return out.String(), nil
}

////

type DcrmHash [32]byte

func (h DcrmHash) Hex() string { return hexutil.Encode(h[:]) }

// Keccak256Hash calculates and returns the Keccak256 hash of the input data,
// converting it to an internal Hash data structure.
func Keccak256Hash(data ...[]byte) (h DcrmHash) {
	d := sha3.NewKeccak256()
	for _, b := range data {
	    _,err := d.Write(b)
	    if err != nil {
		return h 
	    }
	}
	d.Sum(h[:0])
	return h
}

type RpcType int32

const (
    Rpc_REQADDR      RpcType = 0
    Rpc_LOCKOUT     RpcType = 1
    Rpc_SIGN      RpcType = 2
    Rpc_RESHARE     RpcType = 3
)

func GetAllReplyFromGroup(wid int,gid string,rt RpcType,initiator string) []NodeReply {
    if gid == "" {
	return nil
    }

    var ars []NodeReply
    _, enodes := GetGroup(gid)
    nodes := strings.Split(enodes, common.Sep2)
    
    if wid < 0 || wid >= len(workers) {
	for _, node := range nodes {
		node2 := ParseNode(node)
		sta := "Pending"
		ts := ""
		in := "0"
		if strings.EqualFold(initiator,node2) {
		    in = "1"
		}

		nr := NodeReply{Enode:node2,Status:sta,TimeStamp:ts,Initiator:in}
		ars = append(ars,nr)
	}

	return ars
    }

    w := workers[wid]
    if w == nil {
	return nil
    }

    if rt == Rpc_LOCKOUT {
	for _, node := range nodes {
		node2 := ParseNode(node)
		sta := "Pending"
		ts := ""
		in := "0"
		if strings.EqualFold(initiator,node2) {
		    in = "1"
		}

		iter := w.msg_acceptlockoutres.Front()
		if iter != nil {
		    mdss := iter.Value.(string)
		    common.Debug("===================== GetAllReplyFromGroup call CheckRaw,it is Rpc_LOCKOUT ================")
		    key,_,_,_,_ := CheckRaw(mdss)
		    key2 := GetReqAddrKeyByOtherKey(key,rt)
		    exsit,da := GetValueFromPubKeyData(key2)
		    if exsit {
			ac,ok := da.(*AcceptReqAddrData)
			if ok && ac != nil {
			    ret := GetRawReply(w.msg_acceptlockoutres)
			    //sigs:  5:eid1:acc1:eid2:acc2:eid3:acc3:eid4:acc4:eid5:acc5
			    mms := strings.Split(ac.Sigs, common.Sep)
			    for k,mm := range mms {
				if strings.EqualFold(mm,node2) {
				    reply,ok := ret[mms[k+1]]
				    if ok && reply != nil {
					if reply.Accept == "true" {
					    sta = "Agree"
					} else {
					    sta = "DisAgree"
					}
					ts = reply.TimeStamp
				    }

				    break
				}
			    }

			}
		    }
		}
		
		nr := NodeReply{Enode:node2,Status:sta,TimeStamp:ts,Initiator:in}
		ars = append(ars,nr)
	}
    } 
    
    if rt == Rpc_SIGN {
	for _, node := range nodes {
		node2 := ParseNode(node)
		sta := "Pending"
		ts := ""
		in := "0"
		if strings.EqualFold(initiator,node2) {
		    in = "1"
		}

		iter := w.msg_acceptsignres.Front()
		if iter != nil {
		    mdss := iter.Value.(string)
		    key,_,_,_,_ := CheckRaw(mdss)
		    key2 := GetReqAddrKeyByOtherKey(key,rt)
		    exsit,da := GetPubKeyDataValueFromDb2(key2)
		    if exsit {
			ac,ok := da.(*AcceptReqAddrData)
			if ok && ac != nil {
			    ret := GetRawReply(w.msg_acceptsignres)
			    //sigs:  5:eid1:acc1:eid2:acc2:eid3:acc3:eid4:acc4:eid5:acc5
			    mms := strings.Split(ac.Sigs, common.Sep)
			    for k,mm := range mms {
				if strings.EqualFold(mm,node2) {
				    reply,ok := ret[mms[k+1]]
				    if ok && reply != nil {
					common.Info("===================GetAllReplyFromGroup,it is sign=================","key",key,"from",mms[k+1],"Accept",reply.Accept,"raw",mdss)
					if reply.Accept == "true" {
					    sta = "Agree"
					} else {
					    sta = "DisAgree"
					}
					ts = reply.TimeStamp
				    }

				    break
				}
			    }

			}
		    }
		}
		
		nr := NodeReply{Enode:node2,Status:sta,TimeStamp:ts,Initiator:in}
		ars = append(ars,nr)
	}
    } 
    
    if rt == Rpc_RESHARE {
	for _, node := range nodes {
		node2 := ParseNode(node)
		sta := "Pending"
		ts := ""
		in := "0"
		if strings.EqualFold(initiator,node2) {
		    in = "1"
		}

		iter := w.msg_acceptreshareres.Front()
		for iter != nil {
		    mdss := iter.Value.(string)
		    _,from,_,txdata,err := CheckRaw(mdss)
		    if err != nil {
			iter = iter.Next()
			continue
		    }

		    rh,ok := txdata.(*TxDataReShare)
		    if ok {
			h := coins.NewCryptocoinHandler("FSN")
			if h == nil {
			    iter = iter.Next()
			    continue
			}
			
			pk := "04" + node2 
			fr, err := h.PublicKeyToAddress(pk)
			if err != nil {
			    iter = iter.Next()
			    continue
			}

			if strings.EqualFold(from, fr) {
			    sta = "Agree"
			    ts = rh.TimeStamp
			    break
			}
		    }

		    acceptrh,ok := txdata.(*TxDataAcceptReShare)
		    if ok {
			h := coins.NewCryptocoinHandler("FSN")
			if h == nil {
			    iter = iter.Next()
			    continue
			}
			
			pk := "04" + node2 
			fr, err := h.PublicKeyToAddress(pk)
			if err != nil {
			    iter = iter.Next()
			    continue
			}

			if strings.EqualFold(from, fr) {
			    sta = "Agree"
			    ts = acceptrh.TimeStamp
			    break
			}
		    }

		    iter = iter.Next()
		}
		
		nr := NodeReply{Enode:node2,Status:sta,TimeStamp:ts,Initiator:in}
		ars = append(ars,nr)
	}
    } 
    
    if rt == Rpc_REQADDR {
	for _, node := range nodes {
	    node2 := ParseNode(node)
	    sta := "Pending"
	    ts := ""
	    in := "0"
	    if strings.EqualFold(initiator,node2) {
		in = "1"
	    }

	    iter := w.msg_acceptreqaddrres.Front()
	    if iter != nil {
		mdss := iter.Value.(string)
		common.Debug("===================== GetAllReplyFromGroup call CheckRaw,it is Rpc_REQADDR ================")
		key,_,_,_,_ := CheckRaw(mdss)
		exsit,da := GetReqAddrInfoData([]byte(key))
		if !exsit || da == nil {
		    exsit,da = GetPubKeyDataValueFromDb2(key)
		}
		if exsit {
		    ac,ok := da.(*AcceptReqAddrData)
		    if ok && ac != nil {
			ret := GetRawReply(w.msg_acceptreqaddrres)
			//sigs:  5:eid1:acc1:eid2:acc2:eid3:acc3:eid4:acc4:eid5:acc5
			mms := strings.Split(ac.Sigs, common.Sep)
			for k,mm := range mms {
			    if strings.EqualFold(mm,node2) {
				reply,ok := ret[mms[k+1]]
				if ok && reply != nil {
				    if reply.Accept == "true" {
					sta = "Agree"
				    } else {
					sta = "DisAgree"
				    }
				    ts = reply.TimeStamp
				}

				break
			    }
			}

		    }
		}
	    }
	    
	    nr := NodeReply{Enode:node2,Status:sta,TimeStamp:ts,Initiator:in}
	    ars = append(ars,nr)
	}
    }

    return ars
}

func GetReqAddrKeyByOtherKey(key string,rt RpcType) string {
    if key == "" {
	return ""
    }

    if rt == Rpc_LOCKOUT {
	exsit,da := GetValueFromPubKeyData(key)
	if exsit {
	    ad,ok := da.(*AcceptLockOutData)
	    if ok && ad != nil {
		dcrmpks, _ := hex.DecodeString(ad.PubKey)
		exsit,da2 := GetValueFromPubKeyData(string(dcrmpks[:]))
		if exsit && da2 != nil {
		    pd,ok := da2.(*PubKeyData)
		    if ok && pd != nil {
			return pd.Key
		    }
		}
	    }
	}
    }

    if rt == Rpc_SIGN {
	exsit,da := GetSignInfoData([]byte(key))
	if !exsit {
	    exsit,da = GetPubKeyDataValueFromDb2(key)
	}
	if exsit {
	    ad,ok := da.(*AcceptSignData)
	    if ok && ad != nil {
		dcrmpks, _ := hex.DecodeString(ad.PubKey)
		exsit,da2 := GetValueFromPubKeyData(string(dcrmpks[:]))
		if exsit && da2 != nil {
		    pd,ok := da2.(*PubKeyData)
		    if ok && pd != nil {
			return pd.Key
		    }
		}
	    }
	}
    }

    return ""
}

func GetChannelValue(t int, obj interface{}) (string, string, error) {
	timeout := make(chan bool, 1)
	go func() {
		time.Sleep(time.Duration(t) * time.Second) //1000 == 1s
		timeout <- true
	}()

	switch ch := obj.(type) {
	case chan interface{}:
		select {
		case v := <-ch:
			ret, ok := v.(RpcDcrmRes)
			if ok {
				return ret.Ret, ret.Tip, ret.Err
			}
		case <-timeout:
			return "", "dcrm back-end internal error:get result from channel timeout", fmt.Errorf("get data from node fail.")
		}
	case chan string:
		select {
		case v := <-ch:
			return v, "", nil
		case <-timeout:
			return "", "dcrm back-end internal error:get result from channel timeout", fmt.Errorf("get data from node fail.")
		}
	case chan int64:
		select {
		case v := <-ch:
			return strconv.Itoa(int(v)), "", nil
		case <-timeout:
			return "", "dcrm back-end internal error:get result from channel timeout", fmt.Errorf("get data from node fail.")
		}
	case chan int:
		select {
		case v := <-ch:
			return strconv.Itoa(v), "", nil
		case <-timeout:
			return "", "dcrm back-end internal error:get result from channel timeout", fmt.Errorf("get data from node fail.")
		}
	case chan bool:
		select {
		case v := <-ch:
			if !v {
				return "false", "", nil
			} else {
				return "true", "", nil
			}
		case <-timeout:
			return "", "dcrm back-end internal error:get result from channel timeout", fmt.Errorf("get data from node fail.")
		}
	default:
		return "", "dcrm back-end internal error:unknown channel type", fmt.Errorf("unknown ch type.")
	}

	return "", "dcrm back-end internal error:unknown error.", fmt.Errorf("get value fail.")
}

//error type 1
type Err struct {
	Info string
}

func (e Err) Error() string {
	return e.Info
}

type PubAccounts struct {
	Group []AccountsList
}
type AccountsList struct {
	GroupID  string
	Accounts []PubKeyInfo
}

func CheckAcc(eid string, geter_acc string, sigs string) bool {

	if eid == "" || geter_acc == "" || sigs == "" {
	    return false
	}

	//sigs:  5:eid1:acc1:eid2:acc2:eid3:acc3:eid4:acc4:eid5:acc5
	mms := strings.Split(sigs, common.Sep)
	for _, mm := range mms {
//		if strings.EqualFold(mm, eid) {
//			if len(mms) >= (k+1) && strings.EqualFold(mms[k+1], geter_acc) {
//			    return true
//			}
//		}
		
		if strings.EqualFold(geter_acc,mm) { //allow user login diffrent node
		    return true
		}
	}
	
	return false
}

type PubKeyInfo struct {
    PubKey string
    ThresHold string
    TimeStamp string
}

func GetAccounts(geter_acc, mode string) (interface{}, string, error) {
    if accountsdb == nil {
	return nil,"",fmt.Errorf("get accounts fail.")
    }

    gp  := common.NewSafeMap(10)
    var wg sync.WaitGroup

    iter := accountsdb.NewIterator()
    for iter.Next() {
	k := string(iter.Key())
	v := string(iter.Value())
	
	wg.Add(1)
	go func(key string,value interface{}) {
	    defer wg.Done()

	    pubkey,ok := value.(string)
	    if !ok || pubkey == "" {
		return
	    }

	    dcrmpks, _ := hex.DecodeString(pubkey)
	    exsit,data2 := GetValueFromPubKeyData(string(dcrmpks[:]))
	    if !exsit || data2 == nil {
		return
	    }

	    pd,ok := data2.(*PubKeyData)
	    if !ok || pd == nil {
		return
	    }

	    pubkeyhex := hex.EncodeToString([]byte(pd.Pub))
	    gid := pd.GroupId
	    md := pd.Mode
	    limit := pd.LimitNum
	    if mode == md {
		    al, exsit := gp.ReadMap(strings.ToLower(gid))
		    if exsit && al != nil {
			al2,ok := al.([]PubKeyInfo)
			if ok && al2 != nil {
			    tmp := PubKeyInfo{PubKey:pubkeyhex,ThresHold:limit,TimeStamp:pd.KeyGenTime}
			    al2 = append(al2, tmp)
			    //gp[gid] = al
			    gp.WriteMap(strings.ToLower(gid),al2)
			}
		    } else {
			    a := make([]PubKeyInfo, 0)
			    tmp := PubKeyInfo{PubKey:pubkeyhex,ThresHold:limit,TimeStamp:pd.KeyGenTime}
			    a = append(a, tmp)
			    gp.WriteMap(strings.ToLower(gid),a)
			    //gp[gid] = a
		    }
	    }
	}(k,v)
    }
    iter.Release()
    wg.Wait()
    
    als := make([]AccountsList, 0)
    key,value := gp.ListMap()
    for j :=0;j < len(key);j++ {
	v,ok := value[j].([]PubKeyInfo)
	if ok {
	    alNew := AccountsList{GroupID: key[j], Accounts: v}
	    als = append(als, alNew)
	}
    }

    pa := &PubAccounts{Group: als}
    return pa, "", nil
}

func IsCurNode(enodes string, cur string) bool {
	if enodes == "" || cur == "" {
		return false
	}

	s := []rune(enodes)
	en := strings.Split(string(s[8:]), "@")
	return en[0] == cur
}

func GetEnodesByUid(uid *big.Int, cointype string, groupid string) string {
	_, nodes := GetGroup(groupid)
	others := strings.Split(nodes, common.Sep2)
	for _, v := range others {
		node2 := ParseNode(v) //bug??
		id := DoubleHash(node2, cointype)
		if id.Cmp(uid) == 0 {
			return v
		}
	}

	return ""
}

type sortableIDSSlice []*big.Int

func (s sortableIDSSlice) Len() int {
	return len(s)
}

func (s sortableIDSSlice) Less(i, j int) bool {
	return s[i].Cmp(s[j]) <= 0
}

func (s sortableIDSSlice) Swap(i, j int) {
	s[i], s[j] = s[j], s[i]
}

func GetIds(cointype string, groupid string) sortableIDSSlice {
	var ids sortableIDSSlice
	_, nodes := GetGroup(groupid)
	others := strings.Split(nodes, common.Sep2)
	for _, v := range others {
		node2 := ParseNode(v) //bug??
		uid := DoubleHash(node2, cointype)
		ids = append(ids, uid)
	}
	sort.Sort(ids)
	return ids
}

func GetIds2(keytype string, groupid string) sortableIDSSlice {
	var ids sortableIDSSlice
	_, nodes := GetGroup(groupid)
	others := strings.Split(nodes, common.Sep2)
	for _, v := range others {
		node2 := ParseNode(v) //bug??
		uid := DoubleHash2(node2, keytype)
		ids = append(ids, uid)
	}
	sort.Sort(ids)
	return ids
}

func DoubleHash2(id string, keytype string) *big.Int {
	// Generate the random num

	// First, hash with the keccak256
	keccak256 := sha3.NewKeccak256()
	_,err := keccak256.Write([]byte(id))
	if err != nil {
	    return nil
	}


	digestKeccak256 := keccak256.Sum(nil)

	//second, hash with the SHA3-256
	sha3256 := sha3.New256()

	_,err = sha3256.Write(digestKeccak256)
	if err != nil {
	    return nil
	}

	if keytype == "ED25519" {
	    var digest [32]byte
	    copy(digest[:], sha3256.Sum(nil))

	    //////
	    var zero [32]byte
	    var one [32]byte
	    one[0] = 1
	    ed.ScMulAdd(&digest, &digest, &one, &zero)
	    //////
	    digestBigInt := new(big.Int).SetBytes(digest[:])
	    return digestBigInt
	}

	digest := sha3256.Sum(nil)
	// convert the hash ([]byte) to big.Int
	digestBigInt := new(big.Int).SetBytes(digest)
	return digestBigInt
}

