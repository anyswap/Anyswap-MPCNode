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

	"github.com/fsn-dev/cryptoCoins/coins"
	"github.com/fsn-dev/dcrm-walletService/crypto/secp256k1"
	"github.com/fsn-dev/dcrm-walletService/crypto"
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
)

var (
	cur_enode  string
	init_times = 0
	ch_t                     = 300 
	recalc_times = 1 
	waitall                     = ch_t * recalc_times
	reqdata_trytimes = 5
	reqdata_timeout = 60
	KeyFile    string
	
	lock                     sync.Mutex

	db *ethdb.LDBDatabase
	dbsk *ethdb.LDBDatabase
)

func Start(waitmsg uint64,trytimes uint64) {
	cryptocoinsconfig.Init()
	coins.Init()
	InitDev(KeyFile)
	cur_enode = p2pdcrm.GetSelfID()
	dbtmp, err := ethdb.NewLDBDatabase(GetDbDir(), cache, handles)
	//bug
	if err != nil {
		for i := 0; i < 100; i++ {
			dbtmp, err = ethdb.NewLDBDatabase(GetDbDir(), cache, handles)
			if err == nil && dbtmp != nil {
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
	//
	dbsktmp, err := ethdb.NewLDBDatabase(GetSkU1Dir(), cache, handles)
	//bug
	if err != nil {
		for i := 0; i < 100; i++ {
			dbsktmp, err = ethdb.NewLDBDatabase(GetSkU1Dir(), cache, handles)
			if err == nil && dbsktmp != nil {
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
	
	LdbPubKeyData = GetAllPubKeyDataFromDb()

	ch_t = int(waitmsg)
	recalc_times = int(trytimes)
	waitall = ch_t * recalc_times
}

func PutGroup(groupId string) bool {
	return true

	/*if groupId == "" {
		return false
	}

	lock.Lock()
	dir := GetGroupDir()
	//db, err := leveldb.OpenFile(dir, nil)

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
	}
	//

	if err != nil {
		lock.Unlock()
		return false
	}

	var data string
	var b bytes.Buffer
	b.WriteString("")
	b.WriteByte(0)
	b.WriteString("")
	iter := db.NewIterator()
	for iter.Next() {
		key := string(iter.Key())
		value := string(iter.Value())
		if strings.EqualFold(key, "GroupIds") {
			data = value
			break
		}
	}
	iter.Release()
	///////
	if data == "" {
		db.Put([]byte("GroupIds"), []byte(groupId))
		db.Close()
		lock.Unlock()
		return true
	}

	m := strings.Split(data, ":")
	for _, v := range m {
		if strings.EqualFold(v, groupId) {
			db.Close()
			lock.Unlock()
			return true
		}
	}

	data += ":" + groupId
	db.Put([]byte("GroupIds"), []byte(data))

	db.Close()
	lock.Unlock()
	return true*////tmp delete
}

func GetGroupIdByEnode(enode string) string {
	if enode == "" {
		return ""
	}

	lock.Lock()
	dir := GetGroupDir()
	//db, err := leveldb.OpenFile(dir, nil)

	db, err := ethdb.NewLDBDatabase(dir, cache, handles)
	//bug
	if err != nil {
		for i := 0; i < 100; i++ {
			db, err = ethdb.NewLDBDatabase(dir,cache, handles)
			if err == nil && db != nil {
				break
			}

			time.Sleep(time.Duration(1000000))
		}
	}
	//

	if err != nil {
		lock.Unlock()
		return ""
	}

	var data string
	var b bytes.Buffer
	b.WriteString("")
	b.WriteByte(0)
	b.WriteString("")
	iter := db.NewIterator()
	for iter.Next() {
		key := string(iter.Key())
		value := string(iter.Value())
		if strings.EqualFold(key, "GroupIds") {
			data = value
			break
		}
	}
	iter.Release()
	///////
	if data == "" {
		db.Close()
		lock.Unlock()
		return ""
	}

	m := strings.Split(data, ":")
	for _, v := range m {
		if IsInGroup(enode, v) {
			db.Close()
			lock.Unlock()
			return v
		}
	}

	db.Close()
	lock.Unlock()
	return ""
}

func IsInGroup(enode string, groupId string) bool {
	if groupId == "" || enode == "" {
		return false
	}

	cnt, enodes := GetGroup(groupId)
	if cnt <= 0 || enodes == "" {
		return false
	}

	nodes := strings.Split(enodes, common.Sep2)
	for _, node := range nodes {
		node2 := ParseNode(node)
		if strings.EqualFold(node2, enode) {
			return true
		}
	}

	return false
}

func InitDev(keyfile string) {
	cur_enode = discover.GetLocalID().String() //GetSelfEnode()

	go SavePubKeyDataToDb()
	go SaveSkU1ToDb()
	go CommitRpcReq()
	go ec2.GenRandomInt(2048)
	go ec2.GenRandomSafePrime(2048)
}

func InitGroupInfo(groupId string) {
	//cur_enode = GetSelfEnode()
	cur_enode = discover.GetLocalID().String() //GetSelfEnode()
}

func GenRandomSafePrime(length int) {
	ec2.GenRandomSafePrime(length)
}

//=======================================================================

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

func GetDcrmAddr(pubkey string) (string, string, error) {
	var m interface{}
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

	m = &DcrmPubkeyRes{Account: "", PubKey: pubkey, DcrmAddress: addrmp}
	b,_ := json.Marshal(m)
	return string(b), "", nil
}

func ExsitPubKey(account string, cointype string) (string, bool) {
	key := Keccak256Hash([]byte(strings.ToLower(account + ":" + cointype))).Hex()
	exsit,da := GetValueFromPubKeyData(key)
	///////
	if !exsit {
		key = Keccak256Hash([]byte(strings.ToLower(account + ":" + "ALL"))).Hex()
		exsit,da = GetValueFromPubKeyData(key)
		///////
		if !exsit {
			return "", false
		}
	}

	pubs,ok  := da.(*PubKeyData)
	if !ok {
	    return "",false
	}

	pubkey := hex.EncodeToString([]byte(pubs.Pub))
	return pubkey, true
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

func GetGroupSigsDataByRaw(raw string) (string,error) {
    if raw == "" {
	return "",fmt.Errorf("raw data empty")
    }
    
    tx := new(types.Transaction)
    raws := common.FromHex(raw)
    if err := rlp.DecodeBytes(raws, tx); err != nil {
	    return "",err
    }

    signer := types.NewEIP155Signer(big.NewInt(30400)) //
    _, err := types.Sender(signer, tx)
    if err != nil {
	return "",err
    }

    var threshold string
    var mode string
    var groupsigs string
    var groupid string

    req := TxDataReqAddr{}
    err = json.Unmarshal(tx.Data(), &req)
    if err == nil && req.TxType == "REQDCRMADDR" {
	threshold = req.ThresHold
	mode = req.Mode
	groupsigs = req.Sigs
	groupid = req.GroupId
    } else {
	rh := TxDataReShare{}
	err = json.Unmarshal(tx.Data(), &rh)
	if err == nil && rh.TxType == "RESHARE" {
	    threshold = rh.ThresHold
	    mode = rh.Mode
	    groupsigs = rh.Sigs
	    groupid = rh.GroupId
	}
    }

    if threshold == "" || mode == "" || groupid == "" {
	return "",fmt.Errorf("raw data error,it is not REQDCRMADDR tx or RESHARE tx")
    }

    if mode == "1" {
	return "",nil
    }

    if mode == "0" && groupsigs == "" {
	return "",fmt.Errorf("raw data error,must have sigs data when mode = 0")
    }

    nums := strings.Split(threshold, "/")
    nodecnt, _ := strconv.Atoi(nums[1])
    if nodecnt <= 1 {
	return "",fmt.Errorf("threshold error")
    }

    sigs := strings.Split(groupsigs,"|")
    //SigN = enode://xxxxxxxx@ip:portxxxxxxxxxxxxxxxxxxxxxx
    _, enodes := GetGroup(groupid)
    nodes := strings.Split(enodes, common.Sep2)
    if nodecnt != len(sigs) {
	return "",fmt.Errorf("group sigs error")
    }

    sstmp := strconv.Itoa(nodecnt)
    for j := 0; j < nodecnt; j++ {
	en := strings.Split(sigs[j], "@")
	for _, node := range nodes {
	    node2 := ParseNode(node)
	    enId := strings.Split(en[0],"//")
	    if len(enId) < 2 {
		return "",fmt.Errorf("group sigs error")
	    }

	    if strings.EqualFold(node2, enId[1]) {
		enodesigs := []rune(sigs[j])
		if len(enodesigs) <= len(node) {
		    return "",fmt.Errorf("group sigs error")
		}

		sig := enodesigs[len(node):]
		//sigbit, _ := hex.DecodeString(string(sig[:]))
		sigbit := common.FromHex(string(sig[:]))
		if sigbit == nil {
		    return "",fmt.Errorf("group sigs error")
		}

		pub,err := secp256k1.RecoverPubkey(crypto.Keccak256([]byte(node2)),sigbit)
		if err != nil {
		    return "",err
		}
		
		h := coins.NewCryptocoinHandler("FSN")
		if h != nil {
		    pubkey := hex.EncodeToString(pub)
		    from, err := h.PublicKeyToAddress(pubkey)
		    if err != nil {
			return "",err
		    }
		    
		    //5:eid1:acc1:eid2:acc2:eid3:acc3:eid4:acc4:eid5:acc5
		    sstmp += common.Sep
		    sstmp += node2
		    sstmp += common.Sep
		    sstmp += from
		}
	    }
	}
    }

    tmps := strings.Split(sstmp,common.Sep)
    if len(tmps) == (2*nodecnt + 1) {
	return sstmp,nil
    }

    return "",fmt.Errorf("group sigs error")
}

func IsValidReShareAccept(from string,gid string) bool {
    if from == "" || gid == "" {
	return false
    }

    h := coins.NewCryptocoinHandler("FSN")
    if h == nil {
	return false
    }
    
    _, enodes := GetGroup(gid)
    nodes := strings.Split(enodes, common.Sep2)
    for _, node := range nodes {
	node2 := ParseNode(node)
	pk := "04" + node2 
	
	fr, err := h.PublicKeyToAddress(pk)
	if err != nil {
	    return false
	}

	if strings.EqualFold(from, fr) {
	    return true
	}
    }

    return false
}

func CheckGroupEnode(gid string) bool {
    if gid == "" {
	return false
    }

    groupenode := make(map[string]bool)
    _, enodes := GetGroup(gid)
    nodes := strings.Split(enodes, common.Sep2)
    for _, node := range nodes {
	node2 := ParseNode(node)
	_, ok := groupenode[strings.ToLower(node2)]
	if ok {
	    return false
	}

	groupenode[strings.ToLower(node2)] = true
    }

    return true
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

    signer := types.NewEIP155Signer(big.NewInt(30400)) //
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

//	common.Debug("================CheckRaw, it is reqaddr tx=================","raw ",raw,"key ",key,"req ",&req)
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

//	common.Debug("=================CheckRaw, it is lockout tx================","raw ",raw,"key ",key,"lo ",&lo)
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
//	    common.Debug("==============CheckRaw, sign,check group node count error============","limit ",limit,"nodecnt ",nodecnt,"nc ",nc,"groupid ",groupid)
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
//	common.Debug("=================CheckRaw, it is sign tx==================","raw ",raw,"key ",key,"sig ",&sig)
	return key,from.Hex(),fmt.Sprintf("%v", Nonce),&sig,nil
    }

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

	exsit,da := GetValueFromPubKeyData(acceptreq.Key)
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

//	common.Debug("=================CheckRaw, it is acceptreqaddr tx====================","raw ",raw,"key ",acceptreq.Key,"acceptreq ",&acceptreq)
	return "",from.Hex(),"",&acceptreq,nil
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

//	common.Debug("=================CheckRaw, it is acceptlockout tx================","raw ",raw,"key ",acceptlo.Key,"acceptlo ",&acceptlo)
	return "",from.Hex(),"",&acceptlo,nil
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

	exsit,da := GetValueFromPubKeyData(acceptsig.Key)
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
	
//	common.Debug("=================CheckRaw, it is acceptsign tx====================","raw ",raw,"key ",acceptsig.Key,"acceptsig ",&acceptsig)
	return "",from.Hex(),"",&acceptsig,nil
    }

    acceptrh := TxDataAcceptReShare{}
    err = json.Unmarshal(tx.Data(), &acceptrh)
    if err == nil && acceptrh.TxType == "ACCEPTRESHARE" {
	if acceptrh.Accept != "AGREE" && acceptrh.Accept != "DISAGREE" {
	    return "","","",nil,fmt.Errorf("transaction data format error,the lastest segment is not AGREE or DISAGREE")
	}

	exsit,da := GetValueFromPubKeyData(acceptrh.Key)
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

//	common.Debug("=================CheckRaw, it is acceptreshare tx=====================","raw ",raw,"key ",acceptrh.Key,"acceptrh ",&acceptrh)
	return "",from.Hex(),"",&acceptrh,nil
    }

    return "","","",nil,fmt.Errorf("check fail")
}

func InitAcceptData(raw string,workid int,sender string,ch chan interface{}) error {
    if raw == "" || workid < 0 || sender == "" {
	res := RpcDcrmRes{Ret: "", Tip: "init accept data fail.", Err: fmt.Errorf("init accept data fail")}
	ch <- res
	return fmt.Errorf("init accept data fail")
    }

    key,from,nonce,txdata,err := CheckRaw(raw)
    common.Debug("=====================InitAcceptData,get result from call CheckRaw ================","key",key,"from",from,"err",err,"raw",raw)
    if err != nil {
	common.Debug("===============InitAcceptData,check raw===================","err ",err)
	res := RpcDcrmRes{Ret: "", Tip: err.Error(), Err: err}
	ch <- res
	return err
    }
    
    req,ok := txdata.(*TxDataReqAddr)
    if ok {
	common.Debug("===============InitAcceptData, check reqaddr raw success==================","raw ",raw,"key ",key,"from ",from,"nonce ",nonce,"txdata ",req)
	exsit,_ := GetValueFromPubKeyData(key)
	if !exsit {
	    cur_nonce, _, _ := GetReqAddrNonce(from)
	    cur_nonce_num, _ := new(big.Int).SetString(cur_nonce, 10)
	    new_nonce_num, _ := new(big.Int).SetString(nonce, 10)
	    common.Debug("===============InitAcceptData============","reqaddr cur_nonce_num ",cur_nonce_num,"reqaddr new_nonce_num ",new_nonce_num,"key ",key)
	    if new_nonce_num.Cmp(cur_nonce_num) >= 0 {
		_, err := SetReqAddrNonce(from,nonce)
		if err == nil {
		    ars := GetAllReplyFromGroup(workid,req.GroupId,Rpc_REQADDR,sender)
		    sigs,err := GetGroupSigsDataByRaw(raw) 
		    common.Debug("=================InitAcceptData================","get group sigs ",sigs,"err ",err,"key ",key)
		    if err != nil {
			res := RpcDcrmRes{Ret: "", Tip: err.Error(), Err: err}
			ch <- res
			return err
		    }

		    ac := &AcceptReqAddrData{Initiator:sender,Account: from, Cointype: "ALL", GroupId: req.GroupId, Nonce: nonce, LimitNum: req.ThresHold, Mode: req.Mode, TimeStamp: req.TimeStamp, Deal: "false", Accept: "false", Status: "Pending", PubKey: "", Tip: "", Error: "", AllReply: ars, WorkId: workid,Sigs:sigs}
		    err = SaveAcceptReqAddrData(ac)
		    common.Debug("===================call SaveAcceptReqAddrData finish====================","account ",from,"err ",err,"key ",key)
		   if err == nil {
			rch := make(chan interface{}, 1)
			w := workers[workid]
			w.sid = key 
			w.groupid = req.GroupId
			w.limitnum = req.ThresHold
			gcnt, _ := GetGroup(w.groupid)
			w.NodeCnt = gcnt
			w.ThresHold = w.NodeCnt

			nums := strings.Split(w.limitnum, "/")
			if len(nums) == 2 {
			    nodecnt, err := strconv.Atoi(nums[1])
			    if err == nil {
				w.NodeCnt = nodecnt
			    }

			    th, err := strconv.Atoi(nums[0])
			    if err == nil {
				w.ThresHold = th 
			    }
			}

			/////////////
			if req.Mode == "0" { // self-group
				////
				var reply bool
				var tip string
				timeout := make(chan bool, 1)
				go func(wid int) {
					cur_enode = discover.GetLocalID().String() //GetSelfEnode()
					agreeWaitTime := 10 * time.Minute
					agreeWaitTimeOut := time.NewTicker(agreeWaitTime)
					if wid < 0 || wid >= len(workers) || workers[wid] == nil {
						ars := GetAllReplyFromGroup(w.id,req.GroupId,Rpc_REQADDR,sender)	
						_,err = AcceptReqAddr(sender,from, "ALL", req.GroupId, nonce, req.ThresHold, req.Mode, "false", "false", "Failure", "", "workid error", "workid error", ars, wid,"")
						if err != nil {
						    tip = "accept reqaddr error"
						    reply = false
						    timeout <- true
						    return
						}

						tip = "worker id error"
						reply = false
						timeout <- true
						return
					}

					wtmp2 := workers[wid]
					for {
						select {
						case account := <-wtmp2.acceptReqAddrChan:
							common.Debug("(self *RecvMsg) Run(),", "account= ", account, "key = ", key)
							ars := GetAllReplyFromGroup(w.id,req.GroupId,Rpc_REQADDR,sender)
							common.Debug("================== InitAcceptData,get all AcceptReqAddrRes====================","raw ",raw,"result ",ars,"key ",key)
							
							//bug
							reply = true
							for _,nr := range ars {
							    if !strings.EqualFold(nr.Status,"Agree") {
								reply = false
								break
							    }
							}
							//

							if !reply {
								tip = "don't accept req addr"
								_,err = AcceptReqAddr(sender,from, "ALL", req.GroupId,nonce, req.ThresHold, req.Mode, "false", "false", "Failure", "", "don't accept req addr", "don't accept req addr", ars, wid,"")
								if err != nil {
								    tip = "don't accept req addr and accept reqaddr error"
								    timeout <- true
								    return
								}
							} else {
								tip = ""
								_,err = AcceptReqAddr(sender,from, "ALL", req.GroupId,nonce, req.ThresHold, req.Mode, "false", "true", "Pending", "", "", "", ars, wid,"")
								if err != nil {
								    tip = "accept reqaddr error"
								    timeout <- true
								    return
								}
							}

							///////
							timeout <- true
							return
						case <-agreeWaitTimeOut.C:
							common.Debug("================== InitAcceptData, agree wait timeout==================","raw ",raw,"key ",key)
							ars := GetAllReplyFromGroup(w.id,req.GroupId,Rpc_REQADDR,sender)
							//bug: if self not accept and timeout
							_,err = AcceptReqAddr(sender,from, "ALL", req.GroupId, nonce, req.ThresHold, req.Mode, "false", "false", "Timeout", "", "get other node accept req addr result timeout", "get other node accept req addr result timeout", ars, wid,"")
							if err != nil {
							    tip = "get other node accept req addr result timeout and accept reqaddr fail"
							    reply = false
							    timeout <- true
							    return
							}

							tip = "get other node accept req addr result timeout"
							reply = false
							//

							timeout <- true
							return
						}
					}
				}(workid)

				if len(workers[workid].acceptWaitReqAddrChan) == 0 {
					workers[workid].acceptWaitReqAddrChan <- "go on"
				}

				DisAcceptMsg(raw,workid)
				HandleC1Data(ac,key,workid)

				<-timeout

				common.Debug("================== InitAcceptData======================","raw ",raw,"the terminal accept req addr result ",reply,"key ",key)

				ars := GetAllReplyFromGroup(w.id,req.GroupId,Rpc_REQADDR,sender)
				if !reply {
					if tip == "get other node accept req addr result timeout" {
						_,err = AcceptReqAddr(sender,from, "ALL", req.GroupId, nonce, req.ThresHold, req.Mode, "false", "", "Timeout", "", tip, "don't accept req addr.", ars, workid,"")
					} else {
						_,err = AcceptReqAddr(sender,from, "ALL", req.GroupId, nonce, req.ThresHold, req.Mode, "false", "", "Failure", "", tip, "don't accept req addr.", ars, workid,"")
					}

					if err != nil {
					    res := RpcDcrmRes{Ret:"", Tip: tip, Err: fmt.Errorf("don't accept req addr.")}
					    ch <- res
					    return fmt.Errorf("don't accept req addr.")
					}

					res := RpcDcrmRes{Ret: strconv.Itoa(workid) + common.Sep + "rpc_req_dcrmaddr", Tip: tip, Err: fmt.Errorf("don't accept req addr.")}
					ch <- res
					return fmt.Errorf("don't accept req addr.")
				}
			} else {
				if len(workers[workid].acceptWaitReqAddrChan) == 0 {
					workers[workid].acceptWaitReqAddrChan <- "go on"
				}

				ars := GetAllReplyFromGroup(w.id,req.GroupId,Rpc_REQADDR,sender)
				_,err = AcceptReqAddr(sender,from, "ALL", req.GroupId,nonce, req.ThresHold, req.Mode, "false", "true", "Pending", "", "", "", ars, workid,"")
				if err != nil {
				    res := RpcDcrmRes{Ret:"", Tip: err.Error(), Err: err}
				    ch <- res
				    return err
				}
			}

			common.Debug("================== InitAcceptData, start call dcrm_genPubKey====================","w.id ",w.id,"w.groupid ",w.groupid,"key ",key)
			dcrm_genPubKey(w.sid, from, "ALL", rch, req.Mode, nonce)
			chret, tip, cherr := GetChannelValue(waitall, rch)
			common.Debug("================== InitAcceptData , finish dcrm_genPubKey ===================","get return value ",chret,"err ",cherr,"key ",key)
			if cherr != nil {
				ars := GetAllReplyFromGroup(w.id,req.GroupId,Rpc_REQADDR,sender)
				_,err = AcceptReqAddr(sender,from, "ALL", req.GroupId, nonce, req.ThresHold, req.Mode, "false", "", "Failure", "", tip, cherr.Error(), ars, workid,"")
				if err != nil {
				    res := RpcDcrmRes{Ret:"", Tip:err.Error(), Err:err}
				    ch <- res
				    return err
				}

				res := RpcDcrmRes{Ret: strconv.Itoa(workid) + common.Sep + "rpc_req_dcrmaddr", Tip: tip, Err: cherr}
				ch <- res
				return cherr 
			}

			res := RpcDcrmRes{Ret: strconv.Itoa(workid) + common.Sep + "rpc_req_dcrmaddr" + common.Sep + chret, Tip: "", Err: nil}
			ch <- res
			return nil
			/////////////
		   }
		}
	    }
	}
    }

    lo,ok := txdata.(*TxDataLockOut)
    if ok {
	common.Debug("===============InitAcceptData, check lockout raw success=================","raw ",raw,"key ",key,"from ",from,"nonce ",nonce,"txdata ",lo)
	exsit,_ := GetValueFromPubKeyData(key)
	if !exsit {
	    cur_nonce, _, _ := GetLockOutNonce(from)
	    cur_nonce_num, _ := new(big.Int).SetString(cur_nonce, 10)
	    new_nonce_num, _ := new(big.Int).SetString(nonce, 10)
	    common.Debug("===============InitAcceptData================","lockout cur_nonce_num ",cur_nonce_num,"lockout new_nonce_num ",new_nonce_num,"key ",key)
	    if new_nonce_num.Cmp(cur_nonce_num) >= 0 {
		_, err := SetLockOutNonce(from,nonce)
		if err == nil {
		    
		    pubkey := ""
		    lokey := Keccak256Hash([]byte(strings.ToLower(lo.DcrmAddr))).Hex()
		    exsit,loda := GetValueFromPubKeyData(lokey)
		    if exsit {
			_,ok := loda.(*PubKeyData)
			if ok {
			    dcrmpub := (loda.(*PubKeyData)).Pub
			    pubkey = hex.EncodeToString([]byte(dcrmpub))
			}
		    }
		    if pubkey == "" {
			res := RpcDcrmRes{Ret: "", Tip: "dcrm back-end internal error:get pubkey fail", Err: fmt.Errorf("get pubkey fail")}
			ch <- res
			return fmt.Errorf("get pubkey fail") 
		    }
		    
		    ars := GetAllReplyFromGroup(workid,lo.GroupId,Rpc_LOCKOUT,sender)
		    ac := &AcceptLockOutData{Initiator:sender,Account:from, GroupId:lo.GroupId, Nonce: nonce, PubKey: pubkey, DcrmTo: lo.DcrmTo, Value: lo.Value, Cointype: lo.Cointype, LimitNum: lo.ThresHold, Mode: lo.Mode, TimeStamp: lo.TimeStamp, Deal: "false", Accept: "false", Status: "Pending", OutTxHash: "", Tip: "", Error: "", AllReply: ars, WorkId: workid}
		    err := SaveAcceptLockOutData(ac)
		    if err == nil {
			w := workers[workid]
			w.sid = key
			w.groupid = lo.GroupId 
			w.limitnum = lo.ThresHold
			gcnt, _ := GetGroup(w.groupid)
			w.NodeCnt = gcnt
			common.Debug("===================InitAcceptData====================","w.NodeCnt ",w.NodeCnt,"w.groupid ",w.groupid,"wid ",workid,"key ",key)
			w.ThresHold = w.NodeCnt

			nums := strings.Split(w.limitnum, "/")
			if len(nums) == 2 {
			    nodecnt, err := strconv.Atoi(nums[1])
			    if err == nil {
				w.NodeCnt = nodecnt
			    }

			    w.ThresHold = gcnt
			}

			w.DcrmFrom = lo.DcrmAddr

			////////////////////
			if lo.Mode == "0" {
				////
				var reply bool
				var tip string
				timeout := make(chan bool, 1)
				go func(wid int) {
					cur_enode = discover.GetLocalID().String() //GetSelfEnode()
					agreeWaitTime := 10 * time.Minute
					agreeWaitTimeOut := time.NewTicker(agreeWaitTime)

					wtmp2 := workers[wid]

					for {
						select {
						case account := <-wtmp2.acceptLockOutChan:
							common.Debug("InitAcceptData", "account= ", account, "key = ", key)
							ars := GetAllReplyFromGroup(w.id,lo.GroupId,Rpc_LOCKOUT,sender)
							common.Debug("================== InitAcceptData, get all AcceptLockOutRes=================","raw ",raw,"result ",ars,"key ",key)
							
							//bug
							reply = true
							for _,nr := range ars {
							    if !strings.EqualFold(nr.Status,"Agree") {
								reply = false
								break
							    }
							}
							//

							if !reply {
								tip = "don't accept lockout"
								_,err = AcceptLockOut(sender,from, lo.GroupId, nonce, lo.DcrmAddr, lo.ThresHold, "false", "false", "Failure", "", "don't accept lockout", "don't accept lockout", ars, wid)
							} else {
								tip = ""
								_,err = AcceptLockOut(sender,from, lo.GroupId,nonce, lo.DcrmAddr, lo.ThresHold, "false", "true", "Pending", "", "", "", ars, wid)
							}

							if err != nil {
							    tip = "accept lock data error"
							}

							///////
							timeout <- true
							return
						case <-agreeWaitTimeOut.C:
							common.Debug("================== InitAcceptData , agree wait timeout==============","raw ",raw,"key ",key)
							ars := GetAllReplyFromGroup(w.id,lo.GroupId,Rpc_LOCKOUT,sender)
							_,err = AcceptLockOut(sender,from, lo.GroupId,nonce, lo.DcrmAddr, lo.ThresHold, "false", "false", "Timeout", "", "get other node accept lockout result timeout", "get other node accept lockout result timeout", ars, wid)
							reply = false
							tip = "get other node accept lockout result timeout"
							if err != nil {
							    tip = "get other node accept lockout result timeout and accept lockout data fail"
							}
							//

							timeout <- true
							return
						}
					}
				}(workid)

				if len(workers[workid].acceptWaitLockOutChan) == 0 {
					workers[workid].acceptWaitLockOutChan <- "go on"
				}

				DisAcceptMsg(raw,workid)
				reqaddrkey := GetReqAddrKeyByOtherKey(key,Rpc_LOCKOUT)
				exsit,da := GetValueFromPubKeyData(reqaddrkey)
				if !exsit {
				    res := RpcDcrmRes{Ret: "", Tip: "dcrm back-end internal error:get reqaddr sigs data fail", Err: fmt.Errorf("get reqaddr sigs data fail")}
				    ch <- res
				    return fmt.Errorf("get reqaddr sigs data fail") 
				}
				acceptreqdata,ok := da.(*AcceptReqAddrData)
				if !ok || acceptreqdata == nil {
				    res := RpcDcrmRes{Ret: "", Tip: "dcrm back-end internal error:get reqaddr sigs data fail", Err: fmt.Errorf("get reqaddr sigs data fail")}
				    ch <- res
				    return fmt.Errorf("get reqaddr sigs data fail") 
				}

				HandleC1Data(acceptreqdata,key,workid)

				<-timeout

				common.Debug("================== InitAcceptData==================","raw ",raw,"the terminal accept lockout result ",reply,"key ",key)

				if !reply {
					if tip == "get other node accept lockout result timeout" {
						ars := GetAllReplyFromGroup(w.id,lo.GroupId,Rpc_LOCKOUT,sender)
						_,err = AcceptLockOut(sender,from, lo.GroupId, nonce, lo.DcrmAddr, lo.ThresHold, "false", "", "Timeout", "", "get other node accept lockout result timeout", "get other node accept lockout result timeout", ars, workid)
					} else {
						/////////////TODO
						//sid-enode:SendLockOutRes:Success:lockout_tx_hash
						//sid-enode:SendLockOutRes:Fail:err
						mp := []string{w.sid, cur_enode}
						enode := strings.Join(mp, "-")
						s0 := "SendLockOutRes"
						s1 := "Fail"
						s2 := "don't accept lockout."
						ss := enode + common.Sep + s0 + common.Sep + s1 + common.Sep + s2
						SendMsgToDcrmGroup(ss, w.groupid)
						DisMsg(ss)
						_, _, err := GetChannelValue(ch_t, w.bsendlockoutres)
						ars := GetAllReplyFromGroup(w.id,lo.GroupId,Rpc_LOCKOUT,sender)
						if err != nil {
							tip = "get other node terminal accept lockout result timeout" ////bug
							_,err = AcceptLockOut(sender,from, lo.GroupId,nonce, lo.DcrmAddr, lo.ThresHold, "false", "", "Timeout", "", tip, tip, ars, workid)
							if err != nil {
							    tip = tip + "accept lockout data fail"
							}

						} else if w.msg_sendlockoutres.Len() != w.ThresHold {
							_,err = AcceptLockOut(sender,from, lo.GroupId, nonce, lo.DcrmAddr, lo.ThresHold, "false", "", "Failure", "", "get other node lockout result fail", "get other node lockout result fail", ars, workid)
							if err != nil {
							    tip = tip + "accept lockout data fail"
							}

						} else {
							reply2 := "false"
							lohash := ""
							iter := w.msg_sendlockoutres.Front()
							for iter != nil {
								mdss := iter.Value.(string)
								ms := strings.Split(mdss, common.Sep)
								if strings.EqualFold(ms[2], "Success") {
									reply2 = "true"
									lohash = ms[3]
									break
								}

								lohash = ms[3]
								iter = iter.Next()
							}

							if reply2 == "true" {
								_,err = AcceptLockOut(sender,from, lo.GroupId, nonce, lo.DcrmAddr, lo.ThresHold, "true", "true", "Success", lohash, " ", " ", ars, workid)
								if err != nil {
								    tip = tip + "accept lockout data fail"
								}

							} else {
								_,err = AcceptLockOut(sender,from, lo.GroupId,nonce, lo.DcrmAddr, lo.ThresHold, "false", "", "Failure", "", lohash, lohash, ars, workid)
								if err != nil {
								    tip = tip + "accept lockout data fail"
								}

							}
						}
					}

					res := RpcDcrmRes{Ret: strconv.Itoa(workid) + common.Sep + "rpc_lockout", Tip: tip, Err: fmt.Errorf("don't accept lockout.")}
					ch <- res
					return fmt.Errorf("don't accept lockout.") 
				}
			} else {
				if len(workers[workid].acceptWaitLockOutChan) == 0 {
					workers[workid].acceptWaitLockOutChan <- "go on"
				}

				ars := GetAllReplyFromGroup(w.id,lo.GroupId,Rpc_LOCKOUT,sender)
				_,err = AcceptLockOut(sender,from, lo.GroupId, nonce, lo.DcrmAddr, lo.ThresHold, "false", "true", "Pending", "", "", "", ars, workid)
				if err != nil {
				    res := RpcDcrmRes{Ret:"", Tip:err.Error(), Err: err}
				    ch <- res
				    return err
				}
			}

			rch := make(chan interface{}, 1)
			common.Debug("================== InitAcceptData , start call validate_lockout================","key ",key)
			validate_lockout(w.sid,from,lo.DcrmAddr,lo.Cointype, lo.Value, lo.DcrmTo,nonce, lo.Memo,rch)
			chret, tip, cherr := GetChannelValue(waitall, rch)
			common.Debug("================== InitAcceptData, finish and get validate_lockout=================","return value ",chret,"err ",cherr,"key ",key)
			if chret != "" {
				res := RpcDcrmRes{Ret: strconv.Itoa(workid) + common.Sep + "rpc_lockout" + common.Sep + chret, Tip: "", Err: nil}
				ch <- res
				return nil
			}

			ars := GetAllReplyFromGroup(w.id,lo.GroupId,Rpc_LOCKOUT,sender)
			if tip == "get other node accept lockout result timeout" {
				_,err = AcceptLockOut(sender,from, lo.GroupId,nonce, lo.DcrmAddr, lo.ThresHold, "false", "", "Timeout", "", tip, cherr.Error(), ars, workid)
			} else {
				/////////////TODO
				//sid-enode:SendLockOutRes:Success:lockout_tx_hash
				//sid-enode:SendLockOutRes:Fail:err
				mp := []string{w.sid, cur_enode}
				enode := strings.Join(mp, "-")
				s0 := "SendLockOutRes"
				s1 := "Fail"
				s2 := cherr.Error()
				ss := enode + common.Sep + s0 + common.Sep + s1 + common.Sep + s2
				SendMsgToDcrmGroup(ss, w.groupid)
				DisMsg(ss)
				_, _, err := GetChannelValue(ch_t, w.bsendlockoutres)
				if err != nil {
					tip = "get other node terminal accept lockout result timeout" ////bug
					_,err = AcceptLockOut(sender,from, lo.GroupId, nonce, lo.DcrmAddr, lo.ThresHold, "false", "", "Timeout", "", tip, tip, ars, workid)
					if err != nil {
					    tip = tip + " and accept lockout data fail"
					}
			
				} else if w.msg_sendlockoutres.Len() != w.ThresHold {
					_,err = AcceptLockOut(sender,from, lo.GroupId,nonce, lo.DcrmAddr, lo.ThresHold, "false", "", "Failure", "", "get other node lockout result fail", "get other node lockout result fail", ars,workid)
					if err != nil {
					    tip = tip + " and accept lockout data fail"
					}
			
				} else {
					reply2 := "false"
					lohash := ""
					iter := w.msg_sendlockoutres.Front()
					for iter != nil {
						mdss := iter.Value.(string)
						ms := strings.Split(mdss, common.Sep)
						if strings.EqualFold(ms[2], "Success") {
							reply2 = "true"
							lohash = ms[3]
							break
						}

						lohash = ms[3]
						iter = iter.Next()
					}

					if reply2 == "true" {
						_,err = AcceptLockOut(sender,from, lo.GroupId,nonce, lo.DcrmAddr, lo.ThresHold, "true", "true", "Success", lohash, " ", " ", ars, workid)
						if err != nil {
						    tip = tip + " and accept lockout data fail"
						}
			
					} else {
						_,err = AcceptLockOut(sender,from, lo.GroupId,nonce, lo.DcrmAddr, lo.ThresHold, "false", "", "Failure", "", lohash, lohash, ars, workid)
						if err != nil {
						    tip = tip + " and accept lockout data fail"
						}
			
					}
				}
			}

			if cherr != nil {
				res := RpcDcrmRes{Ret: strconv.Itoa(workid) + common.Sep + "rpc_lockout", Tip: tip, Err: cherr}
				ch <- res
				return cherr
			}

			res := RpcDcrmRes{Ret: strconv.Itoa(workid) + common.Sep + "rpc_lockout", Tip: tip, Err: fmt.Errorf("send tx to net fail.")}
			ch <- res
			return fmt.Errorf("send tx to net fail.")
			////////////////////
		    }
		}
	    }
	}
    }

    sig,ok := txdata.(*TxDataSign)
    if ok {
	common.Debug("===============InitAcceptData, it is sign txdata and check sign raw success==================","key ",key,"from ",from,"nonce ",nonce)
	exsit,_ := GetValueFromPubKeyData(key)
	if !exsit {
	    cur_nonce, _, _ := GetSignNonce(from)
	    cur_nonce_num, _ := new(big.Int).SetString(cur_nonce, 10)
	    new_nonce_num, _ := new(big.Int).SetString(nonce, 10)
	    common.Debug("===============InitAcceptData===============","sign cur_nonce_num ",cur_nonce_num,"sign new_nonce_num ",new_nonce_num,"key ",key)
	    //if new_nonce_num.Cmp(cur_nonce_num) >= 0 {
		//_, err := SetSignNonce(from,nonce)
		_, err := SetSignNonce(from,cur_nonce) //bug
		if err == nil {
		    ars := GetAllReplyFromGroup(workid,sig.GroupId,Rpc_SIGN,sender)
		    ac := &AcceptSignData{Initiator:sender,Account: from, GroupId: sig.GroupId, Nonce: nonce, PubKey: sig.PubKey, MsgHash: sig.MsgHash, MsgContext: sig.MsgContext, Keytype: sig.Keytype, LimitNum: sig.ThresHold, Mode: sig.Mode, TimeStamp: sig.TimeStamp, Deal: "false", Accept: "false", Status: "Pending", Rsv: "", Tip: "", Error: "", AllReply: ars, WorkId:workid}
		    err = SaveAcceptSignData(ac)
		    if err == nil {
			common.Debug("===============InitAcceptData,save sign accept data finish===================","ars ",ars,"key ",key)
			w := workers[workid]
			w.sid = key 
			w.groupid = sig.GroupId 
			w.limitnum = sig.ThresHold
			gcnt, _ := GetGroup(w.groupid)
			w.NodeCnt = gcnt
			w.ThresHold = w.NodeCnt

			nums := strings.Split(w.limitnum, "/")
			if len(nums) == 2 {
			    nodecnt, err := strconv.Atoi(nums[1])
			    if err == nil {
				w.NodeCnt = nodecnt
			    }

			    w.ThresHold = gcnt
			}

			w.DcrmFrom = sig.PubKey  // pubkey replace dcrmfrom in sign
			
			if sig.Mode == "0" { // self-group
				////
				var reply bool
				var tip string
				timeout := make(chan bool, 1)
				go func(wid int) {
					cur_enode = discover.GetLocalID().String() //GetSelfEnode()
					agreeWaitTime := 1 * time.Minute
					agreeWaitTimeOut := time.NewTicker(agreeWaitTime)

					wtmp2 := workers[wid]

					for {
						select {
						case account := <-wtmp2.acceptSignChan:
							common.Debug("InitAcceptData,", "account= ", account, "key = ", key)
							ars := GetAllReplyFromGroup(w.id,sig.GroupId,Rpc_SIGN,sender)
							common.Debug("================== InitAcceptData , get all AcceptSignRes===============","result ",ars,"key ",key)
							
							//bug
							reply = true
							for _,nr := range ars {
							    if !strings.EqualFold(nr.Status,"Agree") {
								reply = false
								break
							    }
							}
							//

							if !reply {
								tip = "don't accept sign"
								_,err = AcceptSign(sender,from,sig.PubKey,sig.MsgHash,sig.Keytype,sig.GroupId,nonce,sig.ThresHold,sig.Mode,"true", "false", "Failure", "", "don't accept sign", "don't accept sign", ars,wid)
							} else {
							    	common.Debug("=======================InitAcceptData,11111111111111,set sign pending=============================","key",key)
								tip = ""
								_,err = AcceptSign(sender,from,sig.PubKey,sig.MsgHash,sig.Keytype,sig.GroupId,nonce,sig.ThresHold,sig.Mode,"false", "true", "Pending", "", "", "", ars,wid)
							}

							if err != nil {
							    tip = tip + " and accept sign data fail"
							}

							///////
							timeout <- true
							return
						case <-agreeWaitTimeOut.C:
							common.Debug("================== InitAcceptData , agree wait timeout=============","key ",key)
							ars := GetAllReplyFromGroup(w.id,sig.GroupId,Rpc_SIGN,sender)
							_,err = AcceptSign(sender,from,sig.PubKey,sig.MsgHash,sig.Keytype,sig.GroupId,nonce,sig.ThresHold,sig.Mode,"true", "false", "Timeout", "", "get other node accept sign result timeout", "get other node accept sign result timeout", ars,wid)
							reply = false
							tip = "get other node accept sign result timeout"
							if err != nil {
							    tip = tip + " and accept sign data fail"
							}
							//

							timeout <- true
							return
						}
					}
				}(workid)

				if len(workers[workid].acceptWaitSignChan) == 0 {
					workers[workid].acceptWaitSignChan <- "go on"
				}

				DisAcceptMsg(raw,workid)
				common.Debug("===============InitAcceptData, call DisAcceptMsg finish===================","key ",key)
				reqaddrkey := GetReqAddrKeyByOtherKey(key,Rpc_SIGN)
				exsit,da := GetValueFromPubKeyData(reqaddrkey)
				if !exsit {
					common.Debug("===============InitAcceptData, get req addr key by other key fail ===================","key ",key)
				    res := RpcDcrmRes{Ret: "", Tip: "dcrm back-end internal error:get reqaddr sigs data fail", Err: fmt.Errorf("get reqaddr sigs data fail")}
				    ch <- res
				    return fmt.Errorf("get reqaddr sigs data fail") 
				}

				acceptreqdata,ok := da.(*AcceptReqAddrData)
				if !ok || acceptreqdata == nil {
					common.Debug("===============InitAcceptData, get req addr key by other key error ===================","key ",key)
				    res := RpcDcrmRes{Ret: "", Tip: "dcrm back-end internal error:get reqaddr sigs data fail", Err: fmt.Errorf("get reqaddr sigs data fail")}
				    ch <- res
				    return fmt.Errorf("get reqaddr sigs data fail") 
				}

				common.Debug("===============InitAcceptData, start call HandleC1Data===================","reqaddrkey ",reqaddrkey,"key ",key)

				HandleC1Data(acceptreqdata,key,workid)

				<-timeout

				if !reply {
					if tip == "get other node accept sign result timeout" {
						ars := GetAllReplyFromGroup(w.id,sig.GroupId,Rpc_SIGN,sender)
						_,err = AcceptSign(sender,from,sig.PubKey,sig.MsgHash,sig.Keytype,sig.GroupId,nonce,sig.ThresHold,sig.Mode,"true", "", "Timeout", "", "get other node accept sign result timeout", "get other node accept sign result timeout", ars,workid)
					} else {
						//sid-enode:SendSignRes:Success:rsv
						//sid-enode:SendSignRes:Fail:err
						mp := []string{w.sid, cur_enode}
						enode := strings.Join(mp, "-")
						s0 := "SendSignRes"
						s1 := "Fail"
						s2 := "don't accept sign."
						ss := enode + common.Sep + s0 + common.Sep + s1 + common.Sep + s2
						SendMsgToDcrmGroup(ss, w.groupid)
						DisMsg(ss)
						_, _, err := GetChannelValue(waitall, w.bsendsignres)
						ars := GetAllReplyFromGroup(w.id,sig.GroupId,Rpc_SIGN,sender)
						if err != nil {
							tip = "get other node terminal accept sign result timeout" ////bug
							_,err = AcceptSign(sender,from,sig.PubKey,sig.MsgHash,sig.Keytype,sig.GroupId,nonce,sig.ThresHold,sig.Mode,"true", "", "Timeout", "", tip, tip, ars,workid)
							if err != nil {
							    tip = tip + " and accept sign data fail"
							}

						} else if w.msg_sendsignres.Len() != w.ThresHold {
							_,err = AcceptSign(sender,from,sig.PubKey,sig.MsgHash,sig.Keytype,sig.GroupId,nonce,sig.ThresHold,sig.Mode,"true", "", "Failure", "", "get other node sign result fail", "get other node sign result fail", ars,workid)
							if err != nil {
							    tip = tip + " and accept sign data fail"
							}

						} else {
							reply2 := "false"
							lohash := ""
							iter := w.msg_sendsignres.Front()
							for iter != nil {
								mdss := iter.Value.(string)
								ms := strings.Split(mdss, common.Sep)
								if strings.EqualFold(ms[2], "Success") {
									reply2 = "true"
									lohash = ms[3]
									break
								}

								lohash = ms[3]
								iter = iter.Next()
							}

							if reply2 == "true" {
								_,err = AcceptSign(sender,from,sig.PubKey,sig.MsgHash,sig.Keytype,sig.GroupId,nonce,sig.ThresHold,sig.Mode,"true", "true", "Success", lohash, " ", " ", ars,workid)
								if err != nil {
								    tip = tip + " and accept sign data fail"
								}

							} else {
								_,err = AcceptSign(sender,from,sig.PubKey,sig.MsgHash,sig.Keytype,sig.GroupId,nonce,sig.ThresHold,sig.Mode,"true", "", "Failure", "", lohash,lohash, ars,workid)
								if err != nil {
								    tip = tip + " and accept sign data fail"
								}

							}
						}
					}

					res := RpcDcrmRes{Ret:"", Tip: tip, Err: fmt.Errorf("don't accept sign.")}
					ch <- res
					return fmt.Errorf("don't accept sign.")
				}
			} else {
				if len(workers[workid].acceptWaitSignChan) == 0 {
					workers[workid].acceptWaitSignChan <- "go on"
				}

				ars := GetAllReplyFromGroup(w.id,sig.GroupId,Rpc_SIGN,sender)
				common.Debug("=======================InitAcceptData,2222222222222222222,set sign pending=============================","key",key)
				_,err = AcceptSign(sender,from,sig.PubKey,sig.MsgHash,sig.Keytype,sig.GroupId,nonce,sig.ThresHold,sig.Mode,"false", "true", "Pending", "", "","", ars,workid)
				if err != nil {
				    res := RpcDcrmRes{Ret:"", Tip: err.Error(), Err:err}
				    ch <- res
				    return err
				}
			}

			common.Debug("===============InitAcceptData,begin to sign=================","sig.MsgHash ",sig.MsgHash,"sig.Mode ",sig.Mode,"key ",key)
			rch := make(chan interface{}, 1)
			sign(w.sid, from,sig.PubKey,sig.MsgHash,sig.Keytype,nonce,sig.Mode,rch)
			chret, tip, cherr := GetChannelValue(waitall, rch)
			common.Debug("================== InitAcceptData,finish sig.================","return sign result ",chret,"err ",cherr,"key ",key)
			if chret != "" {
				res := RpcDcrmRes{Ret: chret, Tip: "", Err: nil}
				ch <- res
				return nil
			}

			ars := GetAllReplyFromGroup(w.id,sig.GroupId,Rpc_SIGN,sender)
			if tip == "get other node accept sign result timeout" {
				_,err = AcceptSign(sender,from,sig.PubKey,sig.MsgHash,sig.Keytype,sig.GroupId,nonce,sig.ThresHold,sig.Mode,"true", "", "Timeout", "", tip,cherr.Error(),ars,workid)
			} else {
				//sid-enode:SendSignRes:Success:rsv
				//sid-enode:SendSignRes:Fail:err
				mp := []string{w.sid, cur_enode}
				enode := strings.Join(mp, "-")
				s0 := "SendSignRes"
				s1 := "Fail"
				s2 := cherr.Error()
				ss := enode + common.Sep + s0 + common.Sep + s1 + common.Sep + s2
				SendMsgToDcrmGroup(ss, w.groupid)
				DisMsg(ss)
				_, _, err := GetChannelValue(waitall, w.bsendsignres)
				if err != nil {
					tip = "get other node terminal accept sign result timeout" ////bug
					_,err = AcceptSign(sender,from,sig.PubKey,sig.MsgHash,sig.Keytype,sig.GroupId,nonce,sig.ThresHold,sig.Mode,"true", "", "Timeout", "", tip, tip, ars, workid)
					if err != nil {
					    tip = tip + " and accept sign data fail"
					}

				} else if w.msg_sendsignres.Len() != w.ThresHold {
					_,err = AcceptSign(sender,from,sig.PubKey,sig.MsgHash,sig.Keytype,sig.GroupId,nonce,sig.ThresHold,sig.Mode,"true", "", "Failure", "", "get other node sign result fail", "get other node sign result fail", ars, workid)
					if err != nil {
					    tip = tip + " and accept sign data fail"
					}

				} else {
					reply2 := "false"
					lohash := ""
					iter := w.msg_sendsignres.Front()
					for iter != nil {
						mdss := iter.Value.(string)
						ms := strings.Split(mdss, common.Sep)
						if strings.EqualFold(ms[2], "Success") {
							reply2 = "true"
							lohash = ms[3]
							break
						}

						lohash = ms[3]
						iter = iter.Next()
					}

					if reply2 == "true" {
						_,err = AcceptSign(sender,from,sig.PubKey,sig.MsgHash,sig.Keytype,sig.GroupId,nonce,sig.ThresHold,sig.Mode,"true", "true", "Success", lohash, " ", " ", ars, workid)
						if err != nil {
						    tip = tip + " and accept sign data fail"
						}

					} else {
						_,err = AcceptSign(sender,from,sig.PubKey,sig.MsgHash,sig.Keytype,sig.GroupId,nonce,sig.ThresHold,sig.Mode,"true", "", "Failure", "", lohash, lohash, ars, workid)
						if err != nil {
						    tip = tip + " and accept sign data fail"
						}
					}
				}
			}

			if cherr != nil {
				res := RpcDcrmRes{Ret: "", Tip: tip, Err: cherr}
				ch <- res
				return cherr
			}

			res := RpcDcrmRes{Ret: "", Tip: tip, Err: fmt.Errorf("sign fail.")}
			ch <- res
			return fmt.Errorf("sign fail.")
		    } else {
			common.Debug("===============InitAcceptData, it is sign txdata,but save accept data fail==================","key ",key,"from ",from)
		    }
		} else {
			common.Debug("===============InitAcceptData, it is sign txdata,but set nonce fail==================","key ",key,"from ",from)
		}
	    //}
	} else {
		common.Debug("===============InitAcceptData, it is sign txdata,but has handled before==================","key ",key,"from ",from)
	}
    }

    rh,ok := txdata.(*TxDataReShare)
    if ok {
	ars := GetAllReplyFromGroup(workid,rh.GroupId,Rpc_RESHARE,sender)
	sigs,err := GetGroupSigsDataByRaw(raw) 
	common.Debug("=================InitAcceptData,reshare=================","get group sigs ",sigs,"err ",err,"key ",key)
	if err != nil {
	    res := RpcDcrmRes{Ret: "", Tip: err.Error(), Err: err}
	    ch <- res
	    return err
	}

	ac := &AcceptReShareData{Initiator:sender,Account: from, GroupId: rh.GroupId, TSGroupId:rh.TSGroupId, PubKey: rh.PubKey, LimitNum: rh.ThresHold, PubAccount:rh.Account, Mode:rh.Mode, Sigs:sigs, TimeStamp: rh.TimeStamp, Deal: "false", Accept: "false", Status: "Pending", NewSk: "", Tip: "", Error: "", AllReply: ars, WorkId:workid}
	err = SaveAcceptReShareData(ac)
	common.Debug("===================finish call SaveAcceptReShareData======================","err ",err,"workid ",workid,"account ",from,"group id ",rh.GroupId,"pubkey ",rh.PubKey,"threshold ",rh.ThresHold,"key ",key)
	if err == nil {
	    w := workers[workid]
	    w.sid = key 
	    w.groupid = rh.TSGroupId 
	    w.limitnum = rh.ThresHold
	    gcnt, _ := GetGroup(w.groupid)
	    w.NodeCnt = gcnt
	    w.ThresHold = w.NodeCnt

	    nums := strings.Split(w.limitnum, "/")
	    if len(nums) == 2 {
		nodecnt, err := strconv.Atoi(nums[1])
		if err == nil {
		    w.NodeCnt = nodecnt
		}

		w.ThresHold = gcnt
	    }

	    w.DcrmFrom = rh.PubKey  // pubkey replace dcrmfrom in reshare 

	    var reply bool
	    var tip string
	    timeout := make(chan bool, 1)
	    go func(wid int) {
		    cur_enode = discover.GetLocalID().String() //GetSelfEnode()
		    agreeWaitTime := 10 * time.Minute
		    agreeWaitTimeOut := time.NewTicker(agreeWaitTime)

		    wtmp2 := workers[wid]

		    for {
			    select {
			    case account := <-wtmp2.acceptReShareChan:
				    common.Debug("InitAcceptData", "account= ", account, "key = ", key)
				    ars := GetAllReplyFromGroup(w.id,rh.GroupId,Rpc_RESHARE,sender)
				    common.Debug("================== InitAcceptData, get all AcceptReShareRes================","raw ",raw,"result ",ars,"key ",key)
				    
				    //bug
				    reply = true
				    for _,nr := range ars {
					if !strings.EqualFold(nr.Status,"Agree") {
					    reply = false
					    break
					}
				    }
				    //

				    if !reply {
					    tip = "don't accept reshare"
					    _,err = AcceptReShare(sender,from, rh.GroupId, rh.TSGroupId,rh.PubKey, rh.ThresHold,rh.Mode,"false", "false", "Failure", "", "don't accept reshare", "don't accept reshare", nil, wid)
				    } else {
					    tip = ""
					    _,err = AcceptReShare(sender,from, rh.GroupId, rh.TSGroupId,rh.PubKey, rh.ThresHold,rh.Mode,"false", "false", "pending", "", "", "", ars, wid)
				    }

				    if err != nil {
					tip = tip + " and accept reshare data fail"
				    }

				    ///////
				    timeout <- true
				    return
			    case <-agreeWaitTimeOut.C:
				    common.Debug("================== InitAcceptData, agree wait timeout===================","raw ",raw,"key ",key)
				    ars := GetAllReplyFromGroup(w.id,rh.GroupId,Rpc_RESHARE,sender)
				    _,err = AcceptReShare(sender,from, rh.GroupId, rh.TSGroupId,rh.PubKey, rh.ThresHold,rh.Mode,"false", "false", "Timeout", "", "get other node accept reshare result timeout", "get other node accept reshare result timeout", ars, wid)
				    reply = false
				    tip = "get other node accept reshare result timeout"
				    if err != nil {
					tip = tip + " and accept reshare data fail"
				    }
				    //

				    timeout <- true
				    return
			    }
		    }
	    }(workid)

	    if len(workers[workid].acceptWaitReShareChan) == 0 {
		    workers[workid].acceptWaitReShareChan <- "go on"
	    }

	    DisAcceptMsg(raw,workid)
	    HandleC1Data(nil,key,workid)
	    
	    <-timeout

	    if !reply {
		    //////////////////////reshare result start/////////////////////////
		    if tip == "get other node accept reshare result timeout" {
			    ars := GetAllReplyFromGroup(workid,rh.GroupId,Rpc_RESHARE,sender)
			    _,err = AcceptReShare(sender,from, rh.GroupId, rh.TSGroupId,rh.PubKey, rh.ThresHold, rh.Mode,"false", "", "Timeout", "", "get other node accept reshare result timeout", "get other node accept reshare result timeout", ars,workid)
		    } else {
			    /////////////TODO tmp
			    //sid-enode:SendReShareRes:Success:rsv
			    //sid-enode:SendReShareRes:Fail:err
			    mp := []string{w.sid, cur_enode}
			    enode := strings.Join(mp, "-")
			    s0 := "SendReShareRes"
			    s1 := "Fail"
			    s2 := "don't accept reshare."
			    ss := enode + common.Sep + s0 + common.Sep + s1 + common.Sep + s2
			    SendMsgToDcrmGroup(ss, rh.GroupId)
			    DisMsg(ss)
			    _, _, err := GetChannelValue(ch_t, w.bsendreshareres)
			    ars := GetAllReplyFromGroup(w.id,rh.GroupId,Rpc_RESHARE,sender)
			    if err != nil {
				    tip = "get other node terminal accept reshare result timeout" ////bug
				    _,err = AcceptReShare(sender,from, rh.GroupId, rh.TSGroupId,rh.PubKey, rh.ThresHold,rh.Mode,"false", "", "Timeout", "", tip,tip, ars, workid)
				    if err != nil {
					tip = tip + " and accept reshare data fail"
				    }

			    } else if w.msg_sendreshareres.Len() != w.ThresHold {
				    _,err = AcceptReShare(sender,from, rh.GroupId, rh.TSGroupId,rh.PubKey, rh.ThresHold, rh.Mode,"false", "", "Failure", "", "get other node reshare result fail","get other node reshare result fail",ars, workid)
				    if err != nil {
					tip = tip + " and accept reshare data fail"
				    }
			    } else {
				    reply2 := "false"
				    lohash := ""
				    iter := w.msg_sendreshareres.Front()
				    for iter != nil {
					    mdss := iter.Value.(string)
					    ms := strings.Split(mdss, common.Sep)
					    if strings.EqualFold(ms[2], "Success") {
						    reply2 = "true"
						    lohash = ms[3]
						    break
					    }

					    lohash = ms[3]
					    iter = iter.Next()
				    }

				    if reply2 == "true" {
					    _,err = AcceptReShare(sender,from, rh.GroupId, rh.TSGroupId,rh.PubKey, rh.ThresHold, rh.Mode,"true", "true", "Success", lohash," "," ",ars, workid)
					    if err != nil {
						tip = tip + " and accept reshare data fail"
					    }
				    } else {
					    _,err = AcceptReShare(sender,from, rh.GroupId, rh.TSGroupId,rh.PubKey, rh.ThresHold,rh.Mode,"false", "", "Failure", "",lohash,lohash,ars, workid)
					    if err != nil {
						tip = tip + " and accept reshare data fail"
					    }
				    }
			    }
		    }

		    res2 := RpcDcrmRes{Ret: "", Tip: tip, Err: fmt.Errorf("don't accept reshare.")}
		    ch <- res2
		    return fmt.Errorf("don't accept reshare.")
	    }

	    rch := make(chan interface{}, 1)
	    reshare(w.sid,from,rh.GroupId,rh.PubKey,rh.Account,rh.Mode,sigs,rch)
	    chret, tip, cherr := GetChannelValue(ch_t, rch)
	    if chret != "" {
		    res2 := RpcDcrmRes{Ret: chret, Tip: "", Err: nil}
		    ch <- res2
		    return nil 
	    }

	    if tip == "get other node accept reshare result timeout" {
		    ars := GetAllReplyFromGroup(workid,rh.GroupId,Rpc_RESHARE,sender)
		    _,err = AcceptReShare(sender,from, rh.GroupId, rh.TSGroupId,rh.PubKey, rh.ThresHold,rh.Mode,"false", "", "Timeout", "", "get other node accept reshare result timeout", "get other node accept reshare result timeout", ars,workid)
	    } else {
		    /////////////TODO tmp
		    //sid-enode:SendReShareRes:Success:rsv
		    //sid-enode:SendReShareRes:Fail:err
		    mp := []string{w.sid, cur_enode}
		    enode := strings.Join(mp, "-")
		    s0 := "SendReShareRes"
		    s1 := "Fail"
		    s2 := "don't accept reshare."
		    ss := enode + common.Sep + s0 + common.Sep + s1 + common.Sep + s2
		    SendMsgToDcrmGroup(ss, rh.GroupId)
		    DisMsg(ss)
		    _, _, err := GetChannelValue(ch_t, w.bsendreshareres)
		    ars := GetAllReplyFromGroup(w.id,rh.GroupId,Rpc_RESHARE,sender)
		    if err != nil {
			    tip = "get other node terminal accept reshare result timeout" ////bug
			    _,err = AcceptReShare(sender,from, rh.GroupId, rh.TSGroupId,rh.PubKey, rh.ThresHold,rh.Mode,"false", "", "Timeout", "", tip,tip, ars, workid)
			    if err != nil {
				tip = tip + " and accept reshare data fail"
			    }
		    } else if w.msg_sendsignres.Len() != w.ThresHold {
			    _,err = AcceptReShare(sender,from, rh.GroupId, rh.TSGroupId,rh.PubKey, rh.ThresHold,rh.Mode,"false", "", "Failure", "", "get other node reshare result fail","get other node reshare result fail",ars, workid)
			    if err != nil {
				tip = tip + " and accept reshare data fail"
			    }
		    } else {
			    reply2 := "false"
			    lohash := ""
			    iter := w.msg_sendreshareres.Front()
			    for iter != nil {
				    mdss := iter.Value.(string)
				    ms := strings.Split(mdss, common.Sep)
				    if strings.EqualFold(ms[2], "Success") {
					    reply2 = "true"
					    lohash = ms[3]
					    break
				    }

				    lohash = ms[3]
				    iter = iter.Next()
			    }

			    if reply2 == "true" {
				    _,err = AcceptReShare(sender,from, rh.GroupId, rh.TSGroupId,rh.PubKey, rh.ThresHold,rh.Mode,"true", "true", "Success", lohash," "," ",ars, workid)
				    if err != nil {
					tip = tip + " and accept reshare data fail"
				    }
			    } else {
				    _,err = AcceptReShare(sender,from, rh.GroupId,rh.TSGroupId,rh.PubKey, rh.ThresHold,rh.Mode,"false", "", "Failure", "",lohash,lohash,ars,workid)
				    if err != nil {
					tip = tip + " and accept reshare data fail"
				    }
			    }
		    }
	    }

	    if cherr != nil {
		    res2 := RpcDcrmRes{Ret:"", Tip: tip, Err: cherr}
		    ch <- res2
		    return cherr 
	    }

	    res2 := RpcDcrmRes{Ret:"", Tip: tip, Err: fmt.Errorf("reshare fail.")}
	    ch <- res2
	    return fmt.Errorf("reshare fail.")
	}
    }

    acceptreq,ok := txdata.(*TxDataAcceptReqAddr)
    if ok {
	common.Debug("===============InitAcceptData, check accept reqaddr raw success======================","raw ",raw,"key ",acceptreq.Key,"from ",from,"txdata ",acceptreq)
	w, err := FindWorker(acceptreq.Key)
	if err != nil || w == nil {
	    c1data := acceptreq.Key + "-" + from
	    C1Data.WriteMap(strings.ToLower(c1data),raw)
	    res := RpcDcrmRes{Ret:"Failure", Tip: "get reqaddr accept data fail from db.", Err: fmt.Errorf("get reqaddr accept data fail from db when no find worker")}
	    ch <- res
	    return fmt.Errorf("get reqaddr accept data fail from db when no find worker.")
	}

	exsit,da := GetValueFromPubKeyData(acceptreq.Key)
	if !exsit {
	    res := RpcDcrmRes{Ret:"Failure", Tip: "dcrm back-end internal error:get reqaddr accept data fail from db", Err: fmt.Errorf("get reqaddr accept data fail from db in init accept data")}
	    ch <- res
	    return fmt.Errorf("get reqaddr accept data fail from db in init accept data.")
	}

	ac,ok := da.(*AcceptReqAddrData)
	if !ok || ac == nil {
	    res := RpcDcrmRes{Ret:"Failure", Tip: "dcrm back-end internal error:decode accept data fail", Err: fmt.Errorf("decode accept data fail")}
	    ch <- res
	    return fmt.Errorf("decode accept data fail")
	}

	status := "Pending"
	accept := "false"
	if acceptreq.Accept == "AGREE" {
		accept = "true"
	} else {
		status = "Failure"
	}

	id,_ := GetWorkerId(w)
	DisAcceptMsg(raw,id)
	HandleC1Data(ac,acceptreq.Key,id)

	ars := GetAllReplyFromGroup(id,ac.GroupId,Rpc_REQADDR,ac.Initiator)
	tip, err := AcceptReqAddr(ac.Initiator,ac.Account, ac.Cointype, ac.GroupId, ac.Nonce, ac.LimitNum, ac.Mode, "false", accept, status, "", "", "", ars, ac.WorkId,"")
	if err != nil {
	    res := RpcDcrmRes{Ret:"Failure", Tip: tip, Err: err}
	    ch <- res
	    return err 
	}

	res := RpcDcrmRes{Ret:"Success", Tip: "", Err: nil}
	ch <- res
	return nil
    }

    acceptlo,ok := txdata.(*TxDataAcceptLockOut)
    if ok {
	common.Debug("===============InitAcceptData, check accept lockout raw success=================","raw ",raw,"key ",acceptlo.Key,"from ",from,"txdata ",acceptlo)
	w, err := FindWorker(acceptlo.Key)
	if err != nil || w == nil {
	    c1data := acceptlo.Key + "-" + from
	    C1Data.WriteMap(strings.ToLower(c1data),raw)
	    res := RpcDcrmRes{Ret:"Failure", Tip: "get lockout accept data fail from db when no find worker.", Err: fmt.Errorf("get lockout accept data fail from db when no find worker")}
	    ch <- res
	    return fmt.Errorf("get lockout accept data fail from db when no find worker.")
	}

	exsit,da := GetValueFromPubKeyData(acceptlo.Key)
	if !exsit {
	    res := RpcDcrmRes{Ret:"Failure", Tip: "dcrm back-end internal error:get lockout accept data fail from db in init accept data", Err: fmt.Errorf("get lockout accept data fail from db in init accept data")}
	    ch <- res
	    return fmt.Errorf("get lockout accept data fail from db in init accept data.")
	}

	ac,ok := da.(*AcceptLockOutData)
	if !ok || ac == nil {
	    res := RpcDcrmRes{Ret:"Failure", Tip: "dcrm back-end internal error:decode accept data fail", Err: fmt.Errorf("decode accept data fail")}
	    ch <- res
	    return fmt.Errorf("decode accept data fail")
	}

	dcrmaddr,_,err := GetAddr(ac.PubKey,ac.Cointype)
	if err != nil {
	    res := RpcDcrmRes{Ret:"Failure", Tip: "dcrm back-end internal error:get dcrm addr fail", Err: fmt.Errorf("get dcrm addr fail")}
	    ch <- res
	    return fmt.Errorf("get dcrm addr fail")
	}

	status := "Pending"
	accept := "false"
	if acceptlo.Accept == "AGREE" {
		accept = "true"
	} else {
		status = "Failure"
	}

	id,_ := GetWorkerId(w)
	DisAcceptMsg(raw,id)
	reqaddrkey := GetReqAddrKeyByOtherKey(acceptlo.Key,Rpc_LOCKOUT)
	exsit,da = GetValueFromPubKeyData(reqaddrkey)
	if !exsit {
	    res := RpcDcrmRes{Ret: "", Tip: "dcrm back-end internal error:get reqaddr sigs data fail", Err: fmt.Errorf("get reqaddr sigs data fail")}
	    ch <- res
	    return fmt.Errorf("get reqaddr sigs data fail") 
	}
	acceptreqdata,ok := da.(*AcceptReqAddrData)
	if !ok || acceptreqdata == nil {
	    res := RpcDcrmRes{Ret: "", Tip: "dcrm back-end internal error:get reqaddr sigs data fail", Err: fmt.Errorf("get reqaddr sigs data fail")}
	    ch <- res
	    return fmt.Errorf("get reqaddr sigs data fail") 
	}

	HandleC1Data(acceptreqdata,acceptlo.Key,id)

	ars := GetAllReplyFromGroup(id,ac.GroupId,Rpc_LOCKOUT,ac.Initiator)
	tip, err := AcceptLockOut(ac.Initiator,ac.Account, ac.GroupId, ac.Nonce, dcrmaddr, ac.LimitNum, "false", accept, status, "", "", "", ars, ac.WorkId)
	if err != nil {
	    res := RpcDcrmRes{Ret:"Failure", Tip: tip, Err: err}
	    ch <- res
	    return err 
	}

	res := RpcDcrmRes{Ret:"Success", Tip: "", Err: nil}
	ch <- res
	return nil
    }

    acceptsig,ok := txdata.(*TxDataAcceptSign)
    if ok {
	common.Debug("===============InitAcceptData, it is acceptsign and check accept sign raw success=====================","key ",acceptsig.Key,"from ",from)
	w, err := FindWorker(acceptsig.Key)
	if err != nil || w == nil {
		common.Debug("===============InitAcceptData, it is acceptsign and no find worker=====================","key ",acceptsig.Key,"from ",from)
	    c1data := acceptsig.Key + "-" + from
	    C1Data.WriteMap(strings.ToLower(c1data),raw)
	    res := RpcDcrmRes{Ret:"Failure", Tip: "get sign accept data fail from db when no find worker.", Err: fmt.Errorf("get sign accept data fail from db when no find worker")}
	    ch <- res
	    return fmt.Errorf("get sign accept data fail from db when no find worker.")
	}

	exsit,da := GetValueFromPubKeyData(acceptsig.Key)
	if !exsit {
		common.Debug("===============InitAcceptData, it is acceptsign and get sign accept data fail from db=====================","key ",acceptsig.Key,"from ",from)
	    res := RpcDcrmRes{Ret:"Failure", Tip: "dcrm back-end internal error:get sign accept data fail from db in init accept data", Err: fmt.Errorf("get sign accept data fail from db in init accept data")}
	    ch <- res
	    return fmt.Errorf("get sign accept data fail from db in init accept data.")
	}

	ac,ok := da.(*AcceptSignData)
	if !ok || ac == nil {
		common.Debug("===============InitAcceptData, it is acceptsign and decode accept data fail=====================","key ",acceptsig.Key,"from ",from)
	    res := RpcDcrmRes{Ret:"Failure", Tip: "dcrm back-end internal error:decode accept data fail", Err: fmt.Errorf("decode accept data fail")}
	    ch <- res
	    return fmt.Errorf("decode accept data fail")
	}

	if ac.Deal == "true" || ac.Status == "Success" || ac.Status == "Failure" || ac.Status == "Timeout" {
		common.Debug("===============InitAcceptData, it is acceptsign and sign has handled before=====================","key ",acceptsig.Key,"from ",from)
	    res := RpcDcrmRes{Ret:"", Tip: "sign has handled before", Err: fmt.Errorf("sign has handled before")}
	    ch <- res
	    return fmt.Errorf("sign has handled before")
	}

	status := "Pending"
	accept := "false"
	if acceptsig.Accept == "AGREE" {
		accept = "true"
	} else {
		status = "Failure"
	}

	id,_ := GetWorkerId(w)
	DisAcceptMsg(raw,id)
	reqaddrkey := GetReqAddrKeyByOtherKey(acceptsig.Key,Rpc_SIGN)
	exsit,da = GetValueFromPubKeyData(reqaddrkey)
	if !exsit {
		common.Debug("===============InitAcceptData, it is acceptsign and get reqaddr sigs data fail=====================","key ",acceptsig.Key,"from ",from)
	    res := RpcDcrmRes{Ret: "", Tip: "dcrm back-end internal error:get reqaddr sigs data fail", Err: fmt.Errorf("get reqaddr sigs data fail")}
	    ch <- res
	    return fmt.Errorf("get reqaddr sigs data fail") 
	}
	acceptreqdata,ok := da.(*AcceptReqAddrData)
	if !ok || acceptreqdata == nil {
		common.Debug("===============InitAcceptData, it is acceptsign and get reqaddr sigs data fail 2222222222 =====================","key ",acceptsig.Key,"from ",from)
	    res := RpcDcrmRes{Ret: "", Tip: "dcrm back-end internal error:get reqaddr sigs data fail", Err: fmt.Errorf("get reqaddr sigs data fail")}
	    ch <- res
	    return fmt.Errorf("get reqaddr sigs data fail") 
	}

	HandleC1Data(acceptreqdata,acceptsig.Key,id)

	ars := GetAllReplyFromGroup(id,ac.GroupId,Rpc_SIGN,ac.Initiator)
	if ac.Deal == "true" || ac.Status == "Success" || ac.Status == "Failure" || ac.Status == "Timeout" {
		common.Debug("===============InitAcceptData, it is acceptsign and sign has handled before 222222222=====================","key ",acceptsig.Key,"from ",from)
	    res := RpcDcrmRes{Ret:"", Tip: "sign has handled before", Err: fmt.Errorf("sign has handled before")}
	    ch <- res
	    return fmt.Errorf("sign has handled before")
	}

	common.Debug("=======================InitAcceptData,333333333333333333333333,set sign status =============================","status",status,"key",acceptsig.Key)
	tip, err := AcceptSign(ac.Initiator,ac.Account, ac.PubKey, ac.MsgHash, ac.Keytype, ac.GroupId, ac.Nonce,ac.LimitNum,ac.Mode,"false", accept, status, "", "", "", ars, ac.WorkId)
	if err != nil {
	    res := RpcDcrmRes{Ret:"Failure", Tip: tip, Err: err}
	    ch <- res
	    return err 
	}

	res := RpcDcrmRes{Ret:"Success", Tip: "", Err: nil}
	ch <- res
	return nil
    }

    acceptrh,ok := txdata.(*TxDataAcceptReShare)
    if ok {
	common.Debug("===============InitAcceptData, check accept reshare raw success=====================","raw ",raw,"key ",acceptrh.Key,"from ",from,"txdata ",acceptrh)
	w, err := FindWorker(acceptrh.Key)
	if err != nil || w == nil {
	    c1data := acceptrh.Key + "-" + from
	    C1Data.WriteMap(strings.ToLower(c1data),raw)
	    res := RpcDcrmRes{Ret:"Failure", Tip: "get reshare accept data fail from db when no find worker.", Err: fmt.Errorf("get reshare accept data fail from db when no find worker")}
	    ch <- res
	    return fmt.Errorf("get reshare accept data fail from db whern no find worker.")
	}

	exsit,da := GetValueFromPubKeyData(acceptrh.Key)
	if !exsit {
	    res := RpcDcrmRes{Ret:"Failure", Tip: "dcrm back-end internal error:get reshare accept data fail from db in init accept data", Err: fmt.Errorf("get reshare accept data fail from db in init accept data")}
	    ch <- res
	    return fmt.Errorf("get reshare accept data fail from db in init accept data.")
	}

	ac,ok := da.(*AcceptReShareData)
	if !ok || ac == nil {
	    res := RpcDcrmRes{Ret:"Failure", Tip: "dcrm back-end internal error:decode accept data fail", Err: fmt.Errorf("decode accept data fail")}
	    ch <- res
	    return fmt.Errorf("decode accept data fail")
	}

	status := "Pending"
	accept := "false"
	if acceptrh.Accept == "AGREE" {
		accept = "true"
	} else {
		status = "Failure"
	}

	id,_ := GetWorkerId(w)
	DisAcceptMsg(raw,id)
	HandleC1Data(nil,acceptrh.Key,id)

	ars := GetAllReplyFromGroup(id,ac.GroupId,Rpc_RESHARE,ac.Initiator)
	tip,err := AcceptReShare(ac.Initiator,ac.Account, ac.GroupId, ac.TSGroupId,ac.PubKey, ac.LimitNum, ac.Mode,"false", accept, status, "", "", "", ars,ac.WorkId)
	if err != nil {
	    res := RpcDcrmRes{Ret:"Failure", Tip: tip, Err: err}
	    ch <- res
	    return err 
	}

	res := RpcDcrmRes{Ret:"Success", Tip: "", Err: nil}
	ch <- res
	return nil
    }
	
    common.Debug("===============InitAcceptData, it is not sign txdata and return fail ==================","key ",key,"from ",from,"nonce ",nonce)
    res := RpcDcrmRes{Ret: "", Tip: "init accept data fail.", Err: fmt.Errorf("init accept data fail")}
    ch <- res
    return fmt.Errorf("init accept data fail")
}

func HandleC1Data(ac *AcceptReqAddrData,key string,workid int) {
    //reshare only
    if ac == nil {
	exsit,da := GetValueFromPubKeyData(key)
	if !exsit {
	    return
	}

	ac,ok := da.(*AcceptReShareData)
	if !ok || ac == nil {
	    return
	}

	_, enodes := GetGroup(ac.GroupId)
	nodes := strings.Split(enodes, common.Sep2)
	for _, node := range nodes {
	    node2 := ParseNode(node)
	    pk := "04" + node2 
	     h := coins.NewCryptocoinHandler("FSN")
	     if h == nil {
		continue
	     }

	    fr, err := h.PublicKeyToAddress(pk)
	    if err != nil {
		continue
	    }

	    c1data := key + "-" + fr
	    c1, exist := C1Data.ReadMap(strings.ToLower(c1data))
	    if exist {
		DisAcceptMsg(c1.(string),workid)
		go C1Data.DeleteMap(strings.ToLower(c1data))
	    }
	}

	return
    }
    //reshare only

    if key == "" || workid < 0 || workid >= len(workers) {
	return
    }
   
    mms := strings.Split(ac.Sigs, common.Sep)
    if len(mms) < 3 { //1:eid1:acc1
	return
    }

    count := (len(mms)-1)/2
    for j := 0;j<count;j++ {
	from := mms[2*j+2]
	c1data := key + "-" + from
	c1, exist := C1Data.ReadMap(strings.ToLower(c1data))
	if exist {
	    DisAcceptMsg(c1.(string),workid)
	    go C1Data.DeleteMap(strings.ToLower(c1data))
	}
    }
}

func ReqDcrmAddr(raw string) (string, string, error) {

    common.Debug("=====================ReqDcrmAddr call CheckRaw ================","raw ",raw)
    key,_,_,txdata,err := CheckRaw(raw)
    if err != nil {
	common.Debug("============ReqDcrmAddr==============","err ",err)
	return "",err.Error(),err
    }

    req,ok := txdata.(*TxDataReqAddr)
    if !ok {
	return "","check raw fail,it is not *TxDataReqAddr",fmt.Errorf("check raw fail,it is not *TxDataReqAddr")
    }

    common.Debug("============ReqDcrmAddr,SendMsgToDcrmGroup===============","raw ",raw,"gid ",req.GroupId,"key ",key)
    SendMsgToDcrmGroup(raw, req.GroupId)
    SetUpMsgList(raw,cur_enode)
    return key, "", nil
}

func DisAcceptMsg(raw string,workid int) {
    if raw == "" || workid < 0 || workid >= len(workers) {
	return
    }

    w := workers[workid]
    if w == nil {
	return
    }

    common.Debug("=====================DisAcceptMsg call CheckRaw================","raw ",raw)
    key,from,_,txdata,err := CheckRaw(raw)
    common.Debug("=====================DisAcceptMsg=================","key",key,"err",err)
    if err != nil {
	return
    }
    
    _,ok := txdata.(*TxDataReqAddr)
    if ok {
	if Find(w.msg_acceptreqaddrres,raw) {
		return
	}

	w.msg_acceptreqaddrres.PushBack(raw)
	if w.msg_acceptreqaddrres.Len() >= w.NodeCnt {
	    if !CheckReply(w.msg_acceptreqaddrres,Rpc_REQADDR,key) {
		return
	    }

	    w.bacceptreqaddrres <- true
	    exsit,da := GetValueFromPubKeyData(key)
	    if !exsit {
		return
	    }

	    ac,ok := da.(*AcceptReqAddrData)
	    if !ok || ac == nil {
		return
	    }

	    workers[ac.WorkId].acceptReqAddrChan <- "go on"
	}
    }
    
    _,ok = txdata.(*TxDataLockOut)
    if ok {
	if Find(w.msg_acceptlockoutres, raw) {
	    return
	}

	w.msg_acceptlockoutres.PushBack(raw)
	if w.msg_acceptlockoutres.Len() >= w.ThresHold {
	    if !CheckReply(w.msg_acceptlockoutres,Rpc_LOCKOUT,key) {
		return
	    }

	    w.bacceptlockoutres <- true
	    exsit,da := GetValueFromPubKeyData(key)
	    if !exsit {
		return
	    }

	    ac,ok := da.(*AcceptLockOutData)
	    if !ok || ac == nil {
		return
	    }

	    workers[ac.WorkId].acceptLockOutChan <- "go on"
	}
    }
    
    sig2,ok := txdata.(*TxDataSign)
    if ok {
	    common.Debug("======================DisAcceptMsg, get the msg and it is sign tx===========================","key",key,"from",from,"raw",raw)
	if Find(w.msg_acceptsignres, raw) {
	    common.Debug("======================DisAcceptMsg,the msg is sign tx,and already in list.===========================","key",key,"from",from)
	    return
	}

	    common.Debug("======================DisAcceptMsg,the msg is sign tx,and put it into list.===========================","key",key,"from",from,"sig",sig2)
	w.msg_acceptsignres.PushBack(raw)
	if w.msg_acceptsignres.Len() >= w.ThresHold {
	    if !CheckReply(w.msg_acceptsignres,Rpc_SIGN,key) {
		common.Debug("=====================DisAcceptMsg,check reply fail===================","key",key,"from",from)
		return
	    }

	    common.Debug("=====================DisAcceptMsg,check reply success and will set timeout channel===================","key",key,"from",from)
	    w.bacceptsignres <- true
	    exsit,da := GetValueFromPubKeyData(key)
	    if !exsit {
		return
	    }

	    ac,ok := da.(*AcceptSignData)
	    if !ok || ac == nil {
		return
	    }

	    workers[ac.WorkId].acceptSignChan <- "go on"
	}
    }
    
    _,ok = txdata.(*TxDataReShare)
    if ok {
	if Find(w.msg_acceptreshareres, raw) {
	    return
	}

	w.msg_acceptreshareres.PushBack(raw)
	if w.msg_acceptreshareres.Len() >= w.NodeCnt {
	    if !CheckReply(w.msg_acceptreshareres,Rpc_RESHARE,key) {
		return
	    }

	    w.bacceptreshareres <- true
	    exsit,da := GetValueFromPubKeyData(key)
	    if !exsit {
		return
	    }

	    ac,ok := da.(*AcceptReShareData)
	    if !ok || ac == nil {
		return
	    }

	    workers[ac.WorkId].acceptReShareChan <- "go on"
	}
    }
    
    acceptreq,ok := txdata.(*TxDataAcceptReqAddr)
    if ok {
	if Find(w.msg_acceptreqaddrres,raw) {
		return
	}

	w.msg_acceptreqaddrres.PushBack(raw)
	if w.msg_acceptreqaddrres.Len() >= w.NodeCnt {
	    if !CheckReply(w.msg_acceptreqaddrres,Rpc_REQADDR,acceptreq.Key) {
		return
	    }

	    w.bacceptreqaddrres <- true
	    exsit,da := GetValueFromPubKeyData(acceptreq.Key)
	    if !exsit {
		return
	    }

	    ac,ok := da.(*AcceptReqAddrData)
	    if !ok || ac == nil {
		return
	    }

	    workers[ac.WorkId].acceptReqAddrChan <- "go on"
	}
    }
    
    acceptlockout,ok := txdata.(*TxDataAcceptLockOut)
    if ok {
	if Find(w.msg_acceptlockoutres, raw) {
	    return
	}

	w.msg_acceptlockoutres.PushBack(raw)
	if w.msg_acceptlockoutres.Len() >= w.ThresHold {
	    if !CheckReply(w.msg_acceptlockoutres,Rpc_LOCKOUT,acceptlockout.Key) {
		return
	    }

	    w.bacceptlockoutres <- true
	    exsit,da := GetValueFromPubKeyData(acceptlockout.Key)
	    if !exsit {
		return
	    }

	    ac,ok := da.(*AcceptLockOutData)
	    if !ok || ac == nil {
		return
	    }

	    workers[ac.WorkId].acceptLockOutChan <- "go on"
	}
    }
    
    acceptsig,ok := txdata.(*TxDataAcceptSign)
    if ok {
	    common.Debug("======================DisAcceptMsg, get the msg and it is accept sign tx===========================","key",key,"from",from,"raw",raw)
	if Find(w.msg_acceptsignres, raw) {
	    common.Debug("======================DisAcceptMsg,the msg is accept sign tx,and already in list.===========================","sig key",key,"from",from)
	    return
	}

	    common.Debug("======================DisAcceptMsg,the msg is accept sign tx,and put it into list.===========================","sig key",key,"from",from,"accept sig",acceptsig)
	w.msg_acceptsignres.PushBack(raw)
	if w.msg_acceptsignres.Len() >= w.ThresHold {
	    if !CheckReply(w.msg_acceptsignres,Rpc_SIGN,acceptsig.Key) {
		    common.Debug("======================DisAcceptMsg,the msg is accept sign tx,and check reply fail.===========================","sig key",key,"from",from)
		return
	    }

	    common.Debug("======================DisAcceptMsg,the msg is accept sign tx,and check reply success and will set timeout channel.===========================","sig key",key,"from",from)
	    w.bacceptsignres <- true
	    exsit,da := GetValueFromPubKeyData(acceptsig.Key)
	    if !exsit {
		return
	    }

	    ac,ok := da.(*AcceptSignData)
	    if !ok || ac == nil {
		return
	    }

	    workers[ac.WorkId].acceptSignChan <- "go on"
	}
    }
    
    acceptreshare,ok := txdata.(*TxDataAcceptReShare)
    if ok {
	if Find(w.msg_acceptreshareres, raw) {
	    return
	}

	w.msg_acceptreshareres.PushBack(raw)
	if w.msg_acceptreshareres.Len() >= w.NodeCnt {
	    if !CheckReply(w.msg_acceptreshareres,Rpc_RESHARE,acceptreshare.Key) {
		return
	    }

	    w.bacceptreshareres <- true
	    exsit,da := GetValueFromPubKeyData(acceptreshare.Key)
	    if !exsit {
		return
	    }

	    ac,ok := da.(*AcceptReShareData)
	    if !ok || ac == nil {
		return
	    }

	    workers[ac.WorkId].acceptReShareChan <- "go on"
	}
    }
}

func RpcAcceptReqAddr(raw string) (string, string, error) {
    common.Debug("=====================RpcAcceptReqAddr call CheckRaw ================","raw",raw)
    _,_,_,txdata,err := CheckRaw(raw)
    if err != nil {
	common.Debug("=====================RpcAcceptReqAddr,CheckRaw ================","raw",raw,"err",err)
	return "Failure",err.Error(),err
    }

    acceptreq,ok := txdata.(*TxDataAcceptReqAddr)
    if !ok {
	return "Failure","check raw fail,it is not *TxDataAcceptReqAddr",fmt.Errorf("check raw fail,it is not *TxDataAcceptReqAddr")
    }

    exsit,da := GetValueFromPubKeyData(acceptreq.Key)
    if exsit {
	ac,ok := da.(*AcceptReqAddrData)
	if ok && ac != nil {
	    common.Debug("=====================RpcAcceptReqAddr, SendMsgToDcrmGroup ================","raw",raw,"gid",ac.GroupId,"key",acceptreq.Key)
	    SendMsgToDcrmGroup(raw, ac.GroupId)
	    SetUpMsgList(raw,cur_enode)
	    return "Success", "", nil
	}
    }

    return "Failure","accept fail",fmt.Errorf("accept fail")
}

func RpcAcceptLockOut(raw string) (string, string, error) {
    common.Debug("=====================RpcAcceptLockOut call CheckRaw ================","raw",raw)
    _,_,_,txdata,err := CheckRaw(raw)
    if err != nil {
	common.Debug("=====================RpcAcceptLockOut,CheckRaw ================","raw",raw,"err",err)
	return "Failure",err.Error(),err
    }

    acceptlo,ok := txdata.(*TxDataAcceptLockOut)
    if !ok {
	return "Failure","check raw fail,it is not *TxDataAcceptLockOut",fmt.Errorf("check raw fail,it is not *TxDataAcceptLockOut")
    }

    exsit,da := GetValueFromPubKeyData(acceptlo.Key)
    if exsit {
	ac,ok := da.(*AcceptLockOutData)
	if ok && ac != nil {
	    common.Debug("=====================RpcAcceptLockOut, SendMsgToDcrmGroup ================","raw",raw,"gid",ac.GroupId,"key",acceptlo.Key)
	    SendMsgToDcrmGroup(raw, ac.GroupId)
	    SetUpMsgList(raw,cur_enode)
	    return "Success", "", nil
	}
    }

    return "Failure","accept fail",fmt.Errorf("accept fail")
}

func RpcAcceptSign(raw string) (string, string, error) {
    common.Debug("=====================RpcAcceptSign call CheckRaw ================","raw",raw)
    _,from,_,txdata,err := CheckRaw(raw)
    if err != nil {
	common.Debug("=====================RpcAcceptSign,CheckRaw ================","raw",raw,"err",err)
	return "Failure",err.Error(),err
    }

    acceptsig,ok := txdata.(*TxDataAcceptSign)
    if !ok {
	return "Failure","check raw fail,it is not *TxDataAcceptSign",fmt.Errorf("check raw fail,it is not *TxDataAcceptSign")
    }

    exsit,da := GetValueFromPubKeyData(acceptsig.Key)
    if exsit {
	ac,ok := da.(*AcceptSignData)
	if ok && ac != nil {
	    common.Debug("=====================RpcAcceptSign, SendMsgToDcrmGroup ================","key",acceptsig.Key,"from",from,"raw",raw)
	    SendMsgToDcrmGroup(raw, ac.GroupId)
	    SetUpMsgList(raw,cur_enode)
	    return "Success", "", nil
	}
    }

    return "Failure","accept fail",fmt.Errorf("accept fail")
}

func LockOut(raw string) (string, string, error) {
    common.Debug("=====================LockOut call CheckRaw ================","raw",raw)
    key,_,_,txdata,err := CheckRaw(raw)
    if err != nil {
	common.Debug("=====================LockOut,CheckRaw ================","raw",raw,"err",err)
	return "",err.Error(),err
    }

    lo,ok := txdata.(*TxDataLockOut)
    if !ok {
	return "","check raw fail,it is not *TxDataLockOut",fmt.Errorf("check raw fail,it is not *TxDataLockOut")
    }

    common.Debug("=====================LockOut, SendMsgToDcrmGroup ================","raw",raw,"gid",lo.GroupId,"key",key)
    SendMsgToDcrmGroup(raw, lo.GroupId)
    SetUpMsgList(raw,cur_enode)
    return key, "", nil
}

func ReShare(raw string) (string, string, error) {
    common.Debug("=====================ReShare call CheckRaw ================","raw",raw)
    key,_,_,txdata,err := CheckRaw(raw)
    if err != nil {
	common.Debug("=====================ReShare,CheckRaw ================","raw",raw,"err",err)
	return "",err.Error(),err
    }

    rh,ok := txdata.(*TxDataReShare)
    if !ok {
	return "","check raw fail,it is not *TxDataReShare",fmt.Errorf("check raw fail,it is not *TxDataReShare")
    }

    common.Debug("=====================ReShare, SendMsgToDcrmGroup ================","raw",raw,"gid",rh.GroupId,"key",key)
    SendMsgToDcrmGroup(raw, rh.GroupId)
    SetUpMsgList(raw,cur_enode)
    return key, "", nil
}

func RpcAcceptReShare(raw string) (string, string, error) {
    common.Debug("=====================RpcAcceptReShare call CheckRaw ================","raw",raw)
    _,_,_,txdata,err := CheckRaw(raw)
    if err != nil {
	common.Debug("=====================RpcAcceptReShare,CheckRaw ================","raw",raw,"err",err)
	return "Failure",err.Error(),err
    }

    acceptrh,ok := txdata.(*TxDataAcceptReShare)
    if !ok {
	return "Failure","check raw fail,it is not *TxDataAcceptReShare",fmt.Errorf("check raw fail,it is not *TxDataAcceptReShare")
    }

    exsit,da := GetValueFromPubKeyData(acceptrh.Key)
    if exsit {
	ac,ok := da.(*AcceptReShareData)
	if ok && ac != nil {
	    common.Debug("=====================RpcAcceptReShare, SendMsgToDcrmGroup ================","raw",raw,"gid",ac.GroupId,"key",acceptrh.Key)
	    SendMsgToDcrmGroup(raw, ac.GroupId)
	    SetUpMsgList(raw,cur_enode)
	    return "Success", "", nil
	}
    }

    return "Failure","accept fail",fmt.Errorf("accept fail")
}

func Sign(raw string) (string, string, error) {
    common.Debug("=====================Sign call CheckRaw ================","raw",raw)
    key,from,_,txdata,err := CheckRaw(raw)
    if err != nil {
	common.Debug("=====================Sign,CheckRaw ================","raw",raw,"err",err)
	return "",err.Error(),err
    }

    sig,ok := txdata.(*TxDataSign)
    if !ok {
	return "","check raw fail,it is not *TxDataSign",fmt.Errorf("check raw fail,it is not *TxDataSign")
    }

    common.Debug("=====================Sign, SendMsgToDcrmGroup ================","key",key,"from",from,"raw",raw)
    SendMsgToDcrmGroup(raw, sig.GroupId)
    SetUpMsgList(raw,cur_enode)
    return key, "", nil
}

func get_sign_hash(hash []string,keytype string) string {
    var ids sortableIDSSlice
    for _, v := range hash {
	    uid := DoubleHash2(v, keytype)
	    ids = append(ids, uid)
    }
    sort.Sort(ids)

    ret := ""
    for _,v := range ids {
	ret += fmt.Sprintf("%v",v)
	ret += ":"
    }

    ret += "NULL"
    return ret
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
		//var ret map[string]*SubAddressBalance = make(map[string]*SubAddressBalance, 0)
		for cointype, subaddr := range dp.DcrmAddress {
			wg.Add(1)
			go func(cointype, subaddr string) {
				defer wg.Done()
				balance, _, err := GetBalance(pubkey, cointype, subaddr)
				if err != nil {
					balance = "0"
				}
				//ret[cointype] = &SubAddressBalance{Cointype: cointype, DcrmAddr: subaddr, Balance: balance}
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

	if !PutGroup(groupId) {
		out := "=============Init================" + " get group id = " + groupId + ", put group id fail "
		fmt.Println(out)
		return
	}

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

//===================================================================

type ReqAddrStatus struct {
	Status    string
	PubKey    string
	Tip       string
	Error     string
	AllReply  []NodeReply 
	TimeStamp string
}

func GetReqAddrStatus(key string) (string, string, error) {
	exsit,da := GetValueFromPubKeyData(key)
	///////
	if !exsit || da == nil {
		common.Debug("=====================GetReqAddrStatus,no exist key======================","key",key)
		return "", "dcrm back-end internal error:get reqaddr accept data fail from db when GetReqAddrStatus", fmt.Errorf("dcrm back-end internal error:get reqaddr accept data fail from db when GetReqAddrStatus")
	}

	ac,ok := da.(*AcceptReqAddrData)
	if !ok {
		return "", "dcrm back-end internal error:get reqaddr accept data error from db when GetReqAddrStatus", fmt.Errorf("dcrm back-end internal error:get reqaddr accept data error from db when GetReqAddrStatus")
	}

	los := &ReqAddrStatus{Status: ac.Status, PubKey: ac.PubKey, Tip: ac.Tip, Error: ac.Error, AllReply: ac.AllReply, TimeStamp: ac.TimeStamp}
	ret, _ := json.Marshal(los)
	return string(ret), "", nil
}

type LockOutStatus struct {
	Status    string
	OutTxHash string
	Tip       string
	Error     string
	AllReply  []NodeReply 
	TimeStamp string
}

func GetLockOutStatus(key string) (string, string, error) {
	exsit,da := GetValueFromPubKeyData(key)
	///////
	if !exsit || da == nil {
		return "", "dcrm back-end internal error:get lockout accept data fail from db when GetLockOutStatus", fmt.Errorf("dcrm back-end internal error:get lockout accept data fail from db when GetLockOutStatus")
	}

	ac,ok := da.(*AcceptLockOutData)
	if !ok {
		return "", "dcrm back-end internal error:get lockout accept data error from db when GetLockOutStatus", fmt.Errorf("dcrm back-end internal error:get lockout accept data error from db when GetLockOutStatus")
	}
	los := &LockOutStatus{Status: ac.Status, OutTxHash: ac.OutTxHash, Tip: ac.Tip, Error: ac.Error, AllReply: ac.AllReply, TimeStamp: ac.TimeStamp}
	ret,_ := json.Marshal(los)
	return string(ret), "",nil 
}

type SignStatus struct {
	Status    string
	Rsv []string
	Tip       string
	Error     string
	AllReply  []NodeReply 
	TimeStamp string
}

func GetSignStatus(key string) (string, string, error) {
	exsit,da := GetValueFromPubKeyData(key)
	///////
	if !exsit || da == nil {
		common.Debug("=================GetSignStatus,get sign accept data fail from db================","key",key)
		return "", "dcrm back-end internal error:get sign accept data fail from db when GetSignStatus", fmt.Errorf("dcrm back-end internal error:get sign accept data fail from db when GetSignStatus")
	}

	ac,ok := da.(*AcceptSignData)
	if !ok {
		common.Debug("=================GetSignStatus,get sign accept data error from db================","key",key)
		return "", "dcrm back-end internal error:get sign accept data error from db when GetSignStatus", fmt.Errorf("dcrm back-end internal error:get sign accept data error from db when GetSignStatus")
	}

	rsvs := strings.Split(ac.Rsv,":")
	los := &SignStatus{Status: ac.Status, Rsv: rsvs[:len(rsvs)-1], Tip: ac.Tip, Error: ac.Error, AllReply: ac.AllReply, TimeStamp: ac.TimeStamp}
	ret,_ := json.Marshal(los)
	return string(ret), "",nil 
}

type ReShareStatus struct {
	Status    string
	Pubkey string
	Tip       string
	Error     string
	AllReply  []NodeReply 
	TimeStamp string
}

func GetReShareStatus(key string) (string, string, error) {
	exsit,da := GetValueFromPubKeyData(key)
	///////
	if !exsit || da == nil  {
		return "", "dcrm back-end internal error:get reshare accept data fail from db when GetReShareStatus", fmt.Errorf("dcrm back-end internal error:get reshare accept data fail from db when GetReShareStatus")
	}

	ac,ok := da.(*AcceptReShareData)
	if !ok {
		return "", "dcrm back-end internal error:get reshare accept data error from db when GetReShareStatus", fmt.Errorf("dcrm back-end internal error:get reshare accept data error from db when GetReShareStatus")
	}

	los := &ReShareStatus{Status: ac.Status, Pubkey: ac.PubKey, Tip: ac.Tip, Error: ac.Error, AllReply: ac.AllReply, TimeStamp: ac.TimeStamp}
	ret,_ := json.Marshal(los)
	return string(ret), "",nil 
}

type EnAcc struct {
	Enode    string
	Accounts []string
}

type EnAccs struct {
	EnodeAccounts []EnAcc
}

type ReqAddrReply struct {
	Key       string
	Account   string
	Cointype  string
	GroupId   string
	Nonce     string
	ThresHold  string
	Mode      string
	TimeStamp string
}

func SortCurNodeInfo(value []interface{}) []interface{} {
	if len(value) == 0 {
		return value
	}

	var ids sortableIDSSlice
	for _, v := range value {
		uid := DoubleHash(string(v.([]byte)), "ALL")
		ids = append(ids, uid)
	}

	sort.Sort(ids)

	var ret = make([]interface{}, 0)
	for _, v := range ids {
		for _, vv := range value {
			uid := DoubleHash(string(vv.([]byte)), "ALL")
			if v.Cmp(uid) == 0 {
				ret = append(ret, vv)
				break
			}
		}
	}

	return ret
}

func GetCurNodeReqAddrInfo(geter_acc string) ([]*ReqAddrReply, string, error) {
	var ret []*ReqAddrReply
	var wg sync.WaitGroup
	LdbPubKeyData.RLock()
	for k, v := range LdbPubKeyData.Map {
	    wg.Add(1)
	    go func(key string,value interface{}) {
		defer wg.Done()

		vv,ok := value.(*AcceptReqAddrData)
		if vv == nil || !ok {
		    return
		}

		common.Debug("================GetCurNodeReqAddrInfo, it is *AcceptReqAddrData===================","vv",vv,"vv.Deal",vv.Deal,"vv.Mode",vv.Mode,"vv.Status",vv.Status,"key",key)
		if vv.Deal == "true" || vv.Status == "Success" {
		    return
		}

		if vv.Status != "Pending" {
		    return
		}

		if vv.Mode == "1" {
		    return
		}
		
		if vv.Mode == "0" && !CheckAcc(cur_enode,geter_acc,vv.Sigs) {
		    return
		}

		los := &ReqAddrReply{Key: key, Account: vv.Account, Cointype: vv.Cointype, GroupId: vv.GroupId, Nonce: vv.Nonce, ThresHold: vv.LimitNum, Mode: vv.Mode, TimeStamp: vv.TimeStamp}
		ret = append(ret, los)
		common.Debug("================GetCurNodeReqAddrInfo success return================","key",key)
	    }(k,v)
	}
	LdbPubKeyData.RUnlock()
	wg.Wait()
	return ret, "", nil
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

type LockOutCurNodeInfo struct {
	Key       string
	Account   string
	GroupId   string
	Nonce     string
	DcrmFrom  string
	DcrmTo    string
	Value     string
	Cointype  string
	ThresHold  string
	Mode      string
	TimeStamp string
}

func GetCurNodeLockOutInfo(geter_acc string) ([]*LockOutCurNodeInfo, string, error) {

	var ret []*LockOutCurNodeInfo
	var wg sync.WaitGroup
	LdbPubKeyData.RLock()
	for k, v := range LdbPubKeyData.Map {
	    wg.Add(1)
	    go func(key string,value interface{}) {
		defer wg.Done()

		vv,ok := value.(*AcceptLockOutData)
		if vv == nil || !ok {
		    return
		}

		common.Debug("================GetCurNodeLockOutInfo, it is *AcceptLockOutData===================","vv",vv,"vv.Deal",vv.Deal,"vv.Status",vv.Status,"key",key)
		if vv.Deal == "true" || vv.Status == "Success" {
		    return
		}

		if vv.Status != "Pending" {
		    return
		}

		dcrmaddr,_,err := GetAddr(vv.PubKey,vv.Cointype)
		if err != nil {
		    return
		}

		if !CheckAccept(vv.PubKey,vv.Mode,geter_acc) {
			return
		}
		
		los := &LockOutCurNodeInfo{Key: key, Account: vv.Account, GroupId: vv.GroupId, Nonce: vv.Nonce, DcrmFrom: dcrmaddr, DcrmTo: vv.DcrmTo, Value: vv.Value, Cointype: vv.Cointype, ThresHold: vv.LimitNum, Mode: vv.Mode, TimeStamp: vv.TimeStamp}
		ret = append(ret, los)
		common.Debug("================GetCurNodeLockOutInfo success return===================","key",key)
	    }(k,v)
	}
	LdbPubKeyData.RUnlock()
	wg.Wait()
	return ret, "", nil
}

type SignCurNodeInfo struct {
	Key       string
	Account   string
	PubKey   string
	MsgHash   []string
	MsgContext   []string
	KeyType   string
	GroupId   string
	Nonce     string
	ThresHold  string
	Mode      string
	TimeStamp string
}

func GetCurNodeSignInfo(geter_acc string) ([]*SignCurNodeInfo, string, error) {
	var ret []*SignCurNodeInfo
	var wg sync.WaitGroup
	LdbPubKeyData.RLock()
	for k, v := range LdbPubKeyData.Map {
	    wg.Add(1)
	    go func(key string,value interface{}) {
		defer wg.Done()

		vv,ok := value.(*AcceptSignData)
		if vv == nil || !ok {
		    return
		}

		common.Debug("================GetCurNodeSignInfo======================","vv",vv,"vv.Deal",vv.Deal,"vv.Status",vv.Status,"key",key)
		if vv.Deal == "true" || vv.Status == "Success" {
		    return
		}

		if vv.Status != "Pending" {
		    return
		}

		if !CheckAccept(vv.PubKey,vv.Mode,geter_acc) {
			return
		}
		
		los := &SignCurNodeInfo{Key: key, Account: vv.Account, PubKey:vv.PubKey, MsgHash:vv.MsgHash, MsgContext:vv.MsgContext, KeyType:vv.Keytype, GroupId: vv.GroupId, Nonce: vv.Nonce, ThresHold: vv.LimitNum, Mode: vv.Mode, TimeStamp: vv.TimeStamp}
		ret = append(ret, los)
		common.Debug("================GetCurNodeSignInfo success return=======================","key",key)
	    }(k,v)
	}
	LdbPubKeyData.RUnlock()
	wg.Wait()
	return ret, "", nil
}

type ReShareCurNodeInfo struct {
	Key       string
	PubKey   string
	GroupId   string
	TSGroupId   string
	ThresHold  string
	Account string
	Mode string
	TimeStamp string
}

func GetCurNodeReShareInfo() ([]*ReShareCurNodeInfo, string, error) {
    var ret []*ReShareCurNodeInfo
    var wg sync.WaitGroup
    LdbPubKeyData.RLock()
    for k, v := range LdbPubKeyData.Map {
	wg.Add(1)
	go func(key string,value interface{}) {
	    defer wg.Done()

	    vv,ok := value.(*AcceptReShareData)
	    if vv == nil || !ok {
		return
	    }

	    common.Debug("================GetCurNodeReShareInfo====================","vv",vv,"vv.Deal",vv.Deal,"vv.Status",vv.Status,"key",key)
	    if vv.Deal == "true" || vv.Status == "Success" {
		return
	    }

	    if vv.Status != "Pending" {
		return
	    }

	    los := &ReShareCurNodeInfo{Key: key, PubKey:vv.PubKey, GroupId:vv.GroupId, TSGroupId:vv.TSGroupId,ThresHold: vv.LimitNum, Account:vv.Account, Mode:vv.Mode, TimeStamp: vv.TimeStamp}
	    ret = append(ret, los)
	    common.Debug("================GetCurNodeReShareInfo success return============================","key",key)
	}(k,v)
    }
    LdbPubKeyData.RUnlock()
    wg.Wait()
    return ret, "", nil
}

type LockOutReply struct {
	Enode string
	Reply string
}

type LockOutReplys struct {
	Replys []LockOutReply
}

type TxDataLockOut struct {
    TxType string
    DcrmAddr string
    DcrmTo string
    Value string
    Cointype string
    GroupId string
    ThresHold string
    Mode string
    TimeStamp string
    Memo string
}

type TxDataReShare struct {
    TxType string
    PubKey string
    GroupId string
    TSGroupId string
    ThresHold string
    Account string
    Mode string
    Sigs string
    TimeStamp string
}

type TxDataSign struct {
    TxType string
    PubKey string
    MsgHash []string
    MsgContext []string
    Keytype string
    GroupId string
    ThresHold string
    Mode string
    TimeStamp string
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
	case *PubKeyData:

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

	return nil, fmt.Errorf("decode obj fail.")
}

///////

////compress
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

////uncompress
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

type TxDataReqAddr struct {
    TxType string
    GroupId string
    ThresHold string
    Mode string
    TimeStamp string
    Sigs string
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
		    common.Debug("===================== GetAllReplyFromGroup call CheckRaw,it is Rpc_SIGN ================")
		    key,_,_,_,_ := CheckRaw(mdss)
		    key2 := GetReqAddrKeyByOtherKey(key,rt)
		    exsit,da := GetValueFromPubKeyData(key2)
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
		exsit,da := GetValueFromPubKeyData(key)
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
	exsit,da := GetValueFromPubKeyData(key)
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

type NodeReply struct {
    Enode string
    Status string
    TimeStamp string
    Initiator string // "1"/"0"
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
	gp  := common.NewSafeMap(10)
	//gp := make(map[string][]PubKeyInfo)
	var wg sync.WaitGroup
	LdbPubKeyData.RLock()
	for k, v := range LdbPubKeyData.Map {
	    wg.Add(1)
	    go func(key string,value interface{}) {
		defer wg.Done()

		vv,ok := value.(*AcceptReqAddrData)
		if vv == nil || !ok {
		    return
		}

		if vv.Mode == "1" {
			if !strings.EqualFold(vv.Account,geter_acc) {
			    return
			}
		}

		if vv.Mode == "0" && !CheckAcc(cur_enode,geter_acc,vv.Sigs) {
		    return
		}

		dcrmpks, _ := hex.DecodeString(vv.PubKey)
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
	LdbPubKeyData.RUnlock()
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

