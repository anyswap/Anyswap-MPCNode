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
	"fmt"
	"strings"
	p2pdcrm "github.com/fsn-dev/dcrm-sdk/p2p/layer2"
	"strconv"
	"time"
	"github.com/fsn-dev/dcrm-sdk/crypto/dcrm/dev"
	"github.com/fsn-dev/dcrm-sdk/crypto/dcrm/cryptocoins"
	"github.com/fsn-dev/dcrm-sdk/crypto/dcrm/cryptocoins/types"
	cryptocoinsconfig "github.com/fsn-dev/dcrm-sdk/crypto/dcrm/cryptocoins/config"
	"encoding/json"
)

var (
    tmp2 string
    cur_enode string
    init_times = 0
)

func Start() {
    cryptocoinsconfig.Init()
    cryptocoins.Init()
}

type DcrmPubkeyRes struct {
    Account string
    PubKey string
    Address map[string]string
}

type DcrmAddrRes struct {
    Account string
    PubKey string
    DcrmAddr string
    Cointype string
}

func SendReqToGroup(msg string,rpctype string) (string,error) {
    if strings.EqualFold(rpctype,"rpc_req_dcrmaddr") {
	msgs := strings.Split(msg,":")
	if len(msgs) < 2 {
	    return "",fmt.Errorf("param error.")
	}

	coin := "ALL"
	if types.IsDefaultED25519(msgs[1]) {
	    coin = msgs[1]
	}

	ret,err := dev.SendReqToGroup(coin,rpctype)
	if err != nil || ret == "" {
	    return "",err
	}

	var m interface{}
	if !strings.EqualFold(msgs[1], "All") {
	    h := cryptocoins.NewCryptocoinHandler(msgs[1])
	    if h == nil {
		return "",fmt.Errorf("req addr fail.cointype is not supported.")
	    }

	    ctaddr, err := h.PublicKeyToAddress(ret)
	    if err != nil {
		return "",fmt.Errorf("req addr fail.")
	    }
	    
	    m = &DcrmAddrRes{Account:msgs[0],PubKey:ret,DcrmAddr:ctaddr,Cointype:msgs[1]}
	    b,_ := json.Marshal(m)
	    return string(b),nil
	}
	
	addrmp := make(map[string]string)
	for _, ct := range cryptocoins.Cointypes {
	    if strings.EqualFold(ct, "ALL") {
		continue
	    }

	    h := cryptocoins.NewCryptocoinHandler(ct)
	    if h == nil {
		continue
	    }
	    ctaddr, err := h.PublicKeyToAddress(ret)
	    if err != nil {
		fmt.Printf("============ generate address,error = %+v ==========\n", err.Error())
		continue
	    }
	    addrmp[ct] = ctaddr
	}

	m = &DcrmPubkeyRes{Account:msgs[0],PubKey:ret,Address:addrmp}
	b,_ := json.Marshal(m)
	return string(b),nil
    }
    
    ret,err := dev.SendReqToGroup(msg,rpctype)
    if err != nil || ret == "" {
	return "",err
    }

    return ret,nil
}

func init(){
	p2pdcrm.RegisterRecvCallback(Call)
	p2pdcrm.SdkProtocol_registerBroadcastInGroupCallback(dev.Call)
	p2pdcrm.SdkProtocol_registerSendToGroupCallback(dev.Dcrmcall)
	p2pdcrm.SdkProtocol_registerSendToGroupReturnCallback(dev.Dcrmcallret)
	p2pdcrm.RegisterCallback(dev.Call)

	dev.RegP2pGetGroupCallBack(p2pdcrm.SdkProtocol_getGroup)
	dev.RegP2pSendToGroupAllNodesCallBack(p2pdcrm.SdkProtocol_SendToGroupAllNodes)
	dev.RegP2pGetSelfEnodeCallBack(p2pdcrm.GetSelfID)
	dev.RegP2pBroadcastInGroupOthersCallBack(p2pdcrm.SdkProtocol_broadcastInGroupOthers)
	dev.RegP2pSendMsgToPeerCallBack(p2pdcrm.SendMsgToPeer)
	dev.RegP2pParseNodeCallBack(p2pdcrm.ParseNodeID)
	dev.RegDcrmGetEosAccountCallBack(GetEosAccount)
	dev.InitChan()
}

func Call(msg interface{}) {
	fmt.Println("===========dcrm.Call==============","msg",msg)
    s := msg.(string)
    SetUpMsgList(s)
}

var parts = make(map[int]string)
func receiveSplitKey(msg interface{}){
	fmt.Println("===========receiveSplitKey==============","msg",msg)
	cur_enode = p2pdcrm.GetSelfID()
	
	m := strings.Split(msg.(string),"|")
	if len(m) != 2 {
	    return
	}

	splitkey := m[1]

	head := strings.Split(splitkey, ":")[0]
	body := strings.Split(splitkey, ":")[1]
	if a := strings.Split(body, "#"); len(a) > 1 {
	    tmp2 = a[0]
	    body = a[1]
	}
	p, _ := strconv.Atoi(strings.Split(head, "dcrmslash")[0])
	total, _ := strconv.Atoi(strings.Split(head, "dcrmslash")[1])
	parts[p] = body

	if len(parts) == total {
		var c string = ""
		for i := 1; i <= total; i++ {
			c += parts[i]
		}
		 time.Sleep(time.Duration(2)*time.Second) //1000 == 1s
		////
		Init(m[0])
	}
}

func Init(groupId string) {
    out := "=============Init================" + " get group id = " + groupId
    fmt.Println(out)
    dev.InitDev(groupId)
}

func SetUpMsgList(msg string) {

    mm := strings.Split(msg,"dcrmslash")
    if len(mm) >= 2 {
	receiveSplitKey(msg)
	return
    }
}
//==========================================================

