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
	"os"
	"strconv"
	"os/signal"
	"net"
	"strings"
	"github.com/fsn-dev/dcrm-walletService/rpc"
	"github.com/fsn-dev/dcrm-walletService/internal/common"
	"github.com/fsn-dev/dcrm-walletService/crypto/dcrm"
)

func listenSignal(exit chan int) {
    sig := make(chan os.Signal)
    signal.Notify(sig)

    fmt.Println("============call listenSignal=============")
    for {
	<-sig
	exit <- 1
    }
}

type Service struct {}

// this will be called by dcrm_reqDcrmAddr
// raw: tx raw data
// model: "0"  self-group; "1" non self-group
//return pubkey and coins addr
func (this *Service) ReqDcrmAddr(raw string,model string) map[string]interface{} {   //函数名首字母必须大写
    common.Info("==========call rpc ReqDcrmAddr from web  ===========","raw = ",raw,"model = ",model)

    data := make(map[string]interface{})
    if raw == "" || model == "" || (model != "0" && model != "1") {
	data["result"] = ""
	return map[string]interface{}{
		"Status": "Error",
		"Tip": "parameter error",
		"Error": "parameter error",
		"Data": data,
	}
    }

    ret,tip,err := dcrm.ReqDcrmAddr(raw,model)
    common.Info("===========call rpc ReqDcrmAddr finish.","ret = ",ret,"tip = ",tip,"err = ",err,"","====================")
    if err != nil {
	data["result"] = ""
	return map[string]interface{}{
		"Status": "Error",
		"Tip": tip,
		"Error": err.Error(),
		"Data": data,
	}
    }

    data["result"] = ret
    return map[string]interface{}{
	    "Status": "Success",
	    "Tip": "",
	    "Error": "",
	    "Data": data,
    }
}

func (this *Service) AcceptReqAddr(raw string) map[string]interface{} {
    common.Info("==========call rpc AcceptReqAddr from web ==========","raw = ",raw)

    data := make(map[string]interface{})
    ret,tip,err := dcrm.AcceptReqAddr(raw)
    common.Info("==========finish call rpc AcceptReqAddr, ","ret = ",ret,"tip = ",tip,"err = ",err)
    if err != nil {
	data["result"] = ""
	return map[string]interface{}{
		"Status": "Error",
		"Tip": tip,
		"Error": err.Error(),
		"Data": data,
	}
    }

    data["result"] = ret
    return map[string]interface{}{
	    "Status": "Success",
	    "Tip": "",
	    "Error": "",
	    "Data": data,
    }
}

func (this *Service) AcceptLockOut(raw string) map[string]interface{} {
    common.Info("==========call rpc AcceptLockOut from web ==========","raw = ",raw)

    data := make(map[string]interface{})
    ret,tip,err := dcrm.AcceptLockOut(raw)
    common.Info("==========finish call rpc AcceptLockOut, ","ret = ",ret,"tip = ",tip,"err = ",err)
    if err != nil {
	data["result"] = ""
	return map[string]interface{}{
		"Status": "Error",
		"Tip": tip,
		"Error": err.Error(),
		"Data": data,
	}
    }

    data["result"] = ret
    return map[string]interface{}{
	    "Status": "Success",
	    "Tip": "",
	    "Error": "",
	    "Data": data,
    }
}

func (this *Service) LockOut(raw string) map[string]interface{} {
    common.Info("==========call rpc LockOut from web ===========")

    data := make(map[string]interface{})
    txhash,tip,err := dcrm.LockOut(raw)
    common.Info("==============finish call rpc LockOut,","txhash = ",txhash,"tip = ",tip,"err =",err,"","==============")
    if err != nil {
	data["result"] = ""
	return map[string]interface{}{
		"Status": "Error",
		"Tip": tip,
		"Error": err.Error(),
		"Data": data,
	}
    }

    data["result"] = txhash
    return map[string]interface{}{
	    "Status": "Success",
	    "Tip": "",
	    "Error": "",
	    "Data": data,
    }
}

func (this *Service) GetBalance(account string,cointype string,dcrmaddr string) map[string]interface{} {
    fmt.Println("==============GetBalance================")

    data := make(map[string]interface{})
    if account == "" || cointype == "" || dcrmaddr == "" {
	data["result"] = "0"
	return map[string]interface{}{
		"Status": "Success",
		"Tip": "parameter error,but return 0",
		"Error": "parameter error",
		"Data": data,
	}
    }

    ret,tip,err := dcrm.GetBalance(account,cointype,dcrmaddr)
    fmt.Println("==========GetBalance,ret =%s,tip =%s,err =%v ===========",ret,tip,err)

    if err != nil {
	data["result"] = "0" 
	return map[string]interface{}{
		"Status": "Success",
		"Tip": tip + ",but return 0",
		"Error": err.Error(),
		"Data": data,
	}
    }

    data["result"] = ret
    return map[string]interface{}{
	    "Status": "Success",
	    "Tip": "",
	    "Error": "",
	    "Data": data,
    }
}

func (this *Service) GetReqAddrNonce(account string) map[string]interface{} {
    common.Info("==============call rpc.GetReqAddrNonce from web================","account = ",account)

    data := make(map[string]interface{})
    if account == "" {
	data["result"] = "0"
	return map[string]interface{}{
		"Status": "Success",
		"Tip": "parameter error,but return 0",
		"Error": "parameter error",
		"Data": data,
	}
    }

    ret,tip,err := dcrm.GetReqAddrNonce(account)
    common.Info("==========call rpc.GetReqAddrNonce finish===========","account = ",account,"ret = ",ret,"tip = ",tip,"err = ",err)

    if err != nil {
	data["result"] = "0" 
	return map[string]interface{}{
		"Status": "Success",
		"Tip": tip + ",but return 0",
		"Error": err.Error(),
		"Data": data,
	}
    }

    data["result"] = ret
    return map[string]interface{}{
	    "Status": "Success",
	    "Tip": "",
	    "Error": "",
	    "Data": data,
    }
}

func (this *Service) GetLockOutNonce(account string,cointype string,dcrmaddr string) map[string]interface{} {
    common.Info("==============call rpc GetLockOutNonce from web================")

    data := make(map[string]interface{})
    if account == "" || cointype == "" || dcrmaddr == "" {
	data["result"] = "0"
	return map[string]interface{}{
		"Status": "Success",
		"Tip": "parameter error,but return 0",
		"Error": "parameter error",
		"Data": data,
	}
    }

    ret,tip,err := dcrm.GetLockOutNonce(account,cointype,dcrmaddr)
//    fmt.Println("==========GetLockOutNonce,ret =%s,tip =%s,err =%v ===========",ret,tip,err)

    if err != nil {
	data["result"] = "0" 
	return map[string]interface{}{
		"Status": "Success",
		"Tip": tip + ",but return 0",
		"Error": err.Error(),
		"Data": data,
	}
    }

    data["result"] = ret
    return map[string]interface{}{
	    "Status": "Success",
	    "Tip": "",
	    "Error": "",
	    "Data": data,
    }
}

func (this *Service) GetCurNodeReqAddrInfo(geter_acc string) map[string]interface{} {
    //common.Info("==============call rpc GetCurNodeReqAddrInfo from web ================","geter acc = ",geter_acc)

    data := make(map[string]interface{})
    s,tip,err := dcrm.GetCurNodeReqAddrInfo(geter_acc)
    //fmt.Println("==============rpc.GetCurNodeReqAddrInfo,geter acc =%s,ret =%s,tip =%s,err =%v================",geter_acc,s,tip,err)
    if err != nil {
	data["result"] = ""
	return map[string]interface{}{
		"Status": "Error",
		"Tip": tip,
		"Error": err.Error(),
		"Data": data,
	}
    }

    for k,v := range s {
	data[strconv.Itoa(k)] = v
    }

    return map[string]interface{}{
	    "Status": "Success",
	    "Tip": "",
	    "Error": "",
	    "Data": data,
    }
}

func (this *Service) GetCurNodeLockOutInfo(geter_acc string) map[string]interface{} {
    //common.Info("==============call rpc GetCurNodeLockOutInfo from web ================","geter acc = ",geter_acc)

    data := make(map[string]interface{})
    s,tip,err := dcrm.GetCurNodeLockOutInfo(geter_acc)
    //fmt.Println("==============rpc.GetCurNodeLockOutInfo,geter acc =%s,ret =%s,tip =%s,err =%v================",geter_acc,s,tip,err)
    if err != nil {
	data["result"] = ""
	return map[string]interface{}{
		"Status": "Error",
		"Tip": tip,
		"Error": err.Error(),
		"Data": data,
	}
    }

    for k,v := range s {
	data[strconv.Itoa(k)] = v
    }

    return map[string]interface{}{
	    "Status": "Success",
	    "Tip": "",
	    "Error": "",
	    "Data": data,
    }
}

func (this *Service) GetReqAddrStatus(key string) map[string]interface{} {
    //common.Info("==========call rpc GetReqAddrStatus from web ","key =",key,"","===============")

    data := make(map[string]interface{})
    ret,tip,err := dcrm.GetReqAddrStatus(key)
    //common.Info("==========finish call rpc GetReqAddrStatus,","key = ",key,"ret = ",ret,"tip = ",tip,"err = ",err,"","==========")
    if err != nil {
	data["result"] = ""
	return map[string]interface{}{
		"Status": "Error",
		"Tip": tip,
		"Error": err.Error(),
		"Data": data,
	}
    }

    data["result"] = ret
    return map[string]interface{}{
	    "Status": "Success",
	    "Tip": "",
	    "Error": "",
	    "Data": data,
    }
}

func (this *Service) GetLockOutStatus(key string) map[string]interface{} {
    //common.Info("==========call rpc GetLockOutStatus from web ","key =",key,"","===============")

    data := make(map[string]interface{})
    ret,tip,err := dcrm.GetLockOutStatus(key)
    //common.Info("==========finish call rpc GetLockOutStatus,","key = ",key,"ret = ",ret,"tip = ",tip,"err = ",err,"","==========")
    if err != nil {
	data["result"] = ""
	return map[string]interface{}{
		"Status": "Error",
		"Tip": tip,
		"Error": err.Error(),
		"Data": data,
	}
    }

    data["result"] = ret
    return map[string]interface{}{
	    "Status": "Success",
	    "Tip": "",
	    "Error": "",
	    "Data": data,
    }
}

var (
	rpcport  int
	endpoint string = "0.0.0.0"
	server *rpc.Server
	err      error
)

func RpcInit(port int) {
	rpcport = port
	go startRpcServer()
}

// splitAndTrim splits input separated by a comma
// and trims excessive white space from the substrings.
func splitAndTrim(input string) []string {
	result := strings.Split(input, ",")
	for i, r := range result {
		result[i] = strings.TrimSpace(r)
	}
	return result
}

func startRpcServer() error {
	go func() error {
	    server = rpc.NewServer()
	    service := new(Service)
	    if err := server.RegisterName("dcrm", service); err != nil {
		    panic(err)
	    }

	    // All APIs registered, start the HTTP listener
	    var (
		    listener net.Listener
		    err      error
	    )

	    endpoint = endpoint + ":" + strconv.Itoa(rpcport)
	    if listener, err = net.Listen("tcp", endpoint); err != nil {
		    panic(err)
	    }

	    /////////
	    /*
	    var (
		    extapiURL = "n/a"
		    ipcapiURL = "n/a"
	    )
	    rpcAPI := []rpc.API{
		    {
			    Namespace: "account",
			    Public:    true,
			    Service:   api,
			    Version:   "1.0"},
	    }
	    if c.Bool(utils.RPCEnabledFlag.Name) {

		    vhosts := splitAndTrim(c.GlobalString(utils.RPCVirtualHostsFlag.Name))
		    cors := splitAndTrim(c.GlobalString(utils.RPCCORSDomainFlag.Name))

		    // start http server
		    httpEndpoint := fmt.Sprintf("%s:%d", c.String(utils.RPCListenAddrFlag.Name), c.Int(rpcPortFlag.Name))
		    listener, _, err := rpc.StartHTTPEndpoint(httpEndpoint, rpcAPI, []string{"account"}, cors, vhosts, rpc.DefaultHTTPTimeouts)
		    if err != nil {
			    utils.Fatalf("Could not start RPC api: %v", err)
		    }
		    extapiURL = fmt.Sprintf("http://%s", httpEndpoint)
		    log.Info("HTTP endpoint opened", "url", extapiURL)

		    defer func() {
			    listener.Close()
			    log.Info("HTTP endpoint closed", "url", httpEndpoint)
		    }()

	    }
	    if !c.Bool(utils.IPCDisabledFlag.Name) {
		    if c.IsSet(utils.IPCPathFlag.Name) {
			    ipcapiURL = c.String(utils.IPCPathFlag.Name)
		    } else {
			    ipcapiURL = filepath.Join(configDir, "clef.ipc")
		    }

		    listener, _, err := rpc.StartIPCEndpoint(ipcapiURL, rpcAPI)
		    if err != nil {
			    utils.Fatalf("Could not start IPC api: %v", err)
		    }
		    log.Info("IPC endpoint opened", "url", ipcapiURL)
		    defer func() {
			    listener.Close()
			    log.Info("IPC endpoint closed", "url", ipcapiURL)
		    }()

	    }
	    */
	    /////////

	    vhosts := make([]string, 0)
	    cors := splitAndTrim("*")
	    go rpc.NewHTTPServer(cors, vhosts, rpc.DefaultHTTPTimeouts,server).Serve(listener)
	    rpcstring := "\n==================== RPC Service Start! url = " + fmt.Sprintf("http://%s", endpoint) + " =====================\n"
	    fmt.Println(rpcstring)

	    exit := make(chan int)
	    <-exit

	    server.Stop()

	    return nil
	}()

	return nil
}

//gid = "",get all pubkey of all gid
//gid != "",get all pubkey by gid
func (this *Service) GetAccounts(geter_acc,mode string) map[string]interface{} {
    common.Info("==========call rpc GetAccounts from web,","geter acc = ",geter_acc,"mode = ",mode,"","================")
    data := make(map[string]interface{})
    ret, tip, err := dcrm.GetAccounts(geter_acc,mode)
    common.Info("==========finish call rpc GetAccounts,","geter acc = ",geter_acc,"mode = ",mode,"ret = ",ret,"tip = ",tip,"err = ",err,"","============================")
    if err != nil {
	data["result"] = ""
	return map[string]interface{}{
		"Status": "Error",
		"Tip": tip,
		"Error": err.Error(),
		"Data": data,
	}
    }

    data["result"] = ret
    return map[string]interface{}{
	    "Status": "Success",
	    "Tip": "",
	    "Error": "",
	    "Data": data,
    }
}

func (this *Service) GetAccountsBalance(pubkey string,geter_acc string) map[string]interface{} {
	common.Info("==========call rpc GetAccountsBalance from web,","geter acc = ",geter_acc,"pubkey = ",pubkey,"","================")
	data := make(map[string]interface{})
	if pubkey == "" {
	    data["result"] = ""
	    return map[string]interface{}{
		    "Status": "Error",
		    "Tip": "param is empty",
		    "Error": "param is empty",
		    "Data": data,
	    }
	}

	ret, tip, err := dcrm.GetAccountsBalance(pubkey,geter_acc)
	common.Info("==========finish call rpc GetAccountsBalance,","geter acc = ",geter_acc,"ret = ",ret,"tip = ",tip,"err = ",err,"","============================")
	if err != nil {
	    data["result"] = ""
	    return map[string]interface{}{
		    "Status": "Error",
		    "Tip": tip,
		    "Error": err.Error(),
		    "Data": data,
	    }
	}

	data["result"] = ret
	return map[string]interface{}{
		"Status": "Success",
		"Tip": "",
		"Error": "",
		"Data": data,
	}
}


