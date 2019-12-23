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
	"github.com/fsn-dev/dcrm-walletService/crypto/dcrm"
)

func listenSignal(exit chan int) {
    sig := make(chan os.Signal)
    signal.Notify(sig)

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
    fmt.Println("==========dcrm_reqDcrmAddr,raw = %s,model = %s ===========",raw,model)

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
    fmt.Println("===========dcrm_reqDcrmAddr,ret = %s,tip =%s,err =%v===========",ret,tip,err)
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
    fmt.Println("==========dcrm_acceptReqAddr,raw =%s ===========",raw)

    data := make(map[string]interface{})
    ret,tip,err := dcrm.AcceptReqAddr(raw)
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
    fmt.Println("==========dcrm_acceptLockOut,raw =%s ===========",raw)

    data := make(map[string]interface{})
    ret,tip,err := dcrm.AcceptLockOut(raw)
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
    fmt.Println("==========dcrm_lockOut,raw =%s ===========",raw)

    data := make(map[string]interface{})
    txhash,tip,err := dcrm.LockOut(raw)
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
    fmt.Println("==============dcrm_getBalance================")

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
    fmt.Println("==============dcrm_getReqAddrNonce================")

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

func (this *Service) GetNonce(account string,cointype string,dcrmaddr string) map[string]interface{} {
    fmt.Println("==============dcrm_getNonce================")

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

    ret,tip,err := dcrm.GetNonce(account,cointype,dcrmaddr)

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

func (this *Service) GetCurNodeReqAddrInfo() map[string]interface{} {
    fmt.Println("==============dcrm_getCurNodeReqAddrInfo================")

    data := make(map[string]interface{})
    s,tip,err := dcrm.GetReqAddrReply()
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

func (this *Service) GetCurNodeLockOutInfo() map[string]interface{} {
    fmt.Println("==============dcrm_getCurNodeLockOutInfo================")

    data := make(map[string]interface{})
    s,tip,err := dcrm.GetLockOutReply()
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
    fmt.Println("==========dcrm_getReqAddrStatus,key = %s ===========",key)

    data := make(map[string]interface{})
    ret,tip,err := dcrm.GetReqAddrStatus(key)
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
    fmt.Println("==========dcrm_getLockOutStatus,key = %s ===========",key)

    data := make(map[string]interface{})
    ret,tip,err := dcrm.GetLockOutStatus(key)
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
func (this *Service) GetAccounts(gid,mode string) map[string]interface{} {
    fmt.Println("==========dcrm_getAccounts,gid = %s,mode = %s ===========",gid,mode)
    data := make(map[string]interface{})
    ret, tip, err := dcrm.GetAccounts(gid,mode)
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

func (this *Service) GetAccountsBalance(pubkey string) string {
	if pubkey == "" {
		return packageResult(FAIL, "args account is null", "", "")
	}
	stat := SUCCESS
	ret, tip, err := dcrm.GetPubAccountBalance(pubkey)
	if err != nil {
		stat = FAIL
	}
	fmt.Printf("==== GetAccountsBalance() ====, ret: %v\n", ret)
	return packageResult(stat, tip, "", ret)
}

