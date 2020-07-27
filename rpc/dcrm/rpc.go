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
	"net"
	"os"
	"os/signal"
	"strconv"
	"strings"

	"github.com/fsn-dev/dcrm-walletService/dcrm"
	"github.com/fsn-dev/dcrm-walletService/internal/common"
	"github.com/fsn-dev/dcrm-walletService/rpc"
)

func listenSignal(exit chan int) {
	sig := make(chan os.Signal)
	signal.Notify(sig)

	for {
		<-sig
		exit <- 1
	}
}

type Service struct{}

// this will be called by dcrm_reqDcrmAddr
// raw: tx raw data
//return pubkey and coins addr
func (this *Service) ReqDcrmAddr(raw string) map[string]interface{} { //函数名首字母必须大写
	common.Debug("===============ReqDcrmAddr================","raw",raw)

	data := make(map[string]interface{})
	if raw == "" {
		data["result"] = ""
		return map[string]interface{}{
			"Status": "Error",
			"Tip":    "parameter error",
			"Error":  "parameter error",
			"Data":   data,
		}
	}

	ret, tip, err := dcrm.ReqDcrmAddr(raw)
	common.Debug("=================ReqDcrmAddr==================","ret",ret,"tip",tip,"err",err,"raw",raw)
	if err != nil {
		data["result"] = ""
		return map[string]interface{}{
			"Status": "Error",
			"Tip":    tip,
			"Error":  err.Error(),
			"Data":   data,
		}
	}

	data["result"] = ret
	return map[string]interface{}{
		"Status": "Success",
		"Tip":    "",
		"Error":  "",
		"Data":   data,
	}
}

func (this *Service) AcceptReqAddr(raw string) map[string]interface{} {
	//fmt.Printf("%v ==========call rpc AcceptReqAddr from web,raw = %v==========\n", common.CurrentTime(), raw)

	data := make(map[string]interface{})
	ret, tip, err := dcrm.RpcAcceptReqAddr(raw)
	//fmt.Printf("%v ==========call rpc AcceptReqAddr from web,ret = %v,tip = %v,err = %v,raw = %v==========\n", common.CurrentTime(), ret, tip, err, raw)
	if err != nil {
		data["result"] = "Failure"
		return map[string]interface{}{
			"Status": "Error",
			"Tip":    tip,
			"Error":  err.Error(),
			"Data":   data,
		}
	}

	data["result"] = ret
	return map[string]interface{}{
		"Status": "Success",
		"Tip":    "",
		"Error":  "",
		"Data":   data,
	}
}

func (this *Service) AcceptLockOut(raw string) map[string]interface{} {
	//fmt.Printf("%v ==========call rpc AcceptLockOut from web,raw = %v==========\n", common.CurrentTime(), raw)

	data := make(map[string]interface{})
	ret, tip, err := dcrm.RpcAcceptLockOut(raw)
	//fmt.Printf("%v ==========call rpc AcceptLockOut from web,ret = %v,tip = %v,err = %v,raw = %v==========\n", common.CurrentTime(), ret, tip, err, raw)
	if err != nil {
		data["result"] = "Failure"
		return map[string]interface{}{
			"Status": "Error",
			"Tip":    tip,
			"Error":  err.Error(),
			"Data":   data,
		}
	}

	data["result"] = ret
	return map[string]interface{}{
		"Status": "Success",
		"Tip":    "",
		"Error":  "",
		"Data":   data,
	}
}

func (this *Service) AcceptSign(raw string) map[string]interface{} {
	//fmt.Printf("%v ==========call rpc AcceptSign from web,raw = %v==========\n", common.CurrentTime(), raw)

	data := make(map[string]interface{})
	ret, tip, err := dcrm.RpcAcceptSign(raw)
	//fmt.Printf("%v ==========call rpc AcceptSign from web,ret = %v,tip = %v,err = %v,raw = %v==========\n", common.CurrentTime(), ret, tip, err, raw)
	if err != nil {
		data["result"] = "Failure"
		return map[string]interface{}{
			"Status": "Error",
			"Tip":    tip,
			"Error":  err.Error(),
			"Data":   data,
		}
	}

	data["result"] = ret
	return map[string]interface{}{
		"Status": "Success",
		"Tip":    "",
		"Error":  "",
		"Data":   data,
	}
}

func (this *Service) LockOut(raw string) map[string]interface{} {
	//fmt.Printf("%v ==========call rpc LockOut from web,raw = %v ===========\n", common.CurrentTime(), raw)

	data := make(map[string]interface{})
	txhash, tip, err := dcrm.LockOut(raw)
	//fmt.Printf("%v ==========finish call rpc LockOut from web,txhash = %v,err = %v,raw = %v ===========\n", common.CurrentTime(), txhash, err, raw)
	if err != nil {
		data["result"] = ""
		return map[string]interface{}{
			"Status": "Error",
			"Tip":    tip,
			"Error":  err.Error(),
			"Data":   data,
		}
	}

	data["result"] = txhash
	return map[string]interface{}{
		"Status": "Success",
		"Tip":    "",
		"Error":  "",
		"Data":   data,
	}
}

func (this *Service) Sign(raw string) map[string]interface{} {
	common.Debug("===================Sign=====================","raw",raw)

	data := make(map[string]interface{})
	key, tip, err := dcrm.Sign(raw)
	common.Debug("===================Sign=====================","key",key,"err",err,"raw",raw)
	if err != nil {
		data["result"] = ""
		return map[string]interface{}{
			"Status": "Error",
			"Tip":    tip,
			"Error":  err.Error(),
			"Data":   data,
		}
	}

	data["result"] = key 
	return map[string]interface{}{
		"Status": "Success",
		"Tip":    "",
		"Error":  "",
		"Data":   data,
	}
}

func (this *Service) ReShare(raw string) map[string]interface{} {
	common.Debug("===================ReShare=====================","raw",raw)

	data := make(map[string]interface{})
	key, tip, err := dcrm.ReShare(raw)
	common.Debug("===================Sign=====================","key",key,"err",err,"raw",raw)
	if err != nil {
		data["result"] = ""
		return map[string]interface{}{
			"Status": "Error",
			"Tip":    tip,
			"Error":  err.Error(),
			"Data":   data,
		}
	}

	data["result"] = key
	return map[string]interface{}{
		"Status": "Success",
		"Tip":    "",
		"Error":  "",
		"Data":   data,
	}
}

func (this *Service) GetReShareNonce(account string) map[string]interface{} {
	data := make(map[string]interface{})
	if account == "" {
		data["result"] = "0"
		return map[string]interface{}{
			"Status": "Success",
			"Tip":    "parameter error,but return 0",
			"Error":  "parameter error",
			"Data":   data,
		}
	}

	ret, tip, err := dcrm.GetReShareNonce(account)
	if err != nil {
		data["result"] = "0"
		return map[string]interface{}{
			"Status": "Success",
			"Tip":    tip + ",but return 0",
			"Error":  err.Error(),
			"Data":   data,
		}
	}

	data["result"] = ret
	return map[string]interface{}{
		"Status": "Success",
		"Tip":    "",
		"Error":  "",
		"Data":   data,
	}
}

func (this *Service) AcceptReShare(raw string) map[string]interface{} {
	//fmt.Printf("%v ==========call rpc AcceptReShare from web,raw = %v==========\n", common.CurrentTime(), raw)

	data := make(map[string]interface{})
	ret, tip, err := dcrm.RpcAcceptReShare(raw)
	//fmt.Printf("%v ==========call rpc AcceptReShare from web,ret = %v,tip = %v,err = %v,raw = %v==========\n", common.CurrentTime(), ret, tip, err, raw)
	if err != nil {
		data["result"] = "Failure"
		return map[string]interface{}{
			"Status": "Error",
			"Tip":    tip,
			"Error":  err.Error(),
			"Data":   data,
		}
	}

	data["result"] = ret
	return map[string]interface{}{
		"Status": "Success",
		"Tip":    "",
		"Error":  "",
		"Data":   data,
	}
}

func (this *Service) GetCurNodeReShareInfo() map[string]interface{} {
	s, tip, err := dcrm.GetCurNodeReShareInfo()
	//fmt.Printf("%v ==============finish call rpc GetCurNodeReShareInfo ,ret = %v,err = %v ================\n", common.CurrentTime(), s, err)
	if err != nil {
		return map[string]interface{}{
			"Status": "Error",
			"Tip":    tip,
			"Error":  err.Error(),
			"Data":   "",
		}
	}

	return map[string]interface{}{
		"Status": "Success",
		"Tip":    "",
		"Error":  "",
		"Data":   s,
	}
}

func (this *Service) GetReShareStatus(key string) map[string]interface{} {
	//fmt.Printf("%v ==============call rpc GetReShareStatus from web, key = %v ================\n", common.CurrentTime(), key)
	data := make(map[string]interface{})
	ret, tip, err := dcrm.GetReShareStatus(key)
	//fmt.Printf("%v ==============finish call rpc GetReShareStatus ,ret = %v,err = %v,key = %v ================\n", common.CurrentTime(), ret, err, key)
	if err != nil {
		data["result"] = ""
		return map[string]interface{}{
			"Status": "Error",
			"Tip":    tip,
			"Error":  err.Error(),
			"Data":   data,
		}
	}

	data["result"] = ret
	return map[string]interface{}{
		"Status": "Success",
		"Tip":    "",
		"Error":  "",
		"Data":   data,
	}
}

func (this *Service) GetBalance(account string, cointype string, dcrmaddr string) map[string]interface{} {
	//fmt.Printf("%v ==========call rpc GetBalance from web,account = %v,cointype = %v,dcrm from = %v ===========\n", common.CurrentTime(), account, cointype, dcrmaddr)

	data := make(map[string]interface{})
	if account == "" || cointype == "" || dcrmaddr == "" {
		data["result"] = "0"
		return map[string]interface{}{
			"Status": "Success",
			"Tip":    "parameter error,but return 0",
			"Error":  "parameter error",
			"Data":   data,
		}
	}

	ret, tip, err := dcrm.GetBalance(account, cointype, dcrmaddr)
	//fmt.Printf("%v ==========finish call rpc GetBalance ,balance = %v,err = %v,account = %v,cointype  = %v,dcrm from = %v ===========\n", common.CurrentTime(), ret, err, account, cointype, dcrmaddr)

	if err != nil {
		data["result"] = "0"
		return map[string]interface{}{
			"Status": "Success",
			"Tip":    tip + ",but return 0",
			"Error":  err.Error(),
			"Data":   data,
		}
	}

	data["result"] = ret
	return map[string]interface{}{
		"Status": "Success",
		"Tip":    "",
		"Error":  "",
		"Data":   data,
	}
}

func (this *Service) GetReqAddrNonce(account string) map[string]interface{} {
	//fmt.Println("%v =========call rpc.GetReqAddrNonce from web,account = %v =================", common.CurrentTime(), account)

	data := make(map[string]interface{})
	if account == "" {
		data["result"] = "0"
		return map[string]interface{}{
			"Status": "Success",
			"Tip":    "parameter error,but return 0",
			"Error":  "parameter error",
			"Data":   data,
		}
	}

	ret, tip, err := dcrm.GetReqAddrNonce(account)
	//fmt.Println("%v =========call rpc.GetReqAddrNonce finish,account = %v,ret = %v,tip = %v,err = %v =================", common.CurrentTime(), account, ret, tip, err)

	if err != nil {
		data["result"] = "0"
		return map[string]interface{}{
			"Status": "Success",
			"Tip":    tip + ",but return 0",
			"Error":  err.Error(),
			"Data":   data,
		}
	}

	data["result"] = ret
	return map[string]interface{}{
		"Status": "Success",
		"Tip":    "",
		"Error":  "",
		"Data":   data,
	}
}

func (this *Service) GetLockOutNonce(account string) map[string]interface{} {

	data := make(map[string]interface{})
	if account == "" {
		data["result"] = "0"
		return map[string]interface{}{
			"Status": "Success",
			"Tip":    "parameter error,but return 0",
			"Error":  "parameter error",
			"Data":   data,
		}
	}

	ret, tip, err := dcrm.GetLockOutNonce(account)
	if err != nil {
		data["result"] = "0"
		return map[string]interface{}{
			"Status": "Success",
			"Tip":    tip + ",but return 0",
			"Error":  err.Error(),
			"Data":   data,
		}
	}

	data["result"] = ret
	return map[string]interface{}{
		"Status": "Success",
		"Tip":    "",
		"Error":  "",
		"Data":   data,
	}
}

func (this *Service) GetSignNonce(account string) map[string]interface{} {
	data := make(map[string]interface{})
	if account == "" {
		data["result"] = "0"
		return map[string]interface{}{
			"Status": "Success",
			"Tip":    "parameter error,but return 0",
			"Error":  "parameter error",
			"Data":   data,
		}
	}

	ret, tip, err := dcrm.GetSignNonce(account)
	if err != nil {
		data["result"] = "0"
		return map[string]interface{}{
			"Status": "Success",
			"Tip":    tip + ",but return 0",
			"Error":  err.Error(),
			"Data":   data,
		}
	}

	data["result"] = ret
	return map[string]interface{}{
		"Status": "Success",
		"Tip":    "",
		"Error":  "",
		"Data":   data,
	}
}

func (this *Service) GetCurNodeReqAddrInfo(account string) map[string]interface{} {
	common.Debug("==================GetCurNodeReqAddrInfo====================","account",account)

	s, tip, err := dcrm.GetCurNodeReqAddrInfo(account)
	common.Debug("==================GetCurNodeReqAddrInfo====================","account",account,"ret",s,"err",err)
	if err != nil {
		return map[string]interface{}{
			"Status": "Error",
			"Tip":    tip,
			"Error":  err.Error(),
			"Data":   "",
		}
	}

	return map[string]interface{}{
		"Status": "Success",
		"Tip":    "",
		"Error":  "",
		"Data":   s,
	}
}

func (this *Service) GetCurNodeLockOutInfo(account string) map[string]interface{} {
	common.Debug("==================GetCurNodeLockOutInfo====================","account",account)

	s, tip, err := dcrm.GetCurNodeLockOutInfo(account)
	common.Debug("==================GetCurNodeLockOutInfo====================","account",account,"ret",s,"err",err)
	if err != nil {
		return map[string]interface{}{
			"Status": "Error",
			"Tip":    tip,
			"Error":  err.Error(),
			"Data":   "",
		}
	}

	return map[string]interface{}{
		"Status": "Success",
		"Tip":    "",
		"Error":  "",
		"Data":   s,
	}
}

func (this *Service) GetCurNodeSignInfo(account string) map[string]interface{} {
	common.Debug("==================GetCurNodeSignInfo====================","account",account)

	s, tip, err := dcrm.GetCurNodeSignInfo(account)
	common.Debug("==================GetCurNodeSignInfo====================","account",account,"ret",s,"err",err)
	if err != nil {
		return map[string]interface{}{
			"Status": "Error",
			"Tip":    tip,
			"Error":  err.Error(),
			"Data":   "",
		}
	}

	return map[string]interface{}{
		"Status": "Success",
		"Tip":    "",
		"Error":  "",
		"Data":   s,
	}
}

func (this *Service) GetReqAddrStatus(key string) map[string]interface{} {
	common.Debug("==================GetReqAddrStatus====================","key",key)

	data := make(map[string]interface{})
	ret, tip, err := dcrm.GetReqAddrStatus(key)
	common.Debug("==================GetReqAddrStatus====================","key",key,"ret",ret,"err",err)
	if err != nil {
		data["result"] = ""
		return map[string]interface{}{
			"Status": "Error",
			"Tip":    tip,
			"Error":  err.Error(),
			"Data":   data,
		}
	}

	data["result"] = ret
	return map[string]interface{}{
		"Status": "Success",
		"Tip":    "",
		"Error":  "",
		"Data":   data,
	}
}

func (this *Service) GetLockOutStatus(key string) map[string]interface{} {
	data := make(map[string]interface{})
	ret, tip, err := dcrm.GetLockOutStatus(key)
	if err != nil {
		data["result"] = ""
		return map[string]interface{}{
			"Status": "Error",
			"Tip":    tip,
			"Error":  err.Error(),
			"Data":   data,
		}
	}

	data["result"] = ret
	return map[string]interface{}{
		"Status": "Success",
		"Tip":    "",
		"Error":  "",
		"Data":   data,
	}
}

func (this *Service) GetSignStatus(key string) map[string]interface{} {
	common.Debug("==================GetSignStatus====================","key",key)
	data := make(map[string]interface{})
	ret, tip, err := dcrm.GetSignStatus(key)
	common.Debug("==================GetSignStatus====================","key",key,"ret",ret,"err",err)
	if err != nil {
		data["result"] = ""
		return map[string]interface{}{
			"Status": "Error",
			"Tip":    tip,
			"Error":  err.Error(),
			"Data":   data,
		}
	}

	data["result"] = ret
	return map[string]interface{}{
		"Status": "Success",
		"Tip":    "",
		"Error":  "",
		"Data":   data,
	}
}

func (this *Service) GetDcrmAddr(pubkey string) map[string]interface{} {
	data := make(map[string]interface{})
	ret, tip, err := dcrm.GetDcrmAddr(pubkey)
	if err != nil {
	    data["result"] = ""
	    return map[string]interface{}{
		    "Status": "Error",
		    "Tip":    tip,
		    "Error":  err.Error(),
		    "Data":   data,
	    }
	}

	data["result"] = ret
	return map[string]interface{}{
		"Status": "Success",
		"Tip":    "",
		"Error":  "",
		"Data":   data,
	}
}

var (
	rpcport  int
	endpoint string = "0.0.0.0"
	server   *rpc.Server
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
		go rpc.NewHTTPServer(cors, vhosts, rpc.DefaultHTTPTimeouts, server).Serve(listener)
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
func (this *Service) GetAccounts(account, mode string) map[string]interface{} {
	fmt.Printf("%v ==========call rpc GetAccounts from web, account = %v, mode = %v ================\n", common.CurrentTime(), account, mode)
	data := make(map[string]interface{})
	ret, tip, err := dcrm.GetAccounts(account, mode)
	fmt.Printf("%v ==========finish call rpc GetAccounts ,ret = %v,err = %v,account = %v, mode = %v ================\n", common.CurrentTime(), ret, err, account, mode)
	if err != nil {
		data["result"] = ""
		return map[string]interface{}{
			"Status": "Error",
			"Tip":    tip,
			"Error":  err.Error(),
			"Data":   data,
		}
	}

	data["result"] = ret
	return map[string]interface{}{
		"Status": "Success",
		"Tip":    "",
		"Error":  "",
		"Data":   data,
	}
}

func (this *Service) GetAccountsBalance(pubkey string, account string) map[string]interface{} {
	fmt.Printf("%v ==========call rpc GetAccountsBalance from web, account = %v, pubkey = %v,=============\n", common.CurrentTime(), account, pubkey)
	data := make(map[string]interface{})
	if pubkey == "" {
		data["result"] = ""
		return map[string]interface{}{
			"Status": "Error",
			"Tip":    "param is empty",
			"Error":  "param is empty",
			"Data":   data,
		}
	}

	ret, tip, err := dcrm.GetAccountsBalance(pubkey, account)
	fmt.Printf("%v ==========finish call rpc GetAccountsBalance from web, ret = %v,err = %v,account = %v, pubkey = %v,=============\n", common.CurrentTime(), ret, err, account, pubkey)
	if err != nil {
		data["result"] = ""
		return map[string]interface{}{
			"Status": "Error",
			"Tip":    tip,
			"Error":  err.Error(),
			"Data":   data,
		}
	}

	data["result"] = ret
	return map[string]interface{}{
		"Status": "Success",
		"Tip":    "",
		"Error":  "",
		"Data":   data,
	}
}
