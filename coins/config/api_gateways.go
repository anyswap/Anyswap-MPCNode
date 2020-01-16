/*
 *  Copyright (C) 2018-2019  Fusion Foundation Ltd. All rights reserved.
 *  Copyright (C) 2018-2019  gaozhengxin@fusion.org
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

// 提供api的节点地址
package config

import (
	"github.com/BurntSushi/toml"
	"io"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"runtime"
	"github.com/astaxie/beego/logs"
	"encoding/json"
)

type SimpleApiConfig struct {
	ApiAddress string
}

type RpcClientConfig struct {
	ElectrsAddress string
	Host string
	Port int
	User string
	Passwd string
	Usessl bool
}

type EosConfig struct {
	Nodeos string
	ChainID string
	BalanceTracker string
}

type ApiGatewayConfigs struct {
	RPCCLIENT_TIMEOUT int
	CosmosGateway *SimpleApiConfig
	TronGateway *SimpleApiConfig
	BitcoinGateway *RpcClientConfig
	OmniGateway *RpcClientConfig
	BitcoincashGateway *RpcClientConfig
	EthereumGateway *SimpleApiConfig
	EosGateway *EosConfig
	EvtGateway *SimpleApiConfig
	RippleGateway *SimpleApiConfig
	FusionGateway *SimpleApiConfig
}

var ApiGateways *ApiGatewayConfigs

const RPCCLIENT_TIMEOUT = 30

var datadir string

func SetDatadir(data string) {
	datadir = data
}

var Loaded bool = false

/*func init() {
	if err := LoadApiGateways(); err != nil {
		log.Error(err.Error())
	}
}*/

func Init () {
    err := LoadApiGateways()
    if err != nil {
	    fmt.Println(err.Error())
    }
}

func PrintLogToFile() {
    config:=make(map[string]interface{})
    config["fileName"]="/work/logcoolect.log" 
    //输出文件路径,不存在  默认创建
    config["level"]=logs.LevelDebug
    //设置日志级别
    configStr,err:=json.Marshal(config)
    if err != nil {
	    panic(err)
	    return
    }

    logs.SetLogger("file",string(configStr))
}

func LoadApiGateways () error {
	if datadir == "" {
		datadir = DefaultDataDir()
	}
	PrintLogToFile()
	logs.Info("!!!!!!!!LoadApiGateways!!!!!!!!", "config dir", datadir)
	if ApiGateways == nil {
		ApiGateways = new(ApiGatewayConfigs)
	}
	logs.Debug("========LoadApiGateways===========","ApiGateways",ApiGateways)

	configfilepath := filepath.Join(datadir, "gateways.toml")

	logs.Debug("========LoadApiGateways===========","configfilepath",configfilepath)

	if exists, _ := PathExists(configfilepath); exists {
		logs.Debug("========LoadApiGateways,exist===========")
		_, err := toml.DecodeFile(configfilepath, ApiGateways)
		if err == nil {
			logs.Debug("========LoadApiGateways,toml decodefile===========","ApiGateways",ApiGateways)
			Loaded = true
		}
		logs.Debug("========LoadApiGateways,toml decodefile===========","ApiGateways",ApiGateways,"err",err)
		return err
	} else {
		toml.Decode(defaultConfig, ApiGateways)
		logs.Debug("========LoadApiGateways,toml decode===========","ApiGateways",ApiGateways,"defaultConfig",defaultConfig)
		f, e1 := os.Create(configfilepath)
		if f == nil {
			logs.Debug("cannot create config file.","error",e1)
			return nil
		}
		_, e2 := io.WriteString(f, defaultConfig)
		if e2 != nil {
			logs.Debug("write config file error.", "error", e2)
			return nil
		}
		Loaded = true
	}

	return nil
}

func PathExists(path string) (bool, error) {
	_, err := os.Stat(path)
	if err == nil {
		return true, nil
	}
	if os.IsNotExist(err) {
		return false, nil
	}
	return false, err
}

// DefaultDataDir is the default data directory to use for the databases and other
// persistence requirements.
func DefaultDataDir() string {
	// Try to place the data folder in the user's home dir
	home := homeDir()
	if home != "" {
		if runtime.GOOS == "darwin" {
			return filepath.Join(home, "Library", "dcrm-walletservice")
		} else if runtime.GOOS == "windows" {
			return filepath.Join(home, "AppData", "Roaming", "dcrm-walletservice")
		} else {
			return filepath.Join(home, ".dcrm-walletservice")
		}
	}
	// As we cannot guess a stable location, return empty and handle later
	return ""
}

func homeDir() string {
	if home := os.Getenv("HOME"); home != "" {
		return home
	}
	if usr, err := user.Current(); err == nil {
		return usr.HomeDir
	}
	return ""
}

