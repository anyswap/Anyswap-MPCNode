package utils

import (
	//"crypto/ecdsa"
	//"fmt"
	//"io"
	//"io/ioutil"
	//"math/big"
	//"os"
	//"path/filepath"
	//"strconv"
	//"strings"
	//"text/tabwriter"
	//"text/template"
	//"time"

	//"github.com/fsn-dev/dcrm-walletService/accounts"
	//"github.com/fsn-dev/dcrm-walletService/accounts/keystore"
	//"github.com/fsn-dev/dcrm-walletService/common"
	//"github.com/fsn-dev/dcrm-walletService/common/fdlimit"
	//"github.com/fsn-dev/dcrm-walletService/consensus"
	//"github.com/fsn-dev/dcrm-walletService/consensus/clique"
	//"github.com/fsn-dev/dcrm-walletService/consensus/ethash"
	//"github.com/fsn-dev/dcrm-walletService/core"
	//"github.com/fsn-dev/dcrm-walletService/core/rawdb"
	//"github.com/fsn-dev/dcrm-walletService/core/vm"
	//"github.com/fsn-dev/dcrm-walletService/crypto"
	//"github.com/fsn-dev/dcrm-walletService/eth"
	//"github.com/fsn-dev/dcrm-walletService/eth/downloader"
	//"github.com/fsn-dev/dcrm-walletService/eth/gasprice"
	//"github.com/fsn-dev/dcrm-walletService/ethdb"
	//"github.com/fsn-dev/dcrm-walletService/ethstats"
	//"github.com/fsn-dev/dcrm-walletService/graphql"
	//"github.com/fsn-dev/dcrm-walletService/internal/ethapi"
	//"github.com/fsn-dev/dcrm-walletService/internal/flags"
	//"github.com/fsn-dev/dcrm-walletService/les"
	//"github.com/fsn-dev/dcrm-walletService/log"
	//"github.com/fsn-dev/dcrm-walletService/metrics"
	//"github.com/fsn-dev/dcrm-walletService/metrics/exp"
	//"github.com/fsn-dev/dcrm-walletService/metrics/influxdb"
	//"github.com/fsn-dev/dcrm-walletService/miner"
	//"github.com/fsn-dev/dcrm-walletService/node"
	//"github.com/fsn-dev/dcrm-walletService/p2p"
	//"github.com/fsn-dev/dcrm-walletService/p2p/discv5"
	//"github.com/fsn-dev/dcrm-walletService/p2p/enode"
	//"github.com/fsn-dev/dcrm-walletService/p2p/nat"
	//"github.com/fsn-dev/dcrm-walletService/p2p/netutil"
	//"github.com/fsn-dev/dcrm-walletService/params"
	//pcsclite "github.com/gballet/go-libpcsclite"
	cli "gopkg.in/urfave/cli.v1"
)

// MigrateFlags sets the global flag from a local flag when it's set.
// This is a temporary function used for migrating old command/flags to the
// new format.
//
// e.g. geth account new --keystore /tmp/mykeystore --lightkdf
//
// is equivalent after calling this method with:
//
// geth --keystore /tmp/mykeystore --lightkdf account new
//
// This allows the use of the existing configuration functionality.
// When all flags are migrated this function can be removed and the existing
// configuration functionality must be changed that is uses local flags
func MigrateFlags(action func(ctx *cli.Context) error) func(*cli.Context) error {
	return func(ctx *cli.Context) error {
		for _, name := range ctx.FlagNames() {
			if ctx.IsSet(name) {
				ctx.GlobalSet(name, ctx.String(name))
			}
		}
		return action(ctx)
	}
}
