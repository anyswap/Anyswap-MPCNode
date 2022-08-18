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

	//"github.com/anyswap/Anyswap-MPCNode/accounts"
	//"github.com/anyswap/Anyswap-MPCNode/accounts/keystore"
	//"github.com/anyswap/Anyswap-MPCNode/common"
	//"github.com/anyswap/Anyswap-MPCNode/common/fdlimit"
	//"github.com/anyswap/Anyswap-MPCNode/consensus"
	//"github.com/anyswap/Anyswap-MPCNode/consensus/clique"
	//"github.com/anyswap/Anyswap-MPCNode/consensus/ethash"
	//"github.com/anyswap/Anyswap-MPCNode/core"
	//"github.com/anyswap/Anyswap-MPCNode/core/rawdb"
	//"github.com/anyswap/Anyswap-MPCNode/core/vm"
	//"github.com/anyswap/Anyswap-MPCNode/crypto"
	//"github.com/anyswap/Anyswap-MPCNode/eth"
	//"github.com/anyswap/Anyswap-MPCNode/eth/downloader"
	//"github.com/anyswap/Anyswap-MPCNode/eth/gasprice"
	//"github.com/anyswap/Anyswap-MPCNode/ethdb"
	//"github.com/anyswap/Anyswap-MPCNode/ethstats"
	//"github.com/anyswap/Anyswap-MPCNode/graphql"
	//"github.com/anyswap/Anyswap-MPCNode/internal/ethapi"
	//"github.com/anyswap/Anyswap-MPCNode/internal/flags"
	//"github.com/anyswap/Anyswap-MPCNode/les"
	//"github.com/anyswap/Anyswap-MPCNode/log"
	//"github.com/anyswap/Anyswap-MPCNode/metrics"
	//"github.com/anyswap/Anyswap-MPCNode/metrics/exp"
	//"github.com/anyswap/Anyswap-MPCNode/metrics/influxdb"
	//"github.com/anyswap/Anyswap-MPCNode/miner"
	//"github.com/anyswap/Anyswap-MPCNode/node"
	//"github.com/anyswap/Anyswap-MPCNode/p2p"
	//"github.com/anyswap/Anyswap-MPCNode/p2p/discv5"
	//"github.com/anyswap/Anyswap-MPCNode/p2p/enode"
	//"github.com/anyswap/Anyswap-MPCNode/p2p/nat"
	//"github.com/anyswap/Anyswap-MPCNode/p2p/netutil"
	//"github.com/anyswap/Anyswap-MPCNode/params"
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
