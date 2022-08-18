module github.com/anyswap/Anyswap-MPCNode

go 1.13

require (
	github.com/BurntSushi/toml v0.3.1
	github.com/Djarvur/go-err113 v0.1.0 // indirect
	github.com/agl/ed25519 v0.0.0-20170116200512-5312a6153412
	github.com/aristanetworks/goarista v0.0.0-20191206003309-5d8d36c240c9
	github.com/astaxie/beego v1.12.0
	github.com/binance-chain/go-sdk v1.2.1
	github.com/binance-chain/ledger-cosmos-go v0.9.9 // indirect
	github.com/bombsimon/wsl/v3 v3.1.0 // indirect
	github.com/btcsuite/btcd v0.20.1-beta
	github.com/btcsuite/btcutil v0.0.0-20191219182022-e17c9730c422
	github.com/btcsuite/btcwallet/wallet/txauthor v1.0.0
	github.com/btcsuite/btcwallet/wallet/txrules v1.0.0
	github.com/cosmos/cosmos-sdk v0.37.5
	github.com/cosmos/ledger-cosmos-go v0.11.1 // indirect
	github.com/davecgh/go-spew v1.1.1
	github.com/deckarep/golang-set v1.7.1
	github.com/docker/docker v1.13.1
	github.com/eoscanada/eos-go v0.8.16
	github.com/ethereum/go-ethereum v1.9.14
	github.com/fatih/color v1.9.0 // indirect
	github.com/fsn-dev/cryptoCoins v0.0.0-20200529023326-829372e1fe6e
	github.com/fsnotify/fsnotify v1.4.9 // indirect
	github.com/go-critic/go-critic v0.4.3 // indirect
	github.com/go-logfmt/logfmt v0.5.0 // indirect
	github.com/go-toolsmith/typep v1.0.2 // indirect
	github.com/golang/snappy v0.0.1
	github.com/golangci/gocyclo v0.0.0-20180528144436-0a533e8fa43d // indirect
	github.com/golangci/golangci-lint v1.27.0 // indirect
	github.com/golangci/misspell v0.3.5 // indirect
	github.com/golangci/revgrep v0.0.0-20180812185044-276a5c0a1039 // indirect
	github.com/gorilla/mux v1.7.3
	github.com/gostaticanalysis/analysisutil v0.0.4 // indirect
	github.com/huin/goupnp v1.0.0
	github.com/influxdata/influxdb v1.7.9
	github.com/ipfs/go-cid v0.0.4 // indirect
	github.com/ipfs/go-ipfs-util v0.0.1 // indirect
	github.com/ipfs/go-log v1.0.1
	github.com/jackpal/go-nat-pmp v1.0.2
	github.com/jirfag/go-printf-func-name v0.0.0-20200119135958-7558a9eaa5af // indirect
	github.com/julienschmidt/httprouter v1.3.0
	github.com/lestrrat-go/file-rotatelogs v2.3.0+incompatible
	github.com/lestrrat-go/strftime v1.0.1 // indirect
	github.com/libp2p/go-conn-security v0.1.0 // indirect
	github.com/libp2p/go-libp2p v6.0.23+incompatible
	github.com/libp2p/go-libp2p-circuit v0.1.4 // indirect
	github.com/libp2p/go-libp2p-crypto v0.1.0
	github.com/libp2p/go-libp2p-host v0.1.0
	github.com/libp2p/go-libp2p-interface-connmgr v0.1.0 // indirect
	github.com/libp2p/go-libp2p-interface-pnet v0.1.0 // indirect
	github.com/libp2p/go-libp2p-metrics v0.1.0 // indirect
	github.com/libp2p/go-libp2p-nat v0.0.5 // indirect
	github.com/libp2p/go-libp2p-net v0.1.0
	github.com/libp2p/go-libp2p-peer v0.2.0
	github.com/libp2p/go-libp2p-peerstore v0.1.4
	github.com/libp2p/go-libp2p-protocol v0.1.0 // indirect
	github.com/libp2p/go-libp2p-secio v0.2.1 // indirect
	github.com/libp2p/go-libp2p-transport v0.1.0 // indirect
	github.com/libp2p/go-stream-muxer v0.1.0 // indirect
	github.com/libp2p/go-ws-transport v0.2.0 // indirect
	github.com/mattn/go-colorable v0.1.6 // indirect
	github.com/mitchellh/mapstructure v1.3.2 // indirect
	github.com/multiformats/go-multiaddr v0.2.0
	github.com/multiformats/go-multiaddr-dns v0.2.0 // indirect
	github.com/onrik/ethrpc v1.0.0
	github.com/opentracing/opentracing-go v1.1.0
	github.com/pelletier/go-toml v1.8.0 // indirect
	github.com/prometheus/client_golang v1.3.0 // indirect
	github.com/prometheus/common v0.8.0 // indirect
	github.com/rakyll/statik v0.1.6 // indirect
	github.com/rs/cors v1.7.0
	github.com/rubblelabs/ripple v0.0.0-20190714134121-6dd7d15dd060
	github.com/ryancurrah/gomodguard v1.1.0 // indirect
	github.com/schancel/cashaddr-converter v0.0.0-20181111022653-4769e7add95a
	github.com/sirupsen/logrus v1.6.0
	github.com/sourcegraph/go-diff v0.5.3 // indirect
	github.com/spf13/afero v1.2.2 // indirect
	github.com/spf13/cast v1.3.1 // indirect
	github.com/spf13/cobra v1.0.0 // indirect
	github.com/spf13/viper v1.7.0 // indirect
	github.com/stretchr/objx v0.2.0 // indirect
	github.com/stretchr/testify v1.6.1
	github.com/syndtr/goleveldb v1.0.1-0.20190923125748-758128399b1d
	github.com/tdakkota/asciicheck v0.0.0-20200416200610-e657995f937b // indirect
	github.com/tendermint/tendermint v0.32.9
	github.com/tetafro/godot v0.4.2 // indirect
	github.com/timakin/bodyclose v0.0.0-20200424151742-cb6215831a94 // indirect
	github.com/urfave/cli/v2 v2.2.0 // indirect
	github.com/whyrusleeping/go-logging v0.0.1
	github.com/whyrusleeping/go-smux-multiplex v3.0.16+incompatible // indirect
	github.com/whyrusleeping/go-smux-multistream v2.0.2+incompatible // indirect
	github.com/whyrusleeping/go-smux-yamux v2.0.9+incompatible // indirect
	github.com/whyrusleeping/yamux v1.2.0 // indirect
	github.com/zondax/ledger-go v0.11.0 // indirect
	go.uber.org/atomic v1.5.1 // indirect
	go.uber.org/multierr v1.4.0 // indirect
	go.uber.org/zap v1.13.0 // indirect
	golang.org/x/crypto v0.0.0-20200311171314-f7b00557c8c4
	golang.org/x/mod v0.3.0 // indirect
	golang.org/x/net v0.0.0-20200425230154-ff2c4b7c35a0
	golang.org/x/sys v0.0.0-20200602225109-6fdc65e7d980 // indirect
	golang.org/x/tools v0.0.0-20200609164405-eb789aa7ce50 // indirect
	gopkg.in/ini.v1 v1.57.0 // indirect
	gopkg.in/urfave/cli.v1 v1.20.0
	gopkg.in/yaml.v3 v3.0.0-20200605160147-a5ece683394c // indirect
	honnef.co/go/tools v0.0.1-2020.1.4 // indirect
	mvdan.cc/unparam v0.0.0-20200501210554-b37ab49443f7 // indirect
	sourcegraph.com/sqs/pbtypes v1.0.0 // indirect
)
