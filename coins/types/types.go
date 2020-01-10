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

package types

import (
    "math/big"
    "github.com/fsn-dev/dcrm-walletService/internal/common"
)

type TxOutput struct {
	ToAddress string
	Amount *big.Int
}

type Value struct {
	Cointype string
	Val *big.Int
}

type Balance struct {
	CoinBalance Value
	TokenBalance Value
}

// CallMsg contains parameters for contract calls.
type CallMsg struct {
    From common.Address  // the sender of the 'transaction'
    To *common.Address // the destination contract (nil for contract creation)
    Gas uint64          // if 0, the call executes with near-infinite gas
    GasPrice *big.Int        // wei <-> gas exchange ratio
    Value *big.Int        // amount of wei sent along with the call
    Data []byte          // input data, usually an ABI-encoded contract method invocation
}

// Subscription represents an event subscription where events are
// delivered on a data channel.
type Subscription interface {
    // Unsubscribe cancels the sending of events to the data channel
    // and closes the error channel.
    Unsubscribe()
    // Err returns the subscription error channel. The error channel receives
    // a value if there is an issue with the subscription (e.g. the network connection
    // delivering the events has been closed). Only one value will ever be sent.
    // The error channel is closed by Unsubscribe.
    Err() <-chan error
}

// FilterQuery contains options for contract log filtering.
type FilterQuery struct {
    BlockHash *common.Hash     // used by eth_getLogs, return logs only from block with this hash
    FromBlock *big.Int         // beginning of the queried range, nil means genesis block
    ToBlock   *big.Int         // end of the range, nil means latest block
    Addresses []common.Address // restricts matches to events created by specific contracts

    // The Topic list restricts matches to particular event topics. Each event has a list
    // of topics. Topics matches a prefix of that list. An empty element slice matches any
    // topic. Non-empty elements represent an alternative that matches any of the
    // contained topics.
    //
    // Examples:
    // {} or nil          matches any topic list
    // {{A}}              matches topic A in first position
    // {{}, {B}}          matches any topic in first position, B in second position
    // {{A}, {B}}         matches topic A in first position, B in second position
    // {{A, B}}, {C, D}}  matches topic (A OR B) in first position, (C OR D) in second position
    Topics [][]common.Hash
}

// SyncProgress gives progress indications when the node is synchronising with
// the Ethereum network.
type SyncProgress struct {
    StartingBlock uint64 // Block number where sync began
    CurrentBlock  uint64 // Current block number where sync is at
    HighestBlock  uint64 // Highest alleged block number in the chain
    PulledStates  uint64 // Number of state trie entries already downloaded
    KnownStates   uint64 // Total number of state trie entries known about
}

