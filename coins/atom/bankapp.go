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

package atom

import (
	"encoding/json"

	"github.com/cosmos/cosmos-sdk/codec"
	sdk "github.com/cosmos/cosmos-sdk/types"
)

const (
	app1Name      = "App1"
	bankCodespace = "BANK"
)

func RegisterCodec(cdc *codec.Codec) {
	cdc.RegisterConcrete(MsgSend{}, "cosmos-sdk/MsgSend", nil)
}

var cdc = codec.New()

//------------------------------------------------------------------
// Msg

// MsgSend implements sdk.Msg
var _ sdk.Msg = MsgSend{}

// MsgSend to send coins from Input to Output
type MsgSend struct {
	From   sdk.AccAddress `json:"from_address"`
	To     sdk.AccAddress `json:"to_address"`
	Amount sdk.Coins      `json:"amount"`
}

// NewMsgSend
func NewMsgSend(from, to sdk.AccAddress, amt sdk.Coins) MsgSend {
	return MsgSend{from, to, amt}
}

// Implements Msg.
// nolint
func (msg MsgSend) Route() string { return "send" }
func (msg MsgSend) Type() string  { return "send" }

// Implements Msg. Ensure the addresses are good and the
// amount is positive.
func (msg MsgSend) ValidateBasic() sdk.Error {
	if len(msg.From) == 0 {
		return sdk.ErrInvalidAddress("From address is empty")
	}
	if len(msg.To) == 0 {
		return sdk.ErrInvalidAddress("To address is empty")
	}
	//	if !msg.Amount.IsPositive() {
	//		return sdk.ErrInvalidCoins("Amount is not positive")
	//	}
	return nil
}

// Implements Msg. JSON encode the message.
func (msg MsgSend) GetSignBytes() []byte {
	bz, err := json.Marshal(msg)
	if err != nil {
		panic(err)
	}
	return sdk.MustSortJSON(bz)
}

// Implements Msg. Return the signer.
func (msg MsgSend) GetSigners() []sdk.AccAddress {
	return []sdk.AccAddress{msg.From}
}

/*
// Returns the sdk.Tags for the message
func (msg MsgSend) Tags() sdk.Tags {
	//return sdk.NewTags("sender", []byte(msg.From.String())).
	//	AppendTag("receiver", []byte(msg.To.String()))
	return sdk.NewTags("sender", []byte(msg.From.String())).
		AppendTag("receiver", msg.To.String())
}
*/
//------------------------------------------------------------------
// Tx

// Simple tx to wrap the Msg.
type app1Tx struct {
	MsgSend
}

// This tx only has one Msg.
func (tx app1Tx) GetMsgs() []sdk.Msg {
	return []sdk.Msg{tx.MsgSend}
}

// JSON decode MsgSend.
func tx1Decoder(txBytes []byte) (sdk.Tx, sdk.Error) {
	var tx app1Tx
	err := json.Unmarshal(txBytes, &tx)
	if err != nil {
		return nil, sdk.ErrTxDecode(err.Error())
	}
	return tx, nil
}
