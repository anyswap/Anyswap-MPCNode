package fungible

import "github.com/fsn-dev/dcrm5-libcoins/external/evt/evttypes"

const actionNameTransferFungible = "transferft"

type TransferFungibleParams struct {
	from       string
	to         string
	asset      *evttypes.Asset
	fungibleId string
	memo       string
}


func (it *TransferFungibleParams) SetMemo(memo string) *TransferFungibleParams {
	it.memo = memo
	return it
}

type TransferFungibleArguments struct {
	From   string `json:"from"`   // address
	To     string `json:"to"`     // address
	Number string `json:"number"` // asset
	Memo   string `json:"memo"`   // string
}

func (it *TransferFungibleParams) Arguments() *evttypes.ActionArguments {
	arg := TransferFungibleArguments{
		From:   it.from,
		To:     it.to,
		Number: it.asset.String(),
		Memo:   it.memo,
	}

	return &evttypes.ActionArguments{
		Action: actionNameTransferFungible,
		Args:   arg,
	}
}

func (it *TransferFungibleParams) Action(binargs string) *evttypes.SimpleAction {
	return &evttypes.SimpleAction{
		Data: binargs,
		Action: evttypes.Action{
			Name:   actionNameTransferFungible,
			Domain: fungibleDomain,
			Key:    it.fungibleId,
		},
	}
}
