package fungible

import "github.com/fsn-dev/dcrm-sdk/external/evt/evttypes"

const actionNameIssueFungible = "issuefungible"

type IssueFungibleParams struct {
	address    string
	asset      *evttypes.Asset
	fungibleId string
	memo       string
}


func (it *IssueFungibleParams) SetMemo(memo string) *IssueFungibleParams {
	it.memo = memo
	return it
}

type IssueFungibleArguments struct {
	Address string `json:"address"`
	Number  string `json:"number"`
	Memo    string `json:"memo"`
}

func (it *IssueFungibleParams) Arguments() *evttypes.ActionArguments {
	arg := IssueFungibleArguments{
		Address: it.address,
		Number:  it.asset.String(),
		Memo:    it.memo,
	}

	return &evttypes.ActionArguments{
		Action: actionNameIssueFungible,
		Args:   arg,
	}
}

func (it *IssueFungibleParams) Action(binargs string) *evttypes.SimpleAction {
	return &evttypes.SimpleAction{
		Data: binargs,
		Action: evttypes.Action{
			Name:   actionNameIssueFungible,
			Domain: fungibleDomain,
			Key:    it.fungibleId,
		},
	}
}
