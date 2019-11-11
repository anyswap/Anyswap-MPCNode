package chain

import (
	"github.com/fsn-dev/dcrm5-libcoins/external/evt/evtapi/client"
	//"github.com/fsn-dev/dcrm5-libcoins/external/evt/evttypes"
)

//type AbiJsonToBinRequest = evttypes.ActionArguments
type AbiJsonToBinRequest = ActionArguments

type AbiJsonToBinResult struct {
	Binargs string `json:"binargs"`
}

/*type Args struct {
	Name     string     `json:"name"`
	Creator  string     `json:"creator"`
	Issue    ActionType `json:"issue"`
	Transfer ActionType `json:"transfer"`
	Manage   ActionType `json:"manage"`
}*/

type Args struct {
	Name        string         `json:"name,omitempty"`
	Creator     string         `json:"creator,omitempty"`
	Issue       ActionType     `json:"issue,omitempty"`
	Transfer    ActionType     `json:"transfer,omitempty"`
	Manage      ActionType     `json:"manage,omitempty"`
	TotalSupply int64          `json:"total_supply,omitempty"`
	From        string         `json:"from,omitempty"`
	To          string         `json:"to,omitempty"`
	Number      string         `json:"number,omitempty"`
	Memo        string         `json:"memo,omitempty"`
}

type ActionArguments struct {
	Action      string         `json:"action"`
	Args        Args           `json:"args"`
}

type Authorizers struct {
	Ref    string `json:"ref"`
	Weight int    `json:"weight"`
}

type ActionType struct {
	Name        string        `json:"name"`
	Threshold   int           `json:"threshold"`
	Authorizers []Authorizers `json:"authorizers"`
}

func (it *Instance) AbiJsonToBin(request *AbiJsonToBinRequest) (*AbiJsonToBinResult, *client.ApiError) {
	response := &AbiJsonToBinResult{}

	err := it.Client.Post(it.Path("abi_json_to_bin"), request, response)

	if err != nil {
		return nil, err
	}

	return response, nil
}
