package evt

import (
	"github.com/fsn-dev/dcrm5-libcoins/external/evt/evtapi/client"
	"github.com/fsn-dev/dcrm5-libcoins/external/evt/evttypes"
)

type GetFungibleRequest struct {
	Id string `json:"id"`
}

type GetFungibleResult struct {
	Name          string                 `json:"name"`
	SymName       string                 `json:"sym_name"`
	Sym           string                 `json:"sym"`
	Creator       string                 `json:"creator"`
	CreateTime    string                 `json:"create_time"`
	Issue         evttypes.PermissionDef `json:"issue"`
	Manage        evttypes.PermissionDef `json:"manage"`
	TotalSupply   string                 `json:"total_supply"`
	Metas         []map[string]string    `json:"metas"`
	CurrentSupply string                 `json:"current_supply"`
	Address       string                 `json:"address"`
}

func (it *Instance) GetFungible(id string) (*GetFungibleResult, *client.ApiError) {
	response := &GetFungibleResult{}

	err := it.client.Post(it.path("get_fungible"), &GetFungibleRequest{id}, response)

	if err != nil {
		return nil, err
	}

	return response, nil
}
