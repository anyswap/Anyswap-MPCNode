package evt

import (
	"github.com/fsn-dev/dcrm-walletService/external/evt/evtapi/client"
)

type GetGroupRequest struct {
	Name string `json:"name"`
}

type GetGroupResult struct {
	Name string `json:"name"`
	Key  string `json:"key"`
	Root struct {
		Threshold int `json:"threshold"`
		Weight    int `json:"weight"`
		Nodes     []struct {
			Threshold int `json:"threshold,omitempty"`
			Weight    int `json:"weight"`
			Nodes     []struct {
				Key    string `json:"key"`
				Weight int    `json:"weight"`
			} `json:"nodes,omitempty"`
			Key string `json:"key,omitempty"`
		} `json:"nodes"`
	} `json:"root"`
}

func (it *Instance) GetGroup(domainName string) (*GetGroupResult, *client.ApiError) {
	response := &GetGroupResult{}

	err := it.client.Post(it.path("get_group"), &GetGroupRequest{domainName}, response)

	if err != nil {
		return nil, err
	}

	return response, nil
}
