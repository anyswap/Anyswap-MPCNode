package evt

import (
	"github.com/fsn-dev/dcrm-walletService/external/evt/evtapi/client"
)

type GetTokenRequest struct {
	Domain string `json:"domain"`
	Name   string `json:"name"`
}

type GetTokenResult struct {
}

func (it *Instance) GetToken(domainName string, tokenName string) (*GetTokenResult, *client.ApiError) {
	response := &GetTokenResult{}

	err := it.client.Post(it.path("get_token"), &GetTokenRequest{domainName, tokenName}, response)

	if err != nil {
		return nil, err
	}

	return response, nil
}
