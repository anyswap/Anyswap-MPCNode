package evt

import (
	"github.com/fsn-dev/dcrm-sdk/external/evt/evtapi/client"
	"github.com/fsn-dev/dcrm-sdk/external/evt/evttypes"
)

type GetSuspendRequest struct {
	Id string `json:"id"`
}

type GetSuspendResult struct {
	Name     string `json:"name"`
	Proposer string `json:"proposer"`
	Status   string `json:"status"`
	Trx      struct {
		Expiration            string                `json:"expiration"`
		RefBlockNum           int                   `json:"ref_block_num"`
		RefBlockPrefix        int                   `json:"ref_block_prefix"`
		MaxCharge             int                   `json:"max_charge"`
		Payer                 string                `json:"payer"`
		Actions               []evttypes.FullAction `json:"actions"`
		TransactionExtensions []interface{}         `json:"transaction_extensions"`
	} `json:"trx"`
	SignedKeys []string `json:"signed_keys"`
	Signatures []string `json:"signatures"`
}

func (it *Instance) GetSuspend(id string) (*GetSuspendResult, *client.ApiError) {
	response := &GetSuspendResult{}

	err := it.client.Post(it.path("get_suspend"), &GetSuspendRequest{id}, response)

	if err != nil {
		return nil, err
	}

	return response, nil
}
