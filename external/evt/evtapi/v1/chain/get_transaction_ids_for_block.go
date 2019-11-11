package chain

import "github.com/fsn-dev/dcrm5-libcoins/external/evt/evtapi/client"

type GetTransactionIdsForBlockRequest struct {
	BlockID string `json:"block_id"`
}

type GetTransactionIdsForBlockResult = []string

func (it *Instance) GetTransactionIdsForBlock(blockId string) (*GetTransactionIdsForBlockResult, *client.ApiError) {
	response := &GetTransactionIdsForBlockResult{}

	err := it.Client.Post(it.Path("get_transaction_ids_for_block"), &GetTransactionIdsForBlockRequest{blockId}, response)

	if err != nil {
		return nil, err
	}

	return response, nil
}
