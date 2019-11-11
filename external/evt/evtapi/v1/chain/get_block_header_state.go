package chain

import "github.com/fsn-dev/dcrm5-libcoins/external/evt/evtapi/client"

type GetHeadBlockHeaderStateRequest struct {
	BlockNumOrId string `json:"block_num_or_id"`
}

func (it *Instance) GetBlockHeaderState(blockNumOrId string) (*GetHeadBlockHeaderStateResult, *client.ApiError) {
	result := &GetHeadBlockHeaderStateResult{}

	err := it.Client.Post(it.Path("get_block_header_state"), &GetHeadBlockHeaderStateRequest{blockNumOrId}, result)

	if err != nil {
		return nil, err
	}

	return result, nil
}
