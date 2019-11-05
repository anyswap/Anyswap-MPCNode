package chain

import "github.com/fsn-dev/dcrm-sdk/external/evt/evtapi/client"

type GetInfoResult struct {
	ServerVersion            string `json:"server_version"`
	ChainID                  string `json:"chain_id"`
	EvtAPIVersion            string `json:"evt_api_version"`
	HeadBlockNum             int    `json:"head_block_num"`
	LastIrreversibleBlockNum int    `json:"last_irreversible_block_num"`
	LastIrreversibleBlockID  string `json:"last_irreversible_block_id"`
	HeadBlockID              string `json:"head_block_id"`
	HeadBlockTime            string `json:"head_block_time"`
	HeadBlockProducer        string `json:"head_block_producer"`
	RecentSlots              string `json:"recent_slots"`
	ParticipationRate        string `json:"participation_rate"`
}

func (it *Instance) GetInfo() (*GetInfoResult, *client.ApiError) {
	response := &GetInfoResult{}

	err := it.Client.Get(it.Path("get_info"), response)

	if err != nil {
		return nil, err
	}

	return response, nil
}
