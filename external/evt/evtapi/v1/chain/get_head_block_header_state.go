package chain

import "github.com/fsn-dev/dcrm-walletService/external/evt/evtapi/client"

type Header struct {
	Timestamp         string        `json:"timestamp"`
	Producer          string        `json:"producer"`
	Confirmed         int           `json:"confirmed"`
	Previous          string        `json:"previous"`
	TransactionMroot  string        `json:"transaction_mroot"`
	ActionMroot       string        `json:"action_mroot"`
	ScheduleVersion   int           `json:"schedule_version"`
	HeaderExtensions  []interface{} `json:"header_extensions"`
	ProducerSignature string        `json:"producer_signature"`
}

type PendingSchedule struct {
	Version   int           `json:"version"`
	Producers []interface{} `json:"producers"`
}

type Producer struct {
	ProducerName    string `json:"producer_name"`
	BlockSigningKey string `json:"block_signing_key"`
}

type ActiveSchedule struct {
	Version   int        `json:"version"`
	Producers []Producer `json:"producers"`
}

type BlockrootMerkle struct {
	ActiveNodes []string `json:"_active_nodes"`
	NodeCount   int      `json:"_node_count"`
}

type GetHeadBlockHeaderStateResult struct {
	ID                               string          `json:"id"`
	BlockNum                         int             `json:"block_num"`
	Header                           Header          `json:"header"`
	DposProposedIrreversibleBlocknum int             `json:"dpos_proposed_irreversible_blocknum"`
	DposIrreversibleBlocknum         int             `json:"dpos_irreversible_blocknum"`
	BftIrreversibleBlocknum          int             `json:"bft_irreversible_blocknum"`
	PendingScheduleLibNum            int             `json:"pending_schedule_lib_num"`
	PendingScheduleHash              string          `json:"pending_schedule_hash"`
	PendingSchedule                  PendingSchedule `json:"pending_schedule"`
	ActiveSchedule                   ActiveSchedule  `json:"active_schedule"`
	BlockrootMerkle                  BlockrootMerkle `json:"blockroot_merkle"`
	ProducerToLastProduced           [][]interface{} `json:"producer_to_last_produced"`
	ProducerToLastImpliedIrb         [][]interface{} `json:"producer_to_last_implied_irb"`
	BlockSigningKey                  string          `json:"block_signing_key"`
	ConfirmCount                     []interface{}   `json:"confirm_count"`
	Confirmations                    []interface{}   `json:"confirmations"`
}

func (it *Instance) GetHeadBlockHeaderState() (*GetHeadBlockHeaderStateResult, *client.ApiError) {

	response := &GetHeadBlockHeaderStateResult{}

	err := it.Client.Get(it.Path("get_head_block_header_state"), response)

	if err != nil {
		return nil, err
	}

	return response, nil
}
