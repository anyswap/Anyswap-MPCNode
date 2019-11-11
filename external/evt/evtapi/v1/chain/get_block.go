package chain

import "github.com/fsn-dev/dcrm5-libcoins/external/evt/evtapi/client"

type GetBlockRequest struct {
	BlockNumOrID string `json:"block_num_or_id"`
}

type GetBlockResult struct {
	Timestamp         string        `json:"timestamp"`
	Producer          string        `json:"producer"`
	Confirmed         int           `json:"confirmed"`
	Previous          string        `json:"previous"`
	TransactionMroot  string        `json:"transaction_mroot"`
	ActionMroot       string        `json:"action_mroot"`
	ScheduleVersion   int           `json:"schedule_version"`
	NewProducers      interface{}   `json:"new_producers"`
	HeaderExtensions  []interface{} `json:"header_extensions"`
	ProducerSignature string        `json:"producer_signature"`
	Transactions      []Transaction `json:"transactions"`
	BlockExtensions   []interface{} `json:"block_extensions"`
	ID                string        `json:"id"`
	BlockNum          int           `json:"block_num"`
	RefBlockPrefix    int           `json:"ref_block_prefix"`
}

type Transaction struct {
	Status string               `json:"status"`
	Type   string               `json:"type"`
	Trx    TransactionExtension `json:"trx"`
}

type TransactionExtension struct {
	ID               string           `json:"id"`
	Signatures       []string         `json:"signatures"`
	Compression      string           `json:"compression"`
	PackedTrx        string           `json:"packed_trx"`
	InnerTransaction InnerTransaction `json:"transaction"`
}
type InnerTransaction struct {
	Expiration            string        `json:"expiration"`
	RefBlockNum           int           `json:"ref_block_num"`
	RefBlockPrefix        int64         `json:"ref_block_prefix"`
	MaxCharge             int           `json:"max_charge"`
	Actions               []Action      `json:"actions"`
	Payer                 string        `json:"payer"`
	TransactionExtensions []interface{} `json:"transaction_extensions"`
}

type Action struct {
	Name    string `json:"name"`
	Domain  string `json:"domain"`
	Key     string `json:"key"`
	Data    Data   `json:"data"`
	HexData string `json:"hex_data"`
}

type Data struct {
	From string `json:"from,omitempty"`
	To string `json:"to,omitempty"`
	Number string `json:"number,omitempty"`
	Address string `json:"address,omitempty"`
	Link Link `json:"link"`
}

type Link struct {
	Header     int       `json:"header"`
	Segments   []Segment `json:"segments"`
	Signatures []string  `json:"signatures"`
	Keys       []string  `json:"keys"`
}

type Segment struct {
	Key int `json:"key"`
	//Value string `json:"value"`
}

func (it *Instance) GetBlock(blockNumOrId string) (*GetBlockResult, *client.ApiError) {
	response := &GetBlockResult{}

	err := it.Client.Post(it.Path("get_block"), &GetBlockRequest{BlockNumOrID: blockNumOrId}, response)

	if err != nil {
		return nil, err
	}

	return response, nil
}
