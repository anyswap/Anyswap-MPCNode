package evttypes

type TRXJson struct {
        Id                    string         `json:"-"`
	Expiration            string         `json:"expiration"`
	RefBlockNum           int            `json:"ref_block_num"`
	RefBlockPrefix        int            `json:"ref_block_prefix"`
	MaxCharge             int            `json:"max_charge"`
	Payer                 string         `json:"payer"`
	Actions               []SimpleAction `json:"actions"`
	TransactionExtensions []interface{}  `json:"transaction_extensions"`
}

type SignedTRXJson struct {
	Signatures  []string `json:"signatures"`
	Compression string   `json:"compression"`
	Transaction *TRXJson `json:"transaction"`
}
