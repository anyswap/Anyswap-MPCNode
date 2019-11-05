package evttypes

type EvtLink struct {
	Flag     int `json:"flag"`
	Segments []struct {
		TypeKey int         `json:"typeKey"`
		Value   interface{} `json:"value"`
	} `json:"segments"`
	PublicKeys []string `json:"publicKeys"`
	Signatures []string `json:"signatures"`
}


func ParseEvtLink(evtLink string) (*EvtLink, error) {
	result := &EvtLink{}
	return result, nil
}