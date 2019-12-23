package client

import (
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/fsn-dev/dcrm-walletService/external/evt/evtconfig"
	"github.com/fsn-dev/dcrm-walletService/external/evt/utils"
	"github.com/sirupsen/logrus"
	"io/ioutil"
	"net/http"
)

type Instance struct {
	config *evtconfig.Instance
	logger *logrus.Logger
}

func New(config *evtconfig.Instance, logger *logrus.Logger) *Instance {
	return &Instance{
		config: config,
		logger: logger,
	}
}

func (it *Instance) Post(path string, body interface{}, response interface{}) *ApiError {
	url := it.getUrl(path)
	it.logger.Tracef("post to %v with body %+v\n", url, utils.ShowJsonFormatOfStruct(body))

	bbody, err := json.Marshal(body)

	if err != nil {
		return NewApiError(fmt.Errorf("post parsing error %v", err))
	}
	resp, err := http.Post(url, "application/json", bytes.NewReader(bbody))

	if err != nil {
		return NewApiError(fmt.Errorf("post request error %v", err))
	}

	b, err := ioutil.ReadAll(resp.Body)
// gaozhengxin 619
fmt.Printf("============ EVT client ============\nPost result: %v\n====================================\n",string(b))

	if err != nil {
		return NewApiError(fmt.Errorf("post parsing response error %v", err))
	}

	defer resp.Body.Close()

	if resp.StatusCode >= 300 {
		return parseError(b)
	}

	if it.logger.IsLevelEnabled(logrus.TraceLevel) {
		var prettyJSON bytes.Buffer
		err = json.Indent(&prettyJSON, b, "", "\t")
		if err != nil {
			return NewApiError(err)
		}
		it.logger.Tracef("JSON Response: \n%v\n", string(prettyJSON.Bytes()))
	}

	err = json.Unmarshal(b, &response)

	if err != nil {
		return NewApiError(err)
	}

	return nil
}

func (it *Instance) Get(path string, response interface{}) *ApiError {
	url := it.getUrl(path)
	resp, err := http.Get(url)

	it.logger.Tracef("get %v\n", url)

	if err != nil {
		return NewApiError(fmt.Errorf("get request: %v", err))
	}

	b, err := ioutil.ReadAll(resp.Body)
	defer resp.Body.Close()

	if resp.StatusCode >= 300 {
		return parseError(b)
	}

	if err != nil {
		return NewApiError(fmt.Errorf("get: %v", err))
	}

	err = json.Unmarshal(b, &response)

	if err != nil {
		return NewApiError(err)
	}

	return nil
}

func (it *Instance) getUrl(path string) string {
	return fmt.Sprintf("%v/%v/%v", it.config.HttpPath, it.config.Version, path)
}
