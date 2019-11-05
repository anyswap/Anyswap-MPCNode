package client

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
)

type ApiError struct {
	Err                 error
	ServerErrorResponse *ServerError
}

func (it *ApiError) IsServerError() bool {
	return it.ServerErrorResponse != nil
}

func NewApiError(err error) *ApiError {
	return &ApiError{
		Err: fmt.Errorf("client: %v\n", err.Error()),
	}
}

func parseError(b []byte) (*ApiError) {
	e := &ServerError{}

	err := json.Unmarshal(b, e)

	if err != nil {
		return &ApiError{
			Err: err,
		}
	}

	return &ApiError{
		ServerErrorResponse: e,
	}
}

type ServerError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Error   struct {
		Code    int    `json:"code"`
		Name    string `json:"name"`
		What    string `json:"what"`
		Details []struct {
			Message    string `json:"message"`
			File       string `json:"file"`
			LineNumber int    `json:"line_number"`
			Method     string `json:"method"`
		} `json:"details"`
	} `json:"error"`
}

func (it *ApiError) String() string {
	bb := bytes.Buffer{}

	if it.IsServerError() {
		bb.WriteString("Server Error")
		bb.WriteString(fmt.Sprintf("\nCode: %v\n", it.ServerErrorResponse.Code))
		bb.WriteString(fmt.Sprintf("Message: %v\n", it.ServerErrorResponse.Message))
		bb.WriteString(fmt.Sprintf("What: %v\n", it.ServerErrorResponse.Error.What))

		bb.WriteString("Details: ")

		for _, v := range it.ServerErrorResponse.Error.Details {

			bb.WriteString("\n")
			bb.WriteString(".......................\n")
			bb.WriteString(fmt.Sprintf("Method: %v \nMessage: %v\n", v.Method, v.Message, ))
		}

	} else {
		bb.WriteString(it.Err.Error())
	}

	return bb.String()
}

func (it *ApiError) Error() error {
	if it.IsServerError() {
		return errors.New(it.String())
	}

	return it.Err
}
