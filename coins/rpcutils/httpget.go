/*
 *  Copyright (C) 2018-2019  Fusion Foundation Ltd. All rights reserved.
 *  Copyright (C) 2018-2019  gaozhengxin@fusion.org
 *
 *  This library is free software; you can redistribute it and/or
 *  modify it under the Apache License, Version 2.0.
 *
 *  This library is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  
 *
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 */

package rpcutils

import (
	"crypto/tls"
	"io/ioutil"
	"net/http"
	neturl "net/url"
	"strings"
)

func HttpGet(host string, path string, params map[string][]string) ([]byte, error) {
	scheme := "http"
	if strings.HasPrefix(host, "https") {
		scheme = "https"
		host = strings.Replace(host, "https://", "", -1)
	}
	host = strings.Replace(host, "http://", "", -1)
	host = strings.Trim(host, "/")
	path = strings.Trim(path, "/")
	url := neturl.URL{
		Scheme: scheme,
		Host: host,
		Path: path,
	}
	requrl := url.String()
	values := neturl.Values(params)
	if params != nil {
		requrl = requrl+"?"+values.Encode()
	}

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Transport: tr}
	resp, err := client.Get(requrl)

	//resp, err := http.Get(requrl)
	if err != nil {
		return nil, err
	}

	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)

	return body, err

}
