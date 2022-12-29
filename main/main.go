package main

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"strconv"

	"howett.net/plist"
)

type ServerInfo struct {
	ACL            int64  `plist:"acl"`
	DeviceID       string `plist:"deviceid"`
	Features       int64  `plist:"features"`
	MacAddress     string `plist:"macAddress"`
	Model          string `plist:"model"`
	OSBuildVersion string `plist:"osBuildVersion"`
	Protovers      string `plist:"protovers"`
	Srcvers        string `plist:"srcvers"`
}

func getXML(url string) ([]byte, error) {
	// Make a GET request to the specified URL
	resp, err := http.Get(url)
	if err != nil {
		return nil, fmt.Errorf("Error making GET request: %v", err)
	}
	defer resp.Body.Close()

	// Read the response body
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("Error reading response body: %v", err)
	}

	// Return the body as a byte slice
	return body, nil
}

func main() {
	url := "http://192.168.1.35:7000/server-info"
	res, err := getXML(url)
	if err != nil {
		fmt.Printf("Error getting XML: %v", err)
		return
	}
	var serverInfo ServerInfo
	format, err := plist.Unmarshal(res, &serverInfo)
	if err != nil {
		panic(err)
	}
	fmt.Println(format)
	fmt.Println(serverInfo.Features)
	featuresBinStr := strconv.FormatInt(int64(serverInfo.Features), 2)
	fmt.Println(featuresBinStr)
}
