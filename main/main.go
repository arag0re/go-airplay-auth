package main

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"strconv"

	"howett.net/plist"
)

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
	var plistData map[string]interface{}
	format, err := plist.Unmarshal(res, &plistData)
	if err != nil {
		panic(err)
	}
	fmt.Println(format)
	int := int64(plistData["features"].(int64))
	binaryString := strconv.FormatInt(int64(int), 2)
	fmt.Println(binaryString)

	// Access the data in the Plist struct.
	//fmt.Println("acl:", p.Dict.Acl)
	//fmt.Println("deviceid:", p.Dict.Deviceid)
	//fmt.Println("features:", p.Dict.Features)
	//fmt.Println("macAddress:", p.Dict.MacAddress)
	//fmt.Println("model:", p.Dict.Model)
	//fmt.Println("osBuildVersion:", p.Dict.OsBuildVersion)
	//fmt.Println("protovers:", p.Dict.Protovers)
	//fmt.Println("srcvers:", p.Dict.Srcvers)
}
