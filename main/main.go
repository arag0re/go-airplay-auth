package main

import (
	"bufio"
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha512"
	"encoding/xml"
	"fmt"
	"io"
	"io/ioutil"
	"math"
	"net"
	"net/http"
	"strconv"
	"strings"

	_ "github.com/brutella/hc/crypto"
	"github.com/brutella/hc/log"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/ed25519"
	"howett.net/plist"
	"maze.io/x/crypto/x25519"
)

type Plist struct {
	XMLName xml.Name `xml:"plist"`
	Dict    Dict     `xml:"dict"`
}

type Dict struct {
	Key   string   `xml:"key"`
	Array []string `xml:"array>string"`
}

func post(socket net.Conn, path string, contentType string, CSeq string, data []byte) ([]byte, error) {
	postErr := postData(socket, path, contentType, CSeq, data)
	if postErr != nil {
		return nil, postErr
	}
	resp, err := readResponse(socket)
	if err != nil {
		log.Info.Panic(err)
		return nil, err
	}
	//fmt.Println(resp.StatusCode)
	if resp.StatusCode != http.StatusOK {
		panic(fmt.Errorf("got status %v", resp.StatusCode))
		//return nil, err
	} else {
		defer resp.Body.Close()
		body, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			log.Info.Panic(err)
			return nil, err
		}
		return body, nil
	}
}

func postData(socket net.Conn, path string, contentType string, CSeq string, data []byte) error {
	var req strings.Builder
	req.WriteString(fmt.Sprintf("POST %s HTTP/1.1\r\n", path))
	req.WriteString("User-Agent: AirPlay/415.3\r\n")
	req.WriteString(fmt.Sprintf("Content-Length: %d\r\n", len(data)))
	if contentType != "" {
		req.WriteString(fmt.Sprintf("Content-Type: %s\r\n", contentType))
	}
	if CSeq != "" {
		req.WriteString(fmt.Sprintf("CSeq: %v\r\n", CSeq))
	}
	req.WriteString("\r\n")
	req.Write(data)
	_, err := io.WriteString(socket, req.String())
	return err
}

func readResponse(conn net.Conn) (*http.Response, error) {
	reader := bufio.NewReader(conn)
	statusCode := 0
	statusLine, err := reader.ReadString('\n')
	if err != nil {
		return nil, err
	}
	headers := make(http.Header)
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			return nil, err
		}
		if line == "\r\n" {
			break
		}
		statusParts := strings.SplitN(statusLine, " ", 3)
		if len(statusParts) != 3 {
			return nil, fmt.Errorf("invalid status line: %s", statusLine)
		}
		statusCode, err = strconv.Atoi(statusParts[1])
		if err != nil {
			return nil, err
		}
		parts := strings.SplitN(line, ": ", 2)
		if len(parts) != 2 {
			return nil, fmt.Errorf("invalid header line: %s", line)
		}
		headers.Add(parts[0], parts[1])
	}

	var body []byte
	if headers.Get("Content-Length") != "" {
		length, err := strconv.Atoi(strings.TrimSpace(headers.Get("Content-Length")))
		if err != nil {
			return nil, err
		}
		body = make([]byte, length)
		_, err = io.ReadFull(reader, body)
		if err != nil {
			return nil, err
		}
	} else {
		body, err = ioutil.ReadAll(reader)
		if err != nil {
			return nil, err
		}
	}
	resp := &http.Response{
		Status:        strings.TrimSpace(statusLine),
		StatusCode:    statusCode, // default to OK
		Header:        headers,
		Body:          ioutil.NopCloser(bytes.NewReader(body)),
		ContentLength: int64(len(body)),
	}
	return resp, nil
}

func Parse(data []byte) (map[string]interface{}, error) {
	var plistData map[string]interface{}
	_, err := plist.Unmarshal(data, &plistData)
	if err != nil {
		return nil, err
	}
	return plistData, nil
}

func pairPinStart(addr string) {
	socket, err := openTCPConnection(addr)
	if err != nil {
		panic(err)
	}
	postData(socket, "/pair-pin-start", "", "0", nil)
	socket.Close()
}

func doPairSetup(socket net.Conn) ([]byte, error) {
	featuresToCheck := []int64{int64(math.Pow(2, 0)), int64(math.Pow(2, 7)), int64(math.Pow(2, 9)), int64(math.Pow(2, 14)), int64(math.Pow(2, 19)), int64(math.Pow(2, 20)), int64(math.Pow(2, 48))}
	check := checkForFeatures(socket, featuresToCheck)
	if check {
		fmt.Println("neccessary features are enabled on AirServer")
		void := make([]byte, 32)
		targetPubKey, err := post(socket, "/pair-setup", "application/octet-stream", "1", void)
		if err != nil {
			return nil, err
		}
		var targetPubKey32 [32]byte
		var privKey32 [32]byte
		copy(targetPubKey32[:], targetPubKey)
		private, err := x25519.GenerateKey(rand.Reader)
		if err != nil {
			fmt.Println(err)
			return nil, err
		}
		public := private.Public().(*x25519.PublicKey)
		copy(privKey32[:], private.Bytes())
		resp, err := doPairVerify1(socket, public.Bytes(), targetPubKey)
		if err != nil {
			fmt.Println(err)
			return nil, err
		}
		err1 := doPairVerify2(socket, resp, private, public)
		if err1 != nil {
			panic(err1)
		}
		return nil, nil
	} else {
		fmt.Println("not all neccessary features are enabled on AirServer")
		return nil, nil
	}
}

func parsePublicKey(key []byte) (x25519.PublicKey, error) {
	pub := x25519.PublicKey{}
	pub.SetBytes(key)
	return pub, nil
}

func getSharedKey(privKey *x25519.PrivateKey, pubKey *x25519.PublicKey) ([]byte, error) {
	sharedSecret := privKey.Shared(pubKey)
	return sharedSecret, nil
}

func aesCtr128Encrypt(key []byte, counter []byte, data []byte) []byte {
	block, err := aes.NewCipher(key)
	if err != nil {
		fmt.Println(err)
		return nil
	}
	aesCtr := cipher.NewCTR(block, counter)
	ciphertext := make([]byte, len(data))
	aesCtr.XORKeyStream(ciphertext, data)
	//fmt.Printf("%x\n", len(ciphertext))
	return ciphertext
}

func doPairVerify1(socket net.Conn, public []byte, targetPublic []byte) ([]byte, error) {
	flag := []byte{64, 64, 64, 64}
	data := append(flag, public...)
	data1 := append(data, targetPublic...)
	resp, err := post(socket, "/pair-verify", "application/octet-stream", "2", data1)
	return resp, err
}

func doPairVerify2(socket net.Conn, pairVerify1Response []byte, private *x25519.PrivateKey, public *x25519.PublicKey) error {
	targetPubKey := pairVerify1Response[:32]
	targetPub, err := parsePublicKey(targetPubKey)
	if err != nil {
		fmt.Println(err)
		return nil
	}
	sharedSecret, err := getSharedKey(private, &targetPub)
	if err != nil {
		fmt.Println(err)
		return nil
	}
	ed25519priv := ed25519.NewKeyFromSeed(private.Bytes())
	edPub := ed25519priv.Public().(ed25519.PublicKey)
	curve25519.X25519(private.Bytes(), targetPubKey)
	h := sha512.New()
	h.Write([]byte("Pair-Verify-AES-Key"))
	h.Write(sharedSecret)
	sharedSecretSha512AesKey := h.Sum(nil)[:16]
	h.Reset()
	h.Write([]byte("Pair-Verify-AES-IV"))
	h.Write(sharedSecret)
	sharedSecretSha512AesIV := h.Sum(nil)[:16]
	data := ed25519.Sign(ed25519priv, append(public.Bytes(), targetPubKey...))
	if !ed25519.Verify(edPub, append(public.Bytes(), targetPubKey...), data) {
		fmt.Println("invalid signature")
	} else {
		fmt.Println("signature is valid")
	}
	encrypted := aesCtr128Encrypt(sharedSecretSha512AesKey, sharedSecretSha512AesIV, data)
	arr := append([]byte{0, 0, 0, 0}, encrypted...)
	//fmt.Println(len(arr))
	data1, err := post(socket, "/pair-verify", "application/octet-stream", "3", arr)
	if err != nil {
		return err
	}
	print(data1)
	return nil
}

func checkForFeatures(socket net.Conn, features []int64) bool {
	serverInfo, err := getInfo(socket)
	if err != nil {
		fmt.Printf("err: %v", err)
	}
	serverFeatures := serverInfo["features"].(int64)
	serverFeatures = int64(serverFeatures)
	//featuresToCheck := []int64{int64(math.Pow(2, 0)), int64(math.Pow(2, 7)), int64(math.Pow(2, 9))}
	result := true
	for _, bitmask := range features {
		if serverFeatures&bitmask != bitmask {
			result = false
			break
		}
	}
	return result
}

func openTCPConnection(address string) (net.Conn, error) {
	conn, err := net.Dial("tcp", address)
	if err != nil {
		return nil, err
	}
	return conn, nil
}

func getInfo(socket net.Conn) (info map[string]interface{}, err error) {
	p := Plist{
		Dict: Dict{
			Key:   "qualifier",
			Array: []string{"txtAirPlay"},
		},
	}
	output, err := plist.MarshalIndent(&p, 1, "  ")
	if err != nil {
		fmt.Println(err)
		return
	}
	serverInfo, err := post(socket, "/info", "application/x-apple-binary-plist", "0", output)
	if err != nil {
		log.Info.Panic(err)
		return map[string]interface{}{}, err
	}
	parsed, err := Parse(serverInfo)
	if err != nil {
		log.Info.Panic(err)
		return map[string]interface{}{}, err
	}
	//fmt.Println(parsed)
	return parsed, nil
}

func main() {
	socket, err := openTCPConnection("192.168.1.35:7000")
	if err != nil {
		log.Info.Panic(err)
	}
	data, err := doPairSetup(socket)
	if err != nil {
		log.Info.Panic(err)
	}
	socket.Close()
	fmt.Println(data)
}
