package airplayauth

import (
	"bufio"
	"bytes"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha512"
	"crypto/x509"
	"encoding/hex"
	"encoding/xml"
	"fmt"
	"io"
	"io/ioutil"
	"math"
	"net"
	"net/http"
	"strconv"
	"strings"

	"github.com/brutella/hc/log"
	"github.com/opencoff/go-srp"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/ed25519"
	"github.com/groob/plist"
	"maze.io/x/crypto/x25519"
)

var clientId = ""
var authKey ed25519.PrivateKey
var addr string

const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

type AirPlayAuth struct {
}

type PrivateKey struct {
	PublicKey x25519.PublicKey
	b         []byte
}
type Plist struct {
	XMLName xml.Name `xml:"plist"`
	Dict    Dict     `xml:"dict"`
}
type Dict struct {
	Key   string   `xml:"key"`
	Array []string `xml:"array>string"`
}
type PairSetupPin1Response struct {
	Pk   []byte
	Salt []byte
}
type PairSetupPin2Response struct {
	Proof []byte
}

type PairSetupPin3Response struct {
	Epk     []byte
	AuthTag []byte
}

func (a AirPlayAuth) NewAirPlayAuth(address string, authToken string) error {
	addr = address
	authTokenSplit := strings.Split(authToken, "@")
	clientId = authTokenSplit[0]
	authKeyBytes, err := hex.DecodeString(authTokenSplit[1])
	if err != nil {
		return err
	}
	copy(authKey[:], authKeyBytes)
	fmt.Println("clientId:", clientId)
	fmt.Println("authKey:", authKey)
	//authKey = ed25519.NewKeyFromSeed(authKey)
	return nil
}

func createPListStep1(data map[string]string) ([]byte, error) {
	var b bytes.Buffer
	enc := plist.NewEncoder(&b)
	err := enc.Encode(data)
	if err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}

func createPlist(m map[string][]byte) ([]byte, error) {
	data, err := plist.MarshalIndent(m, "")
	if err != nil {
		return nil, err
	}
	return data, nil
}

func createPListStep2(data map[string][]byte) ([]byte, error) {
	var b bytes.Buffer
	enc := plist.NewEncoder(&b)
	err := enc.Encode(data)
	if err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}

func generateNewAuthToken() string {
	clientID := randomString(16)
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}
	privateKeyDER := x509.MarshalPKCS1PrivateKey(privateKey)
	privateKeyHex := hex.EncodeToString(privateKeyDER)
	return clientID + "@" + privateKeyHex
}

func (a *AirPlayAuth) post(socket net.Conn, path string, contentType string, CSeq string, data []byte) ([]byte, error) {
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
	err := plist.Unmarshal(data, &plistData)
	if err != nil {
		return nil, err
	}
	return plistData, nil
}

func randomString(length int) string {
	b := make([]byte, length)
	_, err := rand.Read(b)
	if err != nil {
		panic(err)
	}
	s := make([]byte, length)
	for i, v := range b {
		s[i] = charset[v%byte(len(charset))]
	}
	return string(s)
}

func (a AirPlayAuth) Auth(socket net.Conn) net.Conn {
	randomPrivateKey := make([]byte, 32)
	_, err := rand.Read(randomPrivateKey)
	if err != nil {
		fmt.Println("Error generating random bytes:", err)
	}
	randomPublicKey := make([]byte, 32)
	_, err1 := rand.Read(randomPublicKey)
	if err1 != nil {
		fmt.Println("Error generating random bytes:", err)
	}
	pairVerify1Response, err := a.doPairVerify1(socket, randomPublicKey, authKey)
	if err != nil {
		fmt.Println("Error generating random bytes:", err)
	}
	pub, err := parsePublicKey(randomPublicKey)
	if err != nil {
		fmt.Println("Error parsing key: ", err)
	}
	privateKey := x25519.PrivateKey{}
	privateKey.SetBytes(randomPrivateKey)
	a.doPairVerify2(socket, pairVerify1Response, &privateKey, &pub)
	println("Pair Verify finished!")
	return socket
}

func (a AirPlayAuth) StartPairing(addr string) {
	socket, err := openTCPConnection(addr)
	if err != nil {
		panic(err)
	}
	a.post(socket, "/pair-pin-start", "", "0", nil)
	socket.Close()
}

func (a AirPlayAuth) Pair(pin string) (net.Conn, error) {
	socket, err := openTCPConnection(addr)
	if err != nil {
		log.Info.Panic(err)
	}
	featuresToCheck := []uint64{uint64(math.Pow(2, 0)), uint64(math.Pow(2, 7)), uint64(math.Pow(2, 9)), uint64(math.Pow(2, 14)), uint64(math.Pow(2, 19)), uint64(math.Pow(2, 20)), uint64(math.Pow(2, 48))}
	check := a.checkForFeatures(socket, featuresToCheck)
	if check {
		fmt.Println("neccessary features are enabled on AirServer")
		pairSetupPin1Response, err := a.doPairSetupPin1(socket)
		if err != nil {
			panic(err)
		}
		srp, err := srp.NewWithHash(crypto.SHA1, 2048)
		if err != nil {
			panic(err)
		}
		c, err := srp.NewClient([]byte(clientId), []byte(pin))
		if err != nil {
			panic(err)
		}
		creds := c.Credentials()
		splittedCreds := strings.Split(creds, ":")
		xA := splittedCreds[1]
		//strings.Split(creds, "")
		server_creds := hex.EncodeToString(pairSetupPin1Response.Salt) + ":" + hex.EncodeToString(pairSetupPin1Response.Pk)
		auth, err := c.Generate(server_creds)
		if err != nil {
			panic(err)
		}
		pairSetupPin2Response, err := a.doPairSetupPin2(socket, []byte(xA), []byte(auth))
		fmt.Println(pairSetupPin2Response)
		if !c.ServerOk(string(pairSetupPin2Response.Proof)) {
			panic("authentication failed")
		}
		return socket, err
	} else {
		fmt.Println("not all neccessary features are enabled on AirServer")
		return nil, err
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

func (a AirPlayAuth) doPairSetupPin1(socket net.Conn) (*PairSetupPin1Response, error) {
	pairSetupPinRequestData, err := createPListStep1(map[string]string{
		"method": "pin",
		"user":   clientId,
	})
	if err != nil {
		return nil, err
	}
	data, err := a.post(socket, "/pair-setup-pin", "application/x-apple-binary-plist", "1", pairSetupPinRequestData)
	if err != nil {
		return nil, err
	}
	pairSetupPin1Response, err := Parse(data)
	if err != nil {
		return nil, err
	}
	if _, okPk := pairSetupPin1Response["pk"]; okPk {
		if _, okSalt := pairSetupPin1Response["salt"]; okSalt {
			pkBytes := pairSetupPin1Response["pk"].([]byte)
			saltBytes := pairSetupPin1Response["salt"].([]byte)
			return &PairSetupPin1Response{Pk: pkBytes, Salt: saltBytes}, nil
		}
	}
	return nil, fmt.Errorf("missing 'pk' and/or 'salt' keys in response")
}

func (a AirPlayAuth) doPairSetupPin2(socket net.Conn, publicClientValueA []byte, clientEvidenceMessageM1 []byte) (PairSetupPin2Response, error) {
	pairSetupPinRequestData, err := createPlist(map[string][]byte{
		"pk":    publicClientValueA,
		"proof": clientEvidenceMessageM1,
	})
	if err != nil {
		return PairSetupPin2Response{}, err
	}
	pairSetupPin2ResponseBytes, err := a.post(socket, "/pair-setup-pin", "application/x-apple-binary-plist", "", pairSetupPinRequestData)
	if err != nil {
		return PairSetupPin2Response{}, err
	}
	pairSetupPin2Response, err := Parse(pairSetupPin2ResponseBytes)
	if err != nil {
		return PairSetupPin2Response{}, err
	}
	if _, ok := pairSetupPin2Response["proof"]; !ok {
		return PairSetupPin2Response{}, fmt.Errorf("missing proof key in response")
	}
	proof, ok := pairSetupPin2Response["proof"].([]byte)
	if !ok {
		return PairSetupPin2Response{}, fmt.Errorf("proof key in response is not of type []byte")
	}
	return PairSetupPin2Response{Proof: proof}, nil
}

func (a AirPlayAuth) doPairSetupPin3(socket net.Conn, sessionKeyHashK []byte) (PairSetupPin3Response, error) {
	sha512Digest := sha512.New()
	sha512Digest.Write([]byte("Pair-Setup-AES-Key"))
	sha512Digest.Write(sessionKeyHashK)
	aesKey := sha512Digest.Sum(nil)[:16]
	sha512Digest.Reset()
	sha512Digest.Write([]byte("Pair-Setup-AES-IV"))
	sha512Digest.Write(sessionKeyHashK)
	aesIV := sha512Digest.Sum(nil)[:16]
	for i := len(aesIV) - 1; i >= 0; i-- {
		aesIV[i]++
		if aesIV[i] != 0 {
			break
		}
	}
	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return PairSetupPin3Response{}, err
	}
	aesGcm, err := cipher.NewGCM(block)
	if err != nil {
		return PairSetupPin3Response{}, err
	}
	aesGcm128ClientLTPK := aesGcm.Seal(nil, aesIV, authKey, nil)
	requestData := make(map[string][]byte)
	requestData["epk"] = aesGcm128ClientLTPK[:len(aesGcm128ClientLTPK)-16]
	requestData["authTag"] = aesGcm128ClientLTPK[len(aesGcm128ClientLTPK)-16:]
	pairSetupPinRequestData, err := createPListStep2(requestData)
	if err != nil {
		return PairSetupPin3Response{}, err
	}
	pairSetupPin3ResponseBytes, err := a.post(socket, "/pair-setup-pin", "application/x-apple-binary-plist", "", pairSetupPinRequestData)
	if err != nil {
		return PairSetupPin3Response{}, err
	}
	pairSetupPin3Response, err := Parse(pairSetupPin3ResponseBytes)
	if err != nil {
		return PairSetupPin3Response{}, err
	}
	if _, ok := pairSetupPin3Response["epk"]; !ok {
		return PairSetupPin3Response{}, fmt.Errorf("missing epk key in response")
	}
	epkV, ok := pairSetupPin3Response["eok"].([]byte)
	if !ok {
		return PairSetupPin3Response{}, fmt.Errorf("epk key in response is not of type []byte")
	}
	if _, ok := pairSetupPin3Response["authTag"]; !ok {
		return PairSetupPin3Response{}, fmt.Errorf("missing authTag key in response")
	}
	authTagV, ok := pairSetupPin3Response["authTag"].([]byte)
	if !ok {
		return PairSetupPin3Response{}, fmt.Errorf("authTag key in response is not of type []byte")
	}
	return PairSetupPin3Response{Epk: epkV, AuthTag: authTagV}, err
}

func (a AirPlayAuth) doPairVerify1(socket net.Conn, public []byte, targetPublic []byte) ([]byte, error) {
	flag := []byte{64, 64, 64, 64}
	data := append(flag, public...)
	data1 := append(data, targetPublic...)
	resp, err := a.post(socket, "/pair-verify", "application/octet-stream", "2", data1)
	return resp, err
}

func (a AirPlayAuth) doPairVerify2(socket net.Conn, pairVerify1Response []byte, private *x25519.PrivateKey, public *x25519.PublicKey) error {
	targetPubKey := pairVerify1Response[:32]
	targetPub, err := parsePublicKey(targetPubKey)
	if err != nil {
		fmt.Println(err)
		return err
	}
	sharedSecret, err := getSharedKey(private, &targetPub)
	if err != nil {
		fmt.Println(err)
		return err
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
	data1, err := a.post(socket, "/pair-verify", "application/octet-stream", "3", arr)
	if err != nil {
		return err
	}
	print(data1)
	return nil
}

func (a AirPlayAuth) checkForFeatures(socket net.Conn, features []uint64) bool {
	serverInfo, err := a.getInfo(socket)
	if err != nil {
		panic(err)
	}
	serverFeatures := serverInfo["features"].(uint64)
	serverFeatures = uint64(serverFeatures)
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

func (a AirPlayAuth) getInfo(socket net.Conn) (info map[string]interface{}, err error) {
	p := Plist{
		Dict: Dict{
			Key:   "qualifier",
			Array: []string{"txtAirPlay"},
		},
	}

	output, err := plist.MarshalIndent(&p, "")
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println(Parse(output))
	serverInfo, err := a.post(socket, "/info", "application/x-apple-binary-plist", "0", output)
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
