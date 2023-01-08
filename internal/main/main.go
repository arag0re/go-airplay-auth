package main

import (
	"bufio"
	"fmt"
	"main/internal/airplayauth"
	"os"
	"strings"
)

const STORED_AUTH_TOKEN = "I1Z22NO1F5VFJPEG@302e020100300506032b657004220420eb92ab919f68cc716f7f85a609531c3de74f87c9f1c9007c35516b4f5ef1fa99"
const ADDR = "192.168.1.35:7000"

func main() {
	var airplay airplayauth.AirPlayAuth
	airplay.NewAirPlayAuth(ADDR, STORED_AUTH_TOKEN)
	airplay.StartPairing(ADDR)
	reader := bufio.NewReader(os.Stdin)
	fmt.Print("Enter pin: ")
	pin, _ := reader.ReadString('\n')
	pin = strings.TrimSpace(pin)
	socket, err := airplay.Pair(pin)
	if err != nil {
		fmt.Println("Pairing failed: ", err)
		panic(err)
	}
	socket, err = airplay.Auth(socket)
	if err != nil {
		fmt.Println("Authentication failed: ", err)
		panic(err)
	}
	//String content = "Content-Location: http://techslides.com/demos/sample-videos/small.mp4\r\n" +
	//		"Start-Position: 0.0\r\n";
	//post(socket, "/play", "text/parameters", content.getBytes("UTF-8"));
	//Thread.sleep(10000);
	socket.Close()
}
