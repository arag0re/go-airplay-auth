package main

import (
	"fmt"
	"io/ioutil"
	"math"
	"net/http"

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

/**
* Spec from:
* https://openairplay.github.io/airplay-spec/features.html
*
**/
type Features struct {
	Video                bool //video supported
	Photo                bool //photo supported
	VideoFairPlay        bool //video protected with FairPlay DRM
	VideoVolumeControl   bool //volume control supported for videos
	VideoHTTPLiveStreams bool //http live streaming supported
	Slideshow            bool //slideshow supported
	//empty
	Screen       bool //mirroring supported
	ScreenRotate bool //screen rotation supported
	Audio        bool //audio supported
	//empty
	AudioRedundant     bool //audio packet redundancy supported
	FPSAPv2pt5_AES_GCM bool //FairPlay secure auth supported
	PhotoCaching       bool //photo preloading supported
	Authentication4    bool //Authentication type 4. FairPlay authentication
	MetadataFeature1   bool //bit 1 of MetadataFeatures. Artwork.
	MetadataFeature2   bool //bit 2 of MetadataFeatures. Progress.
	MetadataFeature0   bool //bit 0 of MetadataFeatures. Text.
	AudioFormat1       bool //support for audio format 1
	AudioFormat2       bool //support for audio format 2. This bit must be set for AirPlay 2 connection to work
	AudioFormat3       bool //support for audio format 3. This bit must be set for AirPlay 2 connection to work
	AudioFormat4       bool //support for audio format 4
	//empty
	Authentication1 bool //Authentication type 1. RSA Authentication
	//empty
	//empty
	HasUnifiedAdvertiserInfo bool
	SupportsLegacyPairing    bool
	//empty
	//empty
	RAOP bool //RAOP is supported on this port. With this bit set your don't need the AirTunes service
	//empty
	IsCarPlay                     bool //Don’t read key from pk record it is known
	SupportsAirPlayVideoPlayQueue bool
	SupportsAirPlayFromCloud      bool
	//empty
	//empty
	//empty
	SupportsCoreUtilsPairingAndEncryption bool //SupportsHKPairingAndAccessControl, SupportsSystemPairing and SupportsTransientPairing implies SupportsCoreUtilsPairingAndEncryption
	//empty
	SupportsBufferedAudio    bool //Bit needed for device to show as supporting multi-room audio
	SupportsPTP              bool //Bit needed for device to show as supporting multi-room audio
	SupportsScreenMultiCodec bool
	SupportsSystemPairing    bool
	//empty
	//empty
	SupportsHKPairingAndAccessControl bool
	//empty
	SupportsTransientPairing bool //SupportsSystemPairing implies SupportsTransientPairing
	//empty
	MetadataFeature4                bool //bit 4 of MetadataFeatures. binary plist.
	SupportsUnifiedPairSetupAndMFi  bool //Authentication type 8. MFi authentication
	SupportsSetPeersExtendedMessage bool
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
	if format == 1 {
		//fmt.Println(format)
		//fmt.Println(serverInfo.Features)
		features := serverInfo.Features
		featuresToCheck := []int64{int64(math.Pow(2, 0)), int64(math.Pow(2, 7)), int64(math.Pow(2, 9))}
		for i, bitmask := range featuresToCheck {
			if features&bitmask == bitmask {
				fmt.Println("The feature set." + fmt.Sprint(i))
			} else {
				fmt.Println("The feature not set." + fmt.Sprint(i))
			}
		}
	}

	//featuresBinStr := strings.TrimLeft(strconv.FormatInt(int64(serverInfo.Features), 2), "-")
	//featuresBits := []rune(featuresBinStr)
	//var features Features
	//for i := 0; i < len(featuresBits); i++ {
	//	if featuresBits[i] == 49 && i == 0 {
	//		features.Video = true
	//	} else if featuresBits[i] == 49 && i == 1{
	//		features.Photo = true
	//	}
	//}
	//fmt.Println(featuresBits)
}
