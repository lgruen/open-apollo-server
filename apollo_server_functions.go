package apollo_server_functions

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	b64 "encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"

	"github.com/librespot-org/librespot-golang/Spotify"
	"github.com/librespot-org/librespot-golang/librespot/core"
	"github.com/librespot-org/librespot-golang/librespot/utils"
)

type ApiTokenResult struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
}

func apiToken(code string) (*ApiTokenResult, error) {
	clientId := os.Getenv("SPOTIFY_CLIENT_ID")
	clientSecret := os.Getenv("SPOTIFY_CLIENT_SECRET")

	if clientId == "" || clientSecret == "" {
		return nil, errors.New("No client ID / secret set")
	}

	resp, err := http.PostForm("https://accounts.spotify.com/api/token",
		url.Values{
			"grant_type":    {"authorization_code"},
			"code":          {code},
			"redirect_uri":  {"open-apollo://callback"},
			"client_id":     {clientId},
			"client_secret": {clientSecret},
		})

	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var res ApiTokenResult
	if err := json.NewDecoder(resp.Body).Decode(&res); err != nil {
		return nil, err
	}

	return &res, nil
}

func Token(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Code string `json:"code"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Can't decode request", http.StatusInternalServerError)
		log.Printf("Decoding error: %v", err)
		return
	}

	apiToken, err := apiToken(req.Code)
	if err != nil {
		http.Error(w, "Can't fetch token", http.StatusInternalServerError)
		log.Printf("apiToken error: %v", err)
		return
	}

	res := struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
		TokenType    string `json:"token_type"`
		ExpiresIn    int    `json:"expires_in"`
	}{
		apiToken.AccessToken,
		apiToken.RefreshToken,
		"Bearer",
		3600,
	}

	buf := new(bytes.Buffer)
	json.NewEncoder(buf).Encode(res)
	fmt.Fprint(w, buf)
}

func apiRefresh(refreshToken string) (*ApiTokenResult, error) {
	clientId := os.Getenv("SPOTIFY_CLIENT_ID")
	clientSecret := os.Getenv("SPOTIFY_CLIENT_SECRET")

	if clientId == "" || clientSecret == "" {
		return nil, errors.New("No client ID / secret set")
	}

	resp, err := http.PostForm("https://accounts.spotify.com/api/token",
		url.Values{
			"grant_type":    {"refresh_token"},
			"refresh_token": {refreshToken},
			"client_id":     {clientId},
			"client_secret": {clientSecret},
		})

	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var res ApiTokenResult
	if err := json.NewDecoder(resp.Body).Decode(&res); err != nil {
		return nil, err
	}

	// Only return changed new refresh tokens.
	if res.RefreshToken == refreshToken {
		res.RefreshToken = ""
	}

	return &res, nil
}

func Refresh(w http.ResponseWriter, r *http.Request) {
	var req struct {
		RefreshToken string `json:"refresh_token"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Can't decode request", http.StatusInternalServerError)
		log.Printf("Decoding error: %v", err)
		return
	}

	apiToken, err := apiRefresh(req.RefreshToken)
	if err != nil {
		http.Error(w, "Can't refresh token", http.StatusInternalServerError)
		log.Printf("apiRefresh error: %v", err)
		return
	}

	res := struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token,omitempty"`
		TokenType    string `json:"token_type"`
		ExpiresIn    int    `json:"expires_in"`
	}{
		apiToken.AccessToken,
		apiToken.RefreshToken,
		"Bearer",
		3600,
	}

	buf := new(bytes.Buffer)
	json.NewEncoder(buf).Encode(res)
	fmt.Fprint(w, buf)
}

// From https://gist.github.com/KhaosT/73d56a3cd0496aefaa74c8e320602547.
func encryptTrackKey(otherPublicKeyBytes []byte, trackKey []byte) ([]byte, error) {
	curve := elliptic.P256()

	ephemeraPrivateKey, err := ecdsa.GenerateKey(curve, rand.Reader)

	if err != nil {
		return nil, err
	}

	ephemeralPublicKey := elliptic.Marshal(curve, ephemeraPrivateKey.X, ephemeraPrivateKey.Y)

	otherPublicKeyX, otherPublicKeyY := elliptic.Unmarshal(curve, otherPublicKeyBytes)

	// ECDH
	x, _ := curve.ScalarMult(otherPublicKeyX, otherPublicKeyY, ephemeraPrivateKey.D.Bytes())
	shared_key := x.Bytes()

	// X963 KDF
	length := 32
	output := make([]byte, 0)
	outlen := 0
	counter := uint32(1)

	for outlen < length {
		h := sha256.New()
		h.Write(shared_key) // Key Material: ECDH Key

		counterBuf := make([]byte, 4)
		binary.BigEndian.PutUint32(counterBuf, counter)
		h.Write(counterBuf)

		h.Write(ephemeralPublicKey) // Shared Info: Our public key

		output = h.Sum(output)
		outlen += h.Size()
		counter += 1
	}

	// Key
	encryptionKey := output[0:16]
	iv := output[16:]

	// AES
	block, _ := aes.NewCipher(encryptionKey)
	aesgcm, _ := cipher.NewGCMWithNonceSize(block, 16)

	ct := aesgcm.Seal(nil, iv, trackKey, nil)

	return append(ephemeralPublicKey, ct...), nil
}

type LoadTrackResult struct {
	FileId   string // OGG file, base 62 encoded.
	TrackKey string // Encrypted and base 64 encoded.
}

func loadTrack(session *core.Session, trackId string, publicKey []byte) (*LoadTrackResult, error) {
	track, err := session.Mercury().GetTrack(utils.Base62ToHex(trackId))
	if err != nil {
		return nil, err
	}

	// Prefer 160 kbps, to reduce bandwidth. Fall back to 96 kbps / 320 kbps.
	var selectedFile *Spotify.AudioFile
	var selectedFormat Spotify.AudioFile_Format
	for _, file := range track.GetFile() {
		format := file.GetFormat()
		if (format == Spotify.AudioFile_OGG_VORBIS_96 && selectedFile == nil) ||
			(format == Spotify.AudioFile_OGG_VORBIS_320 && (selectedFile == nil || selectedFormat == Spotify.AudioFile_OGG_VORBIS_96)) ||
			format == Spotify.AudioFile_OGG_VORBIS_160 {
			selectedFormat = format
			selectedFile = file
		}
	}

	if selectedFile == nil {
		return nil, errors.New("Can't find OGG file")
	}

	trackKey, err := session.Player().LoadTrackKey(track.GetGid(), selectedFile.FileId)
	if err != nil {
		return nil, err
	}

	enc, err := encryptTrackKey(publicKey, trackKey)
	if err != nil {
		return nil, err
	}

	return &LoadTrackResult{
		utils.ConvertTo62(selectedFile.FileId),
		b64.StdEncoding.EncodeToString(enc)}, nil
}

type TrackResponse struct {
	TrackId  string `json:"track_id"`
	FileId   string `json:"file_id"`
	TrackKey string `json:"track_key"`
}

func Track(w http.ResponseWriter, r *http.Request) {
	var req struct {
		TrackId   string `json:"track_id"`
		Token     string `json:"token"`
		PublicKey string `json:"public_key"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Can't decode request", http.StatusInternalServerError)
		log.Printf("Decoding error: %v", err)
		return
	}

	publicKey, err := b64.StdEncoding.DecodeString(req.PublicKey)
	if err != nil {
		http.Error(w, "Can't decode public key", http.StatusInternalServerError)
		log.Printf("Error decoding public key: %v", err)
		return
	}

	session, err := core.LoginOAuthToken(req.Token, "librespot")
	if err != nil {
		http.Error(w, "Can't initialize session", http.StatusInternalServerError)
		log.Printf("Session login error: %v", err)
		return
	}

	track, err := loadTrack(session, req.TrackId, publicKey)
	if err != nil {
		http.Error(w, "Can't find track", http.StatusNotFound)
		log.Printf("loadTrack error for track ID %s: %v", req.TrackId, err)
		return
	}

	res := TrackResponse{
		req.TrackId,
		track.FileId,
		track.TrackKey,
	}

	buf := new(bytes.Buffer)
	json.NewEncoder(buf).Encode(res)
	fmt.Fprint(w, buf)
}

func Tracks(w http.ResponseWriter, r *http.Request) {
	var req struct {
		TrackIds  []string `json:"track_ids"`
		Token     string   `json:"token"`
		PublicKey string   `json:"public_key"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Can't decode request", http.StatusInternalServerError)
		log.Printf("Decoding error: %v", err)
		return
	}

	publicKey, err := b64.StdEncoding.DecodeString(req.PublicKey)
	if err != nil {
		http.Error(w, "Can't decode public key", http.StatusInternalServerError)
		log.Printf("Error decoding public key: %v", err)
		return
	}

	session, err := core.LoginOAuthToken(req.Token, "librespot")
	if err != nil {
		http.Error(w, "Can't initialize session", http.StatusInternalServerError)
		log.Printf("Session login error: %v", err)
		return
	}

	var res struct {
		Tracks []TrackResponse `json:"tracks"`
	}

	for _, trackId := range req.TrackIds {
		track, err := loadTrack(session, trackId, publicKey)

		if err != nil {
			log.Printf("loadTrack error for track ID %s: %v", trackId, err)
		} else {
			res.Tracks = append(res.Tracks, TrackResponse{trackId, track.FileId, track.TrackKey})
		}
	}

	buf := new(bytes.Buffer)
	json.NewEncoder(buf).Encode(res)
	fmt.Fprint(w, buf)
}

func trackUrl(accessToken string, fileId string) (*string, error) {
	// Convert file ID from base 62 to hex.
	url := "https://api.spotify.com/v1/storage-resolve/files/audio/interactive/" + utils.Base62ToHex(fileId) + "?alt=json"
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Add("Authorization", "Bearer "+accessToken)
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var res struct {
		CdnUrl []string `json:"cdnurl"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&res); err != nil {
		return nil, err
	}

	if len(res.CdnUrl) > 0 {
		return &res.CdnUrl[0], nil
	}

	return nil, errors.New("Empty URL list")
}

func StorageResolve(w http.ResponseWriter, r *http.Request) {
	var req struct {
		AccessToken string `json:"access_token"`
		FileId      string `json:"file_id"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Can't decode request", http.StatusInternalServerError)
		log.Printf("Decoding error: %v", err)
		return
	}

	url, err := trackUrl(req.AccessToken, req.FileId)
	if err != nil {
		http.Error(w, "File not found", http.StatusNotFound)
		log.Printf("trackUrl error for file ID %s: %v", req.FileId, err)
		return
	}

	res := struct {
		Url string `json:"url"`
	}{
		*url,
	}

	buf := new(bytes.Buffer)
	json.NewEncoder(buf).Encode(res)
	fmt.Fprint(w, buf)
}
