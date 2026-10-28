package warp

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"golang.org/x/crypto/curve25519"
)

type WarpConfig struct {
	PrivateKey    string
	Address       string
	PeerPublicKey string
	PeerEndpoint  string
	DNS           string
}

type cloudflareResponse struct {
	Result *struct {
		ID      string `json:"id"`
		Token   string `json:"token"`
		Config  *struct {
			Peers []struct {
				PublicKey string `json:"public_key"`
				Endpoint  *struct {
					V4   string `json:"v4"`
					V6   string `json:"v6"`
					Host string `json:"host"`
				} `json:"endpoint"`
			} `json:"peers"`
			Interface *struct {
				Addresses *struct {
					V4 string `json:"v4"`
					V6 string `json:"v6"`
				} `json:"addresses"`
			} `json:"interface"`
		} `json:"config"`
	} `json:"result"`
	Success bool     `json:"success"`
	Errors  []string `json:"errors"`
}

// Register registers a new device with Cloudflare WARP and enables WARP routing.
func Register() (*WarpConfig, error) {
	pk := new([32]byte)
	sk := new([32]byte)
	if _, err := io.ReadFull(rand.Reader, sk[:]); err != nil {
		return nil, fmt.Errorf("failed to generate random key: %w", err)
	}

	curve25519.ScalarBaseMult(pk, sk)

	privB64 := base64.StdEncoding.EncodeToString(sk[:32])
	pubB64 := base64.StdEncoding.EncodeToString(pk[:32])

	reqBody := strings.NewReader(fmt.Sprintf(
		`{"key":"%s","tos":"%s","type":"ios","model":"iPhone11,6","fcm_token":"","device_token":""}`,
		pubB64,
		time.Now().Format(time.RFC3339),
	))

	client := &http.Client{Timeout: 15 * time.Second}

	req, err := http.NewRequest("POST", "https://api.cloudflareclient.com/v0i2003111800/reg", reqBody)
	if err != nil {
		return nil, fmt.Errorf("failed to create registration request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/plain, */*")
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")

	res, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("registration request failed: %w", err)
	}
	defer res.Body.Close()

	resBytes, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read registration response: %w", err)
	}

	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("registration API failed with status %d: %s", res.StatusCode, string(resBytes))
	}

	var resp cloudflareResponse
	if err := json.Unmarshal(resBytes, &resp); err != nil {
		return nil, fmt.Errorf("failed to parse registration response: %w", err)
	}

	if resp.Result == nil || resp.Result.Config == nil || len(resp.Result.Config.Peers) == 0 {
		return nil, fmt.Errorf("invalid registration response: missing config or peers")
	}

	// Enable WARP via PATCH
	patchBody := strings.NewReader(`{"warp_enabled":true}`)
	patchReq, err := http.NewRequest("PATCH", "https://api.cloudflareclient.com/v0i2003111800/reg/"+resp.Result.ID, patchBody)
	if err != nil {
		return nil, fmt.Errorf("failed to create patch request: %w", err)
	}

	patchReq.Header.Set("Content-Type", "application/json")
	patchReq.Header.Set("Accept", "application/json, text/plain, */*")
	patchReq.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")
	patchReq.Header.Set("Authorization", "Bearer "+resp.Result.Token)

	patchRes, err := client.Do(patchReq)
	if err != nil {
		return nil, fmt.Errorf("enable WARP request failed: %w", err)
	}
	defer patchRes.Body.Close()

	if patchRes.StatusCode != http.StatusOK {
		patchBytes, _ := io.ReadAll(patchRes.Body)
		return nil, fmt.Errorf("enable WARP API failed with status %d: %s", patchRes.StatusCode, string(patchBytes))
	}

	v4Addr := ""
	if resp.Result.Config.Interface != nil && resp.Result.Config.Interface.Addresses != nil {
		v4Addr = resp.Result.Config.Interface.Addresses.V4
	}
	if v4Addr == "" {
		v4Addr = "172.16.0.2"
	}

	peerPub := resp.Result.Config.Peers[0].PublicKey
	endpoint := "162.159.192.5:2408"

	return &WarpConfig{
		PrivateKey:    privB64,
		Address:       v4Addr + "/32",
		PeerPublicKey: peerPub,
		PeerEndpoint:  endpoint,
		DNS:           "1.1.1.1",
	}, nil
}

// FormatWireGuardConfig formats WarpConfig in standard WireGuard INI format.
func (cfg *WarpConfig) FormatWireGuardConfig() string {
	return fmt.Sprintf(`[Interface]
PrivateKey = %s
DNS = %s
Address = %s

[Peer]
PublicKey = %s
AllowedIPs = 0.0.0.0/0
Endpoint = %s
`, cfg.PrivateKey, cfg.DNS, cfg.Address, cfg.PeerPublicKey, cfg.PeerEndpoint)
}
