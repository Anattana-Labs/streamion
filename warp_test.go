package main

import (
	"bufio"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/curve25519"
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

type warpResponse struct {
	Result *struct {
		ID      string
		Config  *struct {
			Peers []struct {
				PublicKey string `json:"public_key"`
			}
			Interface *struct {
				Addresses *struct {
					V4 string
				}
			}
		}
		Token string
	}
	Success bool
}

func base64ToHexTest(b64 string) (string, error) {
	decoded, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(decoded), nil
}

func TestWarpAndWireGuardTunnel(t *testing.T) {
	pk := new([32]byte)
	sk := new([32]byte)
	_, err := io.ReadFull(rand.Reader, sk[:])
	if err != nil {
		t.Fatalf("rand failed: %v", err)
	}

	curve25519.ScalarBaseMult(pk, sk)

	reqBody := strings.NewReader(`{"key":"` + base64.StdEncoding.EncodeToString(pk[:]) + `","tos":"` + time.Now().Format(time.RFC3339) + `","type":"ios","model":"iPhone11,6","fcm_token":"","device_token":""}`)

	req, err := http.NewRequest("POST", "https://api.cloudflareclient.com/v0i2003111800/reg", reqBody)
	if err != nil {
		t.Fatalf("req failed: %v", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "okhttp/3.12.1")

	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("HTTP Do failed: %v", err)
	}
	defer res.Body.Close()

	resBytes, err := io.ReadAll(res.Body)
	if err != nil {
		t.Fatalf("ReadAll failed: %v", err)
	}

	if res.StatusCode != 200 {
		t.Fatalf("Registration failed (%d): %s", res.StatusCode, string(resBytes))
	}

	var regResp warpResponse
	err = json.Unmarshal(resBytes, &regResp)
	if err != nil {
		t.Fatalf("json unmarshal failed: %v", err)
	}

	// Enable WARP
	reqBody = strings.NewReader(`{"warp_enabled":true}`)
	patchReq, err := http.NewRequest("PATCH", "https://api.cloudflareclient.com/v0i2003111800/reg/"+regResp.Result.ID, reqBody)
	if err != nil {
		t.Fatalf("patch req failed: %v", err)
	}
	patchReq.Header.Set("Content-Type", "application/json")
	patchReq.Header.Set("Authorization", "Bearer "+regResp.Result.Token)
	patchReq.Header.Set("User-Agent", "okhttp/3.12.1")

	patchRes, err := http.DefaultClient.Do(patchReq)
	if err != nil {
		t.Fatalf("patch Do failed: %v", err)
	}
	defer patchRes.Body.Close()
	if patchRes.StatusCode != 200 {
		b, _ := io.ReadAll(patchRes.Body)
		t.Fatalf("enable warp failed (%d): %s", patchRes.StatusCode, string(b))
	}

	v4Addr := regResp.Result.Config.Interface.Addresses.V4
	peerPub := regResp.Result.Config.Peers[0].PublicKey
	endpoint := "162.159.192.5:2408"

	localIP, err := netip.ParseAddr(v4Addr)
	if err != nil {
		t.Fatalf("parse local IP failed: %v", err)
	}
	dnsIP, _ := netip.ParseAddr("1.1.1.1")

	tunDev, tnetInstance, err := netstack.CreateNetTUN([]netip.Addr{localIP}, []netip.Addr{dnsIP}, 1420)
	if err != nil {
		t.Fatalf("create tun failed: %v", err)
	}

	dev := device.NewDevice(tunDev, conn.NewDefaultBind(), device.NewLogger(device.LogLevelVerbose, "[WG] "))

	privHex, _ := base64ToHexTest(base64.StdEncoding.EncodeToString(sk[:]))
	pubHex, _ := base64ToHexTest(peerPub)

	uapi := fmt.Sprintf("private_key=%s\npublic_key=%s\nendpoint=%s\nallowed_ip=0.0.0.0/0\n", privHex, pubHex, endpoint)
	if err := dev.IpcSet(uapi); err != nil {
		t.Fatalf("ipcset failed: %v", err)
	}

	if err := dev.Up(); err != nil {
		t.Fatalf("dev.up failed: %v", err)
	}
	defer dev.Close()

	// Wait a moment for handshake
	time.Sleep(2 * time.Second)

	// Test Dialing cloudflare.com:80 by domain name
	conn, err := tnetInstance.Dial("tcp", "cloudflare.com:80")
	if err != nil {
		t.Fatalf("Dial domain through VPN failed: %v", err)
	}
	defer conn.Close()

	fmt.Fprintf(conn, "GET /cdn-cgi/trace HTTP/1.1\r\nHost: cloudflare.com\r\nConnection: close\r\n\r\n")

	scanner := bufio.NewScanner(conn)
	var traceOutput []string
	for scanner.Scan() {
		line := scanner.Text()
		traceOutput = append(traceOutput, line)
		if strings.HasPrefix(line, "warp=") || strings.HasPrefix(line, "ip=") {
			t.Logf("VPN Trace: %s", line)
		}
	}
	t.Logf("Full response: %s", strings.Join(traceOutput, "\n"))
}
