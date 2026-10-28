package main

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"net"
	"net/netip"
	"strings"
	"time"

	"github.com/caarlos0/env"
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

type params struct {
	SocksPort string `env:"SOCKS_PORT" envDefault:"1080"`
	// WireGuard Params
	WgPrivateKey    string `env:"WIREGUARD_INTERFACE_PRIVATE_KEY"`
	WgAddress       string `env:"WIREGUARD_INTERFACE_ADDRESS"` // e.g., 10.0.0.2/32
	WgPeerPublicKey string `env:"WIREGUARD_PEER_PUBLIC_KEY"`
	WgPeerEndpoint  string `env:"WIREGUARD_PEER_ENDPOINT"`     // e.g., 1.2.3.4:51820
	WgDNS           string `env:"WIREGUARD_INTERFACE_DNS" envDefault:"1.1.1.1"`
}

var tnet *netstack.Net

func transfer(destination io.WriteCloser, source io.ReadCloser) {
	defer destination.Close()
	defer source.Close()
	io.Copy(destination, source)
}

func startWireGuard(cfg *params) error {
	if cfg.WgPrivateKey == "" || cfg.WgPeerEndpoint == "" {
		log.Println("[INFO] WireGuard config missing. Auto-generating Cloudflare WARP configuration...")
		warpCfg, err := RegisterWarp()
		if err != nil {
			return fmt.Errorf("auto WARP registration failed: %w", err)
		}
		cfg.WgPrivateKey = warpCfg.PrivateKey
		cfg.WgAddress = warpCfg.Address
		cfg.WgPeerPublicKey = warpCfg.PeerPublicKey
		cfg.WgPeerEndpoint = warpCfg.PeerEndpoint
		if cfg.WgDNS == "" {
			cfg.WgDNS = warpCfg.DNS
		}
		log.Printf("[SUCCESS] WARP registered. Local IP: %s, Peer: %s", cfg.WgAddress, cfg.WgPeerEndpoint)
	}

	log.Println("[INFO] Initializing Userspace WireGuard with Cloudflare WARP...")

	localIPs := []netip.Addr{}
	if cfg.WgAddress != "" {
		addrStr := strings.Split(cfg.WgAddress, "/")[0]
		addr, err := netip.ParseAddr(addrStr)
		if err == nil {
			localIPs = append(localIPs, addr)
			log.Printf("[INFO] Local VPN IP: %s", addr)
		} else {
			log.Printf("[WARN] Failed to parse local IP: %v", err)
		}
	}
	
	dnsIP, err := netip.ParseAddr(cfg.WgDNS)
	if err != nil {
		log.Printf("[WARN] Failed to parse DNS IP, using default: %v", err)
		dnsIP, _ = netip.ParseAddr("1.1.1.1")
	}
	log.Printf("[INFO] DNS Server: %s", dnsIP)

	log.Println("[INFO] Creating virtual network interface...")
	tunDev, tnetInstance, err := netstack.CreateNetTUN(
		localIPs,
		[]netip.Addr{dnsIP},
		1420,
	)
	if err != nil {
		return fmt.Errorf("failed to create TUN: %w", err)
	}
	tnet = tnetInstance

	log.Println("[INFO] Initializing WireGuard device...")
	dev := device.NewDevice(tunDev, conn.NewDefaultBind(), device.NewLogger(device.LogLevelSilent, ""))
	
	privateKeyHex, err := base64ToHex(cfg.WgPrivateKey)
	if err != nil {
		return fmt.Errorf("invalid private key (base64 decode failed): %w", err)
	}

	publicKeyHex, err := base64ToHex(cfg.WgPeerPublicKey)
	if err != nil {
		return fmt.Errorf("invalid peer public key (base64 decode failed): %w", err)
	}

	uapi := fmt.Sprintf(`private_key=%s
public_key=%s
endpoint=%s
allowed_ip=0.0.0.0/0
`, privateKeyHex, publicKeyHex, cfg.WgPeerEndpoint)

	if err := dev.IpcSet(uapi); err != nil {
		return fmt.Errorf("failed to configure device: %w", err)
	}
	
	if err := dev.Up(); err != nil {
		return fmt.Errorf("failed to bring up device: %w", err)
	}

	log.Println("[SUCCESS] WireGuard interface is UP - All traffic will route through VPN")
	return nil
}

func main() {
	log.SetFlags(log.LstdFlags | log.Lmsgprefix)
	log.Println("[STARTUP] Initializing SOCKS5 Proxy with Userspace WireGuard")
	
	cfg := params{}
	if err := env.Parse(&cfg); err != nil {
		log.Printf("[WARN] Config parse warning: %+v\n", err)
	}

	if err := startWireGuard(&cfg); err != nil {
		log.Fatalf("[FATAL] Failed to start WireGuard: %v", err)
	}

	// Start SOCKS5 Proxy
	log.Printf("[STARTUP] Starting SOCKS5 proxy server on 127.0.0.1:%s\n", cfg.SocksPort)
	listener, err := net.Listen("tcp", "127.0.0.1:"+cfg.SocksPort)
	if err != nil {
		log.Fatalf("[FATAL] Failed to start SOCKS5 listener: %v", err)
	}

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("[ERROR] SOCKS5 Accept failed: %v", err)
			continue
		}
		go handleSocks(conn)
	}
}

func handleSocks(clientConn net.Conn) {
	defer clientConn.Close()
	remoteAddr := clientConn.RemoteAddr().String()

	// SOCKS5 Handshake
	buf := make([]byte, 256)
	if _, err := io.ReadFull(clientConn, buf[:2]); err != nil {
		return
	}
	if buf[0] != 0x05 { // SOCKS5
		// Silence noise from local loopback probes (often from Render/cloud health checks)
		if !strings.HasPrefix(remoteAddr, "127.0.0.1") && !strings.HasPrefix(remoteAddr, "[::1]") {
			log.Printf("[SOCKS] Dropped non-SOCKS5 connection from %s", remoteAddr)
		}
		return
	}
	nMethods := int(buf[1])
	if _, err := io.ReadFull(clientConn, buf[:nMethods]); err != nil {
		return
	}
	// Select "No Authentication"
	clientConn.Write([]byte{0x05, 0x00})

	// SOCKS5 Request
	if _, err := io.ReadFull(clientConn, buf[:4]); err != nil {
		return
	}
	if buf[1] != 0x01 { // CONNECT command only
		return
	}

	var addr string
	switch buf[3] {
	case 0x01: // IPv4
		if _, err := io.ReadFull(clientConn, buf[:4]); err != nil {
			return
		}
		addr = net.IP(buf[:4]).String()
	case 0x03: // Domain name
		if _, err := io.ReadFull(clientConn, buf[:1]); err != nil {
			return
		}
		addrLen := int(buf[0])
		if _, err := io.ReadFull(clientConn, buf[:addrLen]); err != nil {
			return
		}
		addr = string(buf[:addrLen])
	case 0x04: // IPv6
		if _, err := io.ReadFull(clientConn, buf[:16]); err != nil {
			return
		}
		addr = net.IP(buf[:16]).String()
	default:
		return
	}

	if _, err := io.ReadFull(clientConn, buf[:2]); err != nil {
		return
	}
	port := (int(buf[0]) << 8) | int(buf[1])
	dest := fmt.Sprintf("%s:%d", addr, port)

	log.Printf("[SOCKS] Connection: %s -> %s", remoteAddr, dest)

	// Dial destination
	var destConn net.Conn
	var err error
	if tnet == nil {
		destConn, err = net.DialTimeout("tcp", dest, 15*time.Second)
	} else {
		// Use tnet.Dial but wrap it in a timeout if possible, 
		// though netstack.Dial usually manages its own timeouts/retransmits
		destConn, err = tnet.Dial("tcp", dest)
	}

	if err != nil {
		log.Printf("[SOCKS] Dial failed to %s: %v", dest, err)
		clientConn.Write([]byte{0x05, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}
	defer destConn.Close()

	// Success response
	clientConn.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0})

	go transfer(destConn, clientConn)
	transfer(clientConn, destConn)
	log.Printf("[SOCKS] Closed: %s -> %s", remoteAddr, dest)
}

func base64ToHex(b64 string) (string, error) {
	decoded, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(decoded), nil
}
