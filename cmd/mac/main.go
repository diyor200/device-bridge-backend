// Command mac is the macOS bridge helper: a small CLI that runs the Go core,
// advertises and discovers devices over mDNS, and pairs and exchanges text
// messages. It will later back the SwiftUI app via IPC.
package main

import (
	"bufio"
	"context"
	"encoding/base64"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"

	"github.com/diyorbekabdulaxatov/device-bridge/internal/device"
	"github.com/diyorbekabdulaxatov/device-bridge/internal/pairing"
	"github.com/diyorbekabdulaxatov/device-bridge/internal/transport/mdns"
)

type knownPeer struct {
	Name string
	Addr string
	Key  []byte
}

func main() {
	name := flag.String("name", "", "device display name")
	dir := flag.String("dir", "", "data directory (identity + trust store)")
	port := flag.Int("port", 0, "listen port (0 selects a random port)")
	flag.Parse()

	if *name == "" || *dir == "" {
		fmt.Fprintln(os.Stderr, "usage: bridge -name <name> -dir <dir> [-port <port>]")
		os.Exit(2)
	}

	node, err := device.New(device.Config{
		DataDir:    *dir,
		Name:       *name,
		ListenAddr: fmt.Sprintf("0.0.0.0:%d", *port),
	})
	if err != nil {
		log.Fatalf("device: %v", err)
	}
	defer node.Close()
	if err := node.Start(); err != nil {
		log.Fatalf("start: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	ann, err := mdns.NewAnnouncer(mdns.Config{
		DeviceID:  node.DeviceID(),
		Name:      node.Name(),
		Port:      portFromAddr(node.ListenAddr()),
		PublicKey: node.PublicKey(),
	})
	if err != nil {
		log.Fatalf("advertise: %v", err)
	}
	defer ann.Close()

	disc := mdns.NewDiscoverer(nil)
	peersCh, err := disc.Run(ctx)
	if err != nil {
		log.Fatalf("discover: %v", err)
	}

	var mu sync.Mutex
	peers := map[string]knownPeer{}
	go func() {
		for p := range peersCh {
			if p.DeviceID == node.DeviceID() {
				continue
			}
			mu.Lock()
			peers[p.DeviceID] = knownPeer{Name: p.Name, Addr: p.Addr(), Key: p.PublicKey}
			mu.Unlock()
			fmt.Printf("[discovered] %s (%s)\n", p.Name, shortID(p.DeviceID))
		}
	}()

	node.PairHandler = func(info pairing.Info) bool {
		fmt.Printf("[pair request] %s (%s) — accepting\n", info.Name, shortID(info.DeviceID))
		return true
	}
	node.MessageHandler = func(from, text string) {
		fmt.Printf("[message] %s: %s\n", shortID(from), text)
	}

	fmt.Printf("Device Bridge: %s (%s)\n", node.Name(), shortID(node.DeviceID()))
	fmt.Printf("[this device] id=%s addr=%s key=%s\n",
		node.DeviceID(), node.ListenAddr(), base64.StdEncoding.EncodeToString(node.PublicKey()))
	fmt.Println("commands: list | pair <id> | send <id> <text> | pair-with <id> <addr> <key> | quit")

	scanner := bufio.NewScanner(os.Stdin)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		switch fields[0] {
		case "list":
			mu.Lock()
			if len(peers) == 0 {
				fmt.Println("no devices found")
			} else {
				for id, p := range peers {
					fmt.Printf("  %s  %s  %s\n", shortID(id), p.Name, p.Addr)
				}
			}
			mu.Unlock()

		case "pair":
			if len(fields) < 2 {
				fmt.Println("usage: pair <id>")
				continue
			}
			p, ok := lookup(&mu, peers, fields[1])
			if !ok {
				fmt.Println("unknown device")
				continue
			}
			pair(ctx, node, device.Peer{DeviceID: p.id, Name: p.peer.Name, Addr: p.peer.Addr, PublicKey: p.peer.Key})

		case "pair-with":
			if len(fields) < 4 {
				fmt.Println("usage: pair-with <id> <addr> <base64-key>")
				continue
			}
			key, err := base64.StdEncoding.DecodeString(fields[3])
			if err != nil {
				fmt.Printf("invalid key: %v\n", err)
				continue
			}
			mu.Lock()
			peers[fields[1]] = knownPeer{Name: fields[1], Addr: fields[2], Key: key}
			mu.Unlock()
			pair(ctx, node, device.Peer{DeviceID: fields[1], Name: fields[1], Addr: fields[2], PublicKey: key})

		case "send":
			if len(fields) < 3 {
				fmt.Println("usage: send <id> <text>")
				continue
			}
			p, ok := lookup(&mu, peers, fields[1])
			if !ok {
				fmt.Println("unknown device")
				continue
			}
			if err := node.SendText(ctx, p.id, p.peer.Addr, strings.Join(fields[2:], " ")); err != nil {
				fmt.Printf("send failed: %v\n", err)
			}

		case "quit", "exit":
			return

		default:
			fmt.Println("unknown command")
		}
	}
}

type resolved struct {
	id   string
	peer knownPeer
}

func lookup(mu *sync.Mutex, peers map[string]knownPeer, q string) (resolved, bool) {
	mu.Lock()
	defer mu.Unlock()
	for id, p := range peers {
		if id == q || strings.HasPrefix(id, q) || strings.EqualFold(p.Name, q) {
			return resolved{id: id, peer: p}, true
		}
	}
	return resolved{}, false
}

func pair(ctx context.Context, node *device.Node, peer device.Peer) {
	if err := node.Pair(ctx, peer); err != nil {
		fmt.Printf("pair failed: %v\n", err)
		return
	}
	fmt.Printf("paired with %s (%s)\n", peer.Name, shortID(peer.DeviceID))
}

func shortID(id string) string {
	if len(id) > 8 {
		return id[:8]
	}
	return id
}

func portFromAddr(addr string) int {
	_, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return 0
	}
	p, _ := strconv.Atoi(portStr)
	return p
}
