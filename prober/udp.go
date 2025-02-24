// Copyright 2016 The Prometheus Authors
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package prober

import (
	"bufio"
	"context"
	"fmt"
	"encoding/hex"
	"net"
	"log"
	"regexp"

	"github.com/prometheus/blackbox_exporter/config"
	"github.com/prometheus/client_golang/prometheus"
)

func dialUDP(ctx context.Context, target string, module config.Module, registry *prometheus.Registry, logger log.Logger) (net.Conn, error) {
	var dialProtocol, dialTarget string
	dialer := &net.Dialer{}
	targetAddress, port, err := net.SplitHostPort(target)
	if err != nil {
		log.Printf("Error splitting target address and port: %v", err)
		return nil, err
	}

	ip, err := chooseProtocol(ctx, module.UDP.IPProtocol, false, targetAddress, registry, logger)
	if err != nil {
		log.Printf("Error resolving address: %v",  err)
		return nil, err
	}

	if ip.IP.To4() == nil {
		dialProtocol = "udp6"
	} else {
		dialProtocol = "udp4"
	}
	dialTarget = net.JoinHostPort(ip.String(), port)
	log.Printf("Error dialing UDP: %v", err)
	return dialer.DialContext(ctx, dialProtocol, dialTarget)
}

func ProbeUDP(ctx context.Context, target string, module config.Module, registry *prometheus.Registry, logger log.Logger) bool {
	probeFailedDueToRegex := prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "probe_failed_due_to_regex",
		Help: "Indicates if probe failed due to regex",
	})
	registry.MustRegister(probeFailedDueToRegex)
	deadline, _ := ctx.Deadline()

	conn, err := dialUDP(ctx, target, module, registry, logger)
	if err != nil {
		log.Printf("Error dialing UDP", err)
		return false
	}
	defer conn.Close()
	log.Println("Successfully dialed")
	// Set a deadline to prevent the following code from blocking forever.
	// If a deadline cannot be set, better fail the probe by returning an error
	// now rather than blocking forever.
	if err := conn.SetDeadline(deadline); err != nil {
		log.Printf("Error setting deadline: %v", err)
		return false
	}

	scanner := bufio.NewScanner(conn)
	for i, qr := range module.UDP.QueryResponse {
		log.Println("Processing query response entry", i)
		send := qr.Send
		if qr.Expect.Regexp != nil {
			re, err := regexp.Compile(qr.Expect.String())
			if err != nil {
				log.Printf("msg", "Could not compile into regular expression", qr.Expect, err)
				return false
			}
			var match []int
			// Read lines until one of them matches the configured regexp.
			for scanner.Scan() {
				log.Printf("Read line: %s", scanner.Text())
				match = re.FindSubmatchIndex(scanner.Bytes())
				if match != nil {
					log.Println("Regexp matched", re, scanner.Text())
					break
				}
			}
			if scanner.Err() != nil {
				log.Printf("Error reading from connection: %v", scanner.Err().Error())
				return false
			}
			if match == nil {
				probeFailedDueToRegex.Set(1)
				log.Printf("Regexp did not match", scanner.Text())
				return false
			}
			probeFailedDueToRegex.Set(0)
			send = string(re.Expand(nil, []byte(send), scanner.Bytes(), match))
		}
		if qr.SendHex != "" {
			sendBytes, err := hex.DecodeString(qr.SendHex)
			if err != nil {
				log.Printf("Failed to decode hex string: %v", err)
				return false
			}
			if _, err := conn.Write(sendBytes); err != nil {
				log.Printf("Failed to send: %v", err)
				return false
			}
		} else if send != "" {
			log.Printf("Sending line: %s", send)
			if _, err := fmt.Fprintf(conn, "%s\n", send); err != nil {
				log.Printf("Failed to send: %v", err)
				return false
			}
		}
	}
	return true
}
