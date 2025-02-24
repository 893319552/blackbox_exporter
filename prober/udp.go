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
	"log/slog"
	"regexp"

	"github.com/prometheus/blackbox_exporter/config"
	"github.com/prometheus/client_golang/prometheus"
)

func dialUDP(ctx context.Context, target string, module config.Module, registry *prometheus.Registry, logger *slog.Logger) (net.Conn, error) {
	var dialProtocol, dialTarget string
	dialer := &net.Dialer{}
	targetAddress, port, err := net.SplitHostPort(target)
	if err != nil {
		logger.Error("Error splitting target address and port", "err", err)
		return nil, err
	}

	ip, err := chooseProtocol(ctx, module.UDP.IPProtocol, false, targetAddress, registry, logger)
	if err != nil {
		logger.Error("Error resolving address", "err", err)
		return nil, err
	}

	if ip.IP.To4() == nil {
		dialProtocol = "udp6"
	} else {
		dialProtocol = "udp4"
	}
	dialTarget = net.JoinHostPort(ip.String(), port)
	logger.Error("Error dialing UDP", "err", err)
	return dialer.DialContext(ctx, dialProtocol, dialTarget)
}

func ProbeUDP(ctx context.Context, target string, module config.Module, registry *prometheus.Registry, logger *slog.Logger) bool {
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
		logger.Error("Error setting deadline", "err", err)
		return false
	}

	scanner := bufio.NewScanner(conn)
	for i, qr := range module.UDP.QueryResponse {
		logger.Info("Processing query response entry", "entry_number", i)
		send := qr.Send
		if qr.Expect.Regexp != nil {
			re, err := regexp.Compile(qr.Expect.String())
			if err != nil {
				logger.Error("msg", "Could not compile into regular expression", qr.Expect, err)
				return false
			}
			var match []int
			// Read lines until one of them matches the configured regexp.
			for scanner.Scan() {
				log.Printf("Read line: %s", scanner.Text())
				match = re.FindSubmatchIndex(scanner.Bytes())
				if match != nil {
					logger.Info("Regexp matched", re, scanner.Text())
					break
				}
			}
			if scanner.Err() != nil {
				logger.Error("Error reading from connection", "err", scanner.Err().Error())
				return false
			}
			if match == nil {
				probeFailedDueToRegex.Set(1)
				logger.Error("Regexp did not match", "regexp", qr.Expect.Regexp, "line", scanner.Text())
				return false
			}
			probeFailedDueToRegex.Set(0)
			send = string(re.Expand(nil, []byte(send), scanner.Bytes(), match))
		}
		if qr.SendHex != "" {
			sendBytes, err := hex.DecodeString(qr.SendHex)
			if err != nil {
				logger.Error("Failed to decode hex string", "err", err)
				return false
			}
			if _, err := conn.Write(sendBytes); err != nil {
				logger.Error("Failed to send", "err", err)
				return false
			}
		} else if send != "" {
			log.Printf("Sending line: %s", send)
			if _, err := fmt.Fprintf(conn, "%s\n", send); err != nil {
				logger.Error("Failed to send", "err", err)
				return false
			}
		}
	}
	return true
}
