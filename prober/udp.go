package prober

import (
    "context"
    "encoding/hex"
    "net"
    "regexp"

    "github.com/prometheus/blackbox_exporter/config"
    "github.com/prometheus/client_golang/prometheus"
    "log/slog"
)

func ProbeUDP(ctx context.Context, target string, module config.Module, registry *prometheus.Registry, logger *slog.Logger) bool {
	probeFailedDueToRegex := prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "probe_failed_due_to_regex",
		Help: "Indicates if probe failed due to regex",
	})
	registry.MustRegister(probeFailedDueToRegex)
	deadline, _ := ctx.Deadline()

	packetConn, err := net.ListenPacket("udp", ":0")
	if err != nil {
		logger.Error("Error creating UDP packet connection", "err", err)
		return false
	}
	defer packetConn.Close()
	logger.Info("Successfully created UDP packet connection")
	if err := packetConn.SetDeadline(deadline); err != nil {
		logger.Error("Error setting deadline", "err", err)
		return false
	}

	targetAddr, err := net.ResolveUDPAddr("udp", target)
	if err != nil {
		logger.Error("Error resolving target address", "err", err)
		return false
	}

	buf := make([]byte, 1024)
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
			for {
				n, _, err := packetConn.ReadFrom(buf)
				if err != nil {
					logger.Error("Error reading from connection", "err", err)
					return false
				}
				logger.Debug("Read bytes", "bytes", buf[:n])
				match = re.FindSubmatchIndex(buf[:n])
				if match != nil {
					logger.Info("Regexp matched", "regexp", re.String(), "data", string(buf[:n]))
					break
				}
			}
			if match == nil {
				probeFailedDueToRegex.Set(1)
				logger.Error("Regexp did not match", "regexp", qr.Expect.Regexp)
				return false
			}
			probeFailedDueToRegex.Set(0)
			send = string(re.Expand(nil, []byte(send), buf, match))
		}
		sendBytes := []byte(send)
		if qr.SendHex != "" {
			var err error
			sendBytes, err = hex.DecodeString(qr.SendHex)
			if err != nil {
				logger.Error("Failed to decode hex string", "err", err)
				return false
			}
		}
		if len(sendBytes) > 0 {
			logger.Debug("Sending bytes", "bytes", sendBytes)
			if _, err := packetConn.WriteTo(sendBytes, targetAddr); err != nil {
				logger.Error("Failed to send", "err", err)
				return false
			}
			packetConn.Close()
			return true
		}
	}
	return true
}
