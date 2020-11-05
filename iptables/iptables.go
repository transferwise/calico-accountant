package iptables

import (
	"bufio"
	"bytes"
	"errors"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"io"
	"os/exec"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/monzo/calico-accountant/watch"
	apiv3 "github.com/projectcalico/libcalico-go/lib/apis/v3"
)

type ChainType int
type CountType int

const (
	ToWorkLoad ChainType = iota
	FromWorkLoad
	Drop CountType = iota
	Accept
	AcceptedDrop
)

func chainTypeFromString(str string) ChainType {
	switch str {
	case "fw":
		return FromWorkLoad
	case "tw":
		return ToWorkLoad
	default:
		zap.L().Fatal("Unsupported chain type", zap.String("chain_type", str))
		// unreachable
		return 0
	}
}

func (ct ChainType) String() string {
	switch ct {
	case ToWorkLoad:
		return "tw"
	case FromWorkLoad:
		return "fw"
	default:
		zap.L().Fatal("Unsupported chain type", zap.String("chain_type", ct.String()))
		// unreachable
		return ""
	}
}

func (result *Result) MarshalLogObject(enc zapcore.ObjectEncoder) error {
	enc.AddString("pod_name", result.PodName)
	enc.AddString("pod_namespace", result.PodNamespace)
	enc.AddString("app_label", result.AppLabel)
	enc.AddString("pod_ip", result.PodIP)
	enc.AddString("target", result.Target)
	enc.AddInt("pkt_count", result.PacketCount)
	return nil
}

type Result struct {
	PodName      string
	PodNamespace string
	AppLabel     string
	PodIP        string
	ChainType    ChainType
	CountType    CountType
	PacketCount  int
	Target       string
}

type DropChain struct {
	PacketCount int
}

func Scan(cw watch.CalicoWatcher) ([]*Result, error) {
	// first build a mapping from interface names to workload endpoints
	workloads := cw.ListWorkloadEndpoints()

	interfaceToWorkload := make(map[string]*apiv3.WorkloadEndpoint, len(workloads))
	for _, w := range workloads {
		interfaceToWorkload[w.Spec.InterfaceName] = w
	}

	return iptablesSave(interfaceToWorkload)
}

var (
	appendRegexp    = regexp.MustCompile(`^\[(\d+):\d+] -A cali-([tf]w)-(\S+).*-j (\S+)$`)
	dropPolicyRegex = regexp.MustCompile(`^\[(\d+):\d+] -A (cali-(p[io])-(\S+)).*-j DROP$`)
	dropSlice       = []byte("Drop if no policies passed packet")
	acceptSlice     = []byte("Return if policy accepted")
)

func iptablesSave(interfaceToWorkload map[string]*apiv3.WorkloadEndpoint) ([]*Result, error) {
	cmd := exec.Command("iptables-save", "-t", "filter", "-c")

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		zap.L().Error("Failed to get iptables-save stdout pipe", zap.String("error", err.Error()))
		return nil, err
	}
	err = cmd.Start()
	if err != nil {
		// Failed even before we started, close the pipe.  (This would normally be done
		// by Wait().
		zap.L().Error("Failed to start iptables-save", zap.String("error", err.Error()))
		closeErr := stdout.Close()
		if closeErr != nil {
			zap.L().Error(
				"Error closing iptables-save stdout after Start() failed",
				zap.String("error", err.Error()),
			)
		}
		return nil, err
	}

	results, err := parseFrom(stdout, interfaceToWorkload)
	if err != nil {
		killErr := cmd.Process.Kill()
		if killErr != nil {
			zap.L().Error("Failed to kill iptables-save process", zap.String("error", killErr.Error()))
		}
		return nil, err
	}

	if err := cmd.Wait(); err != nil {
		zap.L().Error("iptables-save failed", zap.String("error", err.Error()))
		return nil, err
	}
	return results, nil
}

// parseFrom extracts useful packet counts from the output of iptables-save
// inspiration is taken from projectcalico/felix/iptables/table.go
func parseFrom(stdout io.Reader, interfaceToWorkload map[string]*apiv3.WorkloadEndpoint) ([]*Result, error) {
	// we expect at most 4 counts per network interface, drop and accept for ingress and egress
	results := make([]*Result, 0, 4*len(interfaceToWorkload))
	dropChains := map[string]DropChain{}

	// Create a buffer because we loop through the output twice.
	var buf bytes.Buffer
	tee := io.TeeReader(stdout, &buf)

	dropScanner := bufio.NewScanner(tee)
	// Parse the entire output to find policies that have DROP actions and store
	// the packet count so it can be used later.
	for dropScanner.Scan() {
		line := dropScanner.Bytes()
		dropCapture := dropPolicyRegex.FindSubmatch(line)
		if dropCapture != nil {
			zap.L().Debug(
				"Found drop policy chain",
				zap.String("chain", string(dropCapture[2])),
				zap.String("pkt_count", string(dropCapture[1])),
			)
			dropPacketCount, err := strconv.Atoi(string(dropCapture[1]))
			if err != nil {
				zap.L().Error(
					"Error parsing dropped packet count for policy",
					zap.String("chain", string(dropCapture[2])),
					zap.String("error", err.Error()),
				)
				continue
			}

			dropChains[string(dropCapture[2])] = DropChain{
				PacketCount: dropPacketCount,
			}
		}
	}

	scanner := bufio.NewScanner(&buf)
	lastTarget := ""
	for scanner.Scan() {
		// Read the next line of the output.
		line := scanner.Bytes()

		captures := appendRegexp.FindSubmatch(line)
		if captures == nil {
			// Skip any non-conforming lines
			continue
		}

		packetCount, err := strconv.Atoi(string(captures[1]))
		if err != nil {
			zap.L().Error("Error parsing packet count", zap.String("error", err.Error()))
			continue
		}

		isDrop := bytes.Contains(line, dropSlice)
		isAccept := bytes.Contains(line, acceptSlice)
		target := string(captures[4])

		if !(isDrop || isAccept) && target != "DROP" {
			lastTarget = target
			continue
		}

		typ := chainTypeFromString(string(captures[2]))
		iface := string(captures[3])

		workload, ok := interfaceToWorkload[iface]
		if !ok {
			zap.L().Error("Couldn't find workload for interface", zap.String("interface", iface))
			continue
		}

		acceptType := Accept
		// If the current packet count is 0, and target points to a policy with a drop rule then
		// use the packet count from the drop rule.
		if packetCount == 0 {
			if v, ok := dropChains[lastTarget]; ok {
				zap.L().Debug(
					"Using packet count from drop policy chain instead",
					zap.Int("pkt_count", v.PacketCount),
					zap.String("chain", lastTarget),
				)
				packetCount = v.PacketCount
				acceptType = AcceptedDrop
			}
		}

		switch {
		case isDrop:
			result, err := buildResult(workload, Drop, typ, packetCount, target)
			if err != nil {
				zap.L().Error(
					"Error building result from line",
					zap.String("type", string(typ)),
					zap.Int("pkt_count", packetCount),
					zap.String("chain", target),
					zap.String("line", string(line)),
					zap.String("error", err.Error()),
				)
				continue
			}
			results = append(results, result)
		case isAccept:
			// When we find an accept line, we care about the target on the previous line
			result, err := buildResult(workload, acceptType, typ, packetCount, lastTarget)
			if err != nil {
				zap.L().Error(
					"Error building result from line",
					zap.String("type", string(typ)),
					zap.Int("pkt_count", packetCount),
					zap.String("chain", lastTarget),
					zap.String("line", string(line)),
					zap.String("error", err.Error()),
				)
				continue
			}
			results = append(results, result)
		}
	}

	if scanner.Err() != nil {
		zap.L().Error("Failed to read iptables-save output", zap.String("error", scanner.Err().Error()))
		return nil, scanner.Err()
	}

	return results, nil
}

func buildResult(workload *apiv3.WorkloadEndpoint, countType CountType, chainType ChainType, packetCount int, target string) (*Result, error) {
	if countType == Drop && target != "DROP" {
		return nil, errors.New("drop count type but not a drop target")
	}

	ips := make([]string, 0, len(workload.Spec.IPNetworks))
	for _, str := range workload.Spec.IPNetworks {
		// remove pointless /32 suffix, if any
		ips = append(ips, strings.TrimSuffix(str, "/32"))
	}
	sort.Strings(ips)

	return &Result{
		PodName:      workload.Spec.Pod,
		PodNamespace: workload.Namespace,
		AppLabel:     workload.Labels["app"],
		PodIP:        strings.Join(ips, ","),
		ChainType:    chainType,
		CountType:    countType,
		PacketCount:  packetCount,
		Target:       target,
	}, nil
}
