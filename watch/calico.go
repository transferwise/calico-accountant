package watch

import (
	"go.uber.org/zap"
	"os"
	"strings"
	"sync"

	"github.com/projectcalico/felix/proto"
	"github.com/projectcalico/felix/rules"
	apiv3 "github.com/projectcalico/libcalico-go/lib/apis/v3"
	"github.com/projectcalico/libcalico-go/lib/backend/api"
	"github.com/projectcalico/libcalico-go/lib/backend/model"
	"github.com/projectcalico/libcalico-go/lib/backend/syncersv1/updateprocessors"
	"github.com/projectcalico/libcalico-go/lib/backend/watchersyncer"
	"github.com/projectcalico/libcalico-go/lib/client"
	"github.com/projectcalico/libcalico-go/lib/names"
)

type CalicoWatcher interface {
	GetPolicyByChainName(string) string
	ListWorkloadEndpoints() []*apiv3.WorkloadEndpoint
}

type calicoWatcher struct {
	policyCache      map[string]string
	policyCacheMtx   sync.RWMutex
	workloadCache    map[model.ResourceKey]*apiv3.WorkloadEndpoint
	workloadCacheMtx sync.RWMutex
	ws               api.Syncer
	node             string
	ready            chan struct{}
}

func New() (CalicoWatcher, error) {
	c, err := client.NewFromEnv()
	if err != nil {
		return nil, err
	}

	resourceTypes := []watchersyncer.ResourceType{
		{
			ListInterface:   model.ResourceListOptions{Kind: apiv3.KindNetworkPolicy},
			UpdateProcessor: updateprocessors.NewNetworkPolicyUpdateProcessor(),
		},
		{
			ListInterface:   model.ResourceListOptions{Kind: apiv3.KindGlobalNetworkPolicy},
			UpdateProcessor: updateprocessors.NewGlobalNetworkPolicyUpdateProcessor(),
		},
		{
			ListInterface: model.ResourceListOptions{Kind: apiv3.KindWorkloadEndpoint},
		},
	}

	cw := &calicoWatcher{
		policyCache:   map[string]string{},
		workloadCache: map[model.ResourceKey]*apiv3.WorkloadEndpoint{},
		node:          getNodeName(),
		ready:         make(chan struct{}),
	}

	cw.ws = watchersyncer.New(
		c.Backend,
		resourceTypes,
		cw,
	)

	cw.ws.Start()

	<-cw.ready
	zap.L().Info("Calico cache filled")

	return cw, nil
}

func (cw *calicoWatcher) GetPolicyByChainName(chain string) string {
	cw.policyCacheMtx.RLock()
	defer cw.policyCacheMtx.RUnlock()
	return cw.policyCache[chain]
}

func (cw *calicoWatcher) ListWorkloadEndpoints() []*apiv3.WorkloadEndpoint {
	cw.workloadCacheMtx.RLock()
	defer cw.workloadCacheMtx.RUnlock()

	ws := make([]*apiv3.WorkloadEndpoint, 0, len(cw.workloadCache))

	for _, v := range cw.workloadCache {
		ws = append(ws, v)
	}
	return ws
}

func (cw *calicoWatcher) OnStatusUpdated(status api.SyncStatus) {
	switch status {
	case api.InSync:
		select {
		case <-cw.ready:
		default:
			close(cw.ready)
		}
	}
}

func (cw *calicoWatcher) OnUpdates(updates []api.Update) {
	for _, up := range updates {
		switch up.Key.(type) {
		case model.PolicyKey:
			cw.onPolicyUpdate(up)
		case model.ResourceKey:
			cw.onWorkloadUpdate(up)
		}
	}
}

func (cw *calicoWatcher) onWorkloadUpdate(up api.Update) {
	k := up.Key.(model.ResourceKey)

	if up.Value == nil {
		cw.workloadCacheMtx.RLock()
		if _, ok := cw.workloadCache[k]; !ok {
			cw.workloadCacheMtx.RUnlock()
			return
		}
		cw.workloadCacheMtx.RUnlock()

		// deletion
		cw.workloadCacheMtx.Lock()
		zap.L().Info("Removing workload", zap.String("workload", up.Key.String()))
		delete(cw.workloadCache, k)
		cw.workloadCacheMtx.Unlock()
		return
	}

	we := up.Value.(*apiv3.WorkloadEndpoint)
	if we.Spec.Node != cw.node {
		return
	}

	zap.L().Info("Adding workload", zap.String("workload", up.Key.String()))
	cw.workloadCacheMtx.Lock()
	cw.workloadCache[k] = we
	cw.workloadCacheMtx.Unlock()
}

func (cw *calicoWatcher) onPolicyUpdate(up api.Update) {
	id := &proto.PolicyID{
		Tier: "default",
		Name: up.Key.(model.PolicyKey).Name,
	}

	if up.Value == nil {
		// deletion
		cw.policyCacheMtx.Lock()
		zap.L().Info(
			"Removing policy",
			zap.String("policy", id.Name),
			zap.String("inbound_chain", rules.PolicyChainName(rules.PolicyInboundPfx, id)),
			zap.String("outbound_chain", rules.PolicyChainName(rules.PolicyOutboundPfx, id)),
		)
		delete(cw.policyCache, rules.PolicyChainName(rules.PolicyInboundPfx, id))
		delete(cw.policyCache, rules.PolicyChainName(rules.PolicyOutboundPfx, id))
		cw.policyCacheMtx.Unlock()
		return
	}

	zap.L().Info(
		"Storing policy",
		zap.String("policy", id.Name),
		zap.String("inbound_chain", rules.PolicyChainName(rules.PolicyInboundPfx, id)),
		zap.String("outbound_chain", rules.PolicyChainName(rules.PolicyOutboundPfx, id)),
	)
	cw.policyCacheMtx.Lock()
	cw.policyCache[rules.PolicyChainName(rules.PolicyInboundPfx, id)] = id.Name
	cw.policyCache[rules.PolicyChainName(rules.PolicyOutboundPfx, id)] = id.Name
	cw.policyCacheMtx.Unlock()
}

// getNodeName is intended to mimic the behaviour of calico node in determineNodeName(), pkg/startup/startup.go
// this is necessary because the node field of workload endpoints is set based on what calico node sees as
// the node name.
func getNodeName() string {
	if nodeName, ok := os.LookupEnv("NODENAME"); ok {
		zap.L().Info("Using NODENAME environment variable", zap.String("value", nodeName))
		return nodeName
	} else if nodeName := strings.ToLower(strings.TrimSpace(os.Getenv("HOSTNAME"))); nodeName != "" {
		zap.L().Info("Using HOSTNAME environment variable as node name", zap.String("value", nodeName))
		return nodeName
	} else if nodeName, err := names.Hostname(); err == nil {
		zap.L().Info("Using names.Hostname() as node name", zap.String("value", nodeName))
		return nodeName
	} else {
		zap.L().Fatal("Error getting hostname", zap.String("error", err.Error()))
		// unreachable...
		return ""
	}
}
