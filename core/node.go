package core

import (
	"fmt"

	panel "github.com/wyx2685/v2node/api/v2board"
	"github.com/wyx2685/v2node/common/singbox"
)

func (v *V2Core) AddNode(tag string, info *panel.NodeInfo, disableSniffing bool) (err error) {
	// Convert a panic while building the inbound (e.g. malformed panel config)
	// into an error so one bad node is skipped instead of crashing the whole
	// process.
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("build inbound for %s panicked: %v", tag, r)
		}
	}()

	// shadow-tls: the public port is fronted by a sing-box process; bind the
	// real Xray SS inbound to a loopback port and point sing-box at it.
	var listenOverride string
	var portOverride int
	shadowTLS := info.Type == "shadowsocks" && info.Common.ShadowTLSEnabled()
	if shadowTLS {
		if !v.singbox.Available() {
			return fmt.Errorf("shadow-tls requested for %s but sing-box binary unavailable", tag)
		}
		portOverride, err = v.singbox.AllocPort(tag)
		if err != nil {
			return fmt.Errorf("alloc loopback port for %s: %s", tag, err)
		}
		listenOverride = "127.0.0.1"
	}

	inBoundConfig, err := buildInbound(info, tag, disableSniffing, listenOverride, portOverride)
	if err != nil {
		if shadowTLS {
			v.singbox.Release(tag)
		}
		return fmt.Errorf("build inbound error: %s", err)
	}
	err = v.addInbound(inBoundConfig)
	if err != nil {
		if shadowTLS {
			v.singbox.Release(tag)
		}
		return fmt.Errorf("add inbound error: %s", err)
	}

	if shadowTLS {
		if err = v.singbox.StartOrReload(singbox.ConfigFromNode(tag, info, portOverride)); err != nil {
			_ = v.removeInbound(tag) // roll back the loopback inbound
			v.singbox.Release(tag)
			return fmt.Errorf("start sing-box front for %s: %s", tag, err)
		}
	}
	return nil
}

func (v *V2Core) DelNode(tag string) error {
	// Stop the sing-box front (frees the public port + loopback reservation)
	// before removing the Xray inbound.
	if v.singbox != nil {
		_ = v.singbox.Stop(tag)
	}
	err := v.removeInbound(tag)
	if err != nil {
		return fmt.Errorf("remove in error: %s", err)
	}
	return nil
}
