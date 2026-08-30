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

	// mieru is not an Xray inbound: run its own protocol.Mux and bridge accepted
	// streams into the dispatcher. Users are pushed later via AddUsers.
	if info.Type == "mieru" {
		return v.mieru.Add(tag, info)
	}

	// Both shadow-tls and simple-obfs "tls" front the public port and bind the
	// real Xray SS inbound to a loopback port. shadow-tls uses a sing-box
	// subprocess; obfs-tls uses a native in-process front.
	var listenOverride string
	var portOverride int
	shadowTLS := info.Type == "shadowsocks" && info.Common.ShadowTLSEnabled()
	obfsTLS := info.Type == "shadowsocks" && !shadowTLS && info.Common.SimpleObfsEnabled()
	if shadowTLS {
		if !v.singbox.Available() {
			return fmt.Errorf("shadow-tls requested for %s but sing-box binary unavailable", tag)
		}
		portOverride, err = v.singbox.AllocPort(tag)
		if err != nil {
			return fmt.Errorf("alloc loopback port for %s: %s", tag, err)
		}
		listenOverride = "127.0.0.1"
	} else if obfsTLS {
		portOverride, err = v.obfs.AllocPort(tag)
		if err != nil {
			return fmt.Errorf("alloc loopback port for %s: %s", tag, err)
		}
		listenOverride = "127.0.0.1"
	}

	inBoundConfig, err := buildInbound(info, tag, disableSniffing, listenOverride, portOverride)
	if err != nil {
		if shadowTLS {
			v.singbox.Release(tag)
		} else if obfsTLS {
			v.obfs.Release(tag)
		}
		return fmt.Errorf("build inbound error: %s", err)
	}
	err = v.addInbound(inBoundConfig)
	if err != nil {
		if shadowTLS {
			v.singbox.Release(tag)
		} else if obfsTLS {
			v.obfs.Release(tag)
		}
		return fmt.Errorf("add inbound error: %s", err)
	}

	if shadowTLS {
		if err = v.singbox.StartOrReload(singbox.ConfigFromNode(tag, info, portOverride)); err != nil {
			_ = v.removeInbound(tag) // roll back the loopback inbound
			v.singbox.Release(tag)
			return fmt.Errorf("start sing-box front for %s: %s", tag, err)
		}
	} else if obfsTLS {
		if err = v.obfs.Start(tag, info.Common.ListenIP, info.Common.ServerPort, portOverride, info.Common.SimpleObfsMode(), info.Common.SimpleObfsHost()); err != nil {
			_ = v.removeInbound(tag) // roll back the loopback inbound
			v.obfs.Release(tag)
			return fmt.Errorf("start obfs-tls front for %s: %s", tag, err)
		}
	}
	return nil
}

func (v *V2Core) DelNode(tag string) error {
	// Free all per-tag state (SNI router, dispatcher counter/camouflage engine,
	// shadowflow config) regardless of node type, so nothing leaks on churn.
	v.cleanupNodeState(tag)
	// mieru node: stop its Mux (no Xray inbound to remove).
	if v.mieru.Has(tag) {
		v.mieru.Del(tag)
		return nil
	}
	// Stop any front (sing-box shadow-tls / native obfs-tls) that owns the
	// public port before removing the Xray inbound.
	if v.singbox != nil {
		_ = v.singbox.Stop(tag)
	}
	if v.obfs != nil {
		v.obfs.Stop(tag)
	}
	err := v.removeInbound(tag)
	if err != nil {
		return fmt.Errorf("remove in error: %s", err)
	}
	return nil
}
