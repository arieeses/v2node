package core

import (
	"fmt"

	panel "github.com/wyx2685/v2node/api/v2board"
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
	inBoundConfig, err := buildInbound(info, tag, disableSniffing)
	if err != nil {
		return fmt.Errorf("build inbound error: %s", err)
	}
	err = v.addInbound(inBoundConfig)
	if err != nil {
		return fmt.Errorf("add inbound error: %s", err)
	}
	return nil
}

func (v *V2Core) DelNode(tag string) error {
	err := v.removeInbound(tag)
	if err != nil {
		return fmt.Errorf("remove in error: %s", err)
	}
	return nil
}
