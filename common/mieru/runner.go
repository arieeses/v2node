package mieru

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"

	apicommon "github.com/enfein/mieru/v3/apis/common"
	"github.com/enfein/mieru/v3/apis/constant"
	"github.com/enfein/mieru/v3/apis/model"
	"github.com/enfein/mieru/v3/apis/trafficpattern"
	mcommon "github.com/enfein/mieru/v3/pkg/common"
	mlog "github.com/enfein/mieru/v3/pkg/log"
	mmetrics "github.com/enfein/mieru/v3/pkg/metrics"
	mprotocol "github.com/enfein/mieru/v3/pkg/protocol"

	log "github.com/sirupsen/logrus"
	xcommon "github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	xnet "github.com/xtls/xray-core/common/net"
	xproto "github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/features/routing"

	panel "github.com/wyx2685/v2node/api/v2board"
	"github.com/wyx2685/v2node/common/format"
)

func init() {
	// mieru crashes (raw SIGSEGV) if it logs with no formatter set. Route its
	// own logging through a NilFormatter so it stays silent — v2node does its
	// own logging via logrus.
	mlog.SetFormatter(&mlog.NilFormatter{})
	// We do our own per-user accounting via the Xray dispatcher and never read
	// mieru's metrics, so stop its periodic metrics dump goroutine.
	mmetrics.DisableMetricsDump()
}

// preRegisterUserMetrics registers a user's mieru upload/download counters as
// plain COUNTERs BEFORE mieru's session code would register them as
// COUNTER_TIME_SERIES. RegisterMetric is LoadOrStore, so mieru then reuses our
// plain counters — critical because a time-series counter appends a protobuf
// History object on EVERY write (counter.go), which under load allocates
// millions of objects, spiking GC/CPU and RSS. We never read these counters.
func preRegisterUserMetrics(uuid string) {
	grp := fmt.Sprintf(mmetrics.UserMetricGroupFormat, uuid)
	mmetrics.RegisterMetric(grp, mmetrics.UserMetricUploadBytes, mmetrics.COUNTER)
	mmetrics.RegisterMetric(grp, mmetrics.UserMetricDownloadBytes, mmetrics.COUNTER)
}

// Runner owns one mieru server (a protocol.Mux) for a node tag and bridges its
// accepted streams into Xray's dispatcher. The Mux is started LAZILY on the
// first user: mieru's mux.Start() fails with "no user found" if started with an
// empty user set, and AddNode runs before AddUsers.
type Runner struct {
	tag  string
	info *panel.NodeInfo
	disp routing.Dispatcher

	mu    sync.Mutex
	mux   *mprotocol.Mux // nil until the first user arrives
	users map[string]panel.UserInfo
}

func NewRunner(tag string, info *panel.NodeInfo, disp routing.Dispatcher) *Runner {
	return &Runner{tag: tag, info: info, disp: disp, users: map[string]panel.UserInfo{}}
}

// startLocked builds and starts the Mux with the current (non-empty) user set.
// Caller must hold r.mu and ensure len(r.users) > 0.
func (r *Runner) startLocked() error {
	endpoints, err := buildEndpoints(r.info)
	if err != nil {
		return err
	}
	tp, err := trafficpattern.NewConfig(nil)
	if err != nil {
		return err
	}
	// Whether to require a user hint on every connection. Defaults ON (rejects
	// hint-less junk before the costly per-user trial-decrypt); operators with
	// clients that don't send a hint can disable it via network_settings. See
	// forceUserHint.
	mux := mprotocol.NewMux(false)
	mux.SetTrafficPattern(tp).
		SetServerUsers(buildUserMap(r.users)).
		SetServerUserHintIsMandatory(forceUserHint(r.info))
	mux.SetEndpoints(endpoints)
	if err := mux.Start(); err != nil {
		return err
	}
	r.mux = mux
	go r.acceptLoop(mux)
	log.WithFields(log.Fields{"tag": r.tag, "port": r.info.Common.ServerPort}).Info("mieru server started")
	return nil
}

// AddUsers merges users, starting the Mux on the first user and atomically
// re-registering the full set afterwards.
func (r *Runner) AddUsers(users []panel.UserInfo) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	for i := range users {
		r.users[users[i].Uuid] = users[i]
		// Register plain counters up front so mieru's session code reuses them
		// instead of building a per-write time series (huge alloc under load).
		preRegisterUserMetrics(users[i].Uuid)
	}
	if r.mux == nil {
		if len(r.users) == 0 {
			return nil
		}
		return r.startLocked()
	}
	r.mux.SetServerUsers(buildUserMap(r.users))
	return nil
}

// DelUsers removes users (by uuid) and atomically re-registers the rest.
func (r *Runner) DelUsers(uuids []string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, u := range uuids {
		delete(r.users, u)
	}
	if r.mux != nil {
		r.mux.SetServerUsers(buildUserMap(r.users))
	}
}

func (r *Runner) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.mux != nil {
		return r.mux.Close()
	}
	return nil
}

func (r *Runner) acceptLoop(mux *mprotocol.Mux) {
	for {
		conn, err := mux.Accept()
		if err != nil {
			// Mux closed on node teardown → Accept fails permanently; exit loop.
			return
		}
		go r.handle(conn)
	}
}

func (r *Runner) handle(conn net.Conn) {
	defer conn.Close()
	uc, ok := conn.(apicommon.UserContext)
	if !ok {
		return
	}

	// Read the client's socks5 request (target) with a short deadline, then clear it.
	mcommon.SetReadTimeout(conn, 10*time.Second)
	req := &model.Request{}
	if err := req.ReadFromSocks5(conn); err != nil {
		return
	}
	mcommon.SetReadTimeout(conn, 0)

	// UserName is only populated AFTER the first data segment (the socks5 request
	// above) is processed — reading it earlier yields "" and breaks per-user
	// accounting/limiting.
	uuid := uc.UserName()

	if req.Command != constant.Socks5ConnectCmd {
		// Only CONNECT (TCP) is bridged for now; UDP-associate can be added later.
		_ = model.WriteSocks5Response(conn, constant.Socks5ReplyCommandNotSupported, zeroBind())
		return
	}
	nas, err := req.ToNetAddrSpec()
	if err != nil {
		_ = model.WriteSocks5Response(conn, constant.Socks5ReplyAddrTypeNotSupported, zeroBind())
		return
	}
	dest := toXrayDest(nas)

	log.WithFields(log.Fields{"tag": r.tag, "user": uuid, "dest": dest.String()}).Debug("mieru request")

	// Attach the node tag + user so the dispatcher counts traffic and applies
	// speed/device limits under this user, exactly like the native protocols.
	email := format.UserTag(r.tag, uuid)
	ctx := session.ContextWithInbound(context.Background(), &session.Inbound{
		Tag:    r.tag,
		Source: xnet.DestinationFromAddr(conn.RemoteAddr()),
		Conn:   conn,
		User:   &xproto.MemoryUser{Email: email, Level: 0},
	})

	link, err := r.disp.Dispatch(ctx, dest)
	if err != nil {
		_ = model.WriteSocks5Response(conn, constant.Socks5ReplyHostUnreachable, zeroBind())
		return
	}
	if err := model.WriteSocks5Response(conn, constant.Socks5ReplySuccess, zeroBind()); err != nil {
		xcommon.Interrupt(link.Reader)
		xcommon.Close(link.Writer)
		return
	}

	// Bridge: uplink conn -> link.Writer, downlink link.Reader -> conn.
	go func() {
		_ = buf.Copy(buf.NewReader(conn), link.Writer)
		xcommon.Close(link.Writer)
	}()
	_ = buf.Copy(link.Reader, buf.NewWriter(conn))
	xcommon.Interrupt(link.Reader)
}

func zeroBind() model.AddrSpec { return model.AddrSpec{IP: net.IPv4zero, Port: 0} }

func toXrayDest(nas model.NetAddrSpec) xnet.Destination {
	var addr xnet.Address
	if len(nas.IP) != 0 {
		addr = xnet.IPAddress(nas.IP)
	} else {
		addr = xnet.DomainAddress(nas.FQDN)
	}
	return xnet.Destination{Network: xnet.Network_TCP, Address: addr, Port: xnet.Port(nas.Port)}
}
