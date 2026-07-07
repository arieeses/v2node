package node

import (
	"context"
	"time"

	log "github.com/sirupsen/logrus"
	panel "github.com/wyx2685/v2node/api/v2board"
	"github.com/wyx2685/v2node/conf"
)

func (c *Controller) reportUserTrafficTask(ctx context.Context) (err error) {
	var reportmin = 0
	var devicemin = 0
	if c.info.Common.BaseConfig != nil {
		reportmin = c.info.Common.BaseConfig.NodeReportMinTraffic
		devicemin = c.info.Common.BaseConfig.DeviceOnlineMinTraffic
	}
	userTraffic, _ := c.server.GetUserTrafficSlice(c.tag, reportmin)
	// Auto speed limit: throttle users whose per-cycle speed exceeds the limit.
	if asl := c.conf.EffectiveAutoSpeedLimit(c.global); asl != nil {
		c.applyAutoSpeedLimit(userTraffic, asl)
	}
	if len(userTraffic) > 0 {
		err = c.apiClient.ReportUserTraffic(ctx, userTraffic)
		if err != nil {
			log.WithFields(log.Fields{
				"tag": c.tag,
				"err": err,
			}).Warn("Report user traffic failed")
		} else {
			log.WithField("tag", c.tag).Infof("Report %d users traffic", len(userTraffic))
		}
	} else {
		log.WithField("tag", c.tag).Debug("No user traffic to report")
	}

	onlineDevice, err := c.limiter.GetOnlineDevice()
	if err != nil {
		log.WithFields(log.Fields{
			"tag": c.tag,
			"err": err,
		}).Info("Get online device failed")
		return nil
	}

	log.WithField("tag", c.tag).Debugf("Traffic: %d users, Online: %d devices", len(userTraffic), len(*onlineDevice))

	if len(*onlineDevice) > 0 {
		var result []panel.OnlineUser
		var nocountUID = make(map[int]struct{})
		for _, traffic := range userTraffic {
			total := traffic.Upload + traffic.Download
			if total < int64(devicemin*1000) {
				nocountUID[traffic.UID] = struct{}{}
			}
		}
		for _, online := range *onlineDevice {
			if _, ok := nocountUID[online.UID]; !ok {
				result = append(result, online)
			}
		}
		data := make(map[int][]string)
		for _, onlineuser := range result {
			// json structure: { UID1:["ip1","ip2"],UID2:["ip3","ip4"] }
			data[onlineuser.UID] = append(data[onlineuser.UID], onlineuser.IP)
		}
		if len(data) != 0 {
			err := c.apiClient.ReportNodeOnlineUsers(ctx, &data)
			if err != nil {
				log.WithFields(log.Fields{
					"tag": c.tag,
					"err": err,
				}).Info("Report online users failed")
			}
		}
		log.WithField("tag", c.tag).Infof("Total %d online users, %d Reported", len(*onlineDevice), len(result))
	}

	return nil
}

// applyAutoSpeedLimit throttles users whose average speed this cycle exceeds
// asl.Limit (Mbps) for WarnTimes consecutive cycles, down to LimitSpeed (Mbps)
// for LimitDuration minutes. Runs on the single report-task goroutine, so the
// speedWarn map needs no locking.
func (c *Controller) applyAutoSpeedLimit(traffic []panel.UserTraffic, asl *conf.AutoSpeedLimitConfig) {
	if c.limiter == nil {
		return
	}
	sec := c.reportInterval.Seconds()
	if sec <= 0 {
		sec = 60
	}
	for _, t := range traffic {
		mbps := float64(t.Upload+t.Download) * 8 / sec / 1e6
		if mbps > float64(asl.Limit) {
			c.speedWarn[t.UID]++
			if c.speedWarn[t.UID] >= asl.WarnTimes {
				c.limiter.SetDynamicSpeedLimitByUID(t.UID, asl.LimitSpeed,
					time.Now().Add(time.Duration(asl.LimitDuration)*time.Minute))
				c.speedWarn[t.UID] = 0
				log.WithFields(log.Fields{"tag": c.tag, "uid": t.UID, "mbps": int(mbps)}).
					Info("Auto speed limit triggered")
			}
		} else {
			delete(c.speedWarn, t.UID) // reset — warns must be consecutive
		}
	}
}

func compareUserList(old, new []panel.UserInfo) (deleted, added, modified []panel.UserInfo) {
	oldMap := make(map[string]panel.UserInfo, len(old))
	for _, u := range old {
		oldMap[u.Uuid] = u
	}

	for _, u := range new {
		if o, ok := oldMap[u.Uuid]; !ok {
			added = append(added, u)
		} else {
			if o.SpeedLimit != u.SpeedLimit || o.DeviceLimit != u.DeviceLimit {
				modified = append(modified, u)
			}
			delete(oldMap, u.Uuid)
		}
	}

	for _, o := range oldMap {
		deleted = append(deleted, o)
	}

	return deleted, added, modified
}
