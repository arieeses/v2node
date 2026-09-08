package anytls

import (
	"crypto/md5"
	"crypto/rand"
	"fmt"
	"math/big"
	"strconv"
	"strings"
)

const CheckMark = -1

var defaultPaddingScheme = []byte(`stop=8
0=30-30
1=100-400
2=400-500,c,500-1000,c,500-1000,c,500-1000,c,500-1000
3=9-9,500-1000
4=500-1000
5=500-1000
6=500-1000
7=500-1000`)

// customServerDefaultScheme 是本端(v2node 服务端)在节点未配置 padding_scheme 时，
// 主动推给客户端(cmdUpdatePaddingScheme)的默认方案。刻意区别于 anytls 公开默认
// (defaultPaddingScheme)——让握手期的 TLS 记录大小分布不同于「标准 anytls」指纹，
// 且 md5 不同，从而躲开基于公开默认方案的特征匹配。尺寸偏向 MTU(≤1460)以更像常规
// HTTPS 分段。可被面板的 padding_scheme 逐节点覆盖(若要每节点唯一，建议在面板另配)。
var customServerDefaultScheme = []byte(`stop=9
0=48-64
1=150-900
2=500-1200,c,800-1400,c,900-1460,c,900-1460
3=16-64,800-1400
4=800-1460
5=800-1460
6=800-1460
7=600-1460
8=400-1200`)

type paddingScheme struct {
	rawScheme []byte
	scheme    map[string]string
	stop      uint32
	md5       string
}

func newPaddingScheme(rawScheme []byte) *paddingScheme {
	p := &paddingScheme{
		rawScheme: rawScheme,
		md5:       fmt.Sprintf("%x", md5.Sum(rawScheme)),
	}

	scheme := make(map[string]string)
	lines := strings.Split(string(rawScheme), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		parts := strings.SplitN(line, "=", 2)
		if len(parts) == 2 {
			scheme[parts[0]] = parts[1]
		}
	}

	if len(scheme) == 0 {
		return nil
	}

	if stop, err := strconv.Atoi(scheme["stop"]); err == nil {
		p.stop = uint32(stop)
	} else {
		return nil
	}

	p.scheme = scheme
	return p
}

func getDefaultPaddingScheme() *paddingScheme {
	return newPaddingScheme(defaultPaddingScheme)
}

func parsePaddingScheme(schemeStr string) (*paddingScheme, error) {
	if schemeStr == "" {
		return nil, nil
	}
	return newPaddingScheme([]byte(schemeStr)), nil
}

func (p *paddingScheme) GenerateRecordPayloadSizes(pkt uint32) []int {
	if p == nil {
		return nil
	}

	pktSizes := []int{}
	key := strconv.Itoa(int(pkt))
	s, ok := p.scheme[key]
	if !ok {
		return pktSizes
	}

	sRanges := strings.Split(s, ",")
	for _, sRange := range sRanges {
		sRange = strings.TrimSpace(sRange)

		if sRange == "c" {
			pktSizes = append(pktSizes, CheckMark)
			continue
		}

		sRangeMinMax := strings.Split(sRange, "-")
		if len(sRangeMinMax) != 2 {
			continue
		}

		_min, err := strconv.ParseInt(sRangeMinMax[0], 10, 64)
		if err != nil {
			continue
		}
		_max, err := strconv.ParseInt(sRangeMinMax[1], 10, 64)
		if err != nil {
			continue
		}

		if _min > _max {
			_min, _max = _max, _min
		}

		if _min <= 0 || _max <= 0 {
			continue
		}

		if _min == _max {
			pktSizes = append(pktSizes, int(_min))
		} else {
			i, _ := rand.Int(rand.Reader, big.NewInt(_max-_min))
			pktSizes = append(pktSizes, int(i.Int64()+_min))
		}
	}

	return pktSizes
}

func getPadding0Size(scheme *paddingScheme) uint16 {
	if scheme == nil {
		return 30
	}

	sizes := scheme.GenerateRecordPayloadSizes(0)
	if len(sizes) > 0 && sizes[0] != CheckMark {
		return uint16(sizes[0])
	}

	return 30
}
