#!/usr/bin/env bash
# v2node 综合调优一键脚本（幂等，可反复运行）
#   适用：512MB / 1GB 等小内存落地节点
#   做的事：zram(压缩内存swap) + 内核网络(BBR) + 内存(GOMEMLIMIT) + THP + 文件句柄
#   不做的事：不配置磁盘 swap（你已每台 2GB 自行配好）；不碰 v2node 配置/节点
#
# 用法： bash <(curl -Ls https://raw.githubusercontent.com/arieeses/v2node/main/script/tune.sh)
set -u

green='\033[0;32m'; yellow='\033[0;33m'; red='\033[0;31m'; plain='\033[0m'
say(){ echo -e "${green}[tune]${plain} $*"; }
warn(){ echo -e "${yellow}[tune]${plain} $*"; }

[ "$(id -u)" = "0" ] || { echo -e "${red}请用 root 运行${plain}"; exit 1; }

RAM_MB=$(awk '/MemTotal/{print int($2/1024)}' /proc/meminfo)
say "检测到物理内存: ${RAM_MB} MB"

# 按内存分档：小机器缓冲小、GOMEMLIMIT 收紧
if   [ "$RAM_MB" -le 700 ]; then BUF=4194304;  MEM_PCT=78   # ~512MB
elif [ "$RAM_MB" -le 1400 ]; then BUF=8388608;  MEM_PCT=80   # ~1GB
else                             BUF=16777216; MEM_PCT=82   # 2GB+
fi
# 激进模式：AGGRESSIVE=1（仅在 CPU 有余量的机器上用！zstd/低GOGC 会加 CPU）
# swap 方案：默认优先 zswap（CPU 通常更低），内核不支持则自动回退 zram。ZSWAP=0 强制用 zram。
USE_ZSWAP=${ZSWAP:-1}
ALGO=lz4; ZSWAP_COMP=lz4; GOGC_LINE=""; ZRAM_FACTOR=100; SWAPPINESS=100; MODE=普通
if [ "${AGGRESSIVE:-0}" = "1" ]; then
  ALGO=zstd; ZSWAP_COMP=zstd           # 压缩率更高 → 换出更多有效内存（更吃 CPU）
  ZRAM_FACTOR=150                      # zram 提到 150% 内存
  MEM_PCT=$(( MEM_PCT - 8 ))           # GOMEMLIMIT 再收紧 8 个点
  GOGC_LINE="Environment=GOGC=50"      # GC 更积极 → 堆更小 → RSS 更低
  SWAPPINESS=150                       # 更积极换页（老内核会自动截到100）
  MODE=激进
fi
ZRAM_MB=$(( RAM_MB * ZRAM_FACTOR / 100 ))   # zram 设备大小（磁盘 swap 兜底溢出）
GOMEM_MB=$(( RAM_MB * MEM_PCT / 100 ))
[ "$USE_ZSWAP" = "1" ] && SWAP_KIND="优先zswap(无则回退zram)" || SWAP_KIND=zram
say "模式: ${MODE}  swap方案: ${SWAP_KIND}  (GOMEMLIMIT=${GOMEM_MB}MiB, swappiness=${SWAPPINESS})"

# ───────────────────────── 1) 内核参数：BBR + 连接 + vm ─────────────────────────
say "写入内核参数 /etc/sysctl.d/99-v2node-tune.conf (缓冲上限 $((BUF/1024/1024))MB)"
modprobe tcp_bbr 2>/dev/null || true
QDISC=fq
cat >/etc/sysctl.d/99-v2node-tune.conf <<EOF
# ==== 拥塞控制 ====
net.core.default_qdisc = ${QDISC}
net.ipv4.tcp_congestion_control = bbr
# ==== 连接扩容（高并发落地）====
net.core.somaxconn = 32768
net.ipv4.tcp_max_syn_backlog = 8192
net.core.netdev_max_backlog = 16384
fs.file-max = 1000000
# ==== 对外连接端口 / 回收 ====
net.ipv4.ip_local_port_range = 1024 65535
net.ipv4.tcp_tw_reuse = 1
net.ipv4.tcp_fin_timeout = 15
# ==== 握手 / 探测 ====
net.ipv4.tcp_fastopen = 3
net.ipv4.tcp_mtu_probing = 1
net.ipv4.tcp_slow_start_after_idle = 0
# ==== 缓冲区（按内存分档，小机器刻意取小，避免 连接数×大buffer 撑爆）====
net.core.rmem_max = ${BUF}
net.core.wmem_max = ${BUF}
net.ipv4.tcp_rmem = 4096 87380 ${BUF}
net.ipv4.tcp_wmem = 4096 65536 ${BUF}
# ==== 内存回收 / swap 配合 ====
vm.swappiness = ${SWAPPINESS}
vm.page-cluster = 0
vm.vfs_cache_pressure = 200
EOF
sysctl --system >/dev/null 2>&1
grep -qw bbr /proc/sys/net/ipv4/tcp_available_congestion_control 2>/dev/null \
  && say "BBR 内核支持 ✓" || warn "当前内核不支持 BBR（需 4.9+），该项不生效，其余照常"

# ───────────────────────── 2) 压缩内存 swap：zram 或 zswap ─────────────────────────
setup_zram() {
  say "配置 zram: ${ZRAM_MB}MB (${ALGO}, 优先级100 高于磁盘swap)"
  cat >/usr/local/sbin/v2node-zram.sh <<'ZS'
#!/usr/bin/env bash
SIZE_MB="$1"
ALGO="${2:-lz4}"
modprobe zram 2>/dev/null
# 幂等：先卸载重建 zram0
swapoff /dev/zram0 2>/dev/null || true
if [ -e /sys/block/zram0/reset ]; then echo 1 > /sys/block/zram0/reset 2>/dev/null || true; fi
# 设压缩算法；内核不支持该算法则回退 lz4
echo "$ALGO" > /sys/block/zram0/comp_algorithm 2>/dev/null || echo lz4 > /sys/block/zram0/comp_algorithm 2>/dev/null || true
echo "${SIZE_MB}M" > /sys/block/zram0/disksize
mkswap /dev/zram0 >/dev/null 2>&1
swapon -p 100 /dev/zram0
# THP 顺带设 madvise（防止大页膨胀 RSS）
echo madvise > /sys/kernel/mm/transparent_hugepage/enabled 2>/dev/null || true
ZS
  chmod +x /usr/local/sbin/v2node-zram.sh
  cat >/etc/systemd/system/v2node-zram.service <<EOF
[Unit]
Description=v2node zram swap + THP madvise
After=multi-user.target
[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/local/sbin/v2node-zram.sh ${ZRAM_MB} ${ALGO}
ExecStop=/bin/bash -c 'swapoff /dev/zram0 2>/dev/null; echo 1 > /sys/block/zram0/reset 2>/dev/null || true'
[Install]
WantedBy=multi-user.target
EOF
  systemctl daemon-reload
  systemctl enable v2node-zram.service >/dev/null 2>&1
  systemctl restart v2node-zram.service && say "zram 已启用 ✓" || warn "zram 启用失败（内核可能无 zram 模块）"
}

if [ "$USE_ZSWAP" = "1" ] && [ -e /sys/module/zswap/parameters/enabled ]; then
  say "配置 zswap: ${ZSWAP_COMP} + zsmalloc + shrinker + pool20%（磁盘swap前的压缩缓存，冷页回写磁盘）"
  systemctl disable --now v2node-zram.service 2>/dev/null || true
  swapoff /dev/zram0 2>/dev/null || true
  cat >/usr/local/sbin/v2node-zswap.sh <<ZW
#!/usr/bin/env bash
# zswap 与 zram 冲突，先确保 zram 关闭
swapoff /dev/zram0 2>/dev/null || true
echo 1 > /sys/module/zswap/parameters/enabled 2>/dev/null || true
echo ${ZSWAP_COMP} > /sys/module/zswap/parameters/compressor 2>/dev/null || echo lz4 > /sys/module/zswap/parameters/compressor 2>/dev/null || true
echo zsmalloc > /sys/module/zswap/parameters/zpool 2>/dev/null || true
echo 20 > /sys/module/zswap/parameters/max_pool_percent 2>/dev/null || true
echo Y > /sys/module/zswap/parameters/shrinker_enabled 2>/dev/null || true
echo madvise > /sys/kernel/mm/transparent_hugepage/enabled 2>/dev/null || true
ZW
  chmod +x /usr/local/sbin/v2node-zswap.sh
  cat >/etc/systemd/system/v2node-zswap.service <<EOF
[Unit]
Description=v2node zswap params + THP madvise
After=multi-user.target
[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/local/sbin/v2node-zswap.sh
[Install]
WantedBy=multi-user.target
EOF
  systemctl daemon-reload
  systemctl enable v2node-zswap.service >/dev/null 2>&1
  systemctl restart v2node-zswap.service
  if [ "$(cat /sys/module/zswap/parameters/enabled 2>/dev/null)" = "Y" ]; then
    say "zswap 已启用 ✓ (comp=$(cat /sys/module/zswap/parameters/compressor 2>/dev/null), pool=$(cat /sys/module/zswap/parameters/max_pool_percent 2>/dev/null)%, shrinker=$(cat /sys/module/zswap/parameters/shrinker_enabled 2>/dev/null))"
  else
    warn "zswap 开启失败，自动回退 zram"
    systemctl disable --now v2node-zswap.service 2>/dev/null || true
    USE_ZSWAP=0
    setup_zram
  fi
else
  if [ "$USE_ZSWAP" = "1" ]; then
    warn "本机内核无 zswap（无 /sys/module/zswap），自动回退 zram"
    USE_ZSWAP=0
  fi
  setup_zram
fi

# ───────────────────────── 3) 文件描述符上限 ─────────────────────────
if ! grep -q "v2node-nofile" /etc/security/limits.conf 2>/dev/null; then
  cat >>/etc/security/limits.conf <<'LIM'
# v2node-nofile
* soft nofile 1000000
* hard nofile 1000000
root soft nofile 1000000
root hard nofile 1000000
LIM
fi

# ───────────────────────── 4) v2node 内存上限（GOMEMLIMIT）─────────────────────────
if systemctl list-unit-files 2>/dev/null | grep -q '^v2node.service'; then
  say "设置 v2node GOMEMLIMIT=${GOMEM_MB}MiB (内存的${MEM_PCT}%) + 文件句柄"
  mkdir -p /etc/systemd/system/v2node.service.d
  cat >/etc/systemd/system/v2node.service.d/tune.conf <<EOF
[Service]
Environment=GOMEMLIMIT=${GOMEM_MB}MiB
${GOGC_LINE}
LimitNOFILE=1000000
EOF
  systemctl daemon-reload
  systemctl restart v2node && say "v2node 已重启（GOMEMLIMIT 生效）✓" || warn "v2node 重启失败，请手动 systemctl restart v2node"
else
  warn "未检测到 v2node.service，跳过 GOMEMLIMIT（装好 v2node 后重跑本脚本）"
fi

# ───────────────────────── 5) 汇总 ─────────────────────────
echo
say "========== 调优完成（${MODE}模式），当前状态 =========="
echo -e "  拥塞控制: $(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null)  qdisc: $(sysctl -n net.core.default_qdisc 2>/dev/null)"
if [ "$USE_ZSWAP" = "1" ]; then
  echo -e "  zswap: enabled=$(cat /sys/module/zswap/parameters/enabled 2>/dev/null) comp=$(cat /sys/module/zswap/parameters/compressor 2>/dev/null) pool=$(cat /sys/module/zswap/parameters/max_pool_percent 2>/dev/null)% shrinker=$(cat /sys/module/zswap/parameters/shrinker_enabled 2>/dev/null)"
else
  echo -e "  zram: ${ALGO} ${ZRAM_MB}MB   压缩比: $(zramctl /dev/zram0 --output DATA,COMPR 2>/dev/null | tail -1 | tr -s ' ' || echo n/a)"
fi
echo -e "  swappiness: $(sysctl -n vm.swappiness 2>/dev/null)  缓冲上限: $((BUF/1024/1024))MB"
echo -e "  GOMEMLIMIT: ${GOMEM_MB}MiB"
echo "  --- swap ---"; swapon --show 2>/dev/null
echo "  --- 内存 ---"; free -m | awk '/Mem:/{print "  可用: "$7"MB"} /Swap:/{print "  swap已用: "$3"MB / "$2"MB"}'
echo "  --- OOM 历史 ---"; echo "  OOM: $(dmesg 2>/dev/null | grep -c -i 'out of memory') 次"
say "======================================="
warn "注意：本脚本已重启 v2node（如已安装）。zram/内核参数开机自动生效。"
