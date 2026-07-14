# fastd 完整配置教程与指令参考

本文根据 `src/config.y`、`src/config.c` 和相关源码整理，覆盖 fastd 当前配置文件支持的指令，并给出从最小双节点到 NAT 穿透、TURN、realm rendezvous、systemd 运行和排障的部署路径。命令行选项不是配置语法的一部分，但本文也列出日常运维所需的命令。

> 示例中的域名、IP、用户名和密钥均为占位符。不要把真实 `secret`、TURN 密码或 realm token 提交到版本库；配置文件和 peer 目录应仅对运行账户及管理员可读。

## 阅读路径

如果是首次部署，按以下顺序阅读即可：

1. 生成密钥，选择 `tap`、`multitap` 或 `tun`，并完成“最小示例”。
2. 使用“部署工作流”把虚拟接口接入路由或二层网络，再验证实际流量。
3. 按需启用“端口映射、打洞和 TURN”；公网固定节点不需要为了“看起来高级”而开启 NAT traversal。
4. 上线后通过 status socket 和“排障顺序”观察运行态，而不是仅凭进程仍在运行判断成功。

## 配置作用域速查

| 指令族 | 主配置 | peer group | peer / peer 文件 | 说明 |
| --- | :---: | :---: | :---: | --- |
| 身份、日志、接口、绑定、`mode`、`secret`、status socket | ✓ | — | — | 进程或本地接口级设置 |
| `method`、peer 生命周期 hook、`include` | ✓ | ✓ | 部分 `include` | group 会继承；peer 文件只能使用 peer 语法 |
| `transport`、`port-mapping`、`hole-punch`、`nat traversal`、TURN | ✓ | ✓ | ✓ | 由更具体的 peer 覆盖继承值 |
| `punch symmetric` / `punch hard-symmetric` | ✓ | — | ✓ | 后者是兼容别名；只改变该 peer 的 symmetric 策略 |
| STUN、realm、punch-control/data relay、punch 时序和预算 | ✓ | — | — | 这些是本机全局控制面设置 |
| `remote`、`key`、`float`、`realm`、peer 专属接口和 MTU | — | — | ✓ | 仅描述一个对端 |

`peer group` 可以嵌套。未被子 group 或 peer 覆盖的设置向下继承；一旦 peer 配置了自己的 TURN server 列表，它使用自己的列表而非追加父级列表。

## 基本语法

- 每条指令以分号 `;` 结束。
- 字符串使用双引号，例如 `"mesh0"`。
- 布尔值只接受 `yes` 或 `no`。
- 端口范围通常是 `1..65535`；`bind` 的端口允许 `0`，表示启动时选择一个固定随机端口。
- 地址可写为 `192.0.2.1:10000`、`192.0.2.1 port 10000`、`[2001:db8::1]:10000`、`[fe80::1%eth0]:10000`。
- `include` 的相对路径按包含它的配置文件所在目录解析。
- peer 文件使用 peer 内部语法，不需要外层 `peer "name" { ... }`。

## 默认值

| 项目 | 默认值 |
| --- | --- |
| `mode` | `tap` |
| `mtu` | `1500` |
| `persist interface` | `yes` |
| `drop capabilities` | `yes` |
| `protocol` | `ec25519-fhmqvc` |
| `compression` | `none` |
| `compression zstd level` | `3` |
| `transport` | `udp` |
| `port-mapping` | `off` |
| `hole-punch` | `off` |
| `turn relay` | `no` |
| `peer discovery` | `no` |
| `punch control relay` | `no` |
| `punch data relay` | `auto` |
| `punch symmetric` | `yes` |
| `punch keepalive` / `punch keepalive interval` | `yes` / `25` 秒 |
| `punch maintenance interval` | `10` 秒 |
| `punch announce interval` | `15` 秒 |
| `punch relay interval` | `10` 秒 |
| `punch max sockets` | `84` |
| `punch max packets` | `800` |
| `punch max attempts` | `1` |
| `punch max backups` | `25` |
| `peer limit` | unlimited |
| `method` | 未配置时回退到 `null` 并打印警告 |

## 最小示例

本机 `fastd.conf`：

```conf
log level info;
interface "fastd0";
bind 0.0.0.0:10000 default ipv4;

method "salsa2012+umac";
secret "本机私钥";

peer "site-b" {
	key "对端公钥";
	remote 203.0.113.20:10000;
}
```

只把 peer 放在单独目录：

```conf
interface "fastd0";
bind any:10000;
method "salsa2012+umac";
secret "本机私钥";

include peers from "peers";
```

`peers/site-b`：

```conf
key "对端公钥";
remote "site-b.example.net" port 10000;
```

## 作用域

fastd 配置有三个主要作用域：

- 主配置：顶层配置文件。
- peer group：`peer group "name" { ... }` 内。
- peer：`peer "name" { ... }` 内，或者 `include peer` / `include peers from` 读取的 peer 文件。

继承规则：

- `method`、hook、`transport`、`port-mapping`、`hole-punch`、`turn relay`、`turn server` 等可在 peer group 中配置。
- peer 可覆盖自己的 `transport`、`port-mapping`、`hole-punch`、`punch symmetric`、`turn relay`、`turn server` 等。
- peer group 可嵌套，子 group 继承父 group 未覆盖的设置。

## 主配置指令

主配置可以使用所有 peer group 指令，另外支持以下全局指令。

### 身份与权限

```conf
user "<user>";
group "<group>";
drop capabilities yes|no|early|force;
```

- `user` / `group`：切换 fastd 运行用户和组。
- `drop capabilities yes`：默认行为，运行 `on up` 后丢弃不再需要的 capabilities。
- `drop capabilities no`：不丢弃 capabilities。
- `drop capabilities early`：在运行 `on up` 前丢弃 capabilities。
- `drop capabilities force`：强制丢弃更多 capabilities，适合已预先准备持久 TUN/TAP 接口的场景。

### 加密、认证和压缩

```conf
protocol "ec25519-fhmqvc";
secret "<secret-key>";
method "<method>";
cipher "<cipher>" use "<implementation>";
mac "<mac>" use "<implementation>";
compression no|none;
compression zstd [level <1-22>];
compression "<algorithm>" [level <1-22>];
secure handshakes yes|no;
```

- `protocol`：目前源码只支持 `ec25519-fhmqvc`。
- `secret`：本机私钥，通常由 `fastd --generate-key` 生成。
- `method`：配置可协商的数据加密/认证方法。可写多条，越靠前优先级越高。
- `cipher` / `mac`：强制选择某个 cipher/MAC 的实现，通常不需要手动设置。
- `compression none` 或 `compression no`：关闭压缩。
- `compression zstd level <n>`：启用 zstd，等级 `1..22`，默认 `3`。
- `secure handshakes`：兼容旧配置的废弃指令；不安全握手已经不再支持。

常见 method 形式：

| method | 说明 |
| --- | --- |
| `salsa2012+umac` | 常用加密认证组合 |
| `salsa20+umac` | Salsa20 + UMAC |
| `aes128-gcm` | AES128-CTR + GMAC 的简写 |
| `null` | 不加密不认证，仅用于测试或受信网络 |
| `null@l2tp` | L2TPv3 格式，常与 L2TP offload 配合 |
| `<cipher>+poly1305` | stream cipher + Poly1305 |
| `<cipher>+<cipher>+umac` | 分离数据加密和认证 tag 加密 |
| `<cipher>+<cipher>+gmac` | 分离数据加密和 GMAC tag 加密 |

可用 cipher 名称取决于编译选项，源码包含 `aes128-ctr`、`salsa20`、`salsa2012`、`null`。可用 MAC 名称包含 `ghash`、`uhash`。

### 日志

```conf
log level fatal|error|warn|info|verbose|debug|debug2;
log to stderr [level fatal|error|warn|info|verbose|debug|debug2];
log to syslog [level fatal|error|warn|info|verbose|debug|debug2];
log to syslog as "<ident>" [level fatal|error|warn|info|verbose|debug|debug2];
hide ip addresses yes|no;
hide mac addresses yes|no;
```

- `log level`：设置默认日志级别。
- `log to stderr`：启用或调整 stderr 日志。
- `log to syslog`：启用或调整 syslog 日志。
- `hide ip addresses` / `hide mac addresses`：日志中隐藏 IP 或 MAC 地址。

### 接口、绑定地址和包标记

```conf
interface "<name>";
bind <IPv4>[:<port>] [interface "<ifname>"] [default [ipv4]];
bind <IPv6>[:<port>] [interface "<ifname>"] [default [ipv6]];
bind any[:<port>] [interface "<ifname>"] [default [ipv4|ipv6]];
bind <IPv4> port <port> [interface "<ifname>"] [default [ipv4]];
bind <IPv6> port <port> [interface "<ifname>"] [default [ipv6]];
bind any port <port> [interface "<ifname>"] [default [ipv4|ipv6]];
packet mark <mark>;
mtu <576-65535>;
pmtu yes|no|auto;
mode tap|multitap|tun;
persist interface yes|no;
offload l2tp yes|no;
forward yes|no;
peer discovery yes|no;
realm server "<url>" token "<token>" id "<local-id>" [stun server "<host>" port <port>];
stun server "<host>":<port>;
stun server "<host>" port <port>;
punch control relay yes|no;
punch data relay auto|yes|no;
punch symmetric yes|no;
punch hard-symmetric yes|no;
punch keepalive yes|no;
punch keepalive interval <seconds>;
punch maintenance interval <seconds>;
punch announce interval <seconds>;
punch relay interval <seconds>;
punch max sockets <1-256>;
punch max packet <1-4096>;
punch max packets <1-4096>;
punch max attempts <1-64>;
punch max backups <1-256>;
```

- `interface`：设置 TUN/TAP 接口名。名称不能包含 `/`。可使用 `%n`（peer 名称）或 `%k`（peer key 前 16 位）为多接口模式生成唯一名称。
- `bind`：绑定本地监听地址。省略端口表示每次 outgoing 连接用动态随机 socket；端口 `0` 表示启动后固定随机端口。
- `default ipv4|ipv6`：指定该 bind 地址作为对应地址族的默认 outgoing bind。
- `packet mark`：Linux 上给 fastd 发出的包设置 mark，可配合策略路由；数字可用十进制、`0x` 十六进制或 `0` 前缀八进制。
- `mtu`：设置 MTU，范围 `576..65535`。
- `pmtu`：兼容旧配置的占位指令，源码中不产生实际效果。
- `mode tap`：所有 peer 共用一个 TAP 接口。
- `mode multitap`：每个 peer 一个 TAP 接口。
- `mode tun`：TUN 模式。
- `persist interface no`：仅在有活跃 session 时创建 peer 专属接口；TAP 模式无实际影响。
- `offload l2tp yes`：启用 Linux L2TP offload。要求 `mode multitap`、`persist interface no`，且不能与 payload compression 同时使用。
- `forward yes`：允许 peer 间转发，注意避免环路。
- `peer discovery yes`：启用基于可信 relay 的 endpoint discovery。TAP relay 在同时开启 `forward yes` 时，会把已连接 peer 的公网 endpoint 和已学习 MAC 通过认证控制包介绍给其他 peer；接收端把该 endpoint 作为额外直连握手目标，可配合 `hole-punch auto`。直连建立前或失败后，相关 MAC 的流量继续回退到 relay；直连建立后切换二层转发表，不重置隧道内已有 TCP 连接。协商出的 method 需要支持认证控制包；`null` / `null@l2tp` 不承载 discovery 消息。
- `realm server`：配置外部 rendezvous server。fastd 使用它注册本机 realm、保持 SSE 事件流、周期性向 peer 的 realm 发起 `/connect`，并把返回或推送的 endpoint 作为临时直连握手目标。realm server 只处理控制面，不中转隧道流量。原版 Hysteria realm server 的 SSE punch 事件不包含来源 peer 身份，fastd 会把这类匿名 endpoint 试探性地用于已配置 `realm` 的 peer，并由 fastd 的认证握手过滤不匹配的 peer。配置 `stun server` 后，fastd 会从实际使用的 IPv4 UDP socket 发送 STUN binding request，并优先通告 STUN 得到的公网 UDP endpoint；未配置 STUN 时只能通告本地 bind 地址，通常只适合公网或已有端口映射的 socket。
- 全局 `stun server`：配置用于 NAT 类型识别的 STUN server，可配置多条。fastd 会周期性探测本机公网 UDP endpoint、NAT 类型、端口范围和可预测 symmetric NAT 的端口步进，并在 `--status` 的 `NAT` 区块中展示；该功能需要编译时启用 `nat_detect` / libnice。配置了全局 STUN 后，已建立连接的 peer 之间还会通过 punch control 包交换 NAT 元数据。
- `punch control relay yes`：允许一个已连接的可信节点在 peer 之间转发 punch control 包，转发控制面 endpoint/NAT 信息。它可用于 A/B 都只与公网节点 C 建立普通连接、但 A/B 之间希望直接打洞的拓扑；A/B 仍需要互相配置 peer 公钥，通常配合全局 `stun server`、`transport udp|auto` 和 `hole-punch udp|auto`。
- `punch data relay auto|yes|no`：控制 NAT traversal 数据 fallback。默认 `auto`，在启用 `nat traversal yes` 或 `punch control relay yes` 时生效；显式 `no` 可关闭。该 fallback 不等于 `forward yes`：它在 TAP/Multitap 模式下转发已学习目的 MAC 的单播包，并且只对 ARP 与 IPv6 Neighbor Discovery 做受限地址解析 relay，帮助首包建立 MAC 学习；其它未知 MAC、广播和组播不会被泛洪。源 peer 和目的 peer 都必须已认证建立并启用 NAT traversal。
- `punch symmetric yes|no`：控制是否启用 symmetric NAT 打洞策略。全局默认 `yes`，peer 可覆盖；开启后，easy-symmetric NAT 使用端口步进预测，普通 symmetric NAT 使用 `punch max sockets` 限制内的有界端口扫描。关闭后，fastd 只使用精确 endpoint / cone 风格打洞，不做 symmetric 端口预测或扫描。
- `punch hard-symmetric yes|no`：已弃用的兼容别名，语义等同于 `punch symmetric yes|no`；新配置请只使用后者。
- `punch keepalive yes|no`：是否在 NAT traversal 路径上定期发送空 payload 保活。默认开启；位于 NAT 后的节点通常不应关闭，否则路由器映射和备用直连路径可能在空闲时失效。
- `punch keepalive interval <seconds>`：保活间隔，默认 25 秒。必须为大于 0 的秒数。
- `punch maintenance interval <seconds>`：打洞任务、临时 socket 与状态的维护周期，默认 10 秒。降低间隔会更快重试，但增加控制面和 socket 开销。
- `punch announce interval <seconds>`：本机 NAT 元数据向已建立 peer 公告的最小间隔，默认 15 秒。
- `punch relay interval <seconds>`：协调节点为同一任务生成 punch 命令的最小间隔，默认 10 秒。
- `punch max sockets`：限制单次 punch 命令可使用的预测/探测 UDP socket 数，默认 `84`，最大 `256`。hard-symmetric NAT 使用该上限；easy-symmetric 预测仍使用 25 端口窗口。
- `punch max packet` / `punch max packets`：限制每轮维护周期内 relay 节点转发的 punch control 包数量，默认 `800`，最大 `4096`；两个写法等价。`punch data relay` 的 ARP/IPv6 ND 自举转发也使用该预算，避免一次向过多 peer 发送地址解析包。
- `punch max attempts`：一个 punch-control endpoint 的认证 handshake 尝试次数上限，默认 1，最大 64。它不是应用流量的重传次数；提高它会增加短时间探测流量。
- `punch max backups`：每个 peer 保持保活的非活动 direct candidate 上限，默认 25，最大 256。有效备用路径可在活动路径失效时被提升；资源受限设备可下调这个值。

### 状态 socket

```conf
status socket "<unix-socket-path>";
```

启用 UNIX status socket。查询方式：

```sh
fastd --config fastd.conf --status
fastd --config fastd.conf --status --json
fastd --status-socket /run/fastd.sock --status
```

普通 `--status` 输出人类可读的表格状态，包含 `Overview`、`NAT`、`Punch`、`Traffic`、`Peers`、`Connections` 和 `Hole Punch` 等区块。`Peers` 展示 peer 名称、公钥、当前 endpoint、接口、MTU 和流量计数；`Connections` 展示已建立连接的 active endpoint、transport、接口和是否通过打洞建立；`NAT` / `Punch` / `Hole Punch` 用于观察 NAT 探测和打洞状态。加 `--json` 输出原始 JSON，更适合脚本、监控和兼容性稳定的机器读取场景。

### 全局生命周期 hook

```conf
on pre-up "<command>";
on post-down "<command>";
```

- `on pre-up`：创建接口前执行。
- `on post-down`：销毁接口后执行。
- 这两个 hook 在源码中固定同步执行，不支持 `sync|async` 关键字。

## Peer group 指令

这些指令可写在主配置顶层或 `peer group "name" { ... }` 中。

### 结构和包含

```conf
peer "name" {
	# peer 配置
}

peer group "name" {
	# peer group 配置
}

peer limit <limit>;

include "<file>";
include peer "<file>" [as "<name>"];
include peers from "<dir>";
```

- `peer`：内联定义一个 peer。
- `peer group`：创建子 group，子 group 继承父 group 的配置。
- `peer limit`：限制当前 group 同时连接数量。
- `include "<file>"`：包含普通配置文件。
- `include peer "<file>" [as "<name>"]`：包含一个 peer 文件。
- `include peers from "<dir>"`：把目录下每个普通文件作为 peer 文件读取，忽略点文件和 `~` 结尾备份文件；收到 SIGHUP 时会重新加载。

### 传输、端口映射、打洞和 TURN

```conf
transport udp|tcp|auto;

port-mapping off|nat-pmp|upnp-igd|pcp|auto;
nat-pmp yes|no;

hole-punch off|tcp|udp|auto;

stun server "<host>":<port>;
stun server "<host>" port <port>;
punch control relay yes|no;
punch data relay auto|yes|no;
punch symmetric yes|no;
punch max sockets <1-256>;
punch max packet <1-4096>;
punch max packets <1-4096>;

turn relay yes|no;
turn server "<address>":<port>;
turn server "<address>" port <port>;
turn server "<address>":<port> user "<username>" password "<password>";
turn server "<address>" port <port> user "<username>" password "<password>";
```

- `transport udp`：默认 UDP 数据传输。
- `transport tcp`：通过 TCP stream 传输 fastd packet。
- `transport auto`：先探测 TCP，失败后回退 UDP。握手中会校验双方实际 transport 一致。
- `port-mapping`：自动映射固定 IPv4 UDP bind 端口。`nat-pmp` 和 `pcp` 会向 IPv4 默认网关申请可续租映射；`upnp-igd` 会通过 UPnP IGD 添加 UDP 映射；`auto` 使用当前构建中可用的所有后端。`nat traversal yes` 会在构建支持时自动选择 `port-mapping auto`；若不希望自动申请路由器映射，在 `nat traversal yes` 后显式写 `port-mapping off`。PCP/NAT-PMP/UPnP IGD 不处理 IPv6-only socket，也不映射每次 peer 尝试用的临时 socket；punch-control 创建的可复用 public UDP listener 可以申请动态映射。
- `nat-pmp yes|no`：兼容别名，等价于 `port-mapping nat-pmp|off`。
- `hole-punch tcp|udp|auto`：启用确定性 IPv4 打洞；默认关闭。双方需要知道彼此公网 IPv4 endpoint；在 TAP relay 转发网络中，`peer discovery yes` 可以由可信 relay 提供这个 endpoint。
- `nat traversal yes`：一键启用 `transport auto`、`hole-punch auto`、`port-mapping auto`（构建支持时）、symmetric NAT 策略、root 上的 punch-control relay、受控 data relay fallback 和 NAT keepalive。需要关闭自动端口映射时，在其后写 `port-mapping off`。
- `stun server`、`punch control relay`、`punch data relay`、所有 `punch … interval`、`punch keepalive`、`punch max sockets`、`punch max packet(s)`、`punch max attempts` 与 `punch max backups` 只能写在主配置中；`punch symmetric` 可写在主配置或 peer 配置中。
- `stun server`：启用全局 NAT 类型识别，结果用于 status 输出和 punch control NAT 元数据交换。该指令不同于 `realm server ... stun server ...`；realm 内嵌 STUN 只用于向 realm server 通告当前 UDP endpoint。
- `punch control relay yes`：启用控制面 endpoint/NAT 信息转发，可在 `forward no` 的可信公网节点上帮助两个已配置彼此公钥的 NAT 后 peer 发起直接 UDP 打洞。
- `punch data relay auto|yes|no`：启用受控数据 fallback。开启后，可信公网节点即使保持 `forward no`，也能在 A/B 直连尚未建立或暂时不可用时中继已学习目的 MAC 的单播数据；同时会 relay ARP/IPv6 ND 来完成初始 MAC 学习，但不会泛洪其它未知目的 MAC 或广播/组播。
- `punch symmetric yes|no`：允许或禁止 symmetric NAT 策略；开启时会同时尝试 easy-symmetric 端口预测和普通 symmetric 有界端口扫描，哪个候选先完成握手就使用哪个。
- `punch max sockets`：限制每次 symmetric punch 使用的 UDP socket 数。
- `punch max packet(s)`：限制 relay 每轮转发 punch control 包的数量，也限制 ARP/IPv6 ND 自举 relay 的发送扇出。
- `turn relay yes`：使用外部 TURN server 进行 UDP relay；需要编译时启用 libnice。
- `turn server`：可配置多条；peer 自己配置 server 后使用 peer 的列表，不再继承 group 列表。

NAT traversal 示例：

```conf
bind 0.0.0.0:10000 default ipv4;
transport auto;
port-mapping auto;
hole-punch auto;
stun server "stun.example.net" port 3478;
punch symmetric yes;

turn relay yes;
turn server "turn.example.net" port 3478 user "fastd" password "secret";
```

Relay-assisted direct peering 示例：

```conf
# relay C
mode tap;
forward yes;
peer discovery yes;
transport auto;
hole-punch auto;

# 节点 A/B
mode tap;
peer discovery yes;
transport auto;
hole-punch auto;
```

- relay C 必须与 A/B 都保持普通 fastd 连接，通常由 A/B 配置 C 的 `remote`。
- C 开启 `forward yes` 后可在直连失败或打洞尚未完成时继续中继内网流量。
- `peer discovery yes` 让 C 把它观察到的 A/B 公网 endpoint 和 MAC 通过认证控制包介绍给另一侧。
- A/B 收到介绍后尝试直连；直连成功后相关 MAC 切到 direct peer，隧道内已有 TCP 连接不需要重建。
- 若打洞失败，转发表仍可回退到 C；如果存在 symmetric NAT、CGNAT 或严格防火墙，通常仍需要 relay/TURN。
- 协商出的 method 需要支持认证控制包；`null` / `null@l2tp` 不承载 discovery 消息。

Punch-control relay 示例：

```conf
# 公网协调节点 C：forward no，控制面打洞，并允许受控单播数据 fallback
forward no;
punch control relay yes;
punch data relay auto;
stun server "stun.example.net" port 3478;

# NAT 后节点 A/B：各自与 C 建立普通 fastd 连接，同时配置对方 peer 公钥
transport udp;
hole-punch udp;
stun server "stun.example.net" port 3478;
punch symmetric yes;
```

- C 必须与 A/B 都建立 fastd session，并且协商 method 要支持认证控制包。
- `punch data relay auto` 会通过受限 ARP/IPv6 ND relay 自举 MAC 学习，随后只转发已学习目的 MAC 的单播数据；它不会替代普通二层转发或泛洪其它未知流量。
- A/B 必须互相配置 peer 公钥；即使没有为对方配置 `remote`，收到 C 转发的 punch control endpoint 后也会主动试探 UDP handshake。
- 全局 `stun server` 让节点发布 NAT 类型和公网 endpoint；`punch symmetric yes` 会同时覆盖 easy-symmetric 端口步进预测和普通 symmetric 有界扫描。
- 该机制仍是机会式 NAT traversal，不保证穿透所有 CGNAT、symmetric NAT 或严格防火墙；失败时需要保留 relay/TURN 等 fallback。

### 方法和 hook

```conf
method "<method>";

on up [sync|async] "<command>";
on down [sync|async] "<command>";
on connect [sync|async] "<command>";
on establish [sync|async] "<command>";
on disestablish [sync|async] "<command>";
on verify [sync|async] "<command>";
```

- `method`：为当前 group 配置协商方法。
- `on up`：接口创建后执行。
- `on down`：接口销毁前执行。
- `on connect`：发送握手准备连接时执行。
- `on establish`：session 建立后执行。
- `on disestablish`：session 断开后执行。
- `on verify`：未知 peer 尝试连接时执行；返回 `0` 接受，否则拒绝。未知 peer 会加入定义该 hook 的 group。
- 这些 hook 的 `sync|async` 可省略；未写时命令本身按 `async` 保存。部分接口创建/销毁路径会为了保证顺序而同步等待。

hook 环境变量：

| 变量 | 说明 |
| --- | --- |
| `FASTD_PID` | 所有 hook 都有，表示 fastd 主进程 PID |
| `INTERFACE` | 接口相关 hook 有，表示接口名 |
| `INTERFACE_MTU` | 接口相关 hook 有，表示接口 MTU |
| `LOCAL_KEY` | peer 相关 hook 有，表示本机公钥 |
| `PEER_KEY` | peer 相关 hook 有，表示 peer 公钥 |
| `PEER_NAME` | peer 相关 hook 有，表示 peer 名称 |
| `LOCAL_ADDRESS` / `LOCAL_PORT` | `on connect`、`on establish`、`on disestablish`、`on verify` 有，表示本地地址和端口 |
| `PEER_ADDRESS` / `PEER_PORT` | `on connect`、`on establish`、`on disestablish`、`on verify` 有，表示对端地址和端口 |

`on pre-up` 和 `on post-down` 不带额外环境变量。TAP 单接口模式下的全局 `on up` / `on down` 只带接口变量；peer 专属接口路径会带 peer 变量。

## Peer 指令

peer 块和 peer 文件支持以下指令。

### 地址、密钥和浮动 peer

```conf
key "<public-key>";
remote <IPv4>:<port>;
remote <IPv6>:<port>;
remote [ipv4|ipv6] "<hostname>":<port>;
remote <IPv4> port <port>;
remote <IPv6> port <port>;
remote [ipv4|ipv6] "<hostname>" port <port>;
remote passive;
realm "<remote-id>";
float yes|no;
include "<file>";
```

- `key`：peer 公钥，必填。
- `remote`：主动连接的对端地址，可配置多条。hostname 前可加 `ipv4` 或 `ipv6` 限制解析地址族。
- `remote passive`：将 peer 固定为纯被动模式。fastd 不解析或拨号该 peer 的 `remote`，不会从 realm/discovery/punch-control 接收候选，也不会创建 hole-punch socket、申请该 peer 的端口映射、发送 NAT metadata、使用 TURN 或 NAT traversal keepalive。它会像传统的无 `remote` floating peer 一样等待对端入站握手，并使用这条通过认证的入站 UDP/TCP 连接建立隧道。该设置优先于该 peer、peer group 和全局的 `nat traversal`、`hole-punch`、`port-mapping`、`turn relay` 和 `punch symmetric` 设置；不要把它用于需要主动连接或 realm rendezvous 的 peer。
- 未配置 `remote` 的 peer 总是 floating，只接受入站连接，不主动连接。
- `realm`：该 peer 在外部 rendezvous server 上的 realm ID。全局配置了 `realm server` 后，即使该 peer 未配置 `remote`，fastd 也会通过 realm 控制面获取临时 endpoint 并主动试探 UDP handshake；匿名 punch 事件会先投递给本机配置了 `realm` 的 peer，由认证握手消歧。通常配合 `transport udp` 和 `hole-punch udp|auto` 使用；它是机会式 NAT traversal，不能保证穿透 symmetric NAT 或严格防火墙。
- `float yes`：允许该 peer 从任意地址/端口建立连接。
- `float no`：只接受配置的 `remote` 地址/端口。
- `include`：在当前 peer 配置中包含另一个文件。

### Peer 覆盖项

```conf
interface "<name>";
mtu <576-65535>;

transport udp|tcp|auto;

port-mapping off|nat-pmp|upnp-igd|pcp|auto;
nat-pmp yes|no;

hole-punch off|tcp|udp|auto;

punch symmetric yes|no;

turn relay yes|no;
turn server "<address>":<port>;
turn server "<address>" port <port>;
turn server "<address>":<port> user "<username>" password "<password>";
turn server "<address>" port <port> user "<username>" password "<password>";
```

- `interface`：peer 专属接口名；TAP 模式下无效果。
- `mtu`：peer 专属 MTU；TAP 模式下无效果。
- `transport`、`port-mapping`、`hole-punch`、`turn relay`、`turn server`：覆盖继承自 group 的值。
- `punch symmetric`：覆盖全局 symmetric NAT punch 策略，用于只对某些 peer 打开或关闭端口预测/扫描。

peer 示例：

```conf
peer "branch-a" {
	key "分支A公钥";
	remote ipv4 "branch-a.example.net" port 10000;
	float no;

	transport auto;
	hole-punch auto;
	turn relay yes;
}
```

## 常见完整示例

### 1. 普通 UDP mesh 节点

```conf
log level info;
interface "fastd0";
bind any:10000 default;

method "salsa2012+umac";
secret "本机私钥";

include peers from "peers";
```

### 2. 启用 NAT-PMP/UPnP/PCP、打洞和 TURN fallback

```conf
log level info;
interface "fastd0";
bind 0.0.0.0:10000 default ipv4;

method "salsa2012+umac";
secret "本机私钥";

transport auto;
port-mapping auto;
hole-punch auto;

turn relay yes;
turn server "turn.example.net" port 3478 user "fastd" password "secret";

peer "site-b" {
	key "对端公钥";
	remote "site-b.example.net" port 10000;
}
```

### 3. 使用 peer group 给不同 peer 设置不同策略

```conf
interface "fastd0";
bind any:10000;
method "salsa2012+umac";
secret "本机私钥";

peer group "direct" {
	transport udp;
	hole-punch off;

	peer "lan-peer" {
		key "对端公钥";
		remote 192.0.2.10:10000;
	}
}

peer group "nat" {
	transport auto;
	port-mapping auto;
	hole-punch auto;

	turn relay yes;
	turn server "turn.example.net" port 3478 user "fastd" password "secret";

	include peers from "nat-peers";
}
```

### 4. 使用 realm rendezvous 连接两个 passive peer

```conf
mode multitap;
forward no;

bind 0.0.0.0:10000 default ipv4;
method "salsa2012+umac";
secret "本机私钥";

realm server "https://realm.example.net:8443" token "shared-token" id "node-a" stun server "stun.example.net" port 3478;

peer "node-b" {
	key "node-b 公钥";
	realm "node-b";
	transport udp;
	hole-punch udp;
}
```

这个模式下 `node-b` 不需要配置 `remote`，仍然是 floating peer。fastd 通过 realm server 交换公网 UDP endpoint，并直接向对方发送 fastd handshake；成功后数据面直接走 A/B 之间的 UDP 流，不经过 realm server。该模式不能替代 TURN relay，遇到无法 UDP 打洞的 NAT 组合仍可能失败。

### 5. L2TP offload 示例

```conf
mode multitap;
persist interface no;
offload l2tp yes;

bind 0.0.0.0:10000;
method "null@l2tp";
secret "本机私钥";

peer "site-b" {
	key "对端公钥";
	remote 203.0.113.20:10000;
	interface "fastd-site-b";
}
```

注意：L2TP offload 要求 Linux L2TP 支持、编译时启用 `offload_l2tp`，且不能启用 payload compression。

## 部署工作流：从空目录到可验证隧道

以下流程适用于两个可互访节点。它故意先不启用 NAT traversal、TURN 或 realm：先证明密钥、监听、路由和 MTU 正确，再增加复杂性。

### 1. 创建目录和密钥

```sh
install -d -m 0750 /etc/fastd/mesh/peers
umask 077
fastd --generate-key
```

在每个节点保存该节点输出的 `Secret`；仅把 `Public` 复制给对端。不要将两台节点的 `Secret` 写成同一个值。可用以下命令从配置中的私钥重新确认公钥：

```sh
fastd --machine-readable --show-key --config /etc/fastd/mesh/fastd.conf
```

### 2. 选择接口模式和地址规划

| 目标 | 推荐模式 | 地址和路由工作 |
| --- | --- | --- |
| 两端或 mesh 的二层网桥 | `tap` | 将一个共享接口接入 bridge，或使用 hook 配置 IP/bridge |
| 每个 peer 都要独立二层接口 | `multitap` | 使用 `interface "fastd-%n";`，每个 peer 分别接入 VLAN、bridge 或策略 |
| 三层点到点 / 路由 VPN | `tun` | 在 hook 或系统网络配置中为 TUN 配置地址和静态路由 |

fastd 只创建和承载 TUN/TAP，不会自动替你分配虚拟 IP、添加路由、启用 Linux 转发或配置防火墙。`tap` 中广播域的环路由网络拓扑负责避免；`forward yes` 也必须谨慎使用。

### 3. 写主配置与 peer 文件

`/etc/fastd/mesh/fastd.conf`：

```conf
mode tun;
interface "fastd0";
bind 0.0.0.0:10000 default ipv4;
log level info;
status socket "/run/fastd/mesh.sock";

method "salsa2012+umac";
secret "<LOCAL_SECRET>";

on up sync "ip addr replace 10.70.0.1/30 dev $INTERFACE; ip link set $INTERFACE up";
on down sync "ip link set $INTERFACE down";

include peers from "peers";
```

`/etc/fastd/mesh/peers/site-b`：

```conf
key "<SITE_B_PUBLIC_KEY>";
remote ipv4 "vpn-b.example.net" port 10000;
float no;
```

对端使用镜像配置和不同的 TUN 地址（例如 `10.70.0.2/30`）。如果使用 shell hook，请为包含空格、分号或变量展开的命令正确加引号，并将脚本改为受版本控制、可单独测试的文件；复杂逻辑不应堆在一行 hook 中。

### 4. 放行外部端口并接入业务网络

至少放行与 `bind` 相同的 UDP 端口；若使用 TCP transport 或 TURN，还要按实际 listener / TURN server 放行相应 TCP/UDP 流量。示例（请按自身防火墙框架调整）：

```sh
nft add rule inet filter input udp dport 10000 accept
sysctl -w net.ipv4.ip_forward=1       # 只有本机要转发三层 VPN 流量时才需要
```

在路由器或远端主机增加到 VPN 子网的路由。例如，远端 LAN `10.80.0.0/24` 经由 site-b 时，需要在本地添加指向 fastd 对端隧道地址的路由。不要用 `forward yes` 代替操作系统三层路由。

### 5. 验证配置、启动与验收

```sh
fastd --verify-config --config /etc/fastd/mesh/fastd.conf
fastd --config /etc/fastd/mesh/fastd.conf --log-level verbose

# 另一个终端：不重启 daemon，只查询运行态
fastd --status-socket /run/fastd/mesh.sock --status
fastd --status-socket /run/fastd/mesh.sock --status --json
ip link show fastd0
ping -I fastd0 10.70.0.2
```

验收应至少包括：两侧 status 显示 established peer、虚拟接口已 UP、双向 ping 或真实业务端口可达、重启其中一端后能重新建立 session。对于 `tap`，还应检查 ARP/MAC 学习及广播域没有环路；对于 `tun`，还应检查返回路由，避免只有单向流量。

## 命令行、重载与 systemd

配置文件和命令行按出现顺序解析：放在后面的设置覆盖前面的设置。日常只需记住下列命令；完整参数可使用 `fastd --help` 查看。

| 目的 | 命令或选项 |
| --- | --- |
| 前台调试 | `fastd --config /etc/fastd/mesh/fastd.conf --log-level debug` |
| 后台运行 | `fastd --daemon --pid-file /run/fastd/mesh.pid --config …` |
| 只校验语法与构建支持 | `fastd --verify-config --config …` |
| 生成 / 查看密钥 | `--generate-key`；`--show-key --config …`；配合 `--machine-readable` |
| 加载一个 peer 或 peer 目录 | `--config-peer FILE`；`--config-peer-dir DIR` |
| 查询 status socket | `--status-socket PATH --status [--json]` |
| 重新读取 peer 目录 | 向主进程发送 `SIGHUP` |

可使用仓库提供的 [systemd 模板](doc/examples/fastd@.service)：

```ini
[Service]
Type=notify
ExecStart=/usr/bin/fastd --syslog-level info --syslog-ident fastd@%I -c /etc/fastd/%I/fastd.conf
ExecReload=/bin/kill -HUP $MAINPID
```

安装为 `/etc/systemd/system/fastd@.service` 后：

```sh
systemctl daemon-reload
systemctl enable --now fastd@mesh
systemctl reload fastd@mesh
journalctl -u fastd@mesh -f
```

`SIGHUP` 的主要用途是重载 `include peers from` 目录；对主配置结构、接口模式、bind 或全局密钥的变更，使用受控重启并重新验证状态，不要假设 reload 会无中断应用所有设置。

## 安全与生产配置清单

- 每个节点使用独立私钥，目录权限建议为 `0750`，包含私钥的文件为 `0640` 或更严格；避免把私钥、TURN 密码和 realm token 写进日志、镜像或 CI 输出。
- 使用真实的认证加密 `method`。`null` 和 `null@l2tp` 只适合非常明确的测试 / offload 场景，不能用于不可信网络，也不承载 discovery 控制包。
- 对固定公网 peer 设置 `float no` 与明确 `remote`；只有需要地址漂移、动态接入或 realm rendezvous 的 peer 才使用 `float yes` 或不配置 `remote`。
- `on verify` 接受未知 peer 时相当于把接入控制交给外部程序。脚本必须校验输入、设置超时并记录审计信息；默认的显式 `peer` 白名单更易审计。
- 仅在需要 peer-to-peer 转发时启用 `forward yes`，并设计无环 topology。把 `punch data relay` 视为受限 NAT fallback，而不是通用二层交换机。
- 启用 `port-mapping auto` 前确认你愿意让进程向本地网关申请映射；在受管企业网络中常应显式设为 `off`，只使用管理员配置的防火墙/NAT 规则。
- 运行 fastd 的账户需要创建或操作 TUN/TAP 所需权限。先在 staging 测试 `drop capabilities early|force`；不能确认时保留默认 `yes`，不要为了省事设为 `no`。

## 排障顺序

1. **无法启动**：先运行 `--verify-config`；再检查所选的 `zstd`、TURN、NAT-PMP/UPnP/PCP、L2TP 是否被当前构建启用。配置解析器会拒绝未编译支持的后端。
2. **接口没有出现**：检查 `mode`、`persist interface`、`on pre-up` / `on up` 日志和 `/dev/net/tun`。`multitap` 且 `persist interface no` 时，peer 未建立前看不到对应接口是预期行为。
3. **有 session 但业务不通**：区分 TUN 路由问题与 TAP bridge/MAC 问题；检查双向路由、rp_filter、防火墙、MTU，以及远端是否允许回程流量。先用小 ping，再用实际 TCP/UDP 业务验证。
4. **NAT 后无法直连**：确认 A/B 都有对方公钥、STUN 可访问、`Hole Punch` 状态有 endpoint/NAT metadata，并保留 C 或 TURN fallback。不要把 `punch control relay` 当作流量 relay；若必须保证业务，配置 `forward yes` 的可信 relay 或 TURN。
5. **直连偶发失效**：查看 keepalive、活动/备用路径、路由器 UDP 超时和 `punch max backups`。在明确资源预算后再调整 socket/packet/interval 上限，避免盲目把所有值设到最大。
6. **status 自动化失败**：用 `--status --json`，检查 JSON 字段而非依赖人类表格字符；确认查询的是运行中 daemon 创建的同一个 UNIX socket。

## 验证配置

```sh
build/src/fastd --verify-config --config fastd.conf
```

如果已安装到系统：

```sh
fastd --verify-config --config /etc/fastd/mesh/fastd.conf
```
