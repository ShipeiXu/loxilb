# domain_fw

`domain_fw` 是一个独立编译的 Linux 内核模块：它在最早的
`NF_INET_PRE_ROUTING` 钩子处丢弃指定的入站 UDP 与 TCP DNS 查询。该模块面向
大型拒绝列表设计，不需要为每个 zone 建立一条 iptables 规则。

代码同时适配 CentOS 7 的 3.10 内核所使用的旧 Netfilter hook ABI，以及
Rocky Linux 9 的 5.14 内核所使用的新 ABI；procfs 控制接口也同时兼容 Linux 5.6
之前的 `file_operations` 与 Linux 5.6 起的 `proc_ops`。必须在目标 Linux 主机上，
或使用目标主机对应的内核头文件编译；不能在 macOS 上构建内核模块。

## 相比 iptables 示例为何更高效

原 iptables 规则在规则表遍历之后使用通用的 `xt_string` Boyer-Moore 字符串
匹配器。它匹配的字节序列并不对应一个完整、有效的 DNS 查询；面对大量 zone
也不能自然扩展，每增加一条规则都会增长数据面的规则遍历路径。

本模块只会对目标端口为 53 的 UDP/TCP 报文执行以下操作：

1. 对 IPv4/IPv6、UDP/TCP 和 DNS 头部做边界检查。
2. 解析一个 DNS 查询问题，并将 QNAME 规范化为小写。
3. 按 DNS 标签反向遍历 Trie，例如 `www.example.com` 依次匹配
   `com → example → www`。每个 zone 节点保存一个 QTYPE 集合。

规则不会线性遍历。查询路径使用 RCU，不获取配置锁；配置更新通过复制并替换对应
zone 的 QTYPE 集合完成。可选的 128 KiB Bloom Filter 对明显不可能命中的 QNAME
跳过 Trie 查找；Bloom Filter 只会产生额外查找，不会导致漏拦截。它默认关闭，应在
实际流量压测表明收益后再启用。

## 编译和加载

先在目标主机安装与当前内核匹配的开发包（通常为 `kernel-devel`），然后执行：

```sh
cd domain_fw
make
sudo insmod domain_fw.ko
```

模块会创建以下控制文件：

```text
/proc/domain_fw/control  # 仅 root 可写的命令接口
/proc/domain_fw/stats    # 计数器和当前规则数量
/proc/domain_fw/rules    # 当前配置的规则导出（只读）
```

可用模块参数：

```sh
sudo insmod domain_fw.ko max_rules=262144
sudo insmod domain_fw.ko dns_port=53
sudo insmod domain_fw.ko tcp_dns=0  # 如不需要 TCP DNS，可关闭它
sudo insmod domain_fw.ko bloom_enabled=1  # 按压测结果选择启用 Bloom Filter
echo 0 | sudo tee /sys/module/domain_fw/parameters/enabled
```

`tcp_dns` 和 `bloom_enabled` 均可在模块加载后动态修改：

```sh
echo 0 | sudo tee /sys/module/domain_fw/parameters/tcp_dns
echo 1 | sudo tee /sys/module/domain_fw/parameters/bloom_enabled
```

默认优先级为 `NF_IP_PRI_FIRST`，早于 raw 表。为与已有 Netfilter 规则栈集成，
可以设置 `hook_priority`，但通常应保持默认值。启用模块后应移除对应的 iptables
规则，否则未被本模块丢弃的报文仍会额外经过该规则。

## 规则语义与配置

`add zone qtype` 会拦截该 zone 本身及它的所有子域。域名不区分大小写，可以带
结尾的点。每个 zone 只有一个 Trie 节点，其中维护一个合并后的 QTYPE 集合。

- zone `*` 表示所有域名。例如 `add * PTR` 会拦截所有 PTR 查询。
- QTYPE `*` 或 `ANY` 表示该 zone 的所有 QTYPE；`TYPE255` 则仅表示 DNS QTYPE
  255。
- 数字类型和常见助记符均可使用，例如 `A`、`AAAA`、`PTR`、`TXT`、`MX`、`NS`、
  `CNAME`、`SRV`、`CAA`、`HTTPS` 等。

在同一 zone 同时配置 `ANY` 和特定 QTYPE 时，特定 QTYPE 会保留；删除 `ANY` 后，
先前配置的特定 QTYPE 规则仍然有效。

```sh
# 拦截 example.com 及其所有子域的所有查询。
echo 'add example.com ANY' | sudo tee /proc/domain_fw/control

# 与“拦截反向 DNS PTR 请求”的原意一致，但会真实解析 QNAME 和 QTYPE，
# 而非搜索一个固定的原始字节序列。
echo 'add in-addr.arpa PTR' | sudo tee /proc/domain_fw/control
echo 'add ip6.arpa PTR' | sudo tee /proc/domain_fw/control

# 拦截所有域名的 TXT 查询。
echo 'add * TXT' | sudo tee /proc/domain_fw/control

# 删除一条规则或清空整个内核规则表。
echo 'del example.com ANY' | sudo tee /proc/domain_fw/control
echo flush | sudo tee /proc/domain_fw/control

cat /proc/domain_fw/stats

# 导出当前生效的显式规则；输出可作为规则文件再次导入。
cat /proc/domain_fw/rules > running-rules.txt
```

`domainfwctl` 是一个不依赖额外软件包的控制工具。加载规则文件时，它会复用同一
个 procfs 文件描述符，避免每条规则重新打开一次文件。规则文件中每行格式为
`ZONE [QTYPE]`；空行和以 `#` 开头的行会被忽略。

```text
# deny-zones.txt
example.com ANY
tracker.example PTR
in-addr.arpa PTR
```

```sh
sudo install -m 0755 domainfwctl /usr/local/sbin/domainfwctl
sudo domainfwctl replace deny-zones.txt
sudo domainfwctl stats
sudo domainfwctl rules > running-rules.txt
```

`rules` 输出格式为 `ZONE QTYPE`。QTYPE 使用无歧义的 `TYPE<n>` 格式，全部
类型使用 `*`；输出顺序不保证按域名排序。该文件可通过 `domainfwctl replace`
重新导入。

`replace` 会先执行 `flush`，再执行 `load`，因此并不是原子化的策略切换。若
策略更新必须原子生效，可在短暂的重载窗口内保留原有 iptables 规则，或者将控制
面扩展为双表加指针切换。

## 处理范围与刻意放行的报文

这是一个 DNS **查询** 过滤器，并非覆盖全部合法 DNS 报文的完整解析器。它会丢弃
符合以下条件的常规 UDP DNS 查询，以及完整包含于一个 TCP segment 中的 TCP DNS
查询：`QR=0`、标准 opcode、`QDCOUNT=1`，且 QNAME 未使用压缩指针。TCP DNS 使用
两字节长度前缀；同一个 TCP segment 中最多检查前 8 个完整 DNS frame。跨 TCP
segment 的半包不会进行连接级重组，会直接放行。DoT、DoH 以及载荷已加密的 DNS
请求不在处理范围内。

IPv4 分片、IPv6 的已分片/jumbo/ESP 报文会直接放行；IPv6 Hop-by-Hop、Routing、
Destination 和 Authentication 扩展头会在 UDP 头之前被正确跳过。若目标内核未
启用 IPv6，则 IPv6 hook 不会被编译或注册，模块仍会正常提供 IPv4 过滤。格式错误
或当前不支持的报文同样会放行，以避免误拦截。

规则名和查询标签只使用标准 DNS 文本表示法的子集：ASCII 可打印字符（不含标签
内的 `.`）。国际化域名应使用 punycode 形式配置，以保证后缀和边界匹配没有歧义。

## 应选择 Netfilter 还是 eBPF？

若部署环境是可控的现代内核与网卡，并且追求最高转发性能，**XDP eBPF 更快**。
它在 skb 分配和完整 Netfilter 流水线之前运行；使用反转 DNS 标签的 LPM trie 很适合
实现 zone 后缀匹配。本仓库已有的 LoxiLB eBPF DNS 代码就是这一方向的示例。在
Rocky 9 上，它适合作为可选的高速路径，但仍应根据实际网卡驱动和流量模型压测。

但若要求一套可稳定部署在 **CentOS 7 和 Rocky 9** 上的实现，推荐使用本
**Netfilter 内核模块**。CentOS 7 的 3.10 内核中 eBPF/XDP 的回移特性、验证器限制、
map 特性和网卡驱动支持并不一致；能在 Rocky 9 上工作的 XDP 对象并不能保证在所有
CentOS 7 主机上可靠运行。本模块仍早于 raw iptables 规则执行，并避免了 `xt_string`
和逐规则遍历，因此能在保证兼容性的前提下显著优于题述的 iptables 实现。
