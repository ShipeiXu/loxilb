// SPDX-License-Identifier: GPL-2.0
/*
 * domain_fw.c - fast DNS zone/QTYPE dropper
 *
 * Rules are stored in a reverse-label trie.  A query for www.example.com
 * walks com -> example -> www, so an example.com rule also applies to all of
 * its descendants without repeated suffix-string hashing.  Packet readers use
 * RCU only; the configuration mutex is never acquired in the data path.
 */

#include <linux/bitmap.h>
#include <linux/ctype.h>
#include <linux/errno.h>
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/in.h>
#include <linux/ip.h>
#if defined(CONFIG_IPV6) || defined(CONFIG_IPV6_MODULE)
#define DOMAINFW_HAVE_IPV6 1
#include <linux/ipv6.h>
#include <linux/netfilter_ipv6.h>
#else
#define DOMAINFW_HAVE_IPV6 0
#endif
#include <linux/jhash.h>
#include <linux/kernel.h>
#include <linux/list.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/percpu.h>
#include <linux/proc_fs.h>
#include <linux/rcupdate.h>
#include <linux/rculist.h>
#include <linux/seq_file.h>
#include <linux/skbuff.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/tcp.h>
#include <linux/types.h>
#include <linux/udp.h>
#include <linux/version.h>
#include <net/net_namespace.h>

#define DOMAINFW_NAME                 "domain_fw"
#define DOMAINFW_PROC_DIR             "domain_fw"
#define DOMAINFW_CONTROL_FILE         "control"
#define DOMAINFW_STATS_FILE           "stats"

#define DOMAINFW_TRIE_BUCKETS         16384U
#define DOMAINFW_MAX_NAME             253U
#define DOMAINFW_MAX_LABEL            63U
#define DOMAINFW_DNS_HEADER_LEN       12U
#define DOMAINFW_DNS_PARSE_MAX        \
	(DOMAINFW_DNS_HEADER_LEN + 255U + 4U)
#define DOMAINFW_TCP_MAX_FRAMES       8U
#define DOMAINFW_COMMAND_MAX          320U
#define DOMAINFW_QTYPE_ALL            0U

/* 128 KiB; the size is a power of two for a cheap bit index. */
#define DOMAINFW_BLOOM_BITS           (1UL << 20)
#define DOMAINFW_BLOOM_HASHES         3U

/* Values are local to retain compatibility with older IPv6 UAPI headers. */
#define DOMAINFW_IP6_HOP              0U
#define DOMAINFW_IP6_ROUTING          43U
#define DOMAINFW_IP6_FRAGMENT         44U
#define DOMAINFW_IP6_ESP              50U
#define DOMAINFW_IP6_AUTH             51U
#define DOMAINFW_IP6_NONE             59U
#define DOMAINFW_IP6_DEST             60U
#define DOMAINFW_IP6_FRAGMENT_MASK    0xfff9U

/* A sorted arbitrary-QTYPE set belonging to one zone trie node. */
struct domainfw_qtype_set {
	struct rcu_head rcu;
	u16 count;
	bool all;
	u16 types[0];
};

struct domainfw_trie_node {
	struct hlist_node hnode;
	struct rcu_head rcu;
	struct domainfw_trie_node *parent;
	struct domainfw_qtype_set __rcu *qtypes;
	unsigned int child_count;
	u8 label_len;
	char label[DOMAINFW_MAX_LABEL + 1];
};

struct domainfw_pcpu_stats {
	u64 queries;
	u64 dropped;
	u64 malformed;
};

#if DOMAINFW_HAVE_IPV6
struct domainfw_v6_ext {
	u8 nexthdr;
	u8 hdrlen;
} __packed;

struct domainfw_v6_frag {
	u8 nexthdr;
	u8 reserved;
	__be16 frag_off;
	__be32 identification;
} __packed;
#endif

static struct hlist_head domainfw_trie[DOMAINFW_TRIE_BUCKETS];
static struct domainfw_trie_node domainfw_root;
static DEFINE_MUTEX(domainfw_config_lock);
static atomic_t domainfw_rule_count = ATOMIC_INIT(0);
static DECLARE_BITMAP(domainfw_bloom, DOMAINFW_BLOOM_BITS);
static struct domainfw_pcpu_stats __percpu *domainfw_stats;

static struct proc_dir_entry *domainfw_proc_dir;
static struct proc_dir_entry *domainfw_proc_control;
static struct proc_dir_entry *domainfw_proc_stats;
static struct proc_dir_entry *domainfw_proc_rules;

static bool enabled = true;
module_param(enabled, bool, 0644);
MODULE_PARM_DESC(enabled, "Enable DNS policy enforcement (default: 1)");

static unsigned int max_rules = 131072;
module_param(max_rules, uint, 0444);
MODULE_PARM_DESC(max_rules, "Maximum configured (zone, QTYPE) rules");

static unsigned int dns_port = 53;
module_param(dns_port, uint, 0444);
MODULE_PARM_DESC(dns_port, "UDP/TCP destination port to inspect (default: 53)");

static bool tcp_dns = true;
module_param(tcp_dns, bool, 0644);
MODULE_PARM_DESC(tcp_dns, "Inspect DNS-over-TCP frames (default: 1)");

static bool bloom_enabled;
module_param(bloom_enabled, bool, 0644);
MODULE_PARM_DESC(bloom_enabled, "Use Bloom filter as a trie negative cache (default: 0)");

static int hook_priority = NF_IP_PRI_FIRST;
module_param(hook_priority, int, 0444);
MODULE_PARM_DESC(hook_priority, "PRE_ROUTING netfilter priority");

static inline void domainfw_stat_query(void)
{
	this_cpu_inc(domainfw_stats->queries);
}

static inline void domainfw_stat_drop(void)
{
	this_cpu_inc(domainfw_stats->dropped);
}

static inline void domainfw_stat_malformed(void)
{
	this_cpu_inc(domainfw_stats->malformed);
}

static u32 domainfw_node_hash(const struct domainfw_trie_node *parent,
			      const char *label, u8 label_len)
{
	return jhash(label, label_len, (u32)(unsigned long)parent) &
	       (DOMAINFW_TRIE_BUCKETS - 1);
}

static void domainfw_qtype_set_free_rcu(struct rcu_head *rcu)
{
	struct domainfw_qtype_set *set;

	set = container_of(rcu, struct domainfw_qtype_set, rcu);
	kfree(set);
}

static void domainfw_node_free_rcu(struct rcu_head *rcu)
{
	struct domainfw_trie_node *node;
	struct domainfw_qtype_set *set;

	node = container_of(rcu, struct domainfw_trie_node, rcu);
	set = rcu_access_pointer(node->qtypes);
	kfree(set);
	kfree(node);
}

static bool domainfw_qtype_has_specific(const struct domainfw_qtype_set *set,
					 u16 qtype)
{
	u16 left = 0;
	u16 right;
	u16 middle;

	if (!set || qtype == DOMAINFW_QTYPE_ALL)
		return false;
	right = set->count;
	while (left < right) {
		middle = left + (right - left) / 2;
		if (set->types[middle] == qtype)
			return true;
		if (set->types[middle] < qtype)
			left = middle + 1;
		else
			right = middle;
	}
	return false;
}

static bool domainfw_qtype_matches(const struct domainfw_qtype_set *set,
				   u16 qtype)
{
	return set && (set->all || domainfw_qtype_has_specific(set, qtype));
}

static struct domainfw_trie_node *
domainfw_find_child_locked(const struct domainfw_trie_node *parent,
				  const char *label, u8 label_len)
{
	struct hlist_node *hnode;
	struct domainfw_trie_node *node;
	u32 bucket = domainfw_node_hash(parent, label, label_len);

	for (hnode = domainfw_trie[bucket].first; hnode; hnode = hnode->next) {
		node = hlist_entry(hnode, struct domainfw_trie_node, hnode);
		if (node->parent == parent && node->label_len == label_len &&
		    !memcmp(node->label, label, label_len))
			return node;
	}
	return NULL;
}

static struct domainfw_trie_node *
domainfw_find_child_rcu(const struct domainfw_trie_node *parent,
			       const char *label, u8 label_len)
{
	struct hlist_node *hnode;
	struct domainfw_trie_node *node;
	u32 bucket = domainfw_node_hash(parent, label, label_len);

	for (hnode = rcu_dereference(domainfw_trie[bucket].first); hnode;
	     hnode = rcu_dereference(hnode->next)) {
		node = hlist_entry(hnode, struct domainfw_trie_node, hnode);
		if (node->parent == parent && node->label_len == label_len &&
		    !memcmp(node->label, label, label_len))
			return node;
	}
	return NULL;
}

static struct domainfw_trie_node *
domainfw_alloc_node(struct domainfw_trie_node *parent,
		    const char *label, u8 label_len)
{
	struct domainfw_trie_node *node;

	node = kzalloc(sizeof(*node), GFP_KERNEL);
	if (!node)
		return NULL;
	node->parent = parent;
	node->label_len = label_len;
	memcpy(node->label, label, label_len);
	node->label[label_len] = '\0';
	return node;
}

/* zone is in presentation form; walk its labels from right to left. */
static struct domainfw_trie_node *
domainfw_get_or_create_zone_locked(const char *zone, u16 zone_len, int *ret)
{
	struct domainfw_trie_node *parent = &domainfw_root;
	struct domainfw_trie_node *node;
	const char *start;
	const char *end;
	u8 label_len;

	if (!zone_len)
		return parent; /* "*" is represented by the root node. */

	end = zone + zone_len;
	for (;;) {
		start = end;
		while (start > zone && start[-1] != '.')
			start--;
		label_len = (u8)(end - start);
		node = domainfw_find_child_locked(parent, start, label_len);
		if (!node) {
			node = domainfw_alloc_node(parent, start, label_len);
			if (!node) {
				*ret = -ENOMEM;
				return NULL;
			}
			hlist_add_head_rcu(&node->hnode,
					   &domainfw_trie[domainfw_node_hash(parent, start,
									       label_len)]);
			parent->child_count++;
		}
		parent = node;
		if (start == zone)
			break;
		end = start - 1;
	}

	return parent;
}

static struct domainfw_trie_node *
domainfw_find_zone_locked(const char *zone, u16 zone_len)
{
	struct domainfw_trie_node *parent = &domainfw_root;
	const char *start;
	const char *end;
	u8 label_len;

	if (!zone_len)
		return parent;

	end = zone + zone_len;
	for (;;) {
		start = end;
		while (start > zone && start[-1] != '.')
			start--;
		label_len = (u8)(end - start);
		parent = domainfw_find_child_locked(parent, start, label_len);
		if (!parent)
			return NULL;
		if (start == zone)
			return parent;
		end = start - 1;
	}
}

static struct domainfw_qtype_set *
domainfw_qtype_set_alloc(u16 count, bool all)
{
	struct domainfw_qtype_set *set;

	set = kzalloc(sizeof(*set) + count * sizeof(set->types[0]), GFP_KERNEL);
	if (!set)
		return NULL;
	set->count = count;
	set->all = all;
	return set;
}

/* Build a replacement set; NULL is a valid empty replacement. */
static int domainfw_qtype_set_update(const struct domainfw_qtype_set *old,
				     u16 qtype, bool add,
				     struct domainfw_qtype_set **replacement)
{
	struct domainfw_qtype_set *new_set;
	bool exists;
	u16 new_count;
	u16 src = 0;
	u16 dst = 0;
	bool inserted = false;

	exists = qtype == DOMAINFW_QTYPE_ALL ? old && old->all :
		 domainfw_qtype_has_specific(old, qtype);
	if (add && exists)
		return -EEXIST;
	if (!add && !exists)
		return -ENOENT;

	new_count = old ? old->count : 0;
	if (qtype != DOMAINFW_QTYPE_ALL) {
		if (add)
			new_count++;
		else
			new_count--;
	}
	if (!(qtype == DOMAINFW_QTYPE_ALL ? add : old && old->all) &&
	    !new_count) {
		*replacement = NULL;
		return 0;
	}

	new_set = domainfw_qtype_set_alloc(new_count,
		qtype == DOMAINFW_QTYPE_ALL ? add : old && old->all);
	if (!new_set)
		return -ENOMEM;

	if (qtype == DOMAINFW_QTYPE_ALL) {
		if (old && old->count)
			memcpy(new_set->types, old->types,
			       old->count * sizeof(old->types[0]));
	} else if (add) {
		for (src = 0; old && src < old->count; src++) {
			if (!inserted && qtype < old->types[src]) {
				new_set->types[dst++] = qtype;
				inserted = true;
			}
			new_set->types[dst++] = old->types[src];
		}
		if (!inserted)
			new_set->types[dst++] = qtype;
	} else {
		for (src = 0; src < old->count; src++)
			if (old->types[src] != qtype)
				new_set->types[dst++] = old->types[src];
	}

	*replacement = new_set;
	return 0;
}

static int domainfw_set_qtype_locked(struct domainfw_trie_node *node,
				     u16 qtype, bool add)
{
	struct domainfw_qtype_set *old;
	struct domainfw_qtype_set *replacement;
	int ret;

	old = rcu_dereference_protected(node->qtypes,
					lockdep_is_held(&domainfw_config_lock));
	ret = domainfw_qtype_set_update(old, qtype, add, &replacement);
	if (ret)
		return ret;
	rcu_assign_pointer(node->qtypes, replacement);
	if (old)
		call_rcu(&old->rcu, domainfw_qtype_set_free_rcu);
	return 0;
}

/* Remove now-empty leaves, retaining all shared prefixes. */
static void domainfw_prune_empty_locked(struct domainfw_trie_node *node)
{
	struct domainfw_trie_node *parent;

	while (node != &domainfw_root && !node->child_count &&
	       !rcu_dereference_protected(node->qtypes,
					 lockdep_is_held(&domainfw_config_lock))) {
		parent = node->parent;
		hlist_del_rcu(&node->hnode);
		parent->child_count--;
		call_rcu(&node->rcu, domainfw_node_free_rcu);
		node = parent;
	}
}

static void domainfw_bloom_add(const char *name, u16 name_len)
{
	u32 first;
	u32 step;
	unsigned int i;

	if (!name_len)
		return;
	first = jhash(name, name_len, 0x9e3779b9U);
	step = jhash(name, name_len, 0x85ebca6bU) | 1U;
	for (i = 0; i < DOMAINFW_BLOOM_HASHES; i++)
		set_bit((first + i * step) & (DOMAINFW_BLOOM_BITS - 1),
			domainfw_bloom);
}

static bool domainfw_bloom_maybe_contains(const char *name, u16 name_len)
{
	u32 first;
	u32 step;
	unsigned int i;

	first = jhash(name, name_len, 0x9e3779b9U);
	step = jhash(name, name_len, 0x85ebca6bU) | 1U;
	for (i = 0; i < DOMAINFW_BLOOM_HASHES; i++)
		if (!test_bit((first + i * step) & (DOMAINFW_BLOOM_BITS - 1),
			      domainfw_bloom))
			return false;
	return true;
}

/* Check every possible zone suffix; false means trie traversal is unnecessary. */
static bool domainfw_bloom_maybe_matches(const char *qname, u16 qname_len)
{
	const char *candidate = qname;
	const char *dot;
	u16 candidate_len = qname_len;

	for (;;) {
		if (domainfw_bloom_maybe_contains(candidate, candidate_len))
			return true;
		dot = memchr(candidate, '.', candidate_len);
		if (!dot)
			return false;
		candidate_len -= (u16)(dot - candidate) + 1;
		candidate = dot + 1;
	}
}

/*
 * Convert to lower-case presentation form.  A zone of "*" is the global
 * trie root and therefore matches every DNS name.  Existing zone semantics
 * already include all descendants, so "*.example.com" is intentionally not
 * needed.
 */
static int domainfw_normalize_zone(char *input, char *output, u16 *output_len)
{
	char *zone = strim(input);
	size_t zone_len = strlen(zone);
	size_t label_len = 0;
	size_t out_len = 0;
	size_t i;

	if (!strcmp(zone, "*")) {
		output[0] = '\0';
		*output_len = 0;
		return 0;
	}
	if (!zone_len)
		return -EINVAL;
	if (zone[zone_len - 1] == '.')
		zone_len--;
	if (!zone_len || zone_len > DOMAINFW_MAX_NAME)
		return -EINVAL;

	for (i = 0; i < zone_len; i++) {
		unsigned char c = zone[i];

		if (c == '.') {
			if (!label_len)
				return -EINVAL;
			output[out_len++] = c;
			label_len = 0;
			continue;
		}
		if (c < 0x21 || c > 0x7e || c == '*')
			return -EINVAL;
		if (++label_len > DOMAINFW_MAX_LABEL)
			return -EINVAL;
		output[out_len++] = tolower(c);
	}
	if (!label_len)
		return -EINVAL;

	output[out_len] = '\0';
	*output_len = (u16)out_len;
	return 0;
}

static int domainfw_parse_qtype(const char *text, u16 *qtype)
{
	struct domainfw_qtype_name {
		const char *name;
		u16 value;
	};
	static const struct domainfw_qtype_name names[] = {
		{ "A", 1 }, { "NS", 2 }, { "CNAME", 5 }, { "SOA", 6 },
		{ "PTR", 12 }, { "MX", 15 }, { "TXT", 16 }, { "AAAA", 28 },
		{ "SRV", 33 }, { "DNAME", 39 }, { "DS", 43 }, { "DNSKEY", 48 },
		{ "SVCB", 64 }, { "HTTPS", 65 }, { "CAA", 257 },
	};
	unsigned int value;
	unsigned int i;
	int ret;

	if (!strcmp(text, "*") || !strcasecmp(text, "ANY")) {
		*qtype = DOMAINFW_QTYPE_ALL;
		return 0;
	}
	for (i = 0; i < ARRAY_SIZE(names); i++) {
		if (!strcasecmp(text, names[i].name)) {
			*qtype = names[i].value;
			return 0;
		}
	}
	if (!strncasecmp(text, "TYPE", 4))
		text += 4;
	ret = kstrtouint(text, 0, &value);
	if (ret || !value || value > U16_MAX)
		return -EINVAL;
	*qtype = (u16)value;
	return 0;
}

static int domainfw_add_rule(char *zone_arg, const char *qtype_arg)
{
	struct domainfw_trie_node *node;
	char zone[DOMAINFW_MAX_NAME + 1];
	u16 zone_len;
	u16 qtype;
	int ret = 0;

	ret = domainfw_normalize_zone(zone_arg, zone, &zone_len);
	if (ret)
		return ret;
	ret = domainfw_parse_qtype(qtype_arg, &qtype);
	if (ret)
		return ret;

	mutex_lock(&domainfw_config_lock);
	if ((unsigned int)atomic_read(&domainfw_rule_count) >= max_rules) {
		ret = -ENOSPC;
		goto out;
	}
	node = domainfw_get_or_create_zone_locked(zone, zone_len, &ret);
	if (!node)
		goto out;
	/* Set Bloom bits before publishing the new RCU-visible rule. */
	domainfw_bloom_add(zone, zone_len);
	ret = domainfw_set_qtype_locked(node, qtype, true);
	if (!ret)
		atomic_inc(&domainfw_rule_count);
	else
		domainfw_prune_empty_locked(node);
out:
	mutex_unlock(&domainfw_config_lock);
	return ret;
}

static int domainfw_del_rule(char *zone_arg, const char *qtype_arg)
{
	struct domainfw_trie_node *node;
	char zone[DOMAINFW_MAX_NAME + 1];
	u16 zone_len;
	u16 qtype;
	int ret;

	ret = domainfw_normalize_zone(zone_arg, zone, &zone_len);
	if (ret)
		return ret;
	ret = domainfw_parse_qtype(qtype_arg, &qtype);
	if (ret)
		return ret;

	mutex_lock(&domainfw_config_lock);
	node = domainfw_find_zone_locked(zone, zone_len);
	if (!node) {
		ret = -ENOENT;
		goto out;
	}
	ret = domainfw_set_qtype_locked(node, qtype, false);
	if (!ret) {
		atomic_dec(&domainfw_rule_count);
		domainfw_prune_empty_locked(node);
	}
out:
	mutex_unlock(&domainfw_config_lock);
	return ret;
}

static void domainfw_flush_rules(void)
{
	struct hlist_node *hnode;
	struct hlist_node *next;
	struct domainfw_trie_node *node;
	struct domainfw_qtype_set *root_set;
	unsigned int i;

	mutex_lock(&domainfw_config_lock);
	root_set = rcu_dereference_protected(domainfw_root.qtypes,
					     lockdep_is_held(&domainfw_config_lock));
	RCU_INIT_POINTER(domainfw_root.qtypes, NULL);
	domainfw_root.child_count = 0;
	for (i = 0; i < DOMAINFW_TRIE_BUCKETS; i++) {
		for (hnode = domainfw_trie[i].first; hnode; hnode = next) {
			next = hnode->next;
			node = hlist_entry(hnode, struct domainfw_trie_node, hnode);
			hlist_del_rcu(&node->hnode);
			call_rcu(&node->rcu, domainfw_node_free_rcu);
		}
	}
	atomic_set(&domainfw_rule_count, 0);
	bitmap_zero(domainfw_bloom, DOMAINFW_BLOOM_BITS);
	mutex_unlock(&domainfw_config_lock);

	if (root_set)
		call_rcu(&root_set->rcu, domainfw_qtype_set_free_rcu);
}

static bool domainfw_rule_matches(const char *qname, u16 qname_len, u16 qtype)
{
	struct domainfw_trie_node *node;
	struct domainfw_trie_node *parent = &domainfw_root;
	struct domainfw_qtype_set *set;
	const char *start;
	const char *end = qname + qname_len;
	u8 label_len;
	bool matched = false;

	rcu_read_lock();
	set = rcu_dereference(domainfw_root.qtypes);
	if (domainfw_qtype_matches(set, qtype)) {
		matched = true;
		goto out;
	}
	if (READ_ONCE(bloom_enabled) &&
	    !domainfw_bloom_maybe_matches(qname, qname_len))
		goto out;

	for (;;) {
		start = end;
		while (start > qname && start[-1] != '.')
			start--;
		label_len = (u8)(end - start);
		node = domainfw_find_child_rcu(parent, start, label_len);
		if (!node)
			break;
		set = rcu_dereference(node->qtypes);
		if (domainfw_qtype_matches(set, qtype)) {
			matched = true;
			break;
		}
		parent = node;
		if (start == qname)
			break;
		end = start - 1;
	}
out:
	rcu_read_unlock();
	return matched;
}

static bool domainfw_tcp_payload(const struct sk_buff *skb,
				  unsigned int tcp_offset, unsigned int tcp_len,
				  unsigned int *dns_offset, unsigned int *dns_len)
{
	struct tcphdr tcpbuf;
	const struct tcphdr *tcph;
	unsigned int tcp_header_len;

	if (tcp_len < sizeof(tcpbuf))
		return false;
	tcph = skb_header_pointer(skb, tcp_offset, sizeof(tcpbuf), &tcpbuf);
	if (!tcph || tcph->doff < 5 || ntohs(tcph->dest) != dns_port)
		return false;
	tcp_header_len = tcph->doff * 4;
	if (tcp_header_len > tcp_len)
		return false;
	*dns_offset = tcp_offset + tcp_header_len;
	*dns_len = tcp_len - tcp_header_len;
	return true;
}

static bool domainfw_ipv4_payload(const struct sk_buff *skb,
				  unsigned int *dns_offset, unsigned int *dns_len,
				  bool *is_tcp)
{
	struct iphdr ipbuf;
	struct udphdr udpbuf;
	const struct iphdr *iph;
	const struct udphdr *udph;
	unsigned int network_offset = skb_network_offset(skb);
	unsigned int ip_header_len;
	unsigned int ip_total_len;
	unsigned int udp_len;

	iph = skb_header_pointer(skb, network_offset, sizeof(ipbuf), &ipbuf);
	if (!iph || iph->version != 4 || iph->ihl < 5 ||
	    (ntohs(iph->frag_off) & (IP_MF | IP_OFFSET)))
		return false;
	ip_header_len = iph->ihl * 4;
	ip_total_len = ntohs(iph->tot_len);
	if (ip_total_len < ip_header_len + sizeof(udpbuf))
		return false;
	*is_tcp = false;

	if (iph->protocol == IPPROTO_TCP) {
		if (!READ_ONCE(tcp_dns))
			return false;
		if (!domainfw_tcp_payload(skb, network_offset + ip_header_len,
					 ip_total_len - ip_header_len,
					 dns_offset, dns_len))
			return false;
		*is_tcp = true;
		return true;
	}
	if (iph->protocol != IPPROTO_UDP)
		return false;
	udph = skb_header_pointer(skb, network_offset + ip_header_len,
				  sizeof(udpbuf), &udpbuf);
	if (!udph || ntohs(udph->dest) != dns_port)
		return false;
	udp_len = ntohs(udph->len);
	if (udp_len < sizeof(udpbuf) + DOMAINFW_DNS_HEADER_LEN ||
	    udp_len > ip_total_len - ip_header_len)
		return false;
	*dns_offset = network_offset + ip_header_len + sizeof(udpbuf);
	*dns_len = udp_len - sizeof(udpbuf);
	return true;
}

#if DOMAINFW_HAVE_IPV6
static bool domainfw_ipv6_payload(const struct sk_buff *skb,
				  unsigned int *dns_offset, unsigned int *dns_len,
				  bool *is_tcp)
{
	struct ipv6hdr ip6buf;
	struct udphdr udpbuf;
	struct domainfw_v6_ext extbuf;
	struct domainfw_v6_frag fragbuf;
	const struct ipv6hdr *ip6h;
	const struct udphdr *udph;
	const struct domainfw_v6_ext *exth;
	const struct domainfw_v6_frag *fragh;
	unsigned int network_offset = skb_network_offset(skb);
	unsigned int offset;
	unsigned int end;
	unsigned int udp_len;
	u8 nexthdr;
	unsigned int i;

	ip6h = skb_header_pointer(skb, network_offset, sizeof(ip6buf), &ip6buf);
	if (!ip6h || ((const u8 *)ip6h)[0] >> 4 != 6 ||
	    !ntohs(ip6h->payload_len))
		return false;
	offset = network_offset + sizeof(*ip6h);
	end = offset + ntohs(ip6h->payload_len);
	nexthdr = ip6h->nexthdr;

	for (i = 0; nexthdr != IPPROTO_UDP && nexthdr != IPPROTO_TCP &&
	     i < 8; i++) {
		if (nexthdr == DOMAINFW_IP6_HOP || nexthdr == DOMAINFW_IP6_ROUTING ||
		    nexthdr == DOMAINFW_IP6_DEST) {
			exth = skb_header_pointer(skb, offset, sizeof(extbuf), &extbuf);
			if (!exth || offset + ((exth->hdrlen + 1) << 3) > end)
				return false;
			nexthdr = exth->nexthdr;
			offset += (exth->hdrlen + 1) << 3;
			continue;
		}
		if (nexthdr == DOMAINFW_IP6_FRAGMENT) {
			fragh = skb_header_pointer(skb, offset, sizeof(fragbuf), &fragbuf);
			if (!fragh || offset + sizeof(*fragh) > end ||
			    (ntohs(fragh->frag_off) & DOMAINFW_IP6_FRAGMENT_MASK))
				return false;
			nexthdr = fragh->nexthdr;
			offset += sizeof(*fragh);
			continue;
		}
		if (nexthdr == DOMAINFW_IP6_AUTH) {
			exth = skb_header_pointer(skb, offset, sizeof(extbuf), &extbuf);
			if (!exth || offset + ((exth->hdrlen + 2) << 2) > end)
				return false;
			nexthdr = exth->nexthdr;
			offset += (exth->hdrlen + 2) << 2;
			continue;
		}
		return false;
	}

	*is_tcp = false;
	if (nexthdr == IPPROTO_TCP) {
		if (!READ_ONCE(tcp_dns))
			return false;
		if (!domainfw_tcp_payload(skb, offset, end - offset,
					 dns_offset, dns_len))
			return false;
		*is_tcp = true;
		return true;
	}
	if (nexthdr != IPPROTO_UDP || offset + sizeof(udpbuf) > end)
		return false;
	udph = skb_header_pointer(skb, offset, sizeof(udpbuf), &udpbuf);
	if (!udph || ntohs(udph->dest) != dns_port)
		return false;
	udp_len = ntohs(udph->len);
	if (udp_len < sizeof(udpbuf) + DOMAINFW_DNS_HEADER_LEN ||
	    udp_len > end - offset)
		return false;
	*dns_offset = offset + sizeof(udpbuf);
	*dns_len = udp_len - sizeof(udpbuf);
	return true;
}
#endif

static noinline bool domainfw_dns_question(const struct sk_buff *skb,
					   unsigned int dns_offset,
					   unsigned int dns_len,
					   char *qname, u16 *qname_len,
					   u16 *qtype)
{
	u8 packet[DOMAINFW_DNS_PARSE_MAX];
	unsigned int copy_len;
	unsigned int pos = DOMAINFW_DNS_HEADER_LEN;
	unsigned int name_len = 0;
	u8 label_len;
	unsigned int i;

	copy_len = min_t(unsigned int, dns_len, sizeof(packet));
	if (copy_len < DOMAINFW_DNS_HEADER_LEN + 5 ||
	    skb_copy_bits(skb, dns_offset, packet, copy_len))
		return false;
	if ((packet[2] & 0x80) || (packet[2] & 0x78) ||
	    packet[4] || packet[5] != 1)
		return false;

	for (;;) {
		if (pos >= copy_len)
			return false;
		label_len = packet[pos++];
		if (!label_len)
			break;
		if (label_len > DOMAINFW_MAX_LABEL || (label_len & 0xc0) ||
		    pos + label_len > copy_len ||
		    name_len + (name_len ? 1 : 0) + label_len > DOMAINFW_MAX_NAME)
			return false;
		if (name_len)
			qname[name_len++] = '.';
		for (i = 0; i < label_len; i++) {
			u8 c = packet[pos++];

			if (c < 0x21 || c > 0x7e || c == '.')
				return false;
			qname[name_len++] = c >= 'A' && c <= 'Z' ?
					  c + ('a' - 'A') : c;
		}
	}
	if (!name_len || pos + 4 > copy_len)
		return false;
	*qtype = ((u16)packet[pos] << 8) | packet[pos + 1];
	if (!*qtype)
		return false;
	qname[name_len] = '\0';
	*qname_len = name_len;
	return true;
}

static unsigned int domainfw_dns_verdict(const struct sk_buff *skb,
					 unsigned int dns_offset, unsigned int dns_len)
{
	char qname[DOMAINFW_MAX_NAME + 1];
	u16 qname_len;
	u16 qtype;

	if (!domainfw_dns_question(skb, dns_offset, dns_len,
				   qname, &qname_len, &qtype)) {
		domainfw_stat_malformed();
		return NF_ACCEPT;
	}
	domainfw_stat_query();
	if (!domainfw_rule_matches(qname, qname_len, qtype))
		return NF_ACCEPT;
	domainfw_stat_drop();
	return NF_DROP;
}

static unsigned int domainfw_tcp_verdict(const struct sk_buff *skb,
					 unsigned int tcp_payload_offset,
					 unsigned int tcp_payload_len)
{
	u8 length_prefix[2];
	unsigned int frame_offset = 0;
	unsigned int frame_len;
	unsigned int i;
	unsigned int verdict;

	for (i = 0; i < DOMAINFW_TCP_MAX_FRAMES; i++) {
		if (tcp_payload_len - frame_offset < sizeof(length_prefix))
			return NF_ACCEPT;
		if (skb_copy_bits(skb, tcp_payload_offset + frame_offset,
				  length_prefix, sizeof(length_prefix)))
			return NF_ACCEPT;
		frame_len = ((unsigned int)length_prefix[0] << 8) |
			    length_prefix[1];
		if (frame_len < DOMAINFW_DNS_HEADER_LEN + 5) {
			domainfw_stat_malformed();
			return NF_ACCEPT;
		}
		if (frame_len > tcp_payload_len - frame_offset -
		    sizeof(length_prefix))
			return NF_ACCEPT; /* TCP stream reassembly is deliberately absent. */
		verdict = domainfw_dns_verdict(skb,
					  tcp_payload_offset + frame_offset +
					  sizeof(length_prefix), frame_len);
		if (verdict == NF_DROP)
			return NF_DROP;
		frame_offset += sizeof(length_prefix) + frame_len;
		if (frame_offset == tcp_payload_len)
			return NF_ACCEPT;
	}
	return NF_ACCEPT;
}

static unsigned int domainfw_inspect(struct sk_buff *skb, int family)
{
	unsigned int dns_offset;
	unsigned int dns_len;
	bool is_dns;
	bool is_tcp;

	if (!READ_ONCE(enabled))
		return NF_ACCEPT;
	if (family == PF_INET)
		is_dns = domainfw_ipv4_payload(skb, &dns_offset, &dns_len, &is_tcp);
#if DOMAINFW_HAVE_IPV6
	else if (family == PF_INET6)
		is_dns = domainfw_ipv6_payload(skb, &dns_offset, &dns_len, &is_tcp);
#endif
	else
		return NF_ACCEPT;
	if (!is_dns)
		return NF_ACCEPT;
	if (is_tcp)
		return domainfw_tcp_verdict(skb, dns_offset, dns_len);
	return domainfw_dns_verdict(skb, dns_offset, dns_len);
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 13, 0)
static unsigned int domainfw_nf_hook(void *priv, struct sk_buff *skb,
				     const struct nf_hook_state *state)
{
	return domainfw_inspect(skb, state->pf);
}
#else
static unsigned int domainfw_nf_hook(const struct nf_hook_ops *ops,
				     struct sk_buff *skb,
				     const struct net_device *in,
				     const struct net_device *out,
				     int (*okfn)(struct sk_buff *))
{
	return domainfw_inspect(skb, ops->pf);
}
#endif

static struct nf_hook_ops domainfw_nf_ops[] = {
	{
		.hook = domainfw_nf_hook,
		.pf = PF_INET,
		.hooknum = NF_INET_PRE_ROUTING,
		.priority = NF_IP_PRI_FIRST,
	},
#if DOMAINFW_HAVE_IPV6
	{
		.hook = domainfw_nf_hook,
		.pf = PF_INET6,
		.hooknum = NF_INET_PRE_ROUTING,
		.priority = NF_IP_PRI_FIRST,
	},
#endif
};

static int domainfw_control_tokens(char *command, char **argv, unsigned int max)
{
	char *cursor = command;
	char *token;
	unsigned int argc = 0;

	while ((token = strsep(&cursor, " \t")) != NULL) {
		if (!*token)
			continue;
		if (argc == max)
			return -E2BIG;
		argv[argc++] = token;
	}
	return argc;
}

static ssize_t domainfw_control_write(struct file *file,
				     const char __user *user_buffer,
				     size_t count, loff_t *offset)
{
	char command[DOMAINFW_COMMAND_MAX];
	char *argv[3];
	int argc;
	int ret;

	if (!count || count >= sizeof(command))
		return -E2BIG;
	if (copy_from_user(command, user_buffer, count))
		return -EFAULT;
	command[count] = '\0';
	argc = domainfw_control_tokens(strim(command), argv, ARRAY_SIZE(argv));
	if (argc < 0)
		return argc;
	if (!argc)
		return -EINVAL;
	if (!strcmp(argv[0], "flush") && argc == 1) {
		domainfw_flush_rules();
		return count;
	}
	if (!strcmp(argv[0], "add") && argc == 3)
		ret = domainfw_add_rule(argv[1], argv[2]);
	else if ((!strcmp(argv[0], "del") || !strcmp(argv[0], "delete")) &&
		 argc == 3)
		ret = domainfw_del_rule(argv[1], argv[2]);
	else
		ret = -EINVAL;
	return ret ? ret : count;
}

static int domainfw_stats_show(struct seq_file *m, void *v)
{
	u64 queries = 0;
	u64 dropped = 0;
	u64 malformed = 0;
	unsigned int cpu;
	struct domainfw_pcpu_stats *stats;

	for_each_possible_cpu(cpu) {
		stats = per_cpu_ptr(domainfw_stats, cpu);
		queries += stats->queries;
		dropped += stats->dropped;
		malformed += stats->malformed;
	}
	seq_printf(m, "enabled %u\n", enabled ? 1 : 0);
	seq_printf(m, "tcp_dns %u\n", tcp_dns ? 1 : 0);
	seq_printf(m, "bloom_enabled %u\n", bloom_enabled ? 1 : 0);
	seq_printf(m, "dns_port %u\n", dns_port);
	seq_printf(m, "rules %d\n", atomic_read(&domainfw_rule_count));
	seq_printf(m, "queries %llu\n", (unsigned long long)queries);
	seq_printf(m, "dropped %llu\n", (unsigned long long)dropped);
	seq_printf(m, "malformed_or_unsupported %llu\n",
		   (unsigned long long)malformed);
	return 0;
}

static int domainfw_stats_open(struct inode *inode, struct file *file)
{
	return single_open(file, domainfw_stats_show, NULL);
}

/* The parent chain is leaf -> TLD, which is normal presentation order. */
static noinline size_t domainfw_format_zone(const struct domainfw_trie_node *node,
					    char *zone)
{
	size_t zone_len = 0;

	if (node == &domainfw_root) {
		zone[0] = '*';
		zone[1] = '\0';
		return 1;
	}

	while (node != &domainfw_root) {
		if (zone_len)
			zone[zone_len++] = '.';
		memcpy(zone + zone_len, node->label, node->label_len);
		zone_len += node->label_len;
		node = node->parent;
	}
	zone[zone_len] = '\0';
	return zone_len;
}

static void domainfw_seq_show_rule_set(struct seq_file *m, const char *zone,
					const struct domainfw_qtype_set *set)
{
	u16 i;

	if (set->all)
		seq_printf(m, "%s *\n", zone);
	for (i = 0; i < set->count && !seq_has_overflowed(m); i++)
		seq_printf(m, "%s TYPE%u\n", zone, set->types[i]);
}

/*
 * Rules are derived from the trie, rather than kept in a second list.  A
 * single_open seq_file will grow its buffer and retry if a large export fills
 * the initial page.  The configuration mutex makes each retry self-consistent.
 */
static int domainfw_rules_show(struct seq_file *m, void *v)
{
	struct hlist_node *hnode;
	struct domainfw_trie_node *node;
	struct domainfw_qtype_set *set;
	char zone[DOMAINFW_MAX_NAME + 1];
	unsigned int i;

	mutex_lock(&domainfw_config_lock);
	set = rcu_dereference_protected(domainfw_root.qtypes,
					lockdep_is_held(&domainfw_config_lock));
	if (set)
		domainfw_seq_show_rule_set(m, "*", set);

	for (i = 0; i < DOMAINFW_TRIE_BUCKETS && !seq_has_overflowed(m); i++) {
		for (hnode = domainfw_trie[i].first; hnode && !seq_has_overflowed(m);
		     hnode = hnode->next) {
			node = hlist_entry(hnode, struct domainfw_trie_node, hnode);
			set = rcu_dereference_protected(node->qtypes,
						lockdep_is_held(&domainfw_config_lock));
			if (!set)
				continue;
			domainfw_format_zone(node, zone);
			domainfw_seq_show_rule_set(m, zone, set);
		}
	}
	mutex_unlock(&domainfw_config_lock);
	return 0;
}

static int domainfw_rules_open(struct inode *inode, struct file *file)
{
	return single_open(file, domainfw_rules_show, NULL);
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 6, 0)
static const struct proc_ops domainfw_control_proc_ops = {
	.proc_write = domainfw_control_write,
	.proc_lseek = no_llseek,
};
static const struct proc_ops domainfw_stats_proc_ops = {
	.proc_open = domainfw_stats_open,
	.proc_read = seq_read,
	.proc_lseek = seq_lseek,
	.proc_release = single_release,
};
static const struct proc_ops domainfw_rules_proc_ops = {
	.proc_open = domainfw_rules_open,
	.proc_read = seq_read,
	.proc_lseek = seq_lseek,
	.proc_release = single_release,
};
#else
static const struct file_operations domainfw_control_proc_ops = {
	.owner = THIS_MODULE,
	.write = domainfw_control_write,
	.llseek = no_llseek,
};
static const struct file_operations domainfw_stats_proc_ops = {
	.owner = THIS_MODULE,
	.open = domainfw_stats_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = single_release,
};
static const struct file_operations domainfw_rules_proc_ops = {
	.owner = THIS_MODULE,
	.open = domainfw_rules_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = single_release,
};
#endif

static void domainfw_remove_proc(void)
{
	if (domainfw_proc_rules)
		remove_proc_entry("rules", domainfw_proc_dir);
	if (domainfw_proc_stats)
		remove_proc_entry(DOMAINFW_STATS_FILE, domainfw_proc_dir);
	if (domainfw_proc_control)
		remove_proc_entry(DOMAINFW_CONTROL_FILE, domainfw_proc_dir);
	if (domainfw_proc_dir)
		remove_proc_entry(DOMAINFW_PROC_DIR, NULL);
	domainfw_proc_stats = NULL;
	domainfw_proc_control = NULL;
	domainfw_proc_rules = NULL;
	domainfw_proc_dir = NULL;
}

static int __init domainfw_init(void)
{
	unsigned int i;
	int ret;

	if (!max_rules || !dns_port || dns_port > U16_MAX)
		return -EINVAL;
	for (i = 0; i < DOMAINFW_TRIE_BUCKETS; i++)
		INIT_HLIST_HEAD(&domainfw_trie[i]);
	RCU_INIT_POINTER(domainfw_root.qtypes, NULL);
	domainfw_root.child_count = 0;
	bitmap_zero(domainfw_bloom, DOMAINFW_BLOOM_BITS);

	domainfw_stats = alloc_percpu(struct domainfw_pcpu_stats);
	if (!domainfw_stats)
		return -ENOMEM;
	for_each_possible_cpu(i)
		memset(per_cpu_ptr(domainfw_stats, i), 0,
		       sizeof(struct domainfw_pcpu_stats));

	domainfw_proc_dir = proc_mkdir(DOMAINFW_PROC_DIR, NULL);
	if (!domainfw_proc_dir) {
		ret = -ENOMEM;
		goto err_stats;
	}
	domainfw_proc_control = proc_create(DOMAINFW_CONTROL_FILE, 0600,
					  domainfw_proc_dir,
					  &domainfw_control_proc_ops);
	if (!domainfw_proc_control) {
		ret = -ENOMEM;
		goto err_proc;
	}
	domainfw_proc_stats = proc_create(DOMAINFW_STATS_FILE, 0400,
					domainfw_proc_dir, &domainfw_stats_proc_ops);
	if (!domainfw_proc_stats) {
		ret = -ENOMEM;
		goto err_proc;
	}
	domainfw_proc_rules = proc_create("rules", 0400, domainfw_proc_dir,
					  &domainfw_rules_proc_ops);
	if (!domainfw_proc_rules) {
		ret = -ENOMEM;
		goto err_proc;
	}

	domainfw_nf_ops[0].priority = hook_priority;
#if DOMAINFW_HAVE_IPV6
	domainfw_nf_ops[1].priority = hook_priority;
#endif
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 13, 0)
	ret = nf_register_net_hooks(&init_net, domainfw_nf_ops,
				    ARRAY_SIZE(domainfw_nf_ops));
#else
	ret = nf_register_hooks(domainfw_nf_ops, ARRAY_SIZE(domainfw_nf_ops));
#endif
	if (ret)
		goto err_proc;
	pr_info(DOMAINFW_NAME ": enabled at PRE_ROUTING priority %d\n",
		hook_priority);
	return 0;

err_proc:
	domainfw_remove_proc();
err_stats:
	free_percpu(domainfw_stats);
	domainfw_stats = NULL;
	return ret;
}

static void __exit domainfw_exit(void)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 13, 0)
	nf_unregister_net_hooks(&init_net, domainfw_nf_ops,
				  ARRAY_SIZE(domainfw_nf_ops));
#else
	nf_unregister_hooks(domainfw_nf_ops, ARRAY_SIZE(domainfw_nf_ops));
#endif
	domainfw_remove_proc();
	domainfw_flush_rules();
	rcu_barrier();
	free_percpu(domainfw_stats);
	domainfw_stats = NULL;
	pr_info(DOMAINFW_NAME ": unloaded\n");
}

module_init(domainfw_init);
module_exit(domainfw_exit);

MODULE_AUTHOR("LoxiLB Authors");
MODULE_DESCRIPTION("Fast DNS zone and QTYPE PRE_ROUTING dropper");
MODULE_LICENSE("GPL");
