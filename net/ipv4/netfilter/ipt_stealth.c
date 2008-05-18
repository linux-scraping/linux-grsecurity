/* Kernel module to add stealth support.
 *
 * Copyright (C) 2002-2006 Brad Spengler  <spender@grsecurity.net>
 *
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/skbuff.h>
#include <linux/net.h>
#include <linux/sched.h>
#include <linux/inet.h>
#include <linux/stddef.h>

#include <net/ip.h>
#include <net/sock.h>
#include <net/tcp.h>
#include <net/udp.h>
#include <net/route.h>
#include <net/inet_common.h>

#include <linux/netfilter_ipv4/ip_tables.h>

MODULE_LICENSE("GPL");

extern struct sock *udp_v4_lookup(struct net *net, u32 saddr, u16 sport, u32 daddr, u16 dport, int dif);

static bool
match(const struct sk_buff *skb,
      const struct net_device *in,
      const struct net_device *out,
      const struct xt_match *match,
      const void *matchinfo,
      int offset,
      unsigned int protoff,
      bool *hotdrop)
{
	struct iphdr *ip = ip_hdr(skb);
	struct tcphdr th;
	struct udphdr uh;
	struct sock *sk = NULL;

	if (!ip || offset) return false;

	switch(ip->protocol) {
	case IPPROTO_TCP:
		if (skb_copy_bits(skb, (ip_hdr(skb))->ihl*4, &th, sizeof(th)) < 0) {
			*hotdrop = true;
			return false;
		}
		if (!(th.syn && !th.ack)) return false;
		sk = inet_lookup_listener(skb->dev->nd_net, &tcp_hashinfo, ip->daddr, th.dest, inet_iif(skb));	
		break;
	case IPPROTO_UDP:
		if (skb_copy_bits(skb, (ip_hdr(skb))->ihl*4, &uh, sizeof(uh)) < 0) {
			*hotdrop = true;
			return false;
		}
		sk = udp_v4_lookup(skb->dev->nd_net, ip->saddr, uh.source, ip->daddr, uh.dest, skb->dev->ifindex);
		break;
	default:
		return false;
	}

	if(!sk) // port is being listened on, match this
		return true;
	else {
		sock_put(sk);
		return false;
	}
}

/* Called when user tries to insert an entry of this type. */
static bool
checkentry(const char *tablename,
           const void *nip,
	   const struct xt_match *match,
           void *matchinfo,
           unsigned int hook_mask)
{
	const struct ipt_ip *ip = (const struct ipt_ip *)nip;

	if(((ip->proto == IPPROTO_TCP && !(ip->invflags & IPT_INV_PROTO)) ||
		((ip->proto == IPPROTO_UDP) && !(ip->invflags & IPT_INV_PROTO)))
		&& (hook_mask & (1 << NF_INET_LOCAL_IN)))
			return true;

	printk("stealth: Only works on TCP and UDP for the INPUT chain.\n");

        return false;
}


static struct xt_match stealth_match __read_mostly = {
	.name = "stealth",
	.family = AF_INET,
	.match = match,
	.checkentry = checkentry,
	.destroy = NULL,
	.me = THIS_MODULE
};

static int __init init(void)
{
	return xt_register_match(&stealth_match);
}

static void __exit fini(void)
{
	xt_unregister_match(&stealth_match);
}

module_init(init);
module_exit(fini);
