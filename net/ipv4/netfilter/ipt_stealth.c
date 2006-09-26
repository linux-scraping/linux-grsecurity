/* Kernel module to add stealth support.
 *
 * Copyright (C) 2002,2005 Brad Spengler  <spender@grsecurity.net>
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

extern struct sock *udp_v4_lookup(u32 saddr, u16 sport, u32 daddr, u16 dport, int dif);

static int
match(const struct sk_buff *skb,
      const struct net_device *in,
      const struct net_device *out,
      const struct xt_match *match,
      const void *matchinfo,
      int offset,
      unsigned int protoff,
      int *hotdrop)
{
	struct iphdr *ip = skb->nh.iph;
	struct tcphdr th;
	struct udphdr uh;
	struct sock *sk = NULL;

	if (!ip || offset) return 0;

	switch(ip->protocol) {
	case IPPROTO_TCP:
		if (skb_copy_bits(skb, skb->nh.iph->ihl*4, &th, sizeof(th)) < 0) {
			*hotdrop = 1;
			return 0;
		}
		if (!(th.syn && !th.ack)) return 0;
		sk = inet_lookup_listener(&tcp_hashinfo, ip->daddr, ntohs(th.dest), ((struct rtable*)skb->dst)->rt_iif);	
		break;
	case IPPROTO_UDP:
		if (skb_copy_bits(skb, skb->nh.iph->ihl*4, &uh, sizeof(uh)) < 0) {
			*hotdrop = 1;
			return 0;
		}
		sk = udp_v4_lookup(ip->saddr, uh.source, ip->daddr, uh.dest, skb->dev->ifindex);
		break;
	default:
		return 0;
	}

	if(!sk) // port is being listened on, match this
		return 1;
	else {
		sock_put(sk);
		return 0;
	}
}

/* Called when user tries to insert an entry of this type. */
static int
checkentry(const char *tablename,
           const void *nip,
	   const struct xt_match *match,
           void *matchinfo,
           unsigned int matchsize,
           unsigned int hook_mask)
{
	const struct ipt_ip *ip = (const struct ipt_ip *)nip;
        if (matchsize != IPT_ALIGN(0))
                return 0;

	if(((ip->proto == IPPROTO_TCP && !(ip->invflags & IPT_INV_PROTO)) ||
		((ip->proto == IPPROTO_UDP) && !(ip->invflags & IPT_INV_PROTO)))
		&& (hook_mask & (1 << NF_IP_LOCAL_IN)))
			return 1;

	printk("stealth: Only works on TCP and UDP for the INPUT chain.\n");

        return 0;
}


static struct ipt_match stealth_match = {
	.name = "stealth",
	.match = match,
	.checkentry = checkentry,
	.destroy = NULL,
	.me = THIS_MODULE
};

static int __init init(void)
{
	return ipt_register_match(&stealth_match);
}

static void __exit fini(void)
{
	ipt_unregister_match(&stealth_match);
}

module_init(init);
module_exit(fini);
