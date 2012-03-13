/*
 * Copyright (C) 2005 - 2011 Emulex
 * All rights reserved.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License version 2
 * as published by the Free Software Foundation. The full GNU General
 * Public License is included in this distribution in the file called COPYING.
 *
 * Contact Information:
 * linux-drivers@emulex.com
 *
 * Emulex
 * 3333 Susan Street
 * Costa Mesa, CA 92626
 */

#include "be.h"

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 28)
void be_netdev_ops_init(struct net_device *netdev, struct net_device_ops *ops)
{
	netdev->open = ops->ndo_open;
	netdev->stop = ops->ndo_stop;
	netdev->hard_start_xmit = ops->ndo_start_xmit;
	netdev->set_mac_address = ops->ndo_set_mac_address;
	netdev->get_stats = ops->ndo_get_stats;
	netdev->set_multicast_list = ops->ndo_set_rx_mode;
	netdev->change_mtu = ops->ndo_change_mtu;
	netdev->vlan_rx_register = ops->ndo_vlan_rx_register;
	netdev->vlan_rx_add_vid = ops->ndo_vlan_rx_add_vid;
	netdev->vlan_rx_kill_vid = ops->ndo_vlan_rx_kill_vid;
	netdev->do_ioctl = ops->ndo_do_ioctl;
#ifdef CONFIG_NET_POLL_CONTROLLER
	netdev->poll_controller = ops->ndo_poll_controller;
#endif
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 27)
	netdev->select_queue = ops->ndo_select_queue;
#endif
}
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 28)
int eth_validate_addr(struct net_device *netdev)
{
	return 0;
}
#endif

/* New NAPI backport */
#if LINUX_VERSION_CODE <= KERNEL_VERSION(2, 6, 24)

int be_poll_compat(struct net_device *netdev, int *budget)
{
	struct napi_struct *napi = netdev->priv;
	u32 work_done, can_do;

	can_do = min(*budget, netdev->quota);
	work_done = napi->poll(napi, can_do);

	*budget -= work_done;
	netdev->quota -= work_done;
	if (napi->rx)
		return (work_done >= can_do);
	return 0;
}


#endif /* New NAPI backport */

int be_netif_napi_add(struct net_device *netdev,
		struct napi_struct *napi,
		int (*poll) (struct napi_struct *, int), int weight)
{
#ifdef HAVE_SIMULATED_MULTI_NAPI
	struct be_adapter *adapter = netdev_priv(netdev);
	struct net_device *nd;

	nd = alloc_netdev(0, "", ether_setup);
	if (!nd)
		return -ENOMEM;
	nd->priv = napi;
	nd->weight = BE_NAPI_WEIGHT;
	nd->poll = be_poll_compat;
	set_bit(__LINK_STATE_START, &nd->state);

	if (napi == &adapter->rx_obj[0].rx_eq.napi)
		napi->rx = true;
	napi->poll = poll;
	napi->dev = nd;
#ifdef RHEL_NEW_NAPI
	napi->napi.dev = netdev;
#endif
	return 0;
#else
	netif_napi_add(netdev, napi, poll, weight);
	return 0;
#endif
}
void be_netif_napi_del(struct net_device *netdev)
{
#ifdef HAVE_SIMULATED_MULTI_NAPI
	struct be_adapter *adapter = netdev_priv(netdev);
	struct napi_struct *napi;
	struct be_rx_obj *rxo;
	int i;

	for_all_rx_queues(adapter, rxo, i) {
		napi = &rxo->rx_eq.napi;
		if (napi->dev) {
			free_netdev(napi->dev);
			napi->dev = NULL;
		}
	}

	napi = &adapter->tx_eq.napi;
	if (napi->dev) {
		free_netdev(napi->dev);
		napi->dev = NULL;
	}
#endif
}
/* INET_LRO backport */
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 27)

#define TCP_HDR_LEN(tcph)		(tcph->doff << 2)
#define IP_HDR_LEN(iph)			(iph->ihl << 2)
#define TCP_PAYLOAD_LENGTH(iph, tcph)	(ntohs(iph->tot_len) - IP_HDR_LEN(iph) \
						- TCP_HDR_LEN(tcph))

#define IPH_LEN_WO_OPTIONS		5
#define TCPH_LEN_WO_OPTIONS		5
#define TCPH_LEN_W_TIMESTAMP		8

#define LRO_MAX_PG_HLEN			64
#define LRO_INC_STATS(lro_mgr, attr)	{ lro_mgr->stats.attr++; }
/*
 * Basic tcp checks whether packet is suitable for LRO
 */
static int lro_tcp_ip_check(struct iphdr *iph, struct tcphdr *tcph,
			    int len, struct net_lro_desc *lro_desc)
{
	/* check ip header: don't aggregate padded frames */
	if (ntohs(iph->tot_len) != len)
		return -1;

	if (iph->ihl != IPH_LEN_WO_OPTIONS)
		return -1;

	if (tcph->cwr || tcph->ece || tcph->urg || !tcph->ack
		|| tcph->rst || tcph->syn || tcph->fin)
		return -1;

	if (INET_ECN_is_ce(ipv4_get_dsfield(iph)))
		return -1;

	if (tcph->doff != TCPH_LEN_WO_OPTIONS
		&& tcph->doff != TCPH_LEN_W_TIMESTAMP)
		return -1;

	/* check tcp options (only timestamp allowed) */
	if (tcph->doff == TCPH_LEN_W_TIMESTAMP) {
		u32 *topt = (u32 *)(tcph + 1);

		if (*topt != htonl((TCPOPT_NOP << 24) | (TCPOPT_NOP << 16)
				| (TCPOPT_TIMESTAMP << 8)
				| TCPOLEN_TIMESTAMP))
			return -1;

		/* timestamp should be in right order */
		topt++;
		if (lro_desc && after(ntohl(lro_desc->tcp_rcv_tsval),
				ntohl(*topt)))
			return -1;

		/* timestamp reply should not be zero */
		topt++;
		if (*topt == 0)
			return -1;
	}

	return 0;
}

static void lro_update_tcp_ip_header(struct net_lro_desc *lro_desc)
{
	struct iphdr *iph = lro_desc->iph;
	struct tcphdr *tcph = lro_desc->tcph;
	u32 *p;
	__wsum tcp_hdr_csum;

	tcph->ack_seq = lro_desc->tcp_ack;
	tcph->window = lro_desc->tcp_window;

	if (lro_desc->tcp_saw_tstamp) {
		p = (u32 *)(tcph + 1);
		*(p+2) = lro_desc->tcp_rcv_tsecr;
	}

	iph->tot_len = htons(lro_desc->ip_tot_len);

	iph->check = 0;
	iph->check = ip_fast_csum((u8 *)lro_desc->iph, iph->ihl);

	tcph->check = 0;
	tcp_hdr_csum = csum_partial((u8 *)tcph, TCP_HDR_LEN(tcph), 0);
	lro_desc->data_csum = csum_add(lro_desc->data_csum, tcp_hdr_csum);
	tcph->check = csum_tcpudp_magic(iph->saddr, iph->daddr,
					lro_desc->ip_tot_len -
					IP_HDR_LEN(iph), IPPROTO_TCP,
					lro_desc->data_csum);
}

static __wsum lro_tcp_data_csum(struct iphdr *iph, struct tcphdr *tcph, int len)
{
	__wsum tcp_csum;
	__wsum tcp_hdr_csum;
	__wsum tcp_ps_hdr_csum;

	tcp_csum = ~csum_unfold(tcph->check);
	tcp_hdr_csum = csum_partial((u8 *)tcph, TCP_HDR_LEN(tcph), tcp_csum);

	tcp_ps_hdr_csum = csum_tcpudp_nofold(iph->saddr, iph->daddr,
					     len + TCP_HDR_LEN(tcph),
					     IPPROTO_TCP, 0);

	return csum_sub(csum_sub(tcp_csum, tcp_hdr_csum),
			tcp_ps_hdr_csum);
}

static void lro_init_desc(struct net_lro_desc *lro_desc, struct sk_buff *skb,
			  struct iphdr *iph, struct tcphdr *tcph,
			  u16 vlan_tag, struct vlan_group *vgrp)
{
	int nr_frags;
	u32 *ptr;
	u32 tcp_data_len = TCP_PAYLOAD_LENGTH(iph, tcph);

	nr_frags = skb_shinfo(skb)->nr_frags;
	lro_desc->parent = skb;
	lro_desc->next_frag = &(skb_shinfo(skb)->frags[nr_frags]);
	lro_desc->iph = iph;
	lro_desc->tcph = tcph;
	lro_desc->tcp_next_seq = ntohl(tcph->seq) + tcp_data_len;
	lro_desc->tcp_ack = ntohl(tcph->ack_seq);
	lro_desc->tcp_window = tcph->window;

	lro_desc->pkt_aggr_cnt = 1;
	lro_desc->ip_tot_len = ntohs(iph->tot_len);

	if (tcph->doff == 8) {
		ptr = (u32 *)(tcph+1);
		lro_desc->tcp_saw_tstamp = 1;
		lro_desc->tcp_rcv_tsval = *(ptr+1);
		lro_desc->tcp_rcv_tsecr = *(ptr+2);
	}

	lro_desc->mss = tcp_data_len;
	lro_desc->vgrp = vgrp;
	lro_desc->vlan_tag = vlan_tag;
	lro_desc->active = 1;

	if (tcp_data_len)
		lro_desc->data_csum = lro_tcp_data_csum(iph, tcph,
						tcp_data_len);

	if (!tcp_data_len)
		lro_desc->ack_cnt++;
}

static inline void lro_clear_desc(struct net_lro_desc *lro_desc)
{
	memset(lro_desc, 0, sizeof(struct net_lro_desc));
}

static void lro_add_common(struct net_lro_desc *lro_desc, struct iphdr *iph,
			   struct tcphdr *tcph, int tcp_data_len)
{
	struct sk_buff *parent = lro_desc->parent;
	u32 *topt;

	lro_desc->pkt_aggr_cnt++;
	lro_desc->ip_tot_len += tcp_data_len;
	lro_desc->tcp_next_seq += tcp_data_len;
	lro_desc->tcp_window = tcph->window;
	lro_desc->tcp_ack = tcph->ack_seq;

	/* don't update tcp_rcv_tsval, would not work with PAWS */
	if (lro_desc->tcp_saw_tstamp) {
		topt = (u32 *) (tcph + 1);
		lro_desc->tcp_rcv_tsecr = *(topt + 2);
	}

	if (tcp_data_len)
		lro_desc->data_csum = csum_block_add(lro_desc->data_csum,
					lro_tcp_data_csum(iph, tcph,
						tcp_data_len),
					parent->len);

	parent->len += tcp_data_len;
	parent->data_len += tcp_data_len;
	if (tcp_data_len > lro_desc->mss)
		lro_desc->mss = tcp_data_len;
}

static void lro_add_frags(struct net_lro_desc *lro_desc,
			  int len, int hlen, int truesize,
			  struct skb_frag_struct *skb_frags,
			  struct iphdr *iph, struct tcphdr *tcph)
{
	struct sk_buff *skb = lro_desc->parent;
	int tcp_data_len = TCP_PAYLOAD_LENGTH(iph, tcph);

	lro_add_common(lro_desc, iph, tcph, tcp_data_len);

	skb->truesize += truesize;

	if (!tcp_data_len) {
		put_page(skb_frags[0].page);
		lro_desc->ack_cnt++;
		return;
	}

	skb_frags[0].page_offset += hlen;
	skb_frags[0].size -= hlen;

	while (tcp_data_len > 0) {
		*(lro_desc->next_frag) = *skb_frags;
		tcp_data_len -= skb_frags->size;
		lro_desc->next_frag++;
		skb_frags++;
		skb_shinfo(skb)->nr_frags++;
	}
}

static int lro_check_tcp_conn(struct net_lro_desc *lro_desc,
			      struct iphdr *iph,
			      struct tcphdr *tcph)
{
	if ((lro_desc->iph->saddr != iph->saddr)
	    || (lro_desc->iph->daddr != iph->daddr)
	    || (lro_desc->tcph->source != tcph->source)
	    || (lro_desc->tcph->dest != tcph->dest))
		return -1;
	return 0;
}

static struct net_lro_desc *lro_get_desc(struct net_lro_mgr *lro_mgr,
					 struct net_lro_desc *lro_arr,
					 struct iphdr *iph,
					 struct tcphdr *tcph)
{
	struct net_lro_desc *lro_desc = NULL;
	struct net_lro_desc *tmp;
	int max_desc = lro_mgr->max_desc;
	int i;

	for (i = 0; i < max_desc; i++) {
		tmp = &lro_arr[i];
		if (tmp->active)
			if (!lro_check_tcp_conn(tmp, iph, tcph)) {
				lro_desc = tmp;
				goto out;
			}
	}

	for (i = 0; i < max_desc; i++) {
		if (!lro_arr[i].active) {
			lro_desc = &lro_arr[i];
			goto out;
		}
	}

	LRO_INC_STATS(lro_mgr, no_desc);
out:
	return lro_desc;
}

static void lro_flush(struct net_lro_mgr *lro_mgr,
		      struct net_lro_desc *lro_desc)
{
	struct be_adapter *adapter = netdev_priv(lro_mgr->dev);

	if (lro_desc->pkt_aggr_cnt > 1)
		lro_update_tcp_ip_header(lro_desc);

	skb_shinfo(lro_desc->parent)->gso_size = lro_desc->mss;

	if (lro_desc->vgrp) {
		if (test_bit(LRO_F_NAPI, &lro_mgr->features))
			vlan_hwaccel_receive_skb(lro_desc->parent,
				lro_desc->vgrp,
				lro_desc->vlan_tag);
		else
			vlan_hwaccel_rx(lro_desc->parent,
				lro_desc->vgrp,
				lro_desc->vlan_tag);

	} else {
		if (test_bit(LRO_F_NAPI, &lro_mgr->features))
			netif_receive_skb(lro_desc->parent);
		else
			netif_rx(lro_desc->parent);
	}

	LRO_INC_STATS(lro_mgr, flushed);
	lro_clear_desc(lro_desc);
}

static struct sk_buff *lro_gen_skb(struct net_lro_mgr *lro_mgr,
				   struct skb_frag_struct *frags,
				   int len, int true_size,
				   void *mac_hdr,
				   int hlen, __wsum sum,
				   u32 ip_summed)
{
	struct sk_buff *skb;
	struct skb_frag_struct *skb_frags;
	int data_len = len;
	int hdr_len = min(len, hlen);

	skb = netdev_alloc_skb(lro_mgr->dev, hlen);
	if (!skb)
		return NULL;

	skb->len = len;
	skb->data_len = len - hdr_len;
	skb->truesize += true_size;
	skb->tail += hdr_len;

	memcpy(skb->data, mac_hdr, hdr_len);

	if (skb->data_len) {
		skb_frags = skb_shinfo(skb)->frags;
		while (data_len > 0) {
			*skb_frags = *frags;
			data_len -= frags->size;
			skb_frags++;
			frags++;
			skb_shinfo(skb)->nr_frags++;
		}
		skb_shinfo(skb)->frags[0].page_offset += hdr_len;
		skb_shinfo(skb)->frags[0].size -= hdr_len;
	} else {
		put_page(frags[0].page);
	}


	skb->ip_summed = ip_summed;
	skb->csum = sum;
	skb->protocol = eth_type_trans(skb, lro_mgr->dev);
	return skb;
}

static struct sk_buff *__lro_proc_segment(struct net_lro_mgr *lro_mgr,
					  struct skb_frag_struct *frags,
					  int len, int true_size,
					  struct vlan_group *vgrp,
					  u16 vlan_tag, void *priv, __wsum sum)
{
	struct net_lro_desc *lro_desc;
	struct iphdr *iph;
	struct tcphdr *tcph;
	struct sk_buff *skb;
	u64 flags;
	void *mac_hdr;
	int mac_hdr_len;
	int hdr_len = LRO_MAX_PG_HLEN;
	int vlan_hdr_len = 0;
	u8 pad_bytes;

	if (!lro_mgr->get_frag_header
	    || lro_mgr->get_frag_header(frags, (void *)&mac_hdr, (void *)&iph,
					(void *)&tcph, &flags, priv)) {
		mac_hdr = page_address(frags->page) + frags->page_offset;
		goto out1;
	}

	if (!(flags & LRO_IPV4) || !(flags & LRO_TCP))
		goto out1;

	hdr_len = (int)((void *)(tcph) + TCP_HDR_LEN(tcph) - mac_hdr);
	mac_hdr_len = (int)((void *)(iph) - mac_hdr);

	lro_desc = lro_get_desc(lro_mgr, lro_mgr->lro_arr, iph, tcph);
	if (!lro_desc)
		goto out1;

	pad_bytes = len - (ntohs(iph->tot_len) + mac_hdr_len);
	if (!TCP_PAYLOAD_LENGTH(iph, tcph) && pad_bytes) {
		len -= pad_bytes; /* trim the packet */
		frags[0].size -= pad_bytes;
		true_size -= pad_bytes;
	}

	if (!lro_desc->active) { /* start new lro session */
		if (lro_tcp_ip_check(iph, tcph, len - mac_hdr_len, NULL))
			goto out1;

		skb = lro_gen_skb(lro_mgr, frags, len, true_size, mac_hdr,
				  hdr_len, 0, lro_mgr->ip_summed_aggr);
		if (!skb)
			goto out;

		if ((skb->protocol == htons(ETH_P_8021Q))
		    && !test_bit(LRO_F_EXTRACT_VLAN_ID, &lro_mgr->features))
			vlan_hdr_len = VLAN_HLEN;

		iph = (void *)(skb->data + vlan_hdr_len);
		tcph = (void *)((u8 *)skb->data + vlan_hdr_len
				+ IP_HDR_LEN(iph));

		lro_init_desc(lro_desc, skb, iph, tcph, vlan_tag, vgrp);
		LRO_INC_STATS(lro_mgr, aggregated);
		return 0;
	}

	if (lro_desc->tcp_next_seq != ntohl(tcph->seq))
		goto out2;

	if (lro_tcp_ip_check(iph, tcph, len - mac_hdr_len, lro_desc))
		goto out2;

	lro_add_frags(lro_desc, len, hdr_len, true_size, frags, iph, tcph);
	LRO_INC_STATS(lro_mgr, aggregated);

	if ((skb_shinfo(lro_desc->parent)->nr_frags >= lro_mgr->max_aggr) ||
	    lro_desc->parent->len > (0xFFFF - lro_mgr->dev->mtu))
		lro_flush(lro_mgr, lro_desc);

	return NULL;

out2: /* send aggregated packets to the stack */
	lro_flush(lro_mgr, lro_desc);

out1:  /* Original packet has to be posted to the stack */
	skb = lro_gen_skb(lro_mgr, frags, len, true_size, mac_hdr,
			  hdr_len, sum, lro_mgr->ip_summed);
out:
	return skb;
}

void lro_receive_frags_compat(struct net_lro_mgr *lro_mgr,
		       struct skb_frag_struct *frags,
		       int len, int true_size, void *priv, __wsum sum)
{
	struct sk_buff *skb;

	skb = __lro_proc_segment(lro_mgr, frags, len, true_size, NULL, 0,
				 priv, sum);
	if (!skb)
		return;

	if (test_bit(LRO_F_NAPI, &lro_mgr->features))
		netif_receive_skb(skb);
	else
		netif_rx(skb);
}

void lro_vlan_hwaccel_receive_frags_compat(struct net_lro_mgr *lro_mgr,
				    struct skb_frag_struct *frags,
				    int len, int true_size,
				    struct vlan_group *vgrp,
				    u16 vlan_tag, void *priv, __wsum sum)
{
	struct sk_buff *skb;

	skb = __lro_proc_segment(lro_mgr, frags, len, true_size, vgrp,
				 vlan_tag, priv, sum);
	if (!skb)
		return;

	if (test_bit(LRO_F_NAPI, &lro_mgr->features))
		vlan_hwaccel_receive_skb(skb, vgrp, vlan_tag);
	else
		vlan_hwaccel_rx(skb, vgrp, vlan_tag);
}

void lro_flush_all_compat(struct net_lro_mgr *lro_mgr)
{
	int i;
	struct net_lro_desc *lro_desc = lro_mgr->lro_arr;

	for (i = 0; i < lro_mgr->max_desc; i++) {
		if (lro_desc[i].active)
			lro_flush(lro_mgr, &lro_desc[i]);
	}
}
#endif /* INET_LRO backport */

#ifndef TX_MQ
struct net_device *alloc_etherdev_mq_compat(int sizeof_priv,
					unsigned int queue_count)
{
	return alloc_etherdev(sizeof_priv);
}

void netif_wake_subqueue_compat(struct net_device *dev, u16 queue_index)
{
	netif_wake_queue(dev);
}

void netif_stop_subqueue_compat(struct net_device *dev, u16 queue_index)
{
	netif_stop_queue(dev);
}

int __netif_subqueue_stopped_compat(const struct net_device *dev,
						u16 queue_index)
{
	return netif_queue_stopped(dev);
}

u16 skb_get_queue_mapping_compat(const struct sk_buff *skb)
{
        return 0;
}

void netif_set_real_num_tx_queues_compat(struct net_device *dev,
					unsigned int txq)
{
	return;
}

u16 skb_tx_hash_compat(const struct net_device *dev,
			const struct sk_buff *skb)
{
	return 0;
}
#endif
