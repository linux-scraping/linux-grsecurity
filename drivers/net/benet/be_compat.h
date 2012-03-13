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

#ifndef BE_COMPAT_H
#define BE_COMPAT_H

/****************** RHEL5 and SLES10 backport ***************************/
#if LINUX_VERSION_CODE <= KERNEL_VERSION(2, 6, 18)

#ifndef upper_32_bits
#define upper_32_bits(n) ((u32)(((n) >> 16) >> 16))
#endif

#ifndef CHECKSUM_PARTIAL
#define CHECKSUM_PARTIAL CHECKSUM_HW
#define CHECKSUM_COMPLETE CHECKSUM_HW
#endif

#if !defined(ip_hdr)
#define ip_hdr(skb)	(skb->nh.iph)
#define ipv6_hdr(skb)	(skb->nh.ipv6h)
#endif

#if !defined(__packed)
#define __packed	__attribute__ ((packed))
#endif

#if !defined(RHEL_MINOR)
/* Only for RH5U1 (Maui) and SLES10 NIC driver */
enum {
	false = 0,
	true = 1
};
#if LINUX_VERSION_CODE == KERNEL_VERSION(2, 6, 18)
/* Only for RH5U1 (Maui) NIC driver */
static inline __attribute__((const))
int __ilog2_u32(u32 n)
{
	return fls(n) - 1;
}
#endif
#endif

#define ETH_FCS_LEN			4
#define bool				u8
#ifndef PTR_ALIGN
#define PTR_ALIGN(p, a)			((typeof(p))			\
					ALIGN((unsigned long)(p), (a)))
#endif
#define list_first_entry(ptr, type, member)				\
			list_entry((ptr)->next, type, member)

#if (defined(RHEL_MINOR) && RHEL_MINOR < 6) || \
	LINUX_VERSION_CODE <= KERNEL_VERSION(2, 6, 16)
#define DEFINE_PCI_DEVICE_TABLE(_table) struct pci_device_id _table[]	\
						__devinitdata
#endif

/* Backport of request_irq */
typedef irqreturn_t(*backport_irq_handler_t) (int, void *);
static inline int
backport_request_irq(unsigned int irq, irqreturn_t(*handler) (int, void *),
		unsigned long flags, const char *dev_name, void *dev_id)
{
	return request_irq(irq,
			(irqreturn_t(*) (int, void *, struct pt_regs *))handler,
			flags, dev_name, dev_id);
}
#define request_irq			backport_request_irq

#endif /*** RHEL5 and SLES10 backport ***/

#if !defined(__packed)
#define __packed			__attribute__ ((packed))
#endif

/****************** SLES10 only backport ***************************/
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 18)

#include <linux/tifm.h>

#define FIELD_SIZEOF(t, f)		(sizeof(((t *)0)->f))
#define IRQF_SHARED			SA_SHIRQ
#define CHECKSUM_PARTIAL		CHECKSUM_HW
#define CHECKSUM_COMPLETE		CHECKSUM_HW
#define DIV_ROUND_UP(n, d)		(((n) + (d) - 1) / (d))
#define NETIF_F_IPV6_CSUM		NETIF_F_IP_CSUM
#define NETIF_F_TSO6			NETIF_F_TSO


static inline struct sk_buff *netdev_alloc_skb(struct net_device *dev,
					       unsigned int length)
{
	/* 16 == NET_PAD_SKB */
	struct sk_buff *skb;
	skb = alloc_skb(length + 16, GFP_ATOMIC);
	if (likely(skb != NULL)) {
		skb_reserve(skb, 16);
		skb->dev = dev;
	}
	return skb;
}

#define PCI_SAVE_STATE(x)

#else  /* SLES10 only backport */

#define PCI_SAVE_STATE(x)	pci_save_state(x)

#endif /* SLES10 only backport */

#if LINUX_VERSION_CODE <= KERNEL_VERSION(2, 6, 31)
#define netdev_tx_t	int
#endif

#ifndef VLAN_PRIO_MASK
#define VLAN_PRIO_MASK          0xe000 /* Priority Code Point */
#define VLAN_PRIO_SHIFT         13
#endif

/*
 * Backport of netdev ops struct
 */
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 28)
struct net_device_ops {
	int	(*ndo_init)(struct net_device *dev);
	void	(*ndo_uninit)(struct net_device *dev);
	int	(*ndo_open)(struct net_device *dev);
	int	(*ndo_stop)(struct net_device *dev);
	int	(*ndo_start_xmit) (struct sk_buff *skb, struct net_device *dev);
	u16	(*ndo_select_queue)(struct net_device *dev,
				    struct sk_buff *skb);
	void	(*ndo_change_rx_flags)(struct net_device *dev, int flags);
	void	(*ndo_set_rx_mode)(struct net_device *dev);
	void	(*ndo_set_multicast_list)(struct net_device *dev);
	int	(*ndo_set_mac_address)(struct net_device *dev, void *addr);
	int	(*ndo_validate_addr)(struct net_device *dev);
	int	(*ndo_do_ioctl)(struct net_device *dev,
			struct ifreq *ifr, int cmd);
	int	(*ndo_set_config)(struct net_device *dev, struct ifmap *map);
	int	(*ndo_change_mtu)(struct net_device *dev, int new_mtu);
	int	(*ndo_neigh_setup)(struct net_device *dev,
				struct neigh_parms *);
	void	(*ndo_tx_timeout) (struct net_device *dev);

	struct net_device_stats* (*ndo_get_stats)(struct net_device *dev);

	void	(*ndo_vlan_rx_register)(struct net_device *dev,
				struct vlan_group *grp);
	void	(*ndo_vlan_rx_add_vid)(struct net_device *dev,
				unsigned short vid);
	void	(*ndo_vlan_rx_kill_vid)(struct net_device *dev,
				unsigned short vid);
#ifdef CONFIG_NET_POLL_CONTROLLER
#define HAVE_NETDEV_POLL
	void	(*ndo_poll_controller)(struct net_device *dev);
#endif
};
extern void be_netdev_ops_init(struct net_device *netdev,
			struct net_device_ops *ops);
extern int eth_validate_addr(struct net_device *);

#endif /* Netdev ops backport */

#if LINUX_VERSION_CODE == KERNEL_VERSION(2, 6, 29)
#undef NETIF_F_GRO
#endif

#ifdef NO_GRO
#if ((defined(RHEL_MAJOR) && (RHEL_MAJOR == 5)))
#undef NETIF_F_GRO
#endif
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 32)
#define HAVE_ETHTOOL_FLASH
#endif

/*
 * Backport of NAPI
 */
#if LINUX_VERSION_CODE <= KERNEL_VERSION(2, 6, 24)

#if defined(RHEL_MINOR) && (RHEL_MINOR > 3)
#define RHEL_NEW_NAPI
#endif

/* We need a new struct that has some meta data beyond rhel 5.4's napi_struct
 * to fix rhel5.4's half-baked new napi implementation.
 * We don't want to use rhel 5.4's broken napi_complete; so
 * define a new be_napi_complete that executes the logic only for Rx
 */

#ifdef RHEL_NEW_NAPI
#define napi_complete			be_napi_complete
typedef struct napi_struct		rhel_napi_struct;
#endif
#define napi_struct			be_napi_struct
#define napi_gro_frags(napi) napi_gro_frags((rhel_napi_struct *) napi)
#define vlan_gro_frags(napi, vlan_grp, vid)\
		vlan_gro_frags((rhel_napi_struct *) napi, vlan_grp, vid)
#define napi_get_frags(napi) napi_get_frags((rhel_napi_struct *) napi)

struct napi_struct {
#ifdef RHEL_NEW_NAPI
	rhel_napi_struct napi;	/* must be the first member */
#endif
	struct net_device *dev;
	int (*poll) (struct napi_struct *napi, int budget);
	bool rx;
};

static inline void napi_complete(struct napi_struct *napi)
{
#ifdef NETIF_F_GRO
	napi_gro_flush((rhel_napi_struct *)napi);
#endif
	netif_rx_complete(napi->dev);
}

static inline void napi_schedule(struct napi_struct *napi)
{
	netif_rx_schedule(napi->dev);
}

static inline void napi_enable(struct napi_struct *napi)
{
	netif_poll_enable(napi->dev);
}

static inline void napi_disable(struct napi_struct *napi)
{
	netif_poll_disable(napi->dev);
}

#if (defined(RHEL_MINOR) && RHEL_MINOR < 6) || \
	LINUX_VERSION_CODE <= KERNEL_VERSION(2, 6, 16)
static inline void vlan_group_set_device(struct vlan_group *vg,
					u16 vlan_id,
					struct net_device *dev)
{
	struct net_device **array;
	if (!vg)
		return;
	array = vg->vlan_devices;
	array[vlan_id] = dev;
}
#endif

#endif /* New NAPI backport */

extern int be_netif_napi_add(struct net_device *netdev,
		struct napi_struct *napi,
		int (*poll) (struct napi_struct *, int), int weight);
extern void be_netif_napi_del(struct net_device *netdev);
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 27)
#define HAVE_SIMULATED_MULTI_NAPI
#endif

/************** Backport of Delayed work queues interface ****************/
#if LINUX_VERSION_CODE <= KERNEL_VERSION(2, 6, 19)
#if (defined(RHEL_MINOR) && RHEL_MINOR < 6) || \
	LINUX_VERSION_CODE <= KERNEL_VERSION(2, 6, 16)
struct delayed_work {
	struct work_struct work;
};
#endif

#define INIT_DELAYED_WORK(_work, _func)				\
		INIT_WORK(&(_work)->work, _func, &(_work)->work)

static inline int backport_cancel_delayed_work_sync(struct delayed_work *work)
{
	cancel_rearming_delayed_work(&work->work);
	return 0;
}
#define cancel_delayed_work_sync backport_cancel_delayed_work_sync

static inline int backport_schedule_delayed_work(struct delayed_work *work,
		unsigned long delay)
{
	if (unlikely(!delay))
		return schedule_work(&work->work);
	else
		return schedule_delayed_work(&work->work, delay);
}
#define schedule_delayed_work backport_schedule_delayed_work
#endif /* backport delayed workqueue */


/************** Backport of INET_LRO **********************************/
#if LINUX_VERSION_CODE > KERNEL_VERSION(2, 6, 18)

#include <linux/inet_lro.h>

#else

#if LINUX_VERSION_CODE == KERNEL_VERSION(2, 6, 18)

#if defined(RHEL_MINOR) && RHEL_MINOR < 6
typedef __u16 __bitwise __sum16;
typedef __u32 __bitwise __wsum;
#endif

#if ((defined(RHEL_MAJOR) && (RHEL_MAJOR == 5) && (RHEL_MINOR <= 3)) || \
	(!defined(RHEL_MINOR)))
static inline __wsum csum_unfold(__sum16 n)
{
	return (__force __wsum)n;
}
#endif

#endif

#define lro_flush_all lro_flush_all_compat
#define lro_vlan_hwaccel_receive_frags lro_vlan_hwaccel_receive_frags_compat
#define lro_receive_frags lro_receive_frags_compat

struct net_lro_stats {
	unsigned long aggregated;
	unsigned long flushed;
	unsigned long no_desc;
};

struct net_lro_desc {
	struct sk_buff *parent;
	struct sk_buff *last_skb;
	struct skb_frag_struct *next_frag;
	struct iphdr *iph;
	struct tcphdr *tcph;
	struct vlan_group *vgrp;
	__wsum  data_csum;
	u32 tcp_rcv_tsecr;
	u32 tcp_rcv_tsval;
	u32 tcp_ack;
	u32 tcp_next_seq;
	u32 skb_tot_frags_len;
	u32 ack_cnt;
	u16 ip_tot_len;
	u16 tcp_saw_tstamp;		/* timestamps enabled */
	u16 tcp_window;
	u16 vlan_tag;
	int pkt_aggr_cnt;		/* counts aggregated packets */
	int vlan_packet;
	int mss;
	int active;
};

struct net_lro_mgr {
	struct net_device *dev;
	struct net_lro_stats stats;

	/* LRO features */
	unsigned long features;
#define LRO_F_NAPI            1  /* Pass packets to stack via NAPI */
#define LRO_F_EXTRACT_VLAN_ID 2  /* Set flag if VLAN IDs are extracted
				from received packets and eth protocol
				    is still ETH_P_8021Q */

	u32 ip_summed;      /* Set in non generated SKBs in page mode */
	u32 ip_summed_aggr; /* Set in aggregated SKBs: CHECKSUM_UNNECESSARY
			     * or CHECKSUM_NONE */

	int max_desc; /* Max number of LRO descriptors  */
	int max_aggr; /* Max number of LRO packets to be aggregated */

	struct net_lro_desc *lro_arr; /* Array of LRO descriptors */

	/* Optimized driver functions
	 * get_skb_header: returns tcp and ip header for packet in SKB
	 */
	int (*get_skb_header)(struct sk_buff *skb, void **ip_hdr,
			      void **tcpudp_hdr, u64 *hdr_flags, void *priv);

	/* hdr_flags: */
#define LRO_IPV4 1 /* ip_hdr is IPv4 header */
#define LRO_TCP  2 /* tcpudp_hdr is TCP header */

	/*
	 * get_frag_header: returns mac, tcp and ip header for packet in SKB
	 *
	 * @hdr_flags: Indicate what kind of LRO has to be done
	 *             (IPv4/IPv6/TCP/UDP)
	 */
	int (*get_frag_header)(struct skb_frag_struct *frag, void **mac_hdr,
			       void **ip_hdr, void **tcpudp_hdr, u64 *hdr_flags,
			       void *priv);
};

extern void lro_receive_skb(struct net_lro_mgr *lro_mgr, struct sk_buff *skb,
			void *priv);

extern void lro_vlan_hwaccel_receive_skb(struct net_lro_mgr *lro_mgr,
			struct sk_buff *skb, struct vlan_group *vgrp,
			u16 vlan_tag, void *priv);

/* This functions aggregate fragments and generate SKBs do pass
 * the packets to the stack.
 *
 * @lro_mgr: LRO manager to use
 * @frags: Fragment to be processed. Must contain entire header in first
 *         element.
 * @len: Length of received data
 * @true_size: Actual size of memory the fragment is consuming
 * @priv: Private data that may be used by driver functions
 *        (for example get_tcp_ip_hdr)
 */
extern void lro_receive_frags_compat(struct net_lro_mgr *lro_mgr,
			struct skb_frag_struct *frags, int len, int true_size,
			void *priv, __wsum sum);

extern void lro_vlan_hwaccel_receive_frags_compat(struct net_lro_mgr *lro_mgr,
			struct skb_frag_struct *frags, int len, int true_size,
			struct vlan_group *vgrp, u16 vlan_tag, void *priv,
			__wsum sum);

/* Forward all aggregated SKBs held by lro_mgr to network stack */
extern void lro_flush_all_compat(struct net_lro_mgr *lro_mgr);

extern void lro_flush_pkt(struct net_lro_mgr *lro_mgr, struct iphdr *iph,
			struct tcphdr *tcph);
#endif /* backport of inet_lro */

#ifndef ETHTOOL_FLASH_MAX_FILENAME
#define ETHTOOL_FLASH_MAX_FILENAME	128
#endif

#if defined(CONFIG_XEN) && !defined(NETIF_F_GRO)
#define BE_INIT_FRAGS_PER_FRAME  (u32) 1
#else
#define BE_INIT_FRAGS_PER_FRAME  (min((u32) 16, (u32) MAX_SKB_FRAGS))
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 32)
#ifdef CONFIG_PCI_IOV
#if (!(defined(RHEL_MAJOR) && (RHEL_MAJOR == 5) && (RHEL_MINOR == 6)))
#undef CONFIG_PCI_IOV
#endif
#endif
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 20)
#define dev_to_node(dev)	-1
#endif


#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 32)
#if (!(defined(RHEL_MAJOR) && (RHEL_MAJOR == 5) && (RHEL_MINOR > 6)))
static inline struct sk_buff *netdev_alloc_skb_ip_align(struct net_device *dev,
		unsigned int length)
{
	struct sk_buff *skb = netdev_alloc_skb(dev, length + NET_IP_ALIGN);

	if (NET_IP_ALIGN && skb)
		skb_reserve(skb, NET_IP_ALIGN);
	return skb;
}
#endif
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 26)
#ifndef netif_set_gso_max_size
#define netif_set_gso_max_size(netdev, size) do {} while (0)
#endif
#endif

#if (LINUX_VERSION_CODE == KERNEL_VERSION(2, 6, 18))
#if defined(RHEL_MINOR) && (RHEL_MINOR <= 4)
static inline int skb_is_gso_v6(const struct sk_buff *skb)
{
	return skb_shinfo(skb)->gso_type & SKB_GSO_TCPV6;
}
#endif
#endif

#if (LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 18))
static inline int skb_is_gso_v6(const struct sk_buff *skb)
{
	return (ip_hdr(skb)->version == 6);
}
#endif

#if (LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 18))
#define DMA_BIT_MASK(n) (((n) == 64) ? ~0ULL : ((1ULL<<(n))-1))
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 32)
#if ((defined(RHEL_MAJOR) && (RHEL_MAJOR == 6)))
#define HAVE_SRIOV_CONFIG
#endif
#endif

#ifndef NETIF_F_VLAN_SG
#define NETIF_F_VLAN_SG NETIF_F_SG
#endif

#ifndef NETIF_F_VLAN_CSUM
#define NETIF_F_VLAN_CSUM NETIF_F_HW_CSUM
#endif

#ifndef NETIF_F_VLAN_TSO
#define NETIF_F_VLAN_TSO NETIF_F_TSO
#endif

#if (LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 27))
#define vlan_features	features
#endif

#ifndef DEFINE_DMA_UNMAP_ADDR
#define DEFINE_DMA_UNMAP_ADDR(bus)	dma_addr_t bus
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 0, 0)

#ifndef netdev_mc_count
#define netdev_mc_count(nd) (nd->mc_count)
#endif

#ifndef netdev_hw_addr
#define netdev_hw_addr dev_mc_list
#endif

#ifndef netdev_for_each_mc_addr
#define netdev_for_each_mc_addr(ha, nd) \
	for (ha = (nd)->mc_list; ha; ha = ha->next)
#endif

#define DMI_ADDR dmi_addr
#else
#define DMI_ADDR addr
#endif

#ifndef VLAN_GROUP_ARRAY_LEN
#define VLAN_GROUP_ARRAY_LEN VLAN_N_VID
#endif
/**************************** Multi TXQ Support ******************************/

/* Supported only in RHEL6 and SL11.1 (barring one execption) */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 32)
#define MQ_TX
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 27)
#define alloc_etherdev_mq(sz, cnt) 		alloc_etherdev(sz)
#define skb_get_queue_mapping(skb)		0
#define skb_tx_hash(dev, skb)			0
#define netif_set_real_num_tx_queues(dev, txq)	do {} while(0)	
#define netif_wake_subqueue(dev, idx)		netif_wake_queue(dev)
#define netif_stop_subqueue(dev, idx)		netif_stop_queue(dev)
#define __netif_subqueue_stopped(dev, idx)	netif_queue_stopped(dev)
#endif /* < 2.6.27 */

#if ((LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 27)) && \
		        (LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 32)))
#define skb_tx_hash(dev, skb)			0
#define netif_set_real_num_tx_queues(dev, txq)	do {} while(0)	
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 32)
#define netif_set_real_num_tx_queues 		be_set_real_num_tx_queues
static inline void be_set_real_num_tx_queues(struct net_device *dev,
						unsigned int txq)
{
	dev->real_num_tx_queues = txq;
}
#endif

#include <linux/if_vlan.h>
static inline void be_reset_skb_tx_vlan(struct sk_buff *skb)
{
#if LINUX_VERSION_CODE > KERNEL_VERSION(2, 6, 18)
	skb->vlan_tci = 0;
#else
	struct vlan_skb_tx_cookie *cookie;

	cookie = VLAN_TX_SKB_CB(skb);
	cookie->magic = 0;
#endif
}

#if (LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 18))
static inline void skb_set_network_header(struct sk_buff *skb, const int offset)
{
	skb->nh.raw = skb->data + offset;
}
#endif

static inline struct sk_buff *be_vlan_put_tag(struct sk_buff *skb,
						unsigned short vlan_tag)
{
	struct sk_buff *new_skb = __vlan_put_tag(skb, vlan_tag);
	/* On kernel versions < 2.6.27 the __vlan_put_tag() function
	 * distorts the network layer hdr pointer in the skb which
	 * affects the detection of UDP/TCP packets down the line in
	 * wrb_fill_hdr().This work-around sets it right.
	 */
#if (LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 27))
	skb_set_network_header(new_skb, VLAN_ETH_HLEN);
#endif
	return new_skb;
}

#ifndef ACCESS_ONCE
#define ACCESS_ONCE(x) (*(volatile typeof(x) *)&(x))
#endif

#endif				/* BE_COMPAT_H */
