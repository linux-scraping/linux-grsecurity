/*
 * Copyright (C) 2005 - 2011 ServerEngines
 * All rights reserved.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License version 2
 * as published by the Free Software Foundation.  The full GNU General
 * Public License is included in this distribution in the file called COPYING.
 *
 * Contact Information:
 * linux-drivers@serverengines.com
 *
 * ServerEngines
 * 209 N. Fair Oaks Ave
 * Sunnyvale, CA 94085
 */
#include <linux/proc_fs.h>
#include "be.h"

char *be_adpt_name[] = {
	"driver/be2net0",
	"driver/be2net1",
	"driver/be2net2",
	"driver/be2net3",
	"driver/be2net4",
	"driver/be2net5",
	"driver/be2net6",
	"driver/be2net7"
};

#define MAX_BE_DEVICES 8
struct proc_dir_entry *be_proc_dir[MAX_BE_DEVICES];

/*File to read Eth Ring Information */
#define BE_ETH_RING_FILE "eth_ring"
#define BE_DRVR_STAT_FILE    "drvr_stat"

/*
 * this file enables user to read a 32 bit CSR register.
 * to read 32 bit value of a register at offset 0x1234,
 * first write the offset 0x1234 (echo "0x1234") in 
 * the file and then read the value from this file.
 * the written offset is latched until another value is written
 */
#define BE_CSR_R_FILE    "csrr"
/*
 * this file enables user to write to a 32 bit CSR register.
 * to write a value 0xdeadbeef to a register at offset 0x1234,
 * write 0x1234 0xdeadbeef (echo "0x1234 0xdeadbeeb") to 
 * the file.
 */
#define BE_CSR_W_FILE	"csrw"

#define BE_PROC_MODE          0600

static char read_eth_ring_buf[4096];
static int read_eth_ring_count;

/*
 * Get Various Eth Ring Properties
 */
static int proc_eth_read_ring(char *page, char **start,
			      off_t off, int count, int *eof, void *data)
{
	int i, n;
	char *p = read_eth_ring_buf;
	struct be_adapter *adapter = (struct be_adapter *) data;

	if (off == 0) {
		/* Reset read_eth_ring_count */
		read_eth_ring_count = 0;

		n = sprintf(p, "                    PhyAddr  VirtAddr  Size  TotalEntries  ProducerIndex  ConsumerIndex  NumUsed\n");
		p += n;
		read_eth_ring_count += n;

		n = sprintf(p, "                    -------  --------  ----  ------------  -------------  -------------  -------\n");
		p += n;
		read_eth_ring_count += n;

		n = sprintf(p, "%s", "EthSendRing");
		p += n;
		read_eth_ring_count += n;

		n = sprintf(p, "         %7lx  %8p  %4u  %12u  %13u  %13u  %7u  \n",
			(long) adapter->tx_obj.q.dma_mem.dma,
			(void *)adapter->tx_obj.q.dma_mem.va,
			(u32) (adapter->tx_obj.q.len *
				sizeof(struct be_eth_wrb)),
			adapter->tx_obj.q.len, adapter->tx_obj.q.head,
			adapter->tx_obj.q.tail,
			atomic_read(&adapter->tx_obj.q.used));

		p += n;
		read_eth_ring_count += n;

		/* Get Eth Send Compl Queue Details */
		n = sprintf(p, "%s", "EthSendCmplRing");
		p += n;
		read_eth_ring_count += n;

		n = sprintf(p, "     %7lx  %8p  %4u  %12u  %13s  %13u  %7s\n",
			    (long)adapter->tx_obj.cq.dma_mem.dma,
			    (void *)adapter->tx_obj.cq.dma_mem.va,
			    (u32) (adapter->tx_obj.cq.len *
				   sizeof(struct be_eth_tx_compl)),
			    adapter->tx_obj.cq.len, "NA", 
			    adapter->tx_obj.cq.tail, "NA");

		p += n;
		read_eth_ring_count += n;
		/* Get Eth Rx Queue Details */
		n = sprintf(p, "%s", "EthRxRing");
		p += n;
		read_eth_ring_count += n;

		n = sprintf(p, "           %7lx  %8p  %4u  %12u  %13u  %13s  %7u  \n",
			    (long)adapter->rx_obj.q.dma_mem.dma,
			    (void *)adapter->rx_obj.q.dma_mem.va,
			    (u32) (adapter->rx_obj.q.len * 
				sizeof(struct be_eth_rx_d)),
			    adapter->rx_obj.q.len, adapter->rx_obj.q.head,"NA",
			    atomic_read(&adapter->rx_obj.q.used));
		p += n;
		read_eth_ring_count += n;

		/* Get Eth Unicast Rx Compl Queue Details */
		n = sprintf(p, "%s", "EthRxCmplRing");
		p += n;
		read_eth_ring_count += n;

		n = sprintf(p, "       %7lx  %8p  %4u  %12u  %13s  %13u  %7s\n",
			    (long)adapter->rx_obj.cq.dma_mem.dma,
			    (void *)adapter->rx_obj.cq.dma_mem.va,
			    (u32) (adapter->rx_obj.cq.len *
				   sizeof(struct be_eth_rx_compl)),
			    adapter->rx_obj.cq.len, "NA", 
			    adapter->rx_obj.cq.tail, "NA");
		p += n;
		read_eth_ring_count += n;

		/* Get Eth Event Queue Details */
		n = sprintf(p, "%s", "EthTxEventRing");
		p += n;
		read_eth_ring_count += n;

		n = sprintf(p,
			    "      %7lx  %8p  %4u  %12u  %13s  %13u  %7s\n",
			    (long) adapter->tx_eq.q.dma_mem.dma,
			    (void *)adapter->tx_eq.q.dma_mem.va,
			    (u32) (adapter->tx_eq.q.len *
				   sizeof(struct be_eq_entry)),
			    adapter->tx_eq.q.len, "NA",
			    adapter->tx_eq.q.tail, "NA");

		p += n;
		read_eth_ring_count += n;

		/* Get Eth Event Queue Details */
		n = sprintf(p, "%s", "EthRxEventRing");
		p += n;
		read_eth_ring_count += n;

		n = sprintf(p,
			    "      %7lx  %8p  %4u  %12u  %13s  %13u  %7s\n",
			    (long) adapter->rx_eq.q.dma_mem.dma,
			    (void *)adapter->rx_eq.q.dma_mem.va,
			    (u32) (adapter->rx_eq.q.len *
				   sizeof(struct be_eq_entry)),
			    adapter->rx_eq.q.len, "NA",
			    adapter->rx_eq.q.tail, "NA");

		p += n;
		read_eth_ring_count += n;
	}

	*start = page;
	/* copy whatever we can */
	if (count < (read_eth_ring_count - off)) {
		i = count;
		*eof = 0;	/* More bytes left */
	} else {
		i = read_eth_ring_count - off;
		*eof = 1;	/* Nothing left. indicate EOF */
	}

	memcpy(page, read_eth_ring_buf + off, i);
	return (i);
}

static int proc_eth_write_ring(struct file *file,
			       const char *buffer, unsigned long count,
			       void *data)
{
	return (count);		/* we do not support write */
}

/*
 * read the driver stats.
 */
static int proc_read_drvr_stat(char *page, char **start,
			       off_t off, int count, int *eof, void *data)
{
	int n, lro_cp;
	char *p = page;
	struct be_adapter *adapter = (struct be_adapter *) data;
	struct net_device *netdev = adapter->netdev;

	if (off == 0) {
		n = sprintf(p, "interface = %s\n", netdev->name);
		p += n;
		n = sprintf(p, "tx_reqs = %d\n",
			    drvr_stats(adapter)->be_tx_reqs);
		p += n;
		n = sprintf(p, "tx_stops = %d\n",
			    drvr_stats(adapter)->be_tx_stops);
		p += n;
		n = sprintf(p, "fwd_reqs = %d\n",
			    drvr_stats(adapter)->be_fwd_reqs);
		p += n;
		n = sprintf(p, "tx_wrbs = %d\n",
			    drvr_stats(adapter)->be_tx_wrbs);
		p += n;
		n = sprintf(p, "rx_poll = %d\n", drvr_stats(adapter)->be_rx_polls);
		p += n;
		n = sprintf(p, "tx_events = %d\n",
			    drvr_stats(adapter)->be_tx_events);
		p += n;
		n = sprintf(p, "rx_events = %d\n",
			    drvr_stats(adapter)->be_rx_events);
		p += n;
		n = sprintf(p, "tx_compl = %d\n",
			    drvr_stats(adapter)->be_tx_compl);
		p += n;
		n = sprintf(p, "rx_compl = %d\n",
			    drvr_stats(adapter)->be_rx_compl);
		p += n;
		n = sprintf(p, "ethrx_post_fail = %d\n",
			    drvr_stats(adapter)->be_ethrx_post_fail);
		p += n;
		n = sprintf(p, "802.3_dropped_frames = %d\n",
			    drvr_stats(adapter)->be_802_3_dropped_frames);
		p += n;
		n = sprintf(p, "802.3_malformed_frames = %d\n",
			    drvr_stats(adapter)->be_802_3_malformed_frames);
		p += n;
		n = sprintf(p, "eth_tx_rate = %d\n",
			    drvr_stats(adapter)->be_tx_rate);
		p += n;
		n = sprintf(p, "eth_rx_rate = %d\n",
			    drvr_stats(adapter)->be_rx_rate);
		p += n;

                lro_cp = (drvr_stats(adapter)->be_lro_hgram_data[0] +
                        drvr_stats(adapter)->be_lro_hgram_data[1] +
                        drvr_stats(adapter)->be_lro_hgram_data[2] +
                        drvr_stats(adapter)->be_lro_hgram_data[3] +
                        drvr_stats(adapter)->be_lro_hgram_data[4] +
                        drvr_stats(adapter)->be_lro_hgram_data[5] +
                        drvr_stats(adapter)->be_lro_hgram_data[6] +
                        drvr_stats(adapter)->be_lro_hgram_data[7])/100;
                lro_cp = (lro_cp == 0) ? 1  : lro_cp; /* avoid divide by 0 */
                n = sprintf(p,
			"LRO data count %% histogram (1, 2-3, 4-5,..,>=16) = "
                        "%d, %d, %d, %d  - %d, %d, %d, %d\n",
                            drvr_stats(adapter)->be_lro_hgram_data[0]/lro_cp,
                            drvr_stats(adapter)->be_lro_hgram_data[1]/lro_cp,
                            drvr_stats(adapter)->be_lro_hgram_data[2]/lro_cp,
                            drvr_stats(adapter)->be_lro_hgram_data[3]/lro_cp,
                            drvr_stats(adapter)->be_lro_hgram_data[4]/lro_cp,
                            drvr_stats(adapter)->be_lro_hgram_data[5]/lro_cp,
                            drvr_stats(adapter)->be_lro_hgram_data[6]/lro_cp,
                            drvr_stats(adapter)->be_lro_hgram_data[7]/lro_cp);
                p += n;

                lro_cp = (drvr_stats(adapter)->be_lro_hgram_ack[0] +
                        drvr_stats(adapter)->be_lro_hgram_ack[1] +
                        drvr_stats(adapter)->be_lro_hgram_ack[2] +
                        drvr_stats(adapter)->be_lro_hgram_ack[3] +
                        drvr_stats(adapter)->be_lro_hgram_ack[4] +
                        drvr_stats(adapter)->be_lro_hgram_ack[5] +
                        drvr_stats(adapter)->be_lro_hgram_ack[6] +
                        drvr_stats(adapter)->be_lro_hgram_ack[7])/100;
                lro_cp = (lro_cp == 0) ? 1  : lro_cp; /* avoid divide by 0 */
                n = sprintf(p,
			"LRO ack count %% histogram (1, 2-3, 4-5,..,>=16) = "
                        "%d, %d, %d, %d  - %d, %d, %d, %d\n",
                            drvr_stats(adapter)->be_lro_hgram_ack[0]/lro_cp,
                            drvr_stats(adapter)->be_lro_hgram_ack[1]/lro_cp,
                            drvr_stats(adapter)->be_lro_hgram_ack[2]/lro_cp,
                            drvr_stats(adapter)->be_lro_hgram_ack[3]/lro_cp,
                            drvr_stats(adapter)->be_lro_hgram_ack[4]/lro_cp,
                            drvr_stats(adapter)->be_lro_hgram_ack[5]/lro_cp,
                            drvr_stats(adapter)->be_lro_hgram_ack[6]/lro_cp,
                            drvr_stats(adapter)->be_lro_hgram_ack[7]/lro_cp);
                p += n;
		n = sprintf(p, "rx_eq_delay = %d \n", adapter->rx_eq.cur_eqd);
		p += n;
		n = sprintf(p, "rx frags per sec=%d \n", 
					drvr_stats(adapter)->be_rx_fps);
		p += n;

	}
	*eof = 1;
	return (p - page);
}

static int proc_write_drvr_stat(struct file *file,
				const char *buffer, unsigned long count,
				void *data)
{
	struct be_adapter *adapter = (struct be_adapter *) data;

	memset(&(adapter->stats.drvr_stats), 0, 
			sizeof(adapter->stats.drvr_stats));
	return (count);		/* we do not support write */
}

#if 0
/* the following are some of the functions that are needed here
 * until all initializations are done by MPU.
 */

u32 
CsrReadDr(void*  BaseAddress, u32 Offset)
{
    u32  *rp;

    rp = (u32 *) (((u8 *) BaseAddress) + Offset);
    return (*rp);
}

/*!

@brief
    This routine writes to a register located within the CSR
    space for a given function object.

@param    
    FuncObj     - Pointer to the function object to read from.
    
@param    
    Offset      - The Offset (in bytes) to write to within the function's CSR space.

@param    
    Value       - The value to write to the register.

@return

@note
    IRQL: any

*/
void 
CsrWriteDr(void*  BaseAddress, u32 Offset, u32 Value)
{
    u32 *Register;

    Register = (u32 *) (((u8 *) BaseAddress) + Offset);

    //TRACE(DL_INFO, "CsrWrite[ %X ] <= %X", Register, Value);
    *Register = Value;
}
u32 be_proc_csrr_offset = -1;	/* to latch the offset of next CSR Read req. */

/*
 * read the csr_r file.  return the 32 bit register value from
 * CSR space at offset latched in the global location 
 * be_proc_csrr_offset
 */
static int proc_read_csr_r(char *page, char **start,
			   off_t off, int count, int *eof, void *data)
{
	struct be_adapter * adapter = (struct be_adapter *)data;
	u32 val;
	int n = 0;
	if (be_proc_csrr_offset == -1)
		return -EINVAL;

	if (off == 0) {
		/* read the CSR at offset be_proc_csrr_offset and return */
		val = CsrReadDr(adapter->csr_va, be_proc_csrr_offset);
		n = sprintf(page, "0x%x\n", val);
	}
	*eof = 1;
	return n;
}

/* 
 * save the written value in be_proc_csrr_offset for next
 * read from the file
 */
static int proc_write_csr_r(struct file *file,
	    const char *buffer, unsigned long count, void *data)
{
	char buf[64];
	u32 n;

	if (count > sizeof(buf) + 1)
		return -EINVAL;
	if (copy_from_user(buf, buffer, count))
		return -EFAULT;
	buf[count] = '\0';

	n = simple_strtoul(buf, NULL, 16);
	if (n < 0x50000)
		be_proc_csrr_offset = n;
	return (count);
}

/*
 * return the latched offset for reading the csr_r file.
 */
static int proc_read_csr_w(char *page, char **start,
			   off_t off, int count, int *eof, void *data)
{

	*eof = 1;
	return sprintf(page, "0x%x\n", be_proc_csrr_offset);
}

/* 
 * the incoming string is of the form "<offset> <value>"
 * where the offset is the offset of the register to be written
 * and value is the value to be written. 
 */
static int proc_write_csr_w(struct file *file,
			    const char *buffer, unsigned long count,
			    void *data)
{
	char buf[64];
	char *p;
	u32 n, val;
	struct be_adapter * adapter = (struct be_adapter *)data;

	if (count > sizeof(buf) + 1)
		return -EINVAL;
	if (copy_from_user(buf, buffer, count))
		return -EFAULT;
	buf[count] = '\0';

	n = simple_strtoul(buf, &p, 16);
	if (n > 0x50000)
		return -EINVAL;

	/* now get the actual value to be written */
	while (*p == ' ' || *p == '\t')
		p++;
	val = simple_strtoul(p, NULL, 16);
	CsrWriteDr(adapter->csr_va, n, val);
	return (count);
}
#endif

void be_init_procfs(struct be_adapter *adapter, int adapt_num)
{
	static struct proc_dir_entry *pde;

	if (adapt_num > MAX_BE_DEVICES - 1)
		return;

	/* create directory */
	be_proc_dir[adapt_num] =
	     proc_mkdir(be_adpt_name[adapt_num], NULL);
	if (be_proc_dir[adapt_num]) {
		(be_proc_dir[adapt_num])->owner = THIS_MODULE;
	}

	pde = create_proc_entry(BE_ETH_RING_FILE, BE_PROC_MODE,
			       be_proc_dir[adapt_num]);
	if (pde) {
		pde->read_proc = proc_eth_read_ring;
		pde->write_proc = proc_eth_write_ring;
		pde->data = adapter;
		pde->owner = THIS_MODULE;
	}

	pde = create_proc_entry(BE_DRVR_STAT_FILE, BE_PROC_MODE,
			       be_proc_dir[adapt_num]);
	if (pde) {
		pde->read_proc = proc_read_drvr_stat;
		pde->write_proc = proc_write_drvr_stat;
		pde->data = adapter;
		pde->owner = THIS_MODULE;
	}

#if 0
	if ((pde = create_proc_entry(BE_CSR_R_FILE, BE_PROC_MODE, be_proc_dir[adapt_num]))) {
		pde->read_proc = proc_read_csr_r;
		pde->write_proc = proc_write_csr_r;
		pde->data = adapter;
		pde->owner = THIS_MODULE;
	}

	if ((pde = create_proc_entry(BE_CSR_W_FILE, BE_PROC_MODE, be_proc_dir[adapt_num]))) {
		pde->read_proc = proc_read_csr_w;
		pde->write_proc = proc_write_csr_w;
		pde->data = adapter;
		pde->owner = THIS_MODULE;
	}
#endif
}

void be_cleanup_procfs(struct be_adapter *adapter, int adapt_num)
{
	if (adapt_num > MAX_BE_DEVICES - 1)
		return;
	remove_proc_entry(BE_ETH_RING_FILE, be_proc_dir[adapt_num]);
	remove_proc_entry(BE_DRVR_STAT_FILE, be_proc_dir[adapt_num]);
	remove_proc_entry(BE_CSR_R_FILE, be_proc_dir[adapt_num]);
	remove_proc_entry(BE_CSR_W_FILE, be_proc_dir[adapt_num]);
	remove_proc_entry(be_adpt_name[adapt_num], NULL);
}
