#include <linux/gfp.h>
#include <linux/initrd.h>
#include <linux/ioport.h>
#include <linux/swap.h>
#include <linux/memblock.h>
#include <linux/bootmem.h>	/* for max_low_pfn */

#include <asm/cacheflush.h>
#include <asm/e820.h>
#include <asm/init.h>
#include <asm/page.h>
#include <asm/page_types.h>
#include <asm/sections.h>
#include <asm/setup.h>
#include <asm/tlbflush.h>
#include <asm/tlb.h>
#include <asm/proto.h>
#include <asm/dma.h>		/* for MAX_DMA_PFN */
#include <asm/desc.h>
#include <asm/bios_ebda.h>

unsigned long __initdata pgt_buf_start;
unsigned long __meminitdata pgt_buf_end;
unsigned long __meminitdata pgt_buf_top;

int after_bootmem;

int direct_gbpages
#ifdef CONFIG_DIRECT_GBPAGES
				= 1
#endif
;

struct map_range {
	unsigned long start;
	unsigned long end;
	unsigned page_size_mask;
};

static void __init find_early_table_space(struct map_range *mr, unsigned long end,
					  int use_pse, int use_gbpages)
{
	unsigned long puds, pmds, ptes, tables, start = 0x100000, good_end = end;
	phys_addr_t base;

	puds = (end + PUD_SIZE - 1) >> PUD_SHIFT;
	tables = roundup(puds * sizeof(pud_t), PAGE_SIZE);

	if (use_gbpages) {
		unsigned long extra;

		extra = end - ((end>>PUD_SHIFT) << PUD_SHIFT);
		pmds = (extra + PMD_SIZE - 1) >> PMD_SHIFT;
	} else
		pmds = (end + PMD_SIZE - 1) >> PMD_SHIFT;

	tables += roundup(pmds * sizeof(pmd_t), PAGE_SIZE);

	if (use_pse) {
		unsigned long extra;

		extra = end - ((end>>PMD_SHIFT) << PMD_SHIFT);
#ifdef CONFIG_X86_32
		extra += PMD_SIZE;
#endif
		/* The first 2/4M doesn't use large pages. */
		if (mr->start < PMD_SIZE)
			extra += mr->end - mr->start;

		ptes = (extra + PAGE_SIZE - 1) >> PAGE_SHIFT;
	} else
		ptes = (end + PAGE_SIZE - 1) >> PAGE_SHIFT;

	tables += roundup(ptes * sizeof(pte_t), PAGE_SIZE);

#ifdef CONFIG_X86_32
	/* for fixmap */
	tables += roundup(__end_of_fixed_addresses * sizeof(pte_t), PAGE_SIZE);
#endif
	good_end = max_pfn_mapped << PAGE_SHIFT;

	base = memblock_find_in_range(start, good_end, tables, PAGE_SIZE);
	if (!base)
		panic("Cannot find space for the kernel page tables");

	pgt_buf_start = base >> PAGE_SHIFT;
	pgt_buf_end = pgt_buf_start;
	pgt_buf_top = pgt_buf_start + (tables >> PAGE_SHIFT);

	printk(KERN_DEBUG "kernel direct mapping tables up to %#lx @ [mem %#010lx-%#010lx]\n",
		end - 1, pgt_buf_start << PAGE_SHIFT,
		(pgt_buf_top << PAGE_SHIFT) - 1);
}

void __init native_pagetable_reserve(u64 start, u64 end)
{
	memblock_reserve(start, end - start);
}

#ifdef CONFIG_X86_32
#define NR_RANGE_MR 3
#else /* CONFIG_X86_64 */
#define NR_RANGE_MR 5
#endif

static int __meminit save_mr(struct map_range *mr, int nr_range,
			     unsigned long start_pfn, unsigned long end_pfn,
			     unsigned long page_size_mask)
{
	if (start_pfn < end_pfn) {
		if (nr_range >= NR_RANGE_MR)
			panic("run out of range for init_memory_mapping\n");
		mr[nr_range].start = start_pfn<<PAGE_SHIFT;
		mr[nr_range].end   = end_pfn<<PAGE_SHIFT;
		mr[nr_range].page_size_mask = page_size_mask;
		nr_range++;
	}

	return nr_range;
}

/*
 * Setup the direct mapping of the physical memory at PAGE_OFFSET.
 * This runs before bootmem is initialized and gets pages directly from
 * the physical memory. To access them they are temporarily mapped.
 */
unsigned long __init_refok init_memory_mapping(unsigned long start,
					       unsigned long end)
{
	unsigned long page_size_mask = 0;
	unsigned long start_pfn, end_pfn;
	unsigned long ret = 0;
	unsigned long pos;

	struct map_range mr[NR_RANGE_MR];
	int nr_range, i;
	int use_pse, use_gbpages;

	printk(KERN_INFO "init_memory_mapping: [mem %#010lx-%#010lx]\n",
	       start, end - 1);

#if defined(CONFIG_DEBUG_PAGEALLOC) || defined(CONFIG_KMEMCHECK)
	/*
	 * For CONFIG_DEBUG_PAGEALLOC, identity mapping will use small pages.
	 * This will simplify cpa(), which otherwise needs to support splitting
	 * large pages into small in interrupt context, etc.
	 */
	use_pse = use_gbpages = 0;
#else
	use_pse = cpu_has_pse;
	use_gbpages = direct_gbpages;
#endif

	/* Enable PSE if available */
	if (cpu_has_pse)
		set_in_cr4(X86_CR4_PSE);

	/* Enable PGE if available */
	if (cpu_has_pge) {
		set_in_cr4(X86_CR4_PGE);
		__supported_pte_mask |= _PAGE_GLOBAL;
	}

	if (use_gbpages)
		page_size_mask |= 1 << PG_LEVEL_1G;
	if (use_pse)
		page_size_mask |= 1 << PG_LEVEL_2M;

	memset(mr, 0, sizeof(mr));
	nr_range = 0;

	/* head if not big page alignment ? */
	start_pfn = start >> PAGE_SHIFT;
	pos = start_pfn << PAGE_SHIFT;
#ifdef CONFIG_X86_32
	/*
	 * Don't use a large page for the first 2/4MB of memory
	 * because there are often fixed size MTRRs in there
	 * and overlapping MTRRs into large pages can cause
	 * slowdowns.
	 */
	if (pos == 0)
		end_pfn = 1<<(PMD_SHIFT - PAGE_SHIFT);
	else
		end_pfn = ((pos + (PMD_SIZE - 1))>>PMD_SHIFT)
				 << (PMD_SHIFT - PAGE_SHIFT);
#else /* CONFIG_X86_64 */
	end_pfn = ((pos + (PMD_SIZE - 1)) >> PMD_SHIFT)
			<< (PMD_SHIFT - PAGE_SHIFT);
#endif
	if (end_pfn > (end >> PAGE_SHIFT))
		end_pfn = end >> PAGE_SHIFT;
	if (start_pfn < end_pfn) {
		nr_range = save_mr(mr, nr_range, start_pfn, end_pfn, 0);
		pos = end_pfn << PAGE_SHIFT;
	}

	/* big page (2M) range */
	start_pfn = ((pos + (PMD_SIZE - 1))>>PMD_SHIFT)
			 << (PMD_SHIFT - PAGE_SHIFT);
#ifdef CONFIG_X86_32
	end_pfn = (end>>PMD_SHIFT) << (PMD_SHIFT - PAGE_SHIFT);
#else /* CONFIG_X86_64 */
	end_pfn = ((pos + (PUD_SIZE - 1))>>PUD_SHIFT)
			 << (PUD_SHIFT - PAGE_SHIFT);
	if (end_pfn > ((end>>PMD_SHIFT)<<(PMD_SHIFT - PAGE_SHIFT)))
		end_pfn = ((end>>PMD_SHIFT)<<(PMD_SHIFT - PAGE_SHIFT));
#endif

	if (start_pfn < end_pfn) {
		nr_range = save_mr(mr, nr_range, start_pfn, end_pfn,
				page_size_mask & (1<<PG_LEVEL_2M));
		pos = end_pfn << PAGE_SHIFT;
	}

#ifdef CONFIG_X86_64
	/* big page (1G) range */
	start_pfn = ((pos + (PUD_SIZE - 1))>>PUD_SHIFT)
			 << (PUD_SHIFT - PAGE_SHIFT);
	end_pfn = (end >> PUD_SHIFT) << (PUD_SHIFT - PAGE_SHIFT);
	if (start_pfn < end_pfn) {
		nr_range = save_mr(mr, nr_range, start_pfn, end_pfn,
				page_size_mask &
				 ((1<<PG_LEVEL_2M)|(1<<PG_LEVEL_1G)));
		pos = end_pfn << PAGE_SHIFT;
	}

	/* tail is not big page (1G) alignment */
	start_pfn = ((pos + (PMD_SIZE - 1))>>PMD_SHIFT)
			 << (PMD_SHIFT - PAGE_SHIFT);
	end_pfn = (end >> PMD_SHIFT) << (PMD_SHIFT - PAGE_SHIFT);
	if (start_pfn < end_pfn) {
		nr_range = save_mr(mr, nr_range, start_pfn, end_pfn,
				page_size_mask & (1<<PG_LEVEL_2M));
		pos = end_pfn << PAGE_SHIFT;
	}
#endif

	/* tail is not big page (2M) alignment */
	start_pfn = pos>>PAGE_SHIFT;
	end_pfn = end>>PAGE_SHIFT;
	nr_range = save_mr(mr, nr_range, start_pfn, end_pfn, 0);

	/* try to merge same page size and continuous */
	for (i = 0; nr_range > 1 && i < nr_range - 1; i++) {
		unsigned long old_start;
		if (mr[i].end != mr[i+1].start ||
		    mr[i].page_size_mask != mr[i+1].page_size_mask)
			continue;
		/* move it */
		old_start = mr[i].start;
		memmove(&mr[i], &mr[i+1],
			(nr_range - 1 - i) * sizeof(struct map_range));
		mr[i--].start = old_start;
		nr_range--;
	}

	for (i = 0; i < nr_range; i++)
		printk(KERN_DEBUG " [mem %#010lx-%#010lx] page %s\n",
				mr[i].start, mr[i].end - 1,
			(mr[i].page_size_mask & (1<<PG_LEVEL_1G))?"1G":(
			 (mr[i].page_size_mask & (1<<PG_LEVEL_2M))?"2M":"4k"));

	/*
	 * Find space for the kernel direct mapping tables.
	 *
	 * Later we should allocate these tables in the local node of the
	 * memory mapped. Unfortunately this is done currently before the
	 * nodes are discovered.
	 */
	if (!after_bootmem)
		find_early_table_space(&mr[0], end, use_pse, use_gbpages);

	for (i = 0; i < nr_range; i++)
		ret = kernel_physical_mapping_init(mr[i].start, mr[i].end,
						   mr[i].page_size_mask);

#ifdef CONFIG_X86_32
	early_ioremap_page_table_range_init();

	load_cr3(swapper_pg_dir);
#endif

	__flush_tlb_all();

	/*
	 * Reserve the kernel pagetable pages we used (pgt_buf_start -
	 * pgt_buf_end) and free the other ones (pgt_buf_end - pgt_buf_top)
	 * so that they can be reused for other purposes.
	 *
	 * On native it just means calling memblock_reserve, on Xen it also
	 * means marking RW the pagetable pages that we allocated before
	 * but that haven't been used.
	 *
	 * In fact on xen we mark RO the whole range pgt_buf_start -
	 * pgt_buf_top, because we have to make sure that when
	 * init_memory_mapping reaches the pagetable pages area, it maps
	 * RO all the pagetable pages, including the ones that are beyond
	 * pgt_buf_end at that time.
	 */
	if (!after_bootmem && pgt_buf_end > pgt_buf_start)
		x86_init.mapping.pagetable_reserve(PFN_PHYS(pgt_buf_start),
				PFN_PHYS(pgt_buf_end));

	if (!after_bootmem)
		early_memtest(start, end);

	return ret >> PAGE_SHIFT;
}


/*
 * devmem_is_allowed() checks to see if /dev/mem access to a certain address
 * is valid. The argument is a physical page number.
 *
 *
 * On x86, access has to be given to the first megabyte of ram because that area
 * contains bios code and data regions used by X and dosemu and similar apps.
 * Access has to be given to non-kernel-ram areas as well, these contain the PCI
 * mmio resources as well as potential bios/acpi data regions.
 */

#ifdef CONFIG_GRKERNSEC_KMEM
static unsigned int ebda_start __read_only;
static unsigned int ebda_end __read_only;
#endif

int devmem_is_allowed(unsigned long pagenr)
{
#ifdef CONFIG_GRKERNSEC_KMEM
	/* allow BDA */
	if (!pagenr)
		return 1;
	/* allow EBDA */
	if (pagenr >= ebda_start && pagenr < ebda_end)
		return 1;
#else
	if (!pagenr)
		return 1;
#ifdef CONFIG_VM86
	if (pagenr < (ISA_START_ADDRESS >> PAGE_SHIFT))
		return 1;
#endif
#endif

	if ((ISA_START_ADDRESS >> PAGE_SHIFT) <= pagenr && pagenr < (ISA_END_ADDRESS >> PAGE_SHIFT))
		return 1;
#ifdef CONFIG_GRKERNSEC_KMEM
	/* throw out everything else below 1MB */
	if (pagenr <= 256)
		return 0;
#endif
	if (iomem_is_exclusive(pagenr << PAGE_SHIFT))
		return 0;
	if (!page_is_ram(pagenr))
		return 1;
	return 0;
}

void free_init_pages(char *what, unsigned long begin, unsigned long end)
{
	unsigned long addr;
	unsigned long begin_aligned, end_aligned;

	/* Make sure boundaries are page aligned */
	begin_aligned = PAGE_ALIGN(begin);
	end_aligned   = end & PAGE_MASK;

	if (WARN_ON(begin_aligned != begin || end_aligned != end)) {
		begin = begin_aligned;
		end   = end_aligned;
	}

	if (begin >= end)
		return;

	addr = begin;

	/*
	 * If debugging page accesses then do not free this memory but
	 * mark them not present - any buggy init-section access will
	 * create a kernel page fault:
	 */
#ifdef CONFIG_DEBUG_PAGEALLOC
	printk(KERN_INFO "debug: unmapping init [mem %#010lx-%#010lx]\n",
		begin, end - 1);
	set_memory_np(begin, (end - begin) >> PAGE_SHIFT);
#else
	/*
	 * We just marked the kernel text read only above, now that
	 * we are going to free part of that, we need to make that
	 * writeable and non-executable first.
	 */
	set_memory_nx(begin, (end - begin) >> PAGE_SHIFT);
	set_memory_rw(begin, (end - begin) >> PAGE_SHIFT);

	printk(KERN_INFO "Freeing %s: %luk freed\n", what, (end - begin) >> 10);

	for (; addr < end; addr += PAGE_SIZE) {
		ClearPageReserved(virt_to_page(addr));
		init_page_count(virt_to_page(addr));
		memset((void *)addr, POISON_FREE_INITMEM, PAGE_SIZE);
		free_page(addr);
		totalram_pages++;
	}
#endif
}

#ifdef CONFIG_GRKERNSEC_KMEM
static inline void gr_init_ebda(void)
{
	unsigned int ebda_addr;
	unsigned int ebda_size = 0;

	ebda_addr = get_bios_ebda();
	if (ebda_addr) {
		ebda_size = *(unsigned char *)phys_to_virt(ebda_addr);
		ebda_size <<= 10;
	}
	if (ebda_addr && ebda_size) {
		ebda_start = ebda_addr >> PAGE_SHIFT;
		ebda_end = min((unsigned int)PAGE_ALIGN(ebda_addr + ebda_size), (unsigned int)0xa0000) >> PAGE_SHIFT;
	} else {
		ebda_start = 0x9f000 >> PAGE_SHIFT;
		ebda_end = 0xa0000 >> PAGE_SHIFT;
	}
}
#else
static inline void gr_init_ebda(void) { }
#endif

void free_initmem(void)
{
#ifdef CONFIG_PAX_KERNEXEC
#ifdef CONFIG_X86_32
	/* PaX: limit KERNEL_CS to actual size */
	unsigned long addr, limit;
	struct desc_struct d;
	int cpu;
#else
	pgd_t *pgd;
	pud_t *pud;
	pmd_t *pmd;
	unsigned long addr, end;
#endif
#endif

	gr_init_ebda();

#ifdef CONFIG_PAX_KERNEXEC
#ifdef CONFIG_X86_32
	limit = paravirt_enabled() ? ktva_ktla(0xffffffff) : (unsigned long)&_etext;
	limit = (limit - 1UL) >> PAGE_SHIFT;

	memset(__LOAD_PHYSICAL_ADDR + PAGE_OFFSET, POISON_FREE_INITMEM, PAGE_SIZE);
	for (cpu = 0; cpu < nr_cpu_ids; cpu++) {
		pack_descriptor(&d, get_desc_base(&get_cpu_gdt_table(cpu)[GDT_ENTRY_KERNEL_CS]), limit, 0x9B, 0xC);
		write_gdt_entry(get_cpu_gdt_table(cpu), GDT_ENTRY_KERNEL_CS, &d, DESCTYPE_S);
	}

	/* PaX: make KERNEL_CS read-only */
	addr = PFN_ALIGN(ktla_ktva((unsigned long)&_text));
	if (!paravirt_enabled())
		set_memory_ro(addr, (PFN_ALIGN(_sdata) - addr) >> PAGE_SHIFT);
/*
		for (addr = ktla_ktva((unsigned long)&_text); addr < (unsigned long)&_sdata; addr += PMD_SIZE) {
			pgd = pgd_offset_k(addr);
			pud = pud_offset(pgd, addr);
			pmd = pmd_offset(pud, addr);
			set_pmd(pmd, __pmd(pmd_val(*pmd) & ~_PAGE_RW));
		}
*/
#ifdef CONFIG_X86_PAE
	set_memory_nx(PFN_ALIGN(__init_begin), (PFN_ALIGN(__init_end) - PFN_ALIGN(__init_begin)) >> PAGE_SHIFT);
/*
	for (addr = (unsigned long)&__init_begin; addr < (unsigned long)&__init_end; addr += PMD_SIZE) {
		pgd = pgd_offset_k(addr);
		pud = pud_offset(pgd, addr);
		pmd = pmd_offset(pud, addr);
		set_pmd(pmd, __pmd(pmd_val(*pmd) | (_PAGE_NX & __supported_pte_mask)));
	}
*/
#endif

#ifdef CONFIG_MODULES
	set_memory_4k((unsigned long)MODULES_EXEC_VADDR, (MODULES_EXEC_END - MODULES_EXEC_VADDR) >> PAGE_SHIFT);
#endif

#else
	/* PaX: make kernel code/rodata read-only, rest non-executable */
	for (addr = __START_KERNEL_map; addr < __START_KERNEL_map + KERNEL_IMAGE_SIZE; addr += PMD_SIZE) {
		pgd = pgd_offset_k(addr);
		pud = pud_offset(pgd, addr);
		pmd = pmd_offset(pud, addr);
		if (!pmd_present(*pmd))
			continue;
		if ((unsigned long)_text <= addr && addr < (unsigned long)_sdata)
			set_pmd(pmd, __pmd(pmd_val(*pmd) & ~_PAGE_RW));
		else
			set_pmd(pmd, __pmd(pmd_val(*pmd) | (_PAGE_NX & __supported_pte_mask)));
	}

	addr = (unsigned long)__va(__pa(__START_KERNEL_map));
	end = addr + KERNEL_IMAGE_SIZE;
	for (; addr < end; addr += PMD_SIZE) {
		pgd = pgd_offset_k(addr);
		pud = pud_offset(pgd, addr);
		pmd = pmd_offset(pud, addr);
		if (!pmd_present(*pmd))
			continue;
		if ((unsigned long)__va(__pa(_text)) <= addr && addr < (unsigned long)__va(__pa(_sdata)))
			set_pmd(pmd, __pmd(pmd_val(*pmd) & ~_PAGE_RW));
	}
#endif

	flush_tlb_all();
#endif

	free_init_pages("unused kernel memory",
			(unsigned long)(&__init_begin),
			(unsigned long)(&__init_end));
}

#ifdef CONFIG_BLK_DEV_INITRD
void free_initrd_mem(unsigned long start, unsigned long end)
{
	/*
	 * end could be not aligned, and We can not align that,
	 * decompresser could be confused by aligned initrd_end
	 * We already reserve the end partial page before in
	 *   - i386_start_kernel()
	 *   - x86_64_start_kernel()
	 *   - relocate_initrd()
	 * So here We can do PAGE_ALIGN() safely to get partial page to be freed
	 */
	free_init_pages("initrd memory", start, PAGE_ALIGN(end));
}
#endif

void __init zone_sizes_init(void)
{
	unsigned long max_zone_pfns[MAX_NR_ZONES];

	memset(max_zone_pfns, 0, sizeof(max_zone_pfns));

#ifdef CONFIG_ZONE_DMA
	max_zone_pfns[ZONE_DMA]		= MAX_DMA_PFN;
#endif
#ifdef CONFIG_ZONE_DMA32
	max_zone_pfns[ZONE_DMA32]	= MAX_DMA32_PFN;
#endif
	max_zone_pfns[ZONE_NORMAL]	= max_low_pfn;
#ifdef CONFIG_HIGHMEM
	max_zone_pfns[ZONE_HIGHMEM]	= max_pfn;
#endif

	free_area_init_nodes(max_zone_pfns);
}

