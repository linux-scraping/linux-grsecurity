/*  Kernel module help for i386.
    Copyright (C) 2001 Rusty Russell.

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
*/
#include <linux/moduleloader.h>
#include <linux/elf.h>
#include <linux/vmalloc.h>
#include <linux/fs.h>
#include <linux/string.h>
#include <linux/kernel.h>
#include <linux/bug.h>

#include <asm/desc.h>
#include <asm/pgtable.h>

#if 0
#define DEBUGP printk
#else
#define DEBUGP(fmt...)
#endif

void *module_alloc(unsigned long size)
{
	if (size == 0)
		return NULL;

#ifdef CONFIG_PAX_KERNEXEC
	return __vmalloc(size, GFP_KERNEL | __GFP_HIGHMEM | __GFP_ZERO, PAGE_KERNEL);
#else
	return vmalloc_exec(size);
#endif

}

#ifdef CONFIG_PAX_KERNEXEC
void *module_alloc_exec(unsigned long size)
{
	struct vm_struct *area;

	if (size == 0)
		return NULL;

	area = __get_vm_area(size, VM_ALLOC, (unsigned long)&MODULES_VADDR, (unsigned long)&MODULES_END);
	if (area)
		return area->addr;

	return NULL;
}
EXPORT_SYMBOL(module_alloc_exec);
#endif

/* Free memory returned from module_alloc */
void module_free(struct module *mod, void *module_region)
{
	vfree(module_region);
	/* FIXME: If module_region == mod->init_region, trim exception
           table entries. */
}

#ifdef CONFIG_PAX_KERNEXEC
void module_free_exec(struct module *mod, void *module_region)
{
	struct vm_struct **p, *tmp;

	if (!module_region)
		return;

	if ((PAGE_SIZE-1) & (unsigned long)module_region) {
		printk(KERN_ERR "Trying to module_free_exec() bad address (%p)\n", module_region);
		WARN_ON(1);
		return;
	}

	write_lock(&vmlist_lock);
	for (p = &vmlist; (tmp = *p) != NULL; p = &tmp->next)
		 if (tmp->addr == module_region)
			break;

	if (tmp) {
		unsigned long cr0;

		pax_open_kernel(cr0);
		memset(tmp->addr, 0xCC, tmp->size);
		pax_close_kernel(cr0);

		*p = tmp->next;
		kfree(tmp);
	}
	write_unlock(&vmlist_lock);

	if (!tmp) {
		printk(KERN_ERR "Trying to module_free_exec() nonexistent vm area (%p)\n",
				module_region);
		WARN_ON(1);
	}
}
EXPORT_SYMBOL(module_free_exec);
#endif

/* We don't need anything special. */
int module_frob_arch_sections(Elf_Ehdr *hdr,
			      Elf_Shdr *sechdrs,
			      char *secstrings,
			      struct module *mod)
{
	return 0;
}

int apply_relocate(Elf32_Shdr *sechdrs,
		   const char *strtab,
		   unsigned int symindex,
		   unsigned int relsec,
		   struct module *me)
{
	unsigned int i;
	Elf32_Rel *rel = (void *)sechdrs[relsec].sh_addr;
	Elf32_Sym *sym;
	uint32_t *plocation, location;

#ifdef CONFIG_PAX_KERNEXEC
	unsigned long cr0;
#endif

	DEBUGP("Applying relocate section %u to %u\n", relsec,
	       sechdrs[relsec].sh_info);
	for (i = 0; i < sechdrs[relsec].sh_size / sizeof(*rel); i++) {
		/* This is where to make the change */
		plocation = (void *)sechdrs[sechdrs[relsec].sh_info].sh_addr + rel[i].r_offset;
		location = (uint32_t)plocation;
		if (sechdrs[sechdrs[relsec].sh_info].sh_flags & SHF_EXECINSTR)
			plocation = ktla_ktva((void *)plocation);
		/* This is the symbol it is referring to.  Note that all
		   undefined symbols have been resolved.  */
		sym = (Elf32_Sym *)sechdrs[symindex].sh_addr
			+ ELF32_R_SYM(rel[i].r_info);

		switch (ELF32_R_TYPE(rel[i].r_info)) {
		case R_386_32:

#ifdef CONFIG_PAX_KERNEXEC
			pax_open_kernel(cr0);
#endif

			/* We add the value into the location given */
			*plocation += sym->st_value;

#ifdef CONFIG_PAX_KERNEXEC
			pax_close_kernel(cr0);
#endif

			break;
		case R_386_PC32:

#ifdef CONFIG_PAX_KERNEXEC
			pax_open_kernel(cr0);
#endif

			/* Add the value, subtract its postition */
			*plocation += sym->st_value - location;

#ifdef CONFIG_PAX_KERNEXEC
			pax_close_kernel(cr0);
#endif

			break;
		default:
			printk(KERN_ERR "module %s: Unknown relocation: %u\n",
			       me->name, ELF32_R_TYPE(rel[i].r_info));
			return -ENOEXEC;
		}
	}
	return 0;
}

int apply_relocate_add(Elf32_Shdr *sechdrs,
		       const char *strtab,
		       unsigned int symindex,
		       unsigned int relsec,
		       struct module *me)
{
	printk(KERN_ERR "module %s: ADD RELOCATION unsupported\n",
	       me->name);
	return -ENOEXEC;
}

int module_finalize(const Elf_Ehdr *hdr,
		    const Elf_Shdr *sechdrs,
		    struct module *me)
{
	const Elf_Shdr *s, *text = NULL, *alt = NULL, *locks = NULL,
		*para = NULL;
	char *secstrings = (void *)hdr + sechdrs[hdr->e_shstrndx].sh_offset;

	for (s = sechdrs; s < sechdrs + hdr->e_shnum; s++) { 
		if (!strcmp(".text", secstrings + s->sh_name))
			text = s;
		if (!strcmp(".altinstructions", secstrings + s->sh_name))
			alt = s;
		if (!strcmp(".smp_locks", secstrings + s->sh_name))
			locks= s;
		if (!strcmp(".parainstructions", secstrings + s->sh_name))
			para = s;
	}

	if (alt) {
		/* patch .altinstructions */
		void *aseg = (void *)alt->sh_addr;
		apply_alternatives(aseg, aseg + alt->sh_size);
	}
	if (locks && text) {
		void *lseg = (void *)locks->sh_addr;
		void *tseg = (void *)text->sh_addr;
		alternatives_smp_module_add(me, me->name,
					    lseg, lseg + locks->sh_size,
					    tseg, tseg + text->sh_size);
	}

	if (para) {
		void *pseg = (void *)para->sh_addr;
		apply_paravirt(pseg, pseg + para->sh_size);
	}

	return module_bug_finalize(hdr, sechdrs, me);
}

void module_arch_cleanup(struct module *mod)
{
	alternatives_smp_module_del(mod);
	module_bug_cleanup(mod);
}
