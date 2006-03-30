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
#include <asm/desc.h>

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
	return vmalloc(size);
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

	area = __get_vm_area(size, 0, (unsigned long)&MODULES_VADDR, (unsigned long)&MODULES_END);
	if (area)
		return area->addr;

	return NULL;
}
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
	for (p = &vmlist ; (tmp = *p) != NULL ;p = &tmp->next)
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

	DEBUGP("Applying relocate section %u to %u\n", relsec,
	       sechdrs[relsec].sh_info);
	for (i = 0; i < sechdrs[relsec].sh_size / sizeof(*rel); i++) {
		/* This is where to make the change */
		plocation = (void *)sechdrs[sechdrs[relsec].sh_info].sh_addr + rel[i].r_offset;
		location = (uint32_t)plocation;
		if (sechdrs[sechdrs[relsec].sh_info].sh_flags & SHF_EXECINSTR)
			plocation = (void *)plocation + __KERNEL_TEXT_OFFSET;
		/* This is the symbol it is referring to.  Note that all
		   undefined symbols have been resolved.  */
		sym = (Elf32_Sym *)sechdrs[symindex].sh_addr
			+ ELF32_R_SYM(rel[i].r_info);

		switch (ELF32_R_TYPE(rel[i].r_info)) {
		case R_386_32:
			/* We add the value into the location given */
			*plocation += sym->st_value;
			break;
		case R_386_PC32:
			/* Add the value, subtract its postition */
			*plocation += sym->st_value - location;
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

extern void apply_alternatives(void *start, void *end); 

int module_finalize(const Elf_Ehdr *hdr,
		    const Elf_Shdr *sechdrs,
		    struct module *me)
{
	const Elf_Shdr *s;
	char *secstrings = (void *)hdr + sechdrs[hdr->e_shstrndx].sh_offset;

	/* look for .altinstructions to patch */ 
	for (s = sechdrs; s < sechdrs + hdr->e_shnum; s++) { 
		void *seg; 		
		if (strcmp(".altinstructions", secstrings + s->sh_name))
			continue;
		seg = (void *)s->sh_addr; 
		apply_alternatives(seg, seg + s->sh_size); 
	} 	
	return 0;
}

void module_arch_cleanup(struct module *mod)
{
}
