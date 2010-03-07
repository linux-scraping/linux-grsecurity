/*
 * This file contains various random system calls that
 * have a non-standard calling sequence on the Linux/i386
 * platform.
 */

#include <linux/errno.h>
#include <linux/sched.h>
#include <linux/mm.h>
#include <linux/fs.h>
#include <linux/smp.h>
#include <linux/sem.h>
#include <linux/msg.h>
#include <linux/shm.h>
#include <linux/stat.h>
#include <linux/syscalls.h>
#include <linux/mman.h>
#include <linux/file.h>
#include <linux/utsname.h>
#include <linux/ipc.h>

#include <linux/uaccess.h>
#include <linux/unistd.h>

#include <asm/syscalls.h>

int i386_mmap_check(unsigned long addr, unsigned long len, unsigned long flags)
{
	unsigned long pax_task_size = TASK_SIZE;

#ifdef CONFIG_PAX_SEGMEXEC
	if (current->mm->pax_flags & MF_PAX_SEGMEXEC)
		pax_task_size = SEGMEXEC_TASK_SIZE;
#endif

	if (len > pax_task_size || addr > pax_task_size - len)
		return -EINVAL;

	return 0;
}

/*
 * Perform the select(nd, in, out, ex, tv) and mmap() system
 * calls. Linux/i386 didn't use to be able to handle more than
 * 4 system call parameters, so these system calls used a memory
 * block for parameter passing..
 */

struct mmap_arg_struct {
	unsigned long addr;
	unsigned long len;
	unsigned long prot;
	unsigned long flags;
	unsigned long fd;
	unsigned long offset;
};

asmlinkage int old_mmap(struct mmap_arg_struct __user *arg)
{
	struct mmap_arg_struct a;
	int err = -EFAULT;

	if (copy_from_user(&a, arg, sizeof(a)))
		goto out;

	err = -EINVAL;
	if (a.offset & ~PAGE_MASK)
		goto out;

	err = sys_mmap_pgoff(a.addr, a.len, a.prot, a.flags,
			a.fd, a.offset >> PAGE_SHIFT);
out:
	return err;
}

unsigned long
arch_get_unmapped_area(struct file *filp, unsigned long addr,
		unsigned long len, unsigned long pgoff, unsigned long flags)
{
	struct mm_struct *mm = current->mm;
	struct vm_area_struct *vma;
	unsigned long start_addr, pax_task_size = TASK_SIZE;

#ifdef CONFIG_PAX_SEGMEXEC
	if (mm->pax_flags & MF_PAX_SEGMEXEC)
		pax_task_size = SEGMEXEC_TASK_SIZE;
#endif

	if (len > pax_task_size)
		return -ENOMEM;

	if (flags & MAP_FIXED)
		return addr;

#ifdef CONFIG_PAX_RANDMMAP
	if (!(mm->pax_flags & MF_PAX_RANDMMAP))
#endif

	if (addr) {
		addr = PAGE_ALIGN(addr);
		vma = find_vma(mm, addr);
		if (pax_task_size - len >= addr &&
		    (!vma || addr + len <= vma->vm_start))
			return addr;
	}
	if (len > mm->cached_hole_size) {
		start_addr = addr = mm->free_area_cache;
	} else {
		start_addr = addr = mm->mmap_base;
		mm->cached_hole_size = 0;
	}

#ifdef CONFIG_PAX_PAGEEXEC
	if (!(__supported_pte_mask & _PAGE_NX) && (mm->pax_flags & MF_PAX_PAGEEXEC) && (flags & MAP_EXECUTABLE) && start_addr >= mm->mmap_base) {
		start_addr = 0x00110000UL;

#ifdef CONFIG_PAX_RANDMMAP
		if (mm->pax_flags & MF_PAX_RANDMMAP)
			start_addr += mm->delta_mmap & 0x03FFF000UL;
#endif

		if (mm->start_brk <= start_addr && start_addr < mm->mmap_base)
			start_addr = addr = mm->mmap_base;
		else
			addr = start_addr;
	}
#endif

full_search:
	for (vma = find_vma(mm, addr); ; vma = vma->vm_next) {
		/* At this point:  (!vma || addr < vma->vm_end). */
		if (pax_task_size - len < addr) {
			/*
			 * Start a new search - just in case we missed
			 * some holes.
			 */
			if (start_addr != mm->mmap_base) {
				start_addr = addr = mm->mmap_base;
				mm->cached_hole_size = 0;
				goto full_search;
			}
			return -ENOMEM;
		}
		if (!vma || addr + len <= vma->vm_start) {
			/*
			 * Remember the place where we stopped the search:
			 */
			mm->free_area_cache = addr + len;
			return addr;
		}
		if (addr + mm->cached_hole_size < vma->vm_start)
			mm->cached_hole_size = vma->vm_start - addr;
		addr = vma->vm_end;
		if (mm->start_brk <= addr && addr < mm->mmap_base) {
			start_addr = addr = mm->mmap_base;
			mm->cached_hole_size = 0;
			goto full_search;
		}
	}
}

unsigned long
arch_get_unmapped_area_topdown(struct file *filp, const unsigned long addr0,
			  const unsigned long len, const unsigned long pgoff,
			  const unsigned long flags)
{
	struct vm_area_struct *vma;
	struct mm_struct *mm = current->mm;
	unsigned long base = mm->mmap_base, addr = addr0, pax_task_size = TASK_SIZE;

#ifdef CONFIG_PAX_SEGMEXEC
	if (mm->pax_flags & MF_PAX_SEGMEXEC)
		pax_task_size = SEGMEXEC_TASK_SIZE;
#endif

	/* requested length too big for entire address space */
	if (len > pax_task_size)
		return -ENOMEM;

	if (flags & MAP_FIXED)
		return addr;

#ifdef CONFIG_PAX_PAGEEXEC
	if (!(__supported_pte_mask & _PAGE_NX) && (mm->pax_flags & MF_PAX_PAGEEXEC) && (flags & MAP_EXECUTABLE))
		goto bottomup;
#endif

#ifdef CONFIG_PAX_RANDMMAP
	if (!(mm->pax_flags & MF_PAX_RANDMMAP))
#endif

	/* requesting a specific address */
	if (addr) {
		addr = PAGE_ALIGN(addr);
		vma = find_vma(mm, addr);
		if (pax_task_size - len >= addr &&
				(!vma || addr + len <= vma->vm_start))
			return addr;
	}

	/* check if free_area_cache is useful for us */
	if (len <= mm->cached_hole_size) {
		mm->cached_hole_size = 0;
		mm->free_area_cache = mm->mmap_base;
	}

	/* either no address requested or can't fit in requested address hole */
	addr = mm->free_area_cache;

	/* make sure it can fit in the remaining address space */
	if (addr > len) {
		vma = find_vma(mm, addr-len);
		if (!vma || addr <= vma->vm_start)
			/* remember the address as a hint for next time */
			return (mm->free_area_cache = addr-len);
	}

	if (mm->mmap_base < len)
		goto bottomup;

	addr = mm->mmap_base-len;

	do {
		/*
		 * Lookup failure means no vma is above this address,
		 * else if new region fits below vma->vm_start,
		 * return with success:
		 */
		vma = find_vma(mm, addr);
		if (!vma || addr+len <= vma->vm_start)
			/* remember the address as a hint for next time */
			return (mm->free_area_cache = addr);

		/* remember the largest hole we saw so far */
		if (addr + mm->cached_hole_size < vma->vm_start)
			mm->cached_hole_size = vma->vm_start - addr;

		/* try just below the current vma->vm_start */
		addr = vma->vm_start-len;
	} while (len < vma->vm_start);

bottomup:
	/*
	 * A failed mmap() very likely causes application failure,
	 * so fall back to the bottom-up function here. This scenario
	 * can happen with large stack limits and large mmap()
	 * allocations.
	 */

#ifdef CONFIG_PAX_SEGMEXEC
	if (mm->pax_flags & MF_PAX_SEGMEXEC)
		mm->mmap_base = SEGMEXEC_TASK_UNMAPPED_BASE;
	else
#endif

	mm->mmap_base = TASK_UNMAPPED_BASE;

#ifdef CONFIG_PAX_RANDMMAP
	if (mm->pax_flags & MF_PAX_RANDMMAP)
		mm->mmap_base += mm->delta_mmap;
#endif

	mm->free_area_cache = mm->mmap_base;
	mm->cached_hole_size = ~0UL;
	addr = arch_get_unmapped_area(filp, addr0, len, pgoff, flags);
	/*
	 * Restore the topdown base:
	 */
	mm->mmap_base = base;
	mm->free_area_cache = base;
	mm->cached_hole_size = ~0UL;

	return addr;
}

struct sel_arg_struct {
	unsigned long n;
	fd_set __user *inp, *outp, *exp;
	struct timeval __user *tvp;
};

asmlinkage int old_select(struct sel_arg_struct __user *arg)
{
	struct sel_arg_struct a;

	if (copy_from_user(&a, arg, sizeof(a)))
		return -EFAULT;
	/* sys_select() does the appropriate kernel locking */
	return sys_select(a.n, a.inp, a.outp, a.exp, a.tvp);
}

/*
 * sys_ipc() is the de-multiplexer for the SysV IPC calls..
 *
 * This is really horribly ugly.
 */
asmlinkage int sys_ipc(uint call, int first, int second,
			int third, void __user *ptr, long fifth)
{
	int version, ret;

	version = call >> 16; /* hack for backward compatibility */
	call &= 0xffff;

	switch (call) {
	case SEMOP:
		return sys_semtimedop(first, (struct sembuf __user *)ptr, second, NULL);
	case SEMTIMEDOP:
		return sys_semtimedop(first, (struct sembuf __user *)ptr, second,
					(__force const struct timespec __user *)fifth);

	case SEMGET:
		return sys_semget(first, second, third);
	case SEMCTL: {
		union semun fourth;
		if (!ptr)
			return -EINVAL;
		if (get_user(fourth.__pad, (void __user * __user *) ptr))
			return -EFAULT;
		return sys_semctl(first, second, third, fourth);
	}

	case MSGSND:
		return sys_msgsnd(first, (struct msgbuf __user *) ptr,
				   second, third);
	case MSGRCV:
		switch (version) {
		case 0: {
			struct ipc_kludge tmp;
			if (!ptr)
				return -EINVAL;

			if (copy_from_user(&tmp,
					   (struct ipc_kludge __user *) ptr,
					   sizeof(tmp)))
				return -EFAULT;
			return sys_msgrcv(first, tmp.msgp, second,
					   tmp.msgtyp, third);
		}
		default:
			return sys_msgrcv(first,
					   (struct msgbuf __user *) ptr,
					   second, fifth, third);
		}
	case MSGGET:
		return sys_msgget((key_t) first, second);
	case MSGCTL:
		return sys_msgctl(first, second, (struct msqid_ds __user *) ptr);

	case SHMAT:
		switch (version) {
		default: {
			ulong raddr;
			ret = do_shmat(first, (char __user *) ptr, second, &raddr);
			if (ret)
				return ret;
			return put_user(raddr, (__force ulong __user *) third);
		}
		case 1:	/* iBCS2 emulator entry point */
			if (!segment_eq(get_fs(), get_ds()))
				return -EINVAL;
			/* The "(ulong *) third" is valid _only_ because of the kernel segment thing */
			return do_shmat(first, (char __user *) ptr, second, (ulong *) third);
		}
	case SHMDT:
		return sys_shmdt((char __user *)ptr);
	case SHMGET:
		return sys_shmget(first, second, third);
	case SHMCTL:
		return sys_shmctl(first, second,
				   (struct shmid_ds __user *) ptr);
	default:
		return -ENOSYS;
	}
}

/*
 * Old cruft
 */
asmlinkage int sys_uname(struct old_utsname __user *name)
{
	int err;
	if (!name)
		return -EFAULT;
	down_read(&uts_sem);
	err = copy_to_user(name, utsname(), sizeof(*name));
	up_read(&uts_sem);
	return err? -EFAULT:0;
}

asmlinkage int sys_olduname(struct oldold_utsname __user *name)
{
	int error;

	if (!name)
		return -EFAULT;
	if (!access_ok(VERIFY_WRITE, name, sizeof(struct oldold_utsname)))
		return -EFAULT;

	down_read(&uts_sem);

	error = __copy_to_user(&name->sysname, &utsname()->sysname,
			       __OLD_UTS_LEN);
	error |= __put_user(0, name->sysname + __OLD_UTS_LEN);
	error |= __copy_to_user(&name->nodename, &utsname()->nodename,
				__OLD_UTS_LEN);
	error |= __put_user(0, name->nodename + __OLD_UTS_LEN);
	error |= __copy_to_user(&name->release, &utsname()->release,
				__OLD_UTS_LEN);
	error |= __put_user(0, name->release + __OLD_UTS_LEN);
	error |= __copy_to_user(&name->version, &utsname()->version,
				__OLD_UTS_LEN);
	error |= __put_user(0, name->version + __OLD_UTS_LEN);
	error |= __copy_to_user(&name->machine, &utsname()->machine,
				__OLD_UTS_LEN);
	error |= __put_user(0, name->machine + __OLD_UTS_LEN);

	up_read(&uts_sem);

	error = error ? -EFAULT : 0;

	return error;
}


/*
 * Do a system call from kernel instead of calling sys_execve so we
 * end up with proper pt_regs.
 */
int kernel_execve(const char *filename, char *const argv[], char *const envp[])
{
	long __res;
	asm volatile ("push %%ebx ; movl %2,%%ebx ; int $0x80 ; pop %%ebx"
	: "=a" (__res)
	: "0" (__NR_execve), "ri" (filename), "c" (argv), "d" (envp) : "memory");
	return __res;
}
