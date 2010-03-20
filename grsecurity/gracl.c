#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/sched.h>
#include <linux/mm.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/namei.h>
#include <linux/mount.h>
#include <linux/tty.h>
#include <linux/proc_fs.h>
#include <linux/smp_lock.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>
#include <linux/types.h>
#include <linux/sysctl.h>
#include <linux/netdevice.h>
#include <linux/ptrace.h>
#include <linux/gracl.h>
#include <linux/gralloc.h>
#include <linux/grsecurity.h>
#include <linux/grinternal.h>
#include <linux/pid_namespace.h>
#include <linux/fdtable.h>
#include <linux/percpu.h>

#include <asm/uaccess.h>
#include <asm/errno.h>
#include <asm/mman.h>

static struct acl_role_db acl_role_set;
static struct name_db name_set;
static struct inodev_db inodev_set;

/* for keeping track of userspace pointers used for subjects, so we
   can share references in the kernel as well
*/

static struct dentry *real_root;
static struct vfsmount *real_root_mnt;

static struct acl_subj_map_db subj_map_set;

static struct acl_role_label *default_role;

static struct acl_role_label *role_list;

static u16 acl_sp_role_value;

extern char *gr_shared_page[4];
static DECLARE_MUTEX(gr_dev_sem);
DEFINE_RWLOCK(gr_inode_lock);

struct gr_arg *gr_usermode;

static unsigned int gr_status __read_only = GR_STATUS_INIT;

extern int chkpw(struct gr_arg *entry, unsigned char *salt, unsigned char *sum);
extern void gr_clear_learn_entries(void);

#ifdef CONFIG_GRKERNSEC_RESLOG
extern void gr_log_resource(const struct task_struct *task,
			    const int res, const unsigned long wanted, const int gt);
#endif

unsigned char *gr_system_salt;
unsigned char *gr_system_sum;

static struct sprole_pw **acl_special_roles = NULL;
static __u16 num_sprole_pws = 0;

static struct acl_role_label *kernel_role = NULL;

static unsigned int gr_auth_attempts = 0;
static unsigned long gr_auth_expires = 0UL;

extern struct vfsmount *sock_mnt;
extern struct vfsmount *pipe_mnt;
extern struct vfsmount *shm_mnt;
static struct acl_object_label *fakefs_obj;

extern int gr_init_uidset(void);
extern void gr_free_uidset(void);
extern void gr_remove_uid(uid_t uid);
extern int gr_find_uid(uid_t uid);

__inline__ int
gr_acl_is_enabled(void)
{
	return (gr_status & GR_READY);
}

char gr_roletype_to_char(void)
{
	switch (current->role->roletype &
		(GR_ROLE_DEFAULT | GR_ROLE_USER | GR_ROLE_GROUP |
		 GR_ROLE_SPECIAL)) {
	case GR_ROLE_DEFAULT:
		return 'D';
	case GR_ROLE_USER:
		return 'U';
	case GR_ROLE_GROUP:
		return 'G';
	case GR_ROLE_SPECIAL:
		return 'S';
	}

	return 'X';
}

__inline__ int
gr_acl_tpe_check(void)
{
	if (unlikely(!(gr_status & GR_READY)))
		return 0;
	if (current->role->roletype & GR_ROLE_TPE)
		return 1;
	else
		return 0;
}

int
gr_handle_rawio(const struct inode *inode)
{
#ifdef CONFIG_GRKERNSEC_CHROOT_CAPS
	if (inode && S_ISBLK(inode->i_mode) &&
	    grsec_enable_chroot_caps && proc_is_chrooted(current) &&
	    !capable(CAP_SYS_RAWIO))
		return 1;
#endif
	return 0;
}

static int
gr_streq(const char *a, const char *b, const unsigned int lena, const unsigned int lenb)
{
	int i;
	unsigned long *l1;
	unsigned long *l2;
	unsigned char *c1;
	unsigned char *c2;
	int num_longs;

	if (likely(lena != lenb))
		return 0;

	l1 = (unsigned long *)a;
	l2 = (unsigned long *)b;

	num_longs = lena / sizeof(unsigned long);

	for (i = num_longs; i--; l1++, l2++) {
		if (unlikely(*l1 != *l2))
			return 0;
	}

	c1 = (unsigned char *) l1;
	c2 = (unsigned char *) l2;

	i = lena - (num_longs * sizeof(unsigned long));	

	for (; i--; c1++, c2++) {
		if (unlikely(*c1 != *c2))
			return 0;
	}

	return 1;
}

static char * __our_d_path(struct dentry *dentry, struct vfsmount *vfsmnt,
	                   struct dentry *root, struct vfsmount *rootmnt,
			   char *buffer, int buflen)
{
	char * end = buffer+buflen;
	char * retval;
	int namelen;

	*--end = '\0';
	buflen--;

	if (buflen < 1)
		goto Elong;
	/* Get '/' right */
	retval = end-1;
	*retval = '/';

	for (;;) {
		struct dentry * parent;

		if (dentry == root && vfsmnt == rootmnt)
			break;
		if (dentry == vfsmnt->mnt_root || IS_ROOT(dentry)) {
			/* Global root? */
			spin_lock(&vfsmount_lock);
			if (vfsmnt->mnt_parent == vfsmnt) {
				spin_unlock(&vfsmount_lock);
				goto global_root;
			}
			dentry = vfsmnt->mnt_mountpoint;
			vfsmnt = vfsmnt->mnt_parent;
			spin_unlock(&vfsmount_lock);
			continue;
		}
		parent = dentry->d_parent;
		prefetch(parent);
		namelen = dentry->d_name.len;
		buflen -= namelen + 1;
		if (buflen < 0)
			goto Elong;
		end -= namelen;
		memcpy(end, dentry->d_name.name, namelen);
		*--end = '/';
		retval = end;
		dentry = parent;
	}

	return retval;

global_root:
	namelen = dentry->d_name.len;
	buflen -= namelen;
	if (buflen < 0)
		goto Elong;
	retval -= namelen-1;	/* hit the slash */
	memcpy(retval, dentry->d_name.name, namelen);
	return retval;
Elong:
	return ERR_PTR(-ENAMETOOLONG);
}

static char *
gen_full_path(struct dentry *dentry, struct vfsmount *vfsmnt,
              struct dentry *root, struct vfsmount *rootmnt, char *buf, int buflen)
{
	char *retval;

	retval = __our_d_path(dentry, vfsmnt, root, rootmnt, buf, buflen);
	if (unlikely(IS_ERR(retval)))
		retval = strcpy(buf, "<path too long>");
	else if (unlikely(retval[1] == '/' && retval[2] == '\0'))
		retval[1] = '\0';

	return retval;
}

static char *
__d_real_path(const struct dentry *dentry, const struct vfsmount *vfsmnt,
		char *buf, int buflen)
{
	char *res;

	/* we can use real_root, real_root_mnt, because this is only called
	   by the RBAC system */
	res = gen_full_path((struct dentry *)dentry, (struct vfsmount *)vfsmnt, real_root, real_root_mnt, buf, buflen);

	return res;
}

static char *
d_real_path(const struct dentry *dentry, const struct vfsmount *vfsmnt,
	    char *buf, int buflen)
{
	char *res;
	struct dentry *root;
	struct vfsmount *rootmnt;
	struct task_struct *reaper = &init_task;

	/* we can't use real_root, real_root_mnt, because they belong only to the RBAC system */
	read_lock(&reaper->fs->lock);
	root = dget(reaper->fs->root.dentry);
	rootmnt = mntget(reaper->fs->root.mnt);
	read_unlock(&reaper->fs->lock);

	spin_lock(&dcache_lock);
	res = gen_full_path((struct dentry *)dentry, (struct vfsmount *)vfsmnt, root, rootmnt, buf, buflen);
	spin_unlock(&dcache_lock);

	dput(root);
	mntput(rootmnt);
	return res;
}

static char *
gr_to_filename_rbac(const struct dentry *dentry, const struct vfsmount *mnt)
{
	char *ret;
	spin_lock(&dcache_lock);
	ret = __d_real_path(dentry, mnt, per_cpu_ptr(gr_shared_page[0],smp_processor_id()),
			     PAGE_SIZE);
	spin_unlock(&dcache_lock);
	return ret;
}

char *
gr_to_filename_nolock(const struct dentry *dentry, const struct vfsmount *mnt)
{
	return __d_real_path(dentry, mnt, per_cpu_ptr(gr_shared_page[0],smp_processor_id()),
			     PAGE_SIZE);
}

char *
gr_to_filename(const struct dentry *dentry, const struct vfsmount *mnt)
{
	return d_real_path(dentry, mnt, per_cpu_ptr(gr_shared_page[0], smp_processor_id()),
			   PAGE_SIZE);
}

char *
gr_to_filename1(const struct dentry *dentry, const struct vfsmount *mnt)
{
	return d_real_path(dentry, mnt, per_cpu_ptr(gr_shared_page[1], smp_processor_id()),
			   PAGE_SIZE);
}

char *
gr_to_filename2(const struct dentry *dentry, const struct vfsmount *mnt)
{
	return d_real_path(dentry, mnt, per_cpu_ptr(gr_shared_page[2], smp_processor_id()),
			   PAGE_SIZE);
}

char *
gr_to_filename3(const struct dentry *dentry, const struct vfsmount *mnt)
{
	return d_real_path(dentry, mnt, per_cpu_ptr(gr_shared_page[3], smp_processor_id()),
			   PAGE_SIZE);
}

__inline__ __u32
to_gr_audit(const __u32 reqmode)
{
	/* masks off auditable permission flags, then shifts them to create
	   auditing flags, and adds the special case of append auditing if
	   we're requesting write */
	return (((reqmode & ~GR_AUDITS) << 10) | ((reqmode & GR_WRITE) ? GR_AUDIT_APPEND : 0));
}

struct acl_subject_label *
lookup_subject_map(const struct acl_subject_label *userp)
{
	unsigned int index = shash(userp, subj_map_set.s_size);
	struct subject_map *match;

	match = subj_map_set.s_hash[index];

	while (match && match->user != userp)
		match = match->next;

	if (match != NULL)
		return match->kernel;
	else
		return NULL;
}

static void
insert_subj_map_entry(struct subject_map *subjmap)
{
	unsigned int index = shash(subjmap->user, subj_map_set.s_size);
	struct subject_map **curr;

	subjmap->prev = NULL;

	curr = &subj_map_set.s_hash[index];
	if (*curr != NULL)
		(*curr)->prev = subjmap;

	subjmap->next = *curr;
	*curr = subjmap;

	return;
}

static struct acl_role_label *
lookup_acl_role_label(const struct task_struct *task, const uid_t uid,
		      const gid_t gid)
{
	unsigned int index = rhash(uid, GR_ROLE_USER, acl_role_set.r_size);
	struct acl_role_label *match;
	struct role_allowed_ip *ipp;
	unsigned int x;

	match = acl_role_set.r_hash[index];

	while (match) {
		if ((match->roletype & (GR_ROLE_DOMAIN | GR_ROLE_USER)) == (GR_ROLE_DOMAIN | GR_ROLE_USER)) {
			for (x = 0; x < match->domain_child_num; x++) {
				if (match->domain_children[x] == uid)
					goto found;
			}
		} else if (match->uidgid == uid && match->roletype & GR_ROLE_USER)
			break;
		match = match->next;
	}
found:
	if (match == NULL) {
	      try_group:
		index = rhash(gid, GR_ROLE_GROUP, acl_role_set.r_size);
		match = acl_role_set.r_hash[index];

		while (match) {
			if ((match->roletype & (GR_ROLE_DOMAIN | GR_ROLE_GROUP)) == (GR_ROLE_DOMAIN | GR_ROLE_GROUP)) {
				for (x = 0; x < match->domain_child_num; x++) {
					if (match->domain_children[x] == gid)
						goto found2;
				}
			} else if (match->uidgid == gid && match->roletype & GR_ROLE_GROUP)
				break;
			match = match->next;
		}
found2:
		if (match == NULL)
			match = default_role;
		if (match->allowed_ips == NULL)
			return match;
		else {
			for (ipp = match->allowed_ips; ipp; ipp = ipp->next) {
				if (likely
				    ((ntohl(task->signal->curr_ip) & ipp->netmask) ==
				     (ntohl(ipp->addr) & ipp->netmask)))
					return match;
			}
			match = default_role;
		}
	} else if (match->allowed_ips == NULL) {
		return match;
	} else {
		for (ipp = match->allowed_ips; ipp; ipp = ipp->next) {
			if (likely
			    ((ntohl(task->signal->curr_ip) & ipp->netmask) ==
			     (ntohl(ipp->addr) & ipp->netmask)))
				return match;
		}
		goto try_group;
	}

	return match;
}

struct acl_subject_label *
lookup_acl_subj_label(const ino_t ino, const dev_t dev,
		      const struct acl_role_label *role)
{
	unsigned int index = fhash(ino, dev, role->subj_hash_size);
	struct acl_subject_label *match;

	match = role->subj_hash[index];

	while (match && (match->inode != ino || match->device != dev ||
	       (match->mode & GR_DELETED))) {
		match = match->next;
	}

	if (match && !(match->mode & GR_DELETED))
		return match;
	else
		return NULL;
}

struct acl_subject_label *
lookup_acl_subj_label_deleted(const ino_t ino, const dev_t dev,
			  const struct acl_role_label *role)
{
	unsigned int index = fhash(ino, dev, role->subj_hash_size);
	struct acl_subject_label *match;

	match = role->subj_hash[index];

	while (match && (match->inode != ino || match->device != dev ||
	       !(match->mode & GR_DELETED))) {
		match = match->next;
	}

	if (match && (match->mode & GR_DELETED))
		return match;
	else
		return NULL;
}

static struct acl_object_label *
lookup_acl_obj_label(const ino_t ino, const dev_t dev,
		     const struct acl_subject_label *subj)
{
	unsigned int index = fhash(ino, dev, subj->obj_hash_size);
	struct acl_object_label *match;

	match = subj->obj_hash[index];

	while (match && (match->inode != ino || match->device != dev ||
	       (match->mode & GR_DELETED))) {
		match = match->next;
	}

	if (match && !(match->mode & GR_DELETED))
		return match;
	else
		return NULL;
}

static struct acl_object_label *
lookup_acl_obj_label_create(const ino_t ino, const dev_t dev,
		     const struct acl_subject_label *subj)
{
	unsigned int index = fhash(ino, dev, subj->obj_hash_size);
	struct acl_object_label *match;

	match = subj->obj_hash[index];

	while (match && (match->inode != ino || match->device != dev ||
	       !(match->mode & GR_DELETED))) {
		match = match->next;
	}

	if (match && (match->mode & GR_DELETED))
		return match;

	match = subj->obj_hash[index];

	while (match && (match->inode != ino || match->device != dev ||
	       (match->mode & GR_DELETED))) {
		match = match->next;
	}

	if (match && !(match->mode & GR_DELETED))
		return match;
	else
		return NULL;
}

static struct name_entry *
lookup_name_entry(const char *name)
{
	unsigned int len = strlen(name);
	unsigned int key = full_name_hash(name, len);
	unsigned int index = key % name_set.n_size;
	struct name_entry *match;

	match = name_set.n_hash[index];

	while (match && (match->key != key || !gr_streq(match->name, name, match->len, len)))
		match = match->next;

	return match;
}

static struct name_entry *
lookup_name_entry_create(const char *name)
{
	unsigned int len = strlen(name);
	unsigned int key = full_name_hash(name, len);
	unsigned int index = key % name_set.n_size;
	struct name_entry *match;

	match = name_set.n_hash[index];

	while (match && (match->key != key || !gr_streq(match->name, name, match->len, len) ||
			 !match->deleted))
		match = match->next;

	if (match && match->deleted)
		return match;

	match = name_set.n_hash[index];

	while (match && (match->key != key || !gr_streq(match->name, name, match->len, len) ||
			 match->deleted))
		match = match->next;

	if (match && !match->deleted)
		return match;
	else
		return NULL;
}

static struct inodev_entry *
lookup_inodev_entry(const ino_t ino, const dev_t dev)
{
	unsigned int index = fhash(ino, dev, inodev_set.i_size);
	struct inodev_entry *match;

	match = inodev_set.i_hash[index];

	while (match && (match->nentry->inode != ino || match->nentry->device != dev))
		match = match->next;

	return match;
}

static void
insert_inodev_entry(struct inodev_entry *entry)
{
	unsigned int index = fhash(entry->nentry->inode, entry->nentry->device,
				    inodev_set.i_size);
	struct inodev_entry **curr;

	entry->prev = NULL;

	curr = &inodev_set.i_hash[index];
	if (*curr != NULL)
		(*curr)->prev = entry;
	
	entry->next = *curr;
	*curr = entry;

	return;
}

static void
__insert_acl_role_label(struct acl_role_label *role, uid_t uidgid)
{
	unsigned int index =
	    rhash(uidgid, role->roletype & (GR_ROLE_USER | GR_ROLE_GROUP), acl_role_set.r_size);
	struct acl_role_label **curr;
	struct acl_role_label *tmp;

	curr = &acl_role_set.r_hash[index];

	/* if role was already inserted due to domains and already has
	   a role in the same bucket as it attached, then we need to
	   combine these two buckets
	*/
	if (role->next) {
		tmp = role->next;
		while (tmp->next)
			tmp = tmp->next;
		tmp->next = *curr;
	} else
		role->next = *curr;
	*curr = role;

	return;
}

static void
insert_acl_role_label(struct acl_role_label *role)
{
	int i;

	if (role_list == NULL) {
		role_list = role;
		role->prev = NULL;
	} else {
		role->prev = role_list;
		role_list = role;
	}
	
	/* used for hash chains */
	role->next = NULL;

	if (role->roletype & GR_ROLE_DOMAIN) {
		for (i = 0; i < role->domain_child_num; i++)
			__insert_acl_role_label(role, role->domain_children[i]);
	} else
		__insert_acl_role_label(role, role->uidgid);
}
					
static int
insert_name_entry(char *name, const ino_t inode, const dev_t device, __u8 deleted)
{
	struct name_entry **curr, *nentry;
	struct inodev_entry *ientry;
	unsigned int len = strlen(name);
	unsigned int key = full_name_hash(name, len);
	unsigned int index = key % name_set.n_size;

	curr = &name_set.n_hash[index];

	while (*curr && ((*curr)->key != key || !gr_streq((*curr)->name, name, (*curr)->len, len)))
		curr = &((*curr)->next);

	if (*curr != NULL)
		return 1;

	nentry = acl_alloc(sizeof (struct name_entry));
	if (nentry == NULL)
		return 0;
	ientry = acl_alloc(sizeof (struct inodev_entry));
	if (ientry == NULL)
		return 0;
	ientry->nentry = nentry;

	nentry->key = key;
	nentry->name = name;
	nentry->inode = inode;
	nentry->device = device;
	nentry->len = len;
	nentry->deleted = deleted;

	nentry->prev = NULL;
	curr = &name_set.n_hash[index];
	if (*curr != NULL)
		(*curr)->prev = nentry;
	nentry->next = *curr;
	*curr = nentry;

	/* insert us into the table searchable by inode/dev */
	insert_inodev_entry(ientry);

	return 1;
}

static void
insert_acl_obj_label(struct acl_object_label *obj,
		     struct acl_subject_label *subj)
{
	unsigned int index =
	    fhash(obj->inode, obj->device, subj->obj_hash_size);
	struct acl_object_label **curr;

	
	obj->prev = NULL;

	curr = &subj->obj_hash[index];
	if (*curr != NULL)
		(*curr)->prev = obj;

	obj->next = *curr;
	*curr = obj;

	return;
}

static void
insert_acl_subj_label(struct acl_subject_label *obj,
		      struct acl_role_label *role)
{
	unsigned int index = fhash(obj->inode, obj->device, role->subj_hash_size);
	struct acl_subject_label **curr;

	obj->prev = NULL;

	curr = &role->subj_hash[index];
	if (*curr != NULL)
		(*curr)->prev = obj;

	obj->next = *curr;
	*curr = obj;

	return;
}

/* allocating chained hash tables, so optimal size is where lambda ~ 1 */

static void *
create_table(__u32 * len, int elementsize)
{
	unsigned int table_sizes[] = {
		7, 13, 31, 61, 127, 251, 509, 1021, 2039, 4093, 8191, 16381,
		32749, 65521, 131071, 262139, 524287, 1048573, 2097143,
		4194301, 8388593, 16777213, 33554393, 67108859
	};
	void *newtable = NULL;
	unsigned int pwr = 0;

	while ((pwr < ((sizeof (table_sizes) / sizeof (table_sizes[0])) - 1)) &&
	       table_sizes[pwr] <= *len)
		pwr++;

	if (table_sizes[pwr] <= *len || (table_sizes[pwr] > ULONG_MAX / elementsize))
		return newtable;

	if ((table_sizes[pwr] * elementsize) <= PAGE_SIZE)
		newtable =
		    kmalloc(table_sizes[pwr] * elementsize, GFP_KERNEL);
	else
		newtable = vmalloc(table_sizes[pwr] * elementsize);

	*len = table_sizes[pwr];

	return newtable;
}

static int
init_variables(const struct gr_arg *arg)
{
	struct task_struct *reaper = &init_task;
	unsigned int stacksize;

	subj_map_set.s_size = arg->role_db.num_subjects;
	acl_role_set.r_size = arg->role_db.num_roles + arg->role_db.num_domain_children;
	name_set.n_size = arg->role_db.num_objects;
	inodev_set.i_size = arg->role_db.num_objects;

	if (!subj_map_set.s_size || !acl_role_set.r_size ||
	    !name_set.n_size || !inodev_set.i_size)
		return 1;

	if (!gr_init_uidset())
		return 1;

	/* set up the stack that holds allocation info */

	stacksize = arg->role_db.num_pointers + 5;

	if (!acl_alloc_stack_init(stacksize))
		return 1;

	/* grab reference for the real root dentry and vfsmount */
	read_lock(&reaper->fs->lock);
	real_root_mnt = mntget(reaper->fs->root.mnt);
	real_root = dget(reaper->fs->root.dentry);
	read_unlock(&reaper->fs->lock);
	
	fakefs_obj = acl_alloc(sizeof(struct acl_object_label));
	if (fakefs_obj == NULL)
		return 1;
	fakefs_obj->mode = GR_FIND | GR_READ | GR_WRITE | GR_EXEC;

	subj_map_set.s_hash =
	    (struct subject_map **) create_table(&subj_map_set.s_size, sizeof(void *));
	acl_role_set.r_hash =
	    (struct acl_role_label **) create_table(&acl_role_set.r_size, sizeof(void *));
	name_set.n_hash = (struct name_entry **) create_table(&name_set.n_size, sizeof(void *));
	inodev_set.i_hash =
	    (struct inodev_entry **) create_table(&inodev_set.i_size, sizeof(void *));

	if (!subj_map_set.s_hash || !acl_role_set.r_hash ||
	    !name_set.n_hash || !inodev_set.i_hash)
		return 1;

	memset(subj_map_set.s_hash, 0,
	       sizeof(struct subject_map *) * subj_map_set.s_size);
	memset(acl_role_set.r_hash, 0,
	       sizeof (struct acl_role_label *) * acl_role_set.r_size);
	memset(name_set.n_hash, 0,
	       sizeof (struct name_entry *) * name_set.n_size);
	memset(inodev_set.i_hash, 0,
	       sizeof (struct inodev_entry *) * inodev_set.i_size);

	return 0;
}

/* free information not needed after startup
   currently contains user->kernel pointer mappings for subjects
*/

static void
free_init_variables(void)
{
	__u32 i;

	if (subj_map_set.s_hash) {
		for (i = 0; i < subj_map_set.s_size; i++) {
			if (subj_map_set.s_hash[i]) {
				kfree(subj_map_set.s_hash[i]);
				subj_map_set.s_hash[i] = NULL;
			}
		}

		if ((subj_map_set.s_size * sizeof (struct subject_map *)) <=
		    PAGE_SIZE)
			kfree(subj_map_set.s_hash);
		else
			vfree(subj_map_set.s_hash);
	}

	return;
}

static void
free_variables(void)
{
	struct acl_subject_label *s;
	struct acl_role_label *r;
	struct task_struct *task, *task2;
	unsigned int x;

	gr_clear_learn_entries();

	read_lock(&tasklist_lock);
	do_each_thread(task2, task) {
		task->acl_sp_role = 0;
		task->acl_role_id = 0;
		task->acl = NULL;
		task->role = NULL;
	} while_each_thread(task2, task);
	read_unlock(&tasklist_lock);

	/* release the reference to the real root dentry and vfsmount */
	if (real_root)
		dput(real_root);
	real_root = NULL;
	if (real_root_mnt)
		mntput(real_root_mnt);
	real_root_mnt = NULL;

	/* free all object hash tables */

	FOR_EACH_ROLE_START(r)
		if (r->subj_hash == NULL)
			goto next_role;
		FOR_EACH_SUBJECT_START(r, s, x)
			if (s->obj_hash == NULL)
				break;
			if ((s->obj_hash_size * sizeof (struct acl_object_label *)) <= PAGE_SIZE)
				kfree(s->obj_hash);
			else
				vfree(s->obj_hash);
		FOR_EACH_SUBJECT_END(s, x)
		FOR_EACH_NESTED_SUBJECT_START(r, s)
			if (s->obj_hash == NULL)
				break;
			if ((s->obj_hash_size * sizeof (struct acl_object_label *)) <= PAGE_SIZE)
				kfree(s->obj_hash);
			else
				vfree(s->obj_hash);
		FOR_EACH_NESTED_SUBJECT_END(s)
		if ((r->subj_hash_size * sizeof (struct acl_subject_label *)) <= PAGE_SIZE)
			kfree(r->subj_hash);
		else
			vfree(r->subj_hash);
		r->subj_hash = NULL;
next_role:
	FOR_EACH_ROLE_END(r)

	acl_free_all();

	if (acl_role_set.r_hash) {
		if ((acl_role_set.r_size * sizeof (struct acl_role_label *)) <=
		    PAGE_SIZE)
			kfree(acl_role_set.r_hash);
		else
			vfree(acl_role_set.r_hash);
	}
	if (name_set.n_hash) {
		if ((name_set.n_size * sizeof (struct name_entry *)) <=
		    PAGE_SIZE)
			kfree(name_set.n_hash);
		else
			vfree(name_set.n_hash);
	}

	if (inodev_set.i_hash) {
		if ((inodev_set.i_size * sizeof (struct inodev_entry *)) <=
		    PAGE_SIZE)
			kfree(inodev_set.i_hash);
		else
			vfree(inodev_set.i_hash);
	}

	gr_free_uidset();

	memset(&name_set, 0, sizeof (struct name_db));
	memset(&inodev_set, 0, sizeof (struct inodev_db));
	memset(&acl_role_set, 0, sizeof (struct acl_role_db));
	memset(&subj_map_set, 0, sizeof (struct acl_subj_map_db));

	default_role = NULL;
	role_list = NULL;

	return;
}

static __u32
count_user_objs(struct acl_object_label *userp)
{
	struct acl_object_label o_tmp;
	__u32 num = 0;

	while (userp) {
		if (copy_from_user(&o_tmp, userp,
				   sizeof (struct acl_object_label)))
			break;

		userp = o_tmp.prev;
		num++;
	}

	return num;
}

static struct acl_subject_label *
do_copy_user_subj(struct acl_subject_label *userp, struct acl_role_label *role);

static int
copy_user_glob(struct acl_object_label *obj)
{
	struct acl_object_label *g_tmp, **guser;
	unsigned int len;
	char *tmp;

	if (obj->globbed == NULL)
		return 0;

	guser = &obj->globbed;
	while (*guser) {
		g_tmp = (struct acl_object_label *)
			acl_alloc(sizeof (struct acl_object_label));
		if (g_tmp == NULL)
			return -ENOMEM;

		if (copy_from_user(g_tmp, *guser,
				   sizeof (struct acl_object_label)))
			return -EFAULT;

		len = strnlen_user(g_tmp->filename, PATH_MAX);

		if (!len || len >= PATH_MAX)
			return -EINVAL;

		if ((tmp = (char *) acl_alloc(len)) == NULL)
			return -ENOMEM;

		if (copy_from_user(tmp, g_tmp->filename, len))
			return -EFAULT;
		tmp[len-1] = '\0';
		g_tmp->filename = tmp;

		*guser = g_tmp;
		guser = &(g_tmp->next);
	}

	return 0;
}

static int
copy_user_objs(struct acl_object_label *userp, struct acl_subject_label *subj,
	       struct acl_role_label *role)
{
	struct acl_object_label *o_tmp;
	unsigned int len;
	int ret;
	char *tmp;

	while (userp) {
		if ((o_tmp = (struct acl_object_label *)
		     acl_alloc(sizeof (struct acl_object_label))) == NULL)
			return -ENOMEM;

		if (copy_from_user(o_tmp, userp,
				   sizeof (struct acl_object_label)))
			return -EFAULT;

		userp = o_tmp->prev;

		len = strnlen_user(o_tmp->filename, PATH_MAX);

		if (!len || len >= PATH_MAX)
			return -EINVAL;

		if ((tmp = (char *) acl_alloc(len)) == NULL)
			return -ENOMEM;

		if (copy_from_user(tmp, o_tmp->filename, len))
			return -EFAULT;
		tmp[len-1] = '\0';
		o_tmp->filename = tmp;

		insert_acl_obj_label(o_tmp, subj);
		if (!insert_name_entry(o_tmp->filename, o_tmp->inode,
				       o_tmp->device, (o_tmp->mode & GR_DELETED) ? 1 : 0))
			return -ENOMEM;

		ret = copy_user_glob(o_tmp);
		if (ret)
			return ret;

		if (o_tmp->nested) {
			o_tmp->nested = do_copy_user_subj(o_tmp->nested, role);
			if (IS_ERR(o_tmp->nested))
				return PTR_ERR(o_tmp->nested);

			/* insert into nested subject list */
			o_tmp->nested->next = role->hash->first;
			role->hash->first = o_tmp->nested;
		}
	}

	return 0;
}

static __u32
count_user_subjs(struct acl_subject_label *userp)
{
	struct acl_subject_label s_tmp;
	__u32 num = 0;

	while (userp) {
		if (copy_from_user(&s_tmp, userp,
				   sizeof (struct acl_subject_label)))
			break;

		userp = s_tmp.prev;
		/* do not count nested subjects against this count, since
		   they are not included in the hash table, but are
		   attached to objects.  We have already counted
		   the subjects in userspace for the allocation 
		   stack
		*/
		if (!(s_tmp.mode & GR_NESTED))
			num++;
	}

	return num;
}

static int
copy_user_allowedips(struct acl_role_label *rolep)
{
	struct role_allowed_ip *ruserip, *rtmp = NULL, *rlast;

	ruserip = rolep->allowed_ips;

	while (ruserip) {
		rlast = rtmp;

		if ((rtmp = (struct role_allowed_ip *)
		     acl_alloc(sizeof (struct role_allowed_ip))) == NULL)
			return -ENOMEM;

		if (copy_from_user(rtmp, ruserip,
				   sizeof (struct role_allowed_ip)))
			return -EFAULT;

		ruserip = rtmp->prev;

		if (!rlast) {
			rtmp->prev = NULL;
			rolep->allowed_ips = rtmp;
		} else {
			rlast->next = rtmp;
			rtmp->prev = rlast;
		}

		if (!ruserip)
			rtmp->next = NULL;
	}

	return 0;
}

static int
copy_user_transitions(struct acl_role_label *rolep)
{
	struct role_transition *rusertp, *rtmp = NULL, *rlast;
	
	unsigned int len;
	char *tmp;

	rusertp = rolep->transitions;

	while (rusertp) {
		rlast = rtmp;

		if ((rtmp = (struct role_transition *)
		     acl_alloc(sizeof (struct role_transition))) == NULL)
			return -ENOMEM;

		if (copy_from_user(rtmp, rusertp,
				   sizeof (struct role_transition)))
			return -EFAULT;

		rusertp = rtmp->prev;

		len = strnlen_user(rtmp->rolename, GR_SPROLE_LEN);

		if (!len || len >= GR_SPROLE_LEN)
			return -EINVAL;

		if ((tmp = (char *) acl_alloc(len)) == NULL)
			return -ENOMEM;

		if (copy_from_user(tmp, rtmp->rolename, len))
			return -EFAULT;
		tmp[len-1] = '\0';
		rtmp->rolename = tmp;

		if (!rlast) {
			rtmp->prev = NULL;
			rolep->transitions = rtmp;
		} else {
			rlast->next = rtmp;
			rtmp->prev = rlast;
		}

		if (!rusertp)
			rtmp->next = NULL;
	}

	return 0;
}

static struct acl_subject_label *
do_copy_user_subj(struct acl_subject_label *userp, struct acl_role_label *role)
{
	struct acl_subject_label *s_tmp = NULL, *s_tmp2;
	unsigned int len;
	char *tmp;
	__u32 num_objs;
	struct acl_ip_label **i_tmp, *i_utmp2;
	struct gr_hash_struct ghash;
	struct subject_map *subjmap;
	unsigned int i_num;
	int err;

	s_tmp = lookup_subject_map(userp);

	/* we've already copied this subject into the kernel, just return
	   the reference to it, and don't copy it over again
	*/
	if (s_tmp)
		return(s_tmp);

	if ((s_tmp = (struct acl_subject_label *)
	    acl_alloc(sizeof (struct acl_subject_label))) == NULL)
		return ERR_PTR(-ENOMEM);

	subjmap = (struct subject_map *)kmalloc(sizeof (struct subject_map), GFP_KERNEL);
	if (subjmap == NULL)
		return ERR_PTR(-ENOMEM);

	subjmap->user = userp;
	subjmap->kernel = s_tmp;
	insert_subj_map_entry(subjmap);

	if (copy_from_user(s_tmp, userp,
			   sizeof (struct acl_subject_label)))
		return ERR_PTR(-EFAULT);

	len = strnlen_user(s_tmp->filename, PATH_MAX);

	if (!len || len >= PATH_MAX)
		return ERR_PTR(-EINVAL);

	if ((tmp = (char *) acl_alloc(len)) == NULL)
		return ERR_PTR(-ENOMEM);

	if (copy_from_user(tmp, s_tmp->filename, len))
		return ERR_PTR(-EFAULT);
	tmp[len-1] = '\0';
	s_tmp->filename = tmp;

	if (!strcmp(s_tmp->filename, "/"))
		role->root_label = s_tmp;

	if (copy_from_user(&ghash, s_tmp->hash, sizeof(struct gr_hash_struct)))
		return ERR_PTR(-EFAULT);

	/* copy user and group transition tables */

	if (s_tmp->user_trans_num) {
		uid_t *uidlist;

		uidlist = (uid_t *)acl_alloc_num(s_tmp->user_trans_num, sizeof(uid_t));
		if (uidlist == NULL)
			return ERR_PTR(-ENOMEM);
		if (copy_from_user(uidlist, s_tmp->user_transitions, s_tmp->user_trans_num * sizeof(uid_t)))
			return ERR_PTR(-EFAULT);

		s_tmp->user_transitions = uidlist;
	}

	if (s_tmp->group_trans_num) {
		gid_t *gidlist;

		gidlist = (gid_t *)acl_alloc_num(s_tmp->group_trans_num, sizeof(gid_t));
		if (gidlist == NULL)
			return ERR_PTR(-ENOMEM);
		if (copy_from_user(gidlist, s_tmp->group_transitions, s_tmp->group_trans_num * sizeof(gid_t)))
			return ERR_PTR(-EFAULT);

		s_tmp->group_transitions = gidlist;
	}

	/* set up object hash table */
	num_objs = count_user_objs(ghash.first);

	s_tmp->obj_hash_size = num_objs;
	s_tmp->obj_hash =
	    (struct acl_object_label **)
	    create_table(&(s_tmp->obj_hash_size), sizeof(void *));

	if (!s_tmp->obj_hash)
		return ERR_PTR(-ENOMEM);

	memset(s_tmp->obj_hash, 0,
	       s_tmp->obj_hash_size *
	       sizeof (struct acl_object_label *));

	/* add in objects */
	err = copy_user_objs(ghash.first, s_tmp, role);

	if (err)
		return ERR_PTR(err);

	/* set pointer for parent subject */
	if (s_tmp->parent_subject) {
		s_tmp2 = do_copy_user_subj(s_tmp->parent_subject, role);

		if (IS_ERR(s_tmp2))
			return s_tmp2;

		s_tmp->parent_subject = s_tmp2;
	}

	/* add in ip acls */

	if (!s_tmp->ip_num) {
		s_tmp->ips = NULL;
		goto insert;
	}

	i_tmp =
	    (struct acl_ip_label **) acl_alloc_num(s_tmp->ip_num,
					       sizeof (struct acl_ip_label *));

	if (!i_tmp)
		return ERR_PTR(-ENOMEM);

	for (i_num = 0; i_num < s_tmp->ip_num; i_num++) {
		*(i_tmp + i_num) =
		    (struct acl_ip_label *)
		    acl_alloc(sizeof (struct acl_ip_label));
		if (!*(i_tmp + i_num))
			return ERR_PTR(-ENOMEM);

		if (copy_from_user
		    (&i_utmp2, s_tmp->ips + i_num,
		     sizeof (struct acl_ip_label *)))
			return ERR_PTR(-EFAULT);

		if (copy_from_user
		    (*(i_tmp + i_num), i_utmp2,
		     sizeof (struct acl_ip_label)))
			return ERR_PTR(-EFAULT);
		
		if ((*(i_tmp + i_num))->iface == NULL)
			continue;

		len = strnlen_user((*(i_tmp + i_num))->iface, IFNAMSIZ);
		if (!len || len >= IFNAMSIZ)
			return ERR_PTR(-EINVAL);
		tmp = acl_alloc(len);
		if (tmp == NULL)
			return ERR_PTR(-ENOMEM);
		if (copy_from_user(tmp, (*(i_tmp + i_num))->iface, len))
			return ERR_PTR(-EFAULT);
		(*(i_tmp + i_num))->iface = tmp;
	}

	s_tmp->ips = i_tmp;

insert:
	if (!insert_name_entry(s_tmp->filename, s_tmp->inode,
			       s_tmp->device, (s_tmp->mode & GR_DELETED) ? 1 : 0))
		return ERR_PTR(-ENOMEM);

	return s_tmp;
}

static int
copy_user_subjs(struct acl_subject_label *userp, struct acl_role_label *role)
{
	struct acl_subject_label s_pre;
	struct acl_subject_label * ret;
	int err;

	while (userp) {
		if (copy_from_user(&s_pre, userp,
				   sizeof (struct acl_subject_label)))
			return -EFAULT;
		
		/* do not add nested subjects here, add
		   while parsing objects
		*/

		if (s_pre.mode & GR_NESTED) {
			userp = s_pre.prev;
			continue;
		}

		ret = do_copy_user_subj(userp, role);

		err = PTR_ERR(ret);
		if (IS_ERR(ret))
			return err;

		insert_acl_subj_label(ret, role);

		userp = s_pre.prev;
	}

	return 0;
}

static int
copy_user_acl(struct gr_arg *arg)
{
	struct acl_role_label *r_tmp = NULL, **r_utmp, *r_utmp2;
	struct sprole_pw *sptmp;
	struct gr_hash_struct *ghash;
	uid_t *domainlist;
	unsigned int r_num;
	unsigned int len;
	char *tmp;
	int err = 0;
	__u16 i;
	__u32 num_subjs;

	/* we need a default and kernel role */
	if (arg->role_db.num_roles < 2)
		return -EINVAL;

	/* copy special role authentication info from userspace */

	num_sprole_pws = arg->num_sprole_pws;
	acl_special_roles = (struct sprole_pw **) acl_alloc_num(num_sprole_pws, sizeof(struct sprole_pw *));

	if (!acl_special_roles) {
		err = -ENOMEM;
		goto cleanup;
	}

	for (i = 0; i < num_sprole_pws; i++) {
		sptmp = (struct sprole_pw *) acl_alloc(sizeof(struct sprole_pw));
		if (!sptmp) {
			err = -ENOMEM;
			goto cleanup;
		}
		if (copy_from_user(sptmp, arg->sprole_pws + i,
				   sizeof (struct sprole_pw))) {
			err = -EFAULT;
			goto cleanup;
		}

		len =
		    strnlen_user(sptmp->rolename, GR_SPROLE_LEN);

		if (!len || len >= GR_SPROLE_LEN) {
			err = -EINVAL;
			goto cleanup;
		}

		if ((tmp = (char *) acl_alloc(len)) == NULL) {
			err = -ENOMEM;
			goto cleanup;
		}

		if (copy_from_user(tmp, sptmp->rolename, len)) {
			err = -EFAULT;
			goto cleanup;
		}
		tmp[len-1] = '\0';
#ifdef CONFIG_GRKERNSEC_ACL_DEBUG
		printk(KERN_ALERT "Copying special role %s\n", tmp);
#endif
		sptmp->rolename = tmp;
		acl_special_roles[i] = sptmp;
	}

	r_utmp = (struct acl_role_label **) arg->role_db.r_table;

	for (r_num = 0; r_num < arg->role_db.num_roles; r_num++) {
		r_tmp = acl_alloc(sizeof (struct acl_role_label));

		if (!r_tmp) {
			err = -ENOMEM;
			goto cleanup;
		}

		if (copy_from_user(&r_utmp2, r_utmp + r_num,
				   sizeof (struct acl_role_label *))) {
			err = -EFAULT;
			goto cleanup;
		}

		if (copy_from_user(r_tmp, r_utmp2,
				   sizeof (struct acl_role_label))) {
			err = -EFAULT;
			goto cleanup;
		}

		len = strnlen_user(r_tmp->rolename, GR_SPROLE_LEN);

		if (!len || len >= PATH_MAX) {
			err = -EINVAL;
			goto cleanup;
		}

		if ((tmp = (char *) acl_alloc(len)) == NULL) {
			err = -ENOMEM;
			goto cleanup;
		}
		if (copy_from_user(tmp, r_tmp->rolename, len)) {
			err = -EFAULT;
			goto cleanup;
		}
		tmp[len-1] = '\0';
		r_tmp->rolename = tmp;

		if (!strcmp(r_tmp->rolename, "default")
		    && (r_tmp->roletype & GR_ROLE_DEFAULT)) {
			default_role = r_tmp;
		} else if (!strcmp(r_tmp->rolename, ":::kernel:::")) {
			kernel_role = r_tmp;
		}

		if ((ghash = (struct gr_hash_struct *) acl_alloc(sizeof(struct gr_hash_struct))) == NULL) {
			err = -ENOMEM;
			goto cleanup;
		}
		if (copy_from_user(ghash, r_tmp->hash, sizeof(struct gr_hash_struct))) {
			err = -EFAULT;
			goto cleanup;
		}

		r_tmp->hash = ghash;

		num_subjs = count_user_subjs(r_tmp->hash->first);

		r_tmp->subj_hash_size = num_subjs;
		r_tmp->subj_hash =
		    (struct acl_subject_label **)
		    create_table(&(r_tmp->subj_hash_size), sizeof(void *));

		if (!r_tmp->subj_hash) {
			err = -ENOMEM;
			goto cleanup;
		}

		err = copy_user_allowedips(r_tmp);
		if (err)
			goto cleanup;

		/* copy domain info */
		if (r_tmp->domain_children != NULL) {
			domainlist = acl_alloc_num(r_tmp->domain_child_num, sizeof(uid_t));
			if (domainlist == NULL) {
				err = -ENOMEM;
				goto cleanup;
			}
			if (copy_from_user(domainlist, r_tmp->domain_children, r_tmp->domain_child_num * sizeof(uid_t))) {
				err = -EFAULT;
				goto cleanup;
			}
			r_tmp->domain_children = domainlist;
		}

		err = copy_user_transitions(r_tmp);
		if (err)
			goto cleanup;

		memset(r_tmp->subj_hash, 0,
		       r_tmp->subj_hash_size *
		       sizeof (struct acl_subject_label *));

		err = copy_user_subjs(r_tmp->hash->first, r_tmp);

		if (err)
			goto cleanup;

		/* set nested subject list to null */
		r_tmp->hash->first = NULL;

		insert_acl_role_label(r_tmp);
	}

	goto return_err;
      cleanup:
	free_variables();
      return_err:
	return err;

}

static int
gracl_init(struct gr_arg *args)
{
	int error = 0;

	memcpy(gr_system_salt, args->salt, GR_SALT_LEN);
	memcpy(gr_system_sum, args->sum, GR_SHA_LEN);

	if (init_variables(args)) {
		gr_log_str(GR_DONT_AUDIT_GOOD, GR_INITF_ACL_MSG, GR_VERSION);
		error = -ENOMEM;
		free_variables();
		goto out;
	}

	error = copy_user_acl(args);
	free_init_variables();
	if (error) {
		free_variables();
		goto out;
	}

	if ((error = gr_set_acls(0))) {
		free_variables();
		goto out;
	}

	pax_open_kernel();
	gr_status |= GR_READY;
	pax_close_kernel();

      out:
	return error;
}

/* derived from glibc fnmatch() 0: match, 1: no match*/

static int
glob_match(const char *p, const char *n)
{
	char c;

	while ((c = *p++) != '\0') {
	switch (c) {
		case '?':
			if (*n == '\0')
				return 1;
			else if (*n == '/')
				return 1;
			break;
		case '\\':
			if (*n != c)
				return 1;
			break;
		case '*':
			for (c = *p++; c == '?' || c == '*'; c = *p++) {
				if (*n == '/')
					return 1;
				else if (c == '?') {
					if (*n == '\0')
						return 1;
					else
						++n;
				}
			}
			if (c == '\0') {
				return 0;
			} else {
				const char *endp;

				if ((endp = strchr(n, '/')) == NULL)
					endp = n + strlen(n);

				if (c == '[') {
					for (--p; n < endp; ++n)
						if (!glob_match(p, n))
							return 0;
				} else if (c == '/') {
					while (*n != '\0' && *n != '/')
						++n;
					if (*n == '/' && !glob_match(p, n + 1))
						return 0;
				} else {
					for (--p; n < endp; ++n)
						if (*n == c && !glob_match(p, n))
							return 0;
				}

				return 1;
			}
		case '[':
			{
			int not;
			char cold;

			if (*n == '\0' || *n == '/')
				return 1;

			not = (*p == '!' || *p == '^');
			if (not)
				++p;

			c = *p++;
			for (;;) {
				unsigned char fn = (unsigned char)*n;

				if (c == '\0')
					return 1;
				else {
					if (c == fn)
						goto matched;
					cold = c;
					c = *p++;

					if (c == '-' && *p != ']') {
						unsigned char cend = *p++;

						if (cend == '\0')
							return 1;

						if (cold <= fn && fn <= cend)
							goto matched;

						c = *p++;
					}
				}

				if (c == ']')
					break;
			}
			if (!not)
				return 1;
			break;
		matched:
			while (c != ']') {
				if (c == '\0')
					return 1;

				c = *p++;
			}
			if (not)
				return 1;
		}
		break;
	default:
		if (c != *n)
			return 1;
	}

	++n;
	}

	if (*n == '\0')
		return 0;

	if (*n == '/')
		return 0;

	return 1;
}

static struct acl_object_label *
chk_glob_label(struct acl_object_label *globbed,
	struct dentry *dentry, struct vfsmount *mnt, char **path)
{
	struct acl_object_label *tmp;

	if (*path == NULL)
		*path = gr_to_filename_nolock(dentry, mnt);

	tmp = globbed;

	while (tmp) {
		if (!glob_match(tmp->filename, *path))
			return tmp;
		tmp = tmp->next;
	}

	return NULL;
}

static struct acl_object_label *
__full_lookup(const struct dentry *orig_dentry, const struct vfsmount *orig_mnt,
	    const ino_t curr_ino, const dev_t curr_dev,
	    const struct acl_subject_label *subj, char **path, const int checkglob)
{
	struct acl_subject_label *tmpsubj;
	struct acl_object_label *retval;
	struct acl_object_label *retval2;

	tmpsubj = (struct acl_subject_label *) subj;
	read_lock(&gr_inode_lock);
	do {
		retval = lookup_acl_obj_label(curr_ino, curr_dev, tmpsubj);
		if (retval) {
			if (checkglob && retval->globbed) {
				retval2 = chk_glob_label(retval->globbed, (struct dentry *)orig_dentry,
						(struct vfsmount *)orig_mnt, path);
				if (retval2)
					retval = retval2;
			}
			break;
		}
	} while ((tmpsubj = tmpsubj->parent_subject));
	read_unlock(&gr_inode_lock);

	return retval;
}

static __inline__ struct acl_object_label *
full_lookup(const struct dentry *orig_dentry, const struct vfsmount *orig_mnt,
	    const struct dentry *curr_dentry,
	    const struct acl_subject_label *subj, char **path, const int checkglob)
{
	return __full_lookup(orig_dentry, orig_mnt,
			     curr_dentry->d_inode->i_ino, 
			     curr_dentry->d_inode->i_sb->s_dev, subj, path, checkglob);
}

static struct acl_object_label *
__chk_obj_label(const struct dentry *l_dentry, const struct vfsmount *l_mnt,
	      const struct acl_subject_label *subj, char *path, const int checkglob)
{
	struct dentry *dentry = (struct dentry *) l_dentry;
	struct vfsmount *mnt = (struct vfsmount *) l_mnt;
	struct acl_object_label *retval;

	spin_lock(&dcache_lock);

	if (unlikely(mnt == shm_mnt || mnt == pipe_mnt || mnt == sock_mnt ||
		/* ignore Eric Biederman */
	    IS_PRIVATE(l_dentry->d_inode))) {
		retval = fakefs_obj;
		goto out;
	}

	for (;;) {
		if (dentry == real_root && mnt == real_root_mnt)
			break;

		if (dentry == mnt->mnt_root || IS_ROOT(dentry)) {
			if (mnt->mnt_parent == mnt)
				break;

			retval = full_lookup(l_dentry, l_mnt, dentry, subj, &path, checkglob);
			if (retval != NULL)
				goto out;

			dentry = mnt->mnt_mountpoint;
			mnt = mnt->mnt_parent;
			continue;
		}

		retval = full_lookup(l_dentry, l_mnt, dentry, subj, &path, checkglob);
		if (retval != NULL)
			goto out;

		dentry = dentry->d_parent;
	}

	retval = full_lookup(l_dentry, l_mnt, dentry, subj, &path, checkglob);

	if (retval == NULL)
		retval = full_lookup(l_dentry, l_mnt, real_root, subj, &path, checkglob);
out:
	spin_unlock(&dcache_lock);
	return retval;
}

static __inline__ struct acl_object_label *
chk_obj_label(const struct dentry *l_dentry, const struct vfsmount *l_mnt,
	      const struct acl_subject_label *subj)
{
	char *path = NULL;
	return __chk_obj_label(l_dentry, l_mnt, subj, path, 1);
}

static __inline__ struct acl_object_label *
chk_obj_label_noglob(const struct dentry *l_dentry, const struct vfsmount *l_mnt,
	      const struct acl_subject_label *subj)
{
	char *path = NULL;
	return __chk_obj_label(l_dentry, l_mnt, subj, path, 0);
}

static __inline__ struct acl_object_label *
chk_obj_create_label(const struct dentry *l_dentry, const struct vfsmount *l_mnt,
		     const struct acl_subject_label *subj, char *path)
{
	return __chk_obj_label(l_dentry, l_mnt, subj, path, 1);
}

static struct acl_subject_label *
chk_subj_label(const struct dentry *l_dentry, const struct vfsmount *l_mnt,
	       const struct acl_role_label *role)
{
	struct dentry *dentry = (struct dentry *) l_dentry;
	struct vfsmount *mnt = (struct vfsmount *) l_mnt;
	struct acl_subject_label *retval;

	spin_lock(&dcache_lock);

	for (;;) {
		if (dentry == real_root && mnt == real_root_mnt)
			break;
		if (dentry == mnt->mnt_root || IS_ROOT(dentry)) {
			if (mnt->mnt_parent == mnt)
				break;

			read_lock(&gr_inode_lock);
			retval =
				lookup_acl_subj_label(dentry->d_inode->i_ino,
						dentry->d_inode->i_sb->s_dev, role);
			read_unlock(&gr_inode_lock);
			if (retval != NULL)
				goto out;

			dentry = mnt->mnt_mountpoint;
			mnt = mnt->mnt_parent;
			continue;
		}

		read_lock(&gr_inode_lock);
		retval = lookup_acl_subj_label(dentry->d_inode->i_ino,
					  dentry->d_inode->i_sb->s_dev, role);
		read_unlock(&gr_inode_lock);
		if (retval != NULL)
			goto out;

		dentry = dentry->d_parent;
	}

	read_lock(&gr_inode_lock);
	retval = lookup_acl_subj_label(dentry->d_inode->i_ino,
				  dentry->d_inode->i_sb->s_dev, role);
	read_unlock(&gr_inode_lock);

	if (unlikely(retval == NULL)) {
		read_lock(&gr_inode_lock);
		retval = lookup_acl_subj_label(real_root->d_inode->i_ino,
					  real_root->d_inode->i_sb->s_dev, role);
		read_unlock(&gr_inode_lock);
	}
out:
	spin_unlock(&dcache_lock);

	return retval;
}

static void
gr_log_learn(const struct dentry *dentry, const struct vfsmount *mnt, const __u32 mode)
{
	struct task_struct *task = current;
	const struct cred *cred = current_cred();

	security_learn(GR_LEARN_AUDIT_MSG, task->role->rolename, task->role->roletype,
		       cred->uid, cred->gid, task->exec_file ? gr_to_filename1(task->exec_file->f_path.dentry,
		       task->exec_file->f_path.mnt) : task->acl->filename, task->acl->filename,
		       1UL, 1UL, gr_to_filename(dentry, mnt), (unsigned long) mode, &task->signal->curr_ip);

	return;
}

static void
gr_log_learn_sysctl(const char *path, const __u32 mode)
{
	struct task_struct *task = current;
	const struct cred *cred = current_cred();

	security_learn(GR_LEARN_AUDIT_MSG, task->role->rolename, task->role->roletype,
		       cred->uid, cred->gid, task->exec_file ? gr_to_filename1(task->exec_file->f_path.dentry,
		       task->exec_file->f_path.mnt) : task->acl->filename, task->acl->filename,
		       1UL, 1UL, path, (unsigned long) mode, &task->signal->curr_ip);

	return;
}

static void
gr_log_learn_id_change(const char type, const unsigned int real, 
		       const unsigned int effective, const unsigned int fs)
{
	struct task_struct *task = current;
	const struct cred *cred = current_cred();

	security_learn(GR_ID_LEARN_MSG, task->role->rolename, task->role->roletype,
		       cred->uid, cred->gid, task->exec_file ? gr_to_filename1(task->exec_file->f_path.dentry,
		       task->exec_file->f_path.mnt) : task->acl->filename, task->acl->filename,
		       type, real, effective, fs, &task->signal->curr_ip);

	return;
}

__u32
gr_check_link(const struct dentry * new_dentry,
	      const struct dentry * parent_dentry,
	      const struct vfsmount * parent_mnt,
	      const struct dentry * old_dentry, const struct vfsmount * old_mnt)
{
	struct acl_object_label *obj;
	__u32 oldmode, newmode;
	__u32 needmode;

	if (unlikely(!(gr_status & GR_READY)))
		return (GR_CREATE | GR_LINK);

	obj = chk_obj_label(old_dentry, old_mnt, current->acl);
	oldmode = obj->mode;

	if (current->acl->mode & (GR_LEARN | GR_INHERITLEARN))
		oldmode |= (GR_CREATE | GR_LINK);

	needmode = GR_CREATE | GR_AUDIT_CREATE | GR_SUPPRESS;
	if (old_dentry->d_inode->i_mode & (S_ISUID | S_ISGID))
		needmode |= GR_SETID | GR_AUDIT_SETID;

	newmode =
	    gr_check_create(new_dentry, parent_dentry, parent_mnt,
			    oldmode | needmode);

	needmode = newmode & (GR_FIND | GR_APPEND | GR_WRITE | GR_EXEC |
			      GR_SETID | GR_READ | GR_FIND | GR_DELETE |
			      GR_INHERIT | GR_AUDIT_INHERIT);

	if (old_dentry->d_inode->i_mode & (S_ISUID | S_ISGID) && !(newmode & GR_SETID))
		goto bad;

	if ((oldmode & needmode) != needmode)
		goto bad;

	needmode = oldmode & (GR_NOPTRACE | GR_PTRACERD | GR_INHERIT | GR_AUDITS);
	if ((newmode & needmode) != needmode)
		goto bad;

	if ((newmode & (GR_CREATE | GR_LINK)) == (GR_CREATE | GR_LINK))
		return newmode;
bad:
	needmode = oldmode;
	if (old_dentry->d_inode->i_mode & (S_ISUID | S_ISGID))
		needmode |= GR_SETID;
	
	if (current->acl->mode & (GR_LEARN | GR_INHERITLEARN)) {
		gr_log_learn(old_dentry, old_mnt, needmode);
		return (GR_CREATE | GR_LINK);
	} else if (newmode & GR_SUPPRESS)
		return GR_SUPPRESS;
	else
		return 0;
}

__u32
gr_search_file(const struct dentry * dentry, const __u32 mode,
	       const struct vfsmount * mnt)
{
	__u32 retval = mode;
	struct acl_subject_label *curracl;
	struct acl_object_label *currobj;

	if (unlikely(!(gr_status & GR_READY)))
		return (mode & ~GR_AUDITS);

	curracl = current->acl;

	currobj = chk_obj_label(dentry, mnt, curracl);
	retval = currobj->mode & mode;

	if (unlikely
	    ((curracl->mode & (GR_LEARN | GR_INHERITLEARN)) && !(mode & GR_NOPTRACE)
	     && (retval != (mode & ~(GR_AUDITS | GR_SUPPRESS))))) {
		__u32 new_mode = mode;

		new_mode &= ~(GR_AUDITS | GR_SUPPRESS);

		retval = new_mode;

		if (new_mode & GR_EXEC && curracl->mode & GR_INHERITLEARN)
			new_mode |= GR_INHERIT;

		if (!(mode & GR_NOLEARN))
			gr_log_learn(dentry, mnt, new_mode);
	}

	return retval;
}

__u32
gr_check_create(const struct dentry * new_dentry, const struct dentry * parent,
		const struct vfsmount * mnt, const __u32 mode)
{
	struct name_entry *match;
	struct acl_object_label *matchpo;
	struct acl_subject_label *curracl;
	char *path;
	__u32 retval;

	if (unlikely(!(gr_status & GR_READY)))
		return (mode & ~GR_AUDITS);

	preempt_disable();
	path = gr_to_filename_rbac(new_dentry, mnt);
	match = lookup_name_entry_create(path);

	if (!match)
		goto check_parent;

	curracl = current->acl;

	read_lock(&gr_inode_lock);
	matchpo = lookup_acl_obj_label_create(match->inode, match->device, curracl);
	read_unlock(&gr_inode_lock);

	if (matchpo) {
		if ((matchpo->mode & mode) !=
		    (mode & ~(GR_AUDITS | GR_SUPPRESS))
		    && curracl->mode & (GR_LEARN | GR_INHERITLEARN)) {
			__u32 new_mode = mode;

			new_mode &= ~(GR_AUDITS | GR_SUPPRESS);

			gr_log_learn(new_dentry, mnt, new_mode);

			preempt_enable();
			return new_mode;
		}
		preempt_enable();
		return (matchpo->mode & mode);
	}

      check_parent:
	curracl = current->acl;

	matchpo = chk_obj_create_label(parent, mnt, curracl, path);
	retval = matchpo->mode & mode;

	if ((retval != (mode & ~(GR_AUDITS | GR_SUPPRESS)))
	    && (curracl->mode & (GR_LEARN | GR_INHERITLEARN))) {
		__u32 new_mode = mode;

		new_mode &= ~(GR_AUDITS | GR_SUPPRESS);

		gr_log_learn(new_dentry, mnt, new_mode);
		preempt_enable();
		return new_mode;
	}

	preempt_enable();
	return retval;
}

int
gr_check_hidden_task(const struct task_struct *task)
{
	if (unlikely(!(gr_status & GR_READY)))
		return 0;

	if (!(task->acl->mode & GR_PROCFIND) && !(current->acl->mode & GR_VIEW))
		return 1;

	return 0;
}

int
gr_check_protected_task(const struct task_struct *task)
{
	if (unlikely(!(gr_status & GR_READY) || !task))
		return 0;

	if ((task->acl->mode & GR_PROTECTED) && !(current->acl->mode & GR_KILL) &&
	    task->acl != current->acl)
		return 1;

	return 0;
}

void
gr_copy_label(struct task_struct *tsk)
{
	tsk->signal->used_accept = 0;
	tsk->acl_sp_role = 0;
	tsk->acl_role_id = current->acl_role_id;
	tsk->acl = current->acl;
	tsk->role = current->role;
	tsk->signal->curr_ip = current->signal->curr_ip;
	if (current->exec_file)
		get_file(current->exec_file);
	tsk->exec_file = current->exec_file;
	tsk->is_writable = current->is_writable;
	if (unlikely(current->signal->used_accept))
		current->signal->curr_ip = 0;

	return;
}

static void
gr_set_proc_res(struct task_struct *task)
{
	struct acl_subject_label *proc;
	unsigned short i;

	proc = task->acl;

	if (proc->mode & (GR_LEARN | GR_INHERITLEARN))
		return;

	for (i = 0; i < RLIM_NLIMITS; i++) {
		if (!(proc->resmask & (1 << i)))
			continue;

		task->signal->rlim[i].rlim_cur = proc->res[i].rlim_cur;
		task->signal->rlim[i].rlim_max = proc->res[i].rlim_max;
	}

	return;
}

int
gr_check_user_change(int real, int effective, int fs)
{
	unsigned int i;
	__u16 num;
	uid_t *uidlist;
	int curuid;
	int realok = 0;
	int effectiveok = 0;
	int fsok = 0;

	if (unlikely(!(gr_status & GR_READY)))
		return 0;

	if (current->acl->mode & (GR_LEARN | GR_INHERITLEARN))
		gr_log_learn_id_change('u', real, effective, fs);

	num = current->acl->user_trans_num;
	uidlist = current->acl->user_transitions;

	if (uidlist == NULL)
		return 0;

	if (real == -1)
		realok = 1;
	if (effective == -1)
		effectiveok = 1;
	if (fs == -1)
		fsok = 1;

	if (current->acl->user_trans_type & GR_ID_ALLOW) {
		for (i = 0; i < num; i++) {
			curuid = (int)uidlist[i];
			if (real == curuid)
				realok = 1;
			if (effective == curuid)
				effectiveok = 1;
			if (fs == curuid)
				fsok = 1;
		}
	} else if (current->acl->user_trans_type & GR_ID_DENY) {
		for (i = 0; i < num; i++) {
			curuid = (int)uidlist[i];
			if (real == curuid)
				break;
			if (effective == curuid)
				break;
			if (fs == curuid)
				break;
		}
		/* not in deny list */
		if (i == num) {
			realok = 1;
			effectiveok = 1;
			fsok = 1;
		}
	}

	if (realok && effectiveok && fsok)
		return 0;
	else {
		gr_log_int(GR_DONT_AUDIT, GR_USRCHANGE_ACL_MSG, realok ? (effectiveok ? (fsok ? 0 : fs) : effective) : real);
		return 1;
	}
}

int
gr_check_group_change(int real, int effective, int fs)
{
	unsigned int i;
	__u16 num;
	gid_t *gidlist;
	int curgid;
	int realok = 0;
	int effectiveok = 0;
	int fsok = 0;

	if (unlikely(!(gr_status & GR_READY)))
		return 0;

	if (current->acl->mode & (GR_LEARN | GR_INHERITLEARN))
		gr_log_learn_id_change('g', real, effective, fs);

	num = current->acl->group_trans_num;
	gidlist = current->acl->group_transitions;

	if (gidlist == NULL)
		return 0;

	if (real == -1)
		realok = 1;
	if (effective == -1)
		effectiveok = 1;
	if (fs == -1)
		fsok = 1;

	if (current->acl->group_trans_type & GR_ID_ALLOW) {
		for (i = 0; i < num; i++) {
			curgid = (int)gidlist[i];
			if (real == curgid)
				realok = 1;
			if (effective == curgid)
				effectiveok = 1;
			if (fs == curgid)
				fsok = 1;
		}
	} else if (current->acl->group_trans_type & GR_ID_DENY) {
		for (i = 0; i < num; i++) {
			curgid = (int)gidlist[i];
			if (real == curgid)
				break;
			if (effective == curgid)
				break;
			if (fs == curgid)
				break;
		}
		/* not in deny list */
		if (i == num) {
			realok = 1;
			effectiveok = 1;
			fsok = 1;
		}
	}

	if (realok && effectiveok && fsok)
		return 0;
	else {
		gr_log_int(GR_DONT_AUDIT, GR_GRPCHANGE_ACL_MSG, realok ? (effectiveok ? (fsok ? 0 : fs) : effective) : real);
		return 1;
	}
}

void
gr_set_role_label(struct task_struct *task, const uid_t uid, const uid_t gid)
{
	struct acl_role_label *role = task->role;
	struct acl_subject_label *subj = NULL;
	struct acl_object_label *obj;
	struct file *filp;

	if (unlikely(!(gr_status & GR_READY)))
		return;

	filp = task->exec_file;

	/* kernel process, we'll give them the kernel role */
	if (unlikely(!filp)) {
		task->role = kernel_role;
		task->acl = kernel_role->root_label;
		return;
	} else if (!task->role || !(task->role->roletype & GR_ROLE_SPECIAL))
		role = lookup_acl_role_label(task, uid, gid);

	/* perform subject lookup in possibly new role
	   we can use this result below in the case where role == task->role
	*/
	subj = chk_subj_label(filp->f_path.dentry, filp->f_path.mnt, role);

	/* if we changed uid/gid, but result in the same role
	   and are using inheritance, don't lose the inherited subject
	   if current subject is other than what normal lookup
	   would result in, we arrived via inheritance, don't
	   lose subject
	*/
	if (role != task->role || (!(task->acl->mode & GR_INHERITLEARN) &&
				   (subj == task->acl)))
		task->acl = subj;

	task->role = role;

	task->is_writable = 0;

	/* ignore additional mmap checks for processes that are writable 
	   by the default ACL */
	obj = chk_obj_label(filp->f_path.dentry, filp->f_path.mnt, default_role->root_label);
	if (unlikely(obj->mode & GR_WRITE))
		task->is_writable = 1;
	obj = chk_obj_label(filp->f_path.dentry, filp->f_path.mnt, task->role->root_label);
	if (unlikely(obj->mode & GR_WRITE))
		task->is_writable = 1;

#ifdef CONFIG_GRKERNSEC_ACL_DEBUG
	printk(KERN_ALERT "Set role label for (%s:%d): role:%s, subject:%s\n", task->comm, task->pid, task->role->rolename, task->acl->filename);
#endif

	gr_set_proc_res(task);

	return;
}

int
gr_set_proc_label(const struct dentry *dentry, const struct vfsmount *mnt,
		  const int unsafe_share)
{
	struct task_struct *task = current;
	struct acl_subject_label *newacl;
	struct acl_object_label *obj;
	__u32 retmode;

	if (unlikely(!(gr_status & GR_READY)))
		return 0;

	newacl = chk_subj_label(dentry, mnt, task->role);

	task_lock(task);
	if ((((task->ptrace & PT_PTRACED) || unsafe_share) &&
	     !(task->acl->mode & GR_POVERRIDE) && (task->acl != newacl) &&
	     !(task->role->roletype & GR_ROLE_GOD) &&
	     !gr_search_file(dentry, GR_PTRACERD, mnt) &&
	     !(task->acl->mode & (GR_LEARN | GR_INHERITLEARN)))) {
                task_unlock(task);
		if (unsafe_share)
			gr_log_fs_generic(GR_DONT_AUDIT, GR_UNSAFESHARE_EXEC_ACL_MSG, dentry, mnt);
		else
			gr_log_fs_generic(GR_DONT_AUDIT, GR_PTRACE_EXEC_ACL_MSG, dentry, mnt);
		return -EACCES;
	}
	task_unlock(task);

	obj = chk_obj_label(dentry, mnt, task->acl);
	retmode = obj->mode & (GR_INHERIT | GR_AUDIT_INHERIT);

	if (!(task->acl->mode & GR_INHERITLEARN) &&
	    ((newacl->mode & GR_LEARN) || !(retmode & GR_INHERIT))) {
		if (obj->nested)
			task->acl = obj->nested;
		else
			task->acl = newacl;
	} else if (retmode & GR_INHERIT && retmode & GR_AUDIT_INHERIT)
		gr_log_str_fs(GR_DO_AUDIT, GR_INHERIT_ACL_MSG, task->acl->filename, dentry, mnt);

	task->is_writable = 0;

	/* ignore additional mmap checks for processes that are writable 
	   by the default ACL */
	obj = chk_obj_label(dentry, mnt, default_role->root_label);
	if (unlikely(obj->mode & GR_WRITE))
		task->is_writable = 1;
	obj = chk_obj_label(dentry, mnt, task->role->root_label);
	if (unlikely(obj->mode & GR_WRITE))
		task->is_writable = 1;

	gr_set_proc_res(task);

#ifdef CONFIG_GRKERNSEC_ACL_DEBUG
	printk(KERN_ALERT "Set subject label for (%s:%d): role:%s, subject:%s\n", task->comm, task->pid, task->role->rolename, task->acl->filename);
#endif
	return 0;
}

/* always called with valid inodev ptr */
static void
do_handle_delete(struct inodev_entry *inodev, const ino_t ino, const dev_t dev)
{
	struct acl_object_label *matchpo;
	struct acl_subject_label *matchps;
	struct acl_subject_label *subj;
	struct acl_role_label *role;
	unsigned int x;

	FOR_EACH_ROLE_START(role)
		FOR_EACH_SUBJECT_START(role, subj, x)
			if ((matchpo = lookup_acl_obj_label(ino, dev, subj)) != NULL)
				matchpo->mode |= GR_DELETED;
		FOR_EACH_SUBJECT_END(subj,x)
		FOR_EACH_NESTED_SUBJECT_START(role, subj)
			if (subj->inode == ino && subj->device == dev)
				subj->mode |= GR_DELETED;
		FOR_EACH_NESTED_SUBJECT_END(subj)
		if ((matchps = lookup_acl_subj_label(ino, dev, role)) != NULL)
			matchps->mode |= GR_DELETED;
	FOR_EACH_ROLE_END(role)

	inodev->nentry->deleted = 1;

	return;
}

void
gr_handle_delete(const ino_t ino, const dev_t dev)
{
	struct inodev_entry *inodev;

	if (unlikely(!(gr_status & GR_READY)))
		return;

	write_lock(&gr_inode_lock);
	inodev = lookup_inodev_entry(ino, dev);
	if (inodev != NULL)
		do_handle_delete(inodev, ino, dev);
	write_unlock(&gr_inode_lock);

	return;
}

static void
update_acl_obj_label(const ino_t oldinode, const dev_t olddevice,
		     const ino_t newinode, const dev_t newdevice,
		     struct acl_subject_label *subj)
{
	unsigned int index = fhash(oldinode, olddevice, subj->obj_hash_size);
	struct acl_object_label *match;

	match = subj->obj_hash[index];

	while (match && (match->inode != oldinode ||
	       match->device != olddevice ||
	       !(match->mode & GR_DELETED)))
		match = match->next;

	if (match && (match->inode == oldinode)
	    && (match->device == olddevice)
	    && (match->mode & GR_DELETED)) {
		if (match->prev == NULL) {
			subj->obj_hash[index] = match->next;
			if (match->next != NULL)
				match->next->prev = NULL;
		} else {
			match->prev->next = match->next;
			if (match->next != NULL)
				match->next->prev = match->prev;
		}
		match->prev = NULL;
		match->next = NULL;
		match->inode = newinode;
		match->device = newdevice;
		match->mode &= ~GR_DELETED;

		insert_acl_obj_label(match, subj);
	}

	return;
}

static void
update_acl_subj_label(const ino_t oldinode, const dev_t olddevice,
		      const ino_t newinode, const dev_t newdevice,
		      struct acl_role_label *role)
{
	unsigned int index = fhash(oldinode, olddevice, role->subj_hash_size);
	struct acl_subject_label *match;

	match = role->subj_hash[index];

	while (match && (match->inode != oldinode ||
	       match->device != olddevice ||
	       !(match->mode & GR_DELETED)))
		match = match->next;

	if (match && (match->inode == oldinode)
	    && (match->device == olddevice)
	    && (match->mode & GR_DELETED)) {
		if (match->prev == NULL) {
			role->subj_hash[index] = match->next;
			if (match->next != NULL)
				match->next->prev = NULL;
		} else {
			match->prev->next = match->next;
			if (match->next != NULL)
				match->next->prev = match->prev;
		}
		match->prev = NULL;
		match->next = NULL;
		match->inode = newinode;
		match->device = newdevice;
		match->mode &= ~GR_DELETED;

		insert_acl_subj_label(match, role);
	}

	return;
}

static void
update_inodev_entry(const ino_t oldinode, const dev_t olddevice,
		    const ino_t newinode, const dev_t newdevice)
{
	unsigned int index = fhash(oldinode, olddevice, inodev_set.i_size);
	struct inodev_entry *match;

	match = inodev_set.i_hash[index];

	while (match && (match->nentry->inode != oldinode ||
	       match->nentry->device != olddevice || !match->nentry->deleted))
		match = match->next;

	if (match && (match->nentry->inode == oldinode)
	    && (match->nentry->device == olddevice) &&
	    match->nentry->deleted) {
		if (match->prev == NULL) {
			inodev_set.i_hash[index] = match->next;
			if (match->next != NULL)
				match->next->prev = NULL;
		} else {
			match->prev->next = match->next;
			if (match->next != NULL)
				match->next->prev = match->prev;
		}
		match->prev = NULL;
		match->next = NULL;
		match->nentry->inode = newinode;
		match->nentry->device = newdevice;
		match->nentry->deleted = 0;

		insert_inodev_entry(match);
	}

	return;
}

static void
do_handle_create(const struct name_entry *matchn, const struct dentry *dentry,
		 const struct vfsmount *mnt)
{
	struct acl_subject_label *subj;
	struct acl_role_label *role;
	unsigned int x;
	
	FOR_EACH_ROLE_START(role)
		update_acl_subj_label(matchn->inode, matchn->device,
				      dentry->d_inode->i_ino,
				      dentry->d_inode->i_sb->s_dev, role);

		FOR_EACH_NESTED_SUBJECT_START(role, subj)
			if ((subj->inode == dentry->d_inode->i_ino) &&
			    (subj->device == dentry->d_inode->i_sb->s_dev)) {
				subj->inode = dentry->d_inode->i_ino;
				subj->device = dentry->d_inode->i_sb->s_dev;
			}
		FOR_EACH_NESTED_SUBJECT_END(subj)
		FOR_EACH_SUBJECT_START(role, subj, x)
			update_acl_obj_label(matchn->inode, matchn->device,
					     dentry->d_inode->i_ino,
					     dentry->d_inode->i_sb->s_dev, subj);
		FOR_EACH_SUBJECT_END(subj,x)
	FOR_EACH_ROLE_END(role)

	update_inodev_entry(matchn->inode, matchn->device,
			    dentry->d_inode->i_ino, dentry->d_inode->i_sb->s_dev);

	return;
}

void
gr_handle_create(const struct dentry *dentry, const struct vfsmount *mnt)
{
	struct name_entry *matchn;

	if (unlikely(!(gr_status & GR_READY)))
		return;

	preempt_disable();
	matchn = lookup_name_entry(gr_to_filename_rbac(dentry, mnt));

	if (unlikely((unsigned long)matchn)) {
		write_lock(&gr_inode_lock);
		do_handle_create(matchn, dentry, mnt);
		write_unlock(&gr_inode_lock);
	}
	preempt_enable();

	return;
}

void
gr_handle_rename(struct inode *old_dir, struct inode *new_dir,
		 struct dentry *old_dentry,
		 struct dentry *new_dentry,
		 struct vfsmount *mnt, const __u8 replace)
{
	struct name_entry *matchn;
	struct inodev_entry *inodev;

	/* vfs_rename swaps the name and parent link for old_dentry and
	   new_dentry
	   at this point, old_dentry has the new name, parent link, and inode
	   for the renamed file
	   if a file is being replaced by a rename, new_dentry has the inode
	   and name for the replaced file
	*/

	if (unlikely(!(gr_status & GR_READY)))
		return;

	preempt_disable();
	matchn = lookup_name_entry(gr_to_filename_rbac(old_dentry, mnt));

	/* we wouldn't have to check d_inode if it weren't for
	   NFS silly-renaming
	 */

	write_lock(&gr_inode_lock);
	if (unlikely(replace && new_dentry->d_inode)) {
		inodev = lookup_inodev_entry(new_dentry->d_inode->i_ino,
					     new_dentry->d_inode->i_sb->s_dev);
		if (inodev != NULL && (new_dentry->d_inode->i_nlink <= 1))
			do_handle_delete(inodev, new_dentry->d_inode->i_ino,
					 new_dentry->d_inode->i_sb->s_dev);
	}

	inodev = lookup_inodev_entry(old_dentry->d_inode->i_ino,
				     old_dentry->d_inode->i_sb->s_dev);
	if (inodev != NULL && (old_dentry->d_inode->i_nlink <= 1))
		do_handle_delete(inodev, old_dentry->d_inode->i_ino,
				 old_dentry->d_inode->i_sb->s_dev);

	if (unlikely((unsigned long)matchn))
		do_handle_create(matchn, old_dentry, mnt);

	write_unlock(&gr_inode_lock);
	preempt_enable();

	return;
}

static int
lookup_special_role_auth(__u16 mode, const char *rolename, unsigned char **salt,
			 unsigned char **sum)
{
	struct acl_role_label *r;
	struct role_allowed_ip *ipp;
	struct role_transition *trans;
	unsigned int i;
	int found = 0;

	/* check transition table */

	for (trans = current->role->transitions; trans; trans = trans->next) {
		if (!strcmp(rolename, trans->rolename)) {
			found = 1;
			break;
		}
	}

	if (!found)
		return 0;

	/* handle special roles that do not require authentication
	   and check ip */

	FOR_EACH_ROLE_START(r)
		if (!strcmp(rolename, r->rolename) &&
		    (r->roletype & GR_ROLE_SPECIAL)) {
			found = 0;
			if (r->allowed_ips != NULL) {
				for (ipp = r->allowed_ips; ipp; ipp = ipp->next) {
					if ((ntohl(current->signal->curr_ip) & ipp->netmask) ==
					     (ntohl(ipp->addr) & ipp->netmask))
						found = 1;
				}
			} else
				found = 2;
			if (!found)
				return 0;

			if (((mode == GR_SPROLE) && (r->roletype & GR_ROLE_NOPW)) ||
			    ((mode == GR_SPROLEPAM) && (r->roletype & GR_ROLE_PAM))) {
				*salt = NULL;
				*sum = NULL;
				return 1;
			}
		}
	FOR_EACH_ROLE_END(r)

	for (i = 0; i < num_sprole_pws; i++) {
		if (!strcmp(rolename, acl_special_roles[i]->rolename)) {
			*salt = acl_special_roles[i]->salt;
			*sum = acl_special_roles[i]->sum;
			return 1;
		}
	}

	return 0;
}

static void
assign_special_role(char *rolename)
{
	struct acl_object_label *obj;
	struct acl_role_label *r;
	struct acl_role_label *assigned = NULL;
	struct task_struct *tsk;
	struct file *filp;

	FOR_EACH_ROLE_START(r)
		if (!strcmp(rolename, r->rolename) &&
		    (r->roletype & GR_ROLE_SPECIAL)) {
			assigned = r;
			break;
		}
	FOR_EACH_ROLE_END(r)

	if (!assigned)
		return;

	read_lock(&tasklist_lock);
	read_lock(&grsec_exec_file_lock);

	tsk = current->parent;
	if (tsk == NULL)
		goto out_unlock;

	filp = tsk->exec_file;
	if (filp == NULL)
		goto out_unlock;

	tsk->is_writable = 0;

	tsk->acl_sp_role = 1;
	tsk->acl_role_id = ++acl_sp_role_value;
	tsk->role = assigned;
	tsk->acl = chk_subj_label(filp->f_path.dentry, filp->f_path.mnt, tsk->role);

	/* ignore additional mmap checks for processes that are writable 
	   by the default ACL */
	obj = chk_obj_label(filp->f_path.dentry, filp->f_path.mnt, default_role->root_label);
	if (unlikely(obj->mode & GR_WRITE))
		tsk->is_writable = 1;
	obj = chk_obj_label(filp->f_path.dentry, filp->f_path.mnt, tsk->role->root_label);
	if (unlikely(obj->mode & GR_WRITE))
		tsk->is_writable = 1;

#ifdef CONFIG_GRKERNSEC_ACL_DEBUG
	printk(KERN_ALERT "Assigning special role:%s subject:%s to process (%s:%d)\n", tsk->role->rolename, tsk->acl->filename, tsk->comm, tsk->pid);
#endif

out_unlock:
	read_unlock(&grsec_exec_file_lock);
	read_unlock(&tasklist_lock);
	return;
}

int gr_check_secure_terminal(struct task_struct *task)
{
	struct task_struct *p, *p2, *p3;
	struct files_struct *files;
	struct fdtable *fdt;
	struct file *our_file = NULL, *file;
	int i;

	if (task->signal->tty == NULL)
		return 1;

	files = get_files_struct(task);
	if (files != NULL) {
		rcu_read_lock();
		fdt = files_fdtable(files);
		for (i=0; i < fdt->max_fds; i++) {
			file = fcheck_files(files, i);
			if (file && (our_file == NULL) && (file->private_data == task->signal->tty)) {
				get_file(file);
				our_file = file;
			}
		}
		rcu_read_unlock();
		put_files_struct(files);
	}

	if (our_file == NULL)
		return 1;

	read_lock(&tasklist_lock);
	do_each_thread(p2, p) {
		files = get_files_struct(p);
		if (files == NULL ||
		    (p->signal && p->signal->tty == task->signal->tty)) {
			if (files != NULL)
				put_files_struct(files);
			continue;
		}
		rcu_read_lock();
		fdt = files_fdtable(files);
		for (i=0; i < fdt->max_fds; i++) {
			file = fcheck_files(files, i);
			if (file && S_ISCHR(file->f_path.dentry->d_inode->i_mode) &&
			    file->f_path.dentry->d_inode->i_rdev == our_file->f_path.dentry->d_inode->i_rdev) {
				p3 = task;
				while (p3->pid > 0) {
					if (p3 == p)
						break;
					p3 = p3->parent;
				}
				if (p3 == p)
					break;
				gr_log_ttysniff(GR_DONT_AUDIT_GOOD, GR_TTYSNIFF_ACL_MSG, p);
				gr_handle_alertkill(p);
				rcu_read_unlock();
				put_files_struct(files);
				read_unlock(&tasklist_lock);
				fput(our_file);
				return 0;
			}
		}
		rcu_read_unlock();
		put_files_struct(files);
	} while_each_thread(p2, p);
	read_unlock(&tasklist_lock);

	fput(our_file);
	return 1;
}

ssize_t
write_grsec_handler(struct file *file, const char * buf, size_t count, loff_t *ppos)
{
	struct gr_arg_wrapper uwrap;
	unsigned char *sprole_salt = NULL;
	unsigned char *sprole_sum = NULL;
	int error = sizeof (struct gr_arg_wrapper);
	int error2 = 0;

	down(&gr_dev_sem);

	if ((gr_status & GR_READY) && !(current->acl->mode & GR_KERNELAUTH)) {
		error = -EPERM;
		goto out;
	}

	if (count != sizeof (struct gr_arg_wrapper)) {
		gr_log_int_int(GR_DONT_AUDIT_GOOD, GR_DEV_ACL_MSG, (int)count, (int)sizeof(struct gr_arg_wrapper));
		error = -EINVAL;
		goto out;
	}

	
	if (gr_auth_expires && time_after_eq(get_seconds(), gr_auth_expires)) {
		gr_auth_expires = 0;
		gr_auth_attempts = 0;
	}

	if (copy_from_user(&uwrap, buf, sizeof (struct gr_arg_wrapper))) {
		error = -EFAULT;
		goto out;
	}

	if ((uwrap.version != GRSECURITY_VERSION) || (uwrap.size != sizeof(struct gr_arg))) {
		error = -EINVAL;
		goto out;
	}

	if (copy_from_user(gr_usermode, uwrap.arg, sizeof (struct gr_arg))) {
		error = -EFAULT;
		goto out;
	}

	if (gr_usermode->mode != GR_SPROLE && gr_usermode->mode != GR_SPROLEPAM &&
	    gr_auth_attempts >= CONFIG_GRKERNSEC_ACL_MAXTRIES &&
	    time_after(gr_auth_expires, get_seconds())) {
		error = -EBUSY;
		goto out;
	}

	/* if non-root trying to do anything other than use a special role,
	   do not attempt authentication, do not count towards authentication
	   locking
	 */

	if (gr_usermode->mode != GR_SPROLE && gr_usermode->mode != GR_STATUS &&
	    gr_usermode->mode != GR_UNSPROLE && gr_usermode->mode != GR_SPROLEPAM &&
	    current_uid()) {
		error = -EPERM;
		goto out;
	}

	/* ensure pw and special role name are null terminated */

	gr_usermode->pw[GR_PW_LEN - 1] = '\0';
	gr_usermode->sp_role[GR_SPROLE_LEN - 1] = '\0';

	/* Okay. 
	 * We have our enough of the argument structure..(we have yet
	 * to copy_from_user the tables themselves) . Copy the tables
	 * only if we need them, i.e. for loading operations. */

	switch (gr_usermode->mode) {
	case GR_STATUS:
			if (gr_status & GR_READY) {
				error = 1;
				if (!gr_check_secure_terminal(current))
					error = 3;
			} else
				error = 2;
			goto out;
	case GR_SHUTDOWN:
		if ((gr_status & GR_READY)
		    && !(chkpw(gr_usermode, gr_system_salt, gr_system_sum))) {
			pax_open_kernel();
			gr_status &= ~GR_READY;
			pax_close_kernel();

			gr_log_noargs(GR_DONT_AUDIT_GOOD, GR_SHUTS_ACL_MSG);
			free_variables();
			memset(gr_usermode, 0, sizeof (struct gr_arg));
			memset(gr_system_salt, 0, GR_SALT_LEN);
			memset(gr_system_sum, 0, GR_SHA_LEN);
		} else if (gr_status & GR_READY) {
			gr_log_noargs(GR_DONT_AUDIT, GR_SHUTF_ACL_MSG);
			error = -EPERM;
		} else {
			gr_log_noargs(GR_DONT_AUDIT_GOOD, GR_SHUTI_ACL_MSG);
			error = -EAGAIN;
		}
		break;
	case GR_ENABLE:
		if (!(gr_status & GR_READY) && !(error2 = gracl_init(gr_usermode)))
			gr_log_str(GR_DONT_AUDIT_GOOD, GR_ENABLE_ACL_MSG, GR_VERSION);
		else {
			if (gr_status & GR_READY)
				error = -EAGAIN;
			else
				error = error2;
			gr_log_str(GR_DONT_AUDIT, GR_ENABLEF_ACL_MSG, GR_VERSION);
		}
		break;
	case GR_RELOAD:
		if (!(gr_status & GR_READY)) {
			gr_log_str(GR_DONT_AUDIT_GOOD, GR_RELOADI_ACL_MSG, GR_VERSION);
			error = -EAGAIN;
		} else if (!(chkpw(gr_usermode, gr_system_salt, gr_system_sum))) {
			lock_kernel();

			pax_open_kernel();
			gr_status &= ~GR_READY;
			pax_close_kernel();

			free_variables();
			if (!(error2 = gracl_init(gr_usermode))) {
				unlock_kernel();
				gr_log_str(GR_DONT_AUDIT_GOOD, GR_RELOAD_ACL_MSG, GR_VERSION);
			} else {
				unlock_kernel();
				error = error2;
				gr_log_str(GR_DONT_AUDIT, GR_RELOADF_ACL_MSG, GR_VERSION);
			}
		} else {
			gr_log_str(GR_DONT_AUDIT, GR_RELOADF_ACL_MSG, GR_VERSION);
			error = -EPERM;
		}
		break;
	case GR_SEGVMOD:
		if (unlikely(!(gr_status & GR_READY))) {
			gr_log_noargs(GR_DONT_AUDIT_GOOD, GR_SEGVMODI_ACL_MSG);
			error = -EAGAIN;
			break;
		}

		if (!(chkpw(gr_usermode, gr_system_salt, gr_system_sum))) {
			gr_log_noargs(GR_DONT_AUDIT_GOOD, GR_SEGVMODS_ACL_MSG);
			if (gr_usermode->segv_device && gr_usermode->segv_inode) {
				struct acl_subject_label *segvacl;
				segvacl =
				    lookup_acl_subj_label(gr_usermode->segv_inode,
							  gr_usermode->segv_device,
							  current->role);
				if (segvacl) {
					segvacl->crashes = 0;
					segvacl->expires = 0;
				}
			} else if (gr_find_uid(gr_usermode->segv_uid) >= 0) {
				gr_remove_uid(gr_usermode->segv_uid);
			}
		} else {
			gr_log_noargs(GR_DONT_AUDIT, GR_SEGVMODF_ACL_MSG);
			error = -EPERM;
		}
		break;
	case GR_SPROLE:
	case GR_SPROLEPAM:
		if (unlikely(!(gr_status & GR_READY))) {
			gr_log_noargs(GR_DONT_AUDIT_GOOD, GR_SPROLEI_ACL_MSG);
			error = -EAGAIN;
			break;
		}

		if (current->role->expires && time_after_eq(get_seconds(), current->role->expires)) {
			current->role->expires = 0;
			current->role->auth_attempts = 0;
		}

		if (current->role->auth_attempts >= CONFIG_GRKERNSEC_ACL_MAXTRIES &&
		    time_after(current->role->expires, get_seconds())) {
			error = -EBUSY;
			goto out;
		}

		if (lookup_special_role_auth
		    (gr_usermode->mode, gr_usermode->sp_role, &sprole_salt, &sprole_sum)
		    && ((!sprole_salt && !sprole_sum)
			|| !(chkpw(gr_usermode, sprole_salt, sprole_sum)))) {
			char *p = "";
			assign_special_role(gr_usermode->sp_role);
			read_lock(&tasklist_lock);
			if (current->parent)
				p = current->parent->role->rolename;
			read_unlock(&tasklist_lock);
			gr_log_str_int(GR_DONT_AUDIT_GOOD, GR_SPROLES_ACL_MSG,
					p, acl_sp_role_value);
		} else {
			gr_log_str(GR_DONT_AUDIT, GR_SPROLEF_ACL_MSG, gr_usermode->sp_role);
			error = -EPERM;
			if(!(current->role->auth_attempts++))
				current->role->expires = get_seconds() + CONFIG_GRKERNSEC_ACL_TIMEOUT;

			goto out;
		}
		break;
	case GR_UNSPROLE:
		if (unlikely(!(gr_status & GR_READY))) {
			gr_log_noargs(GR_DONT_AUDIT_GOOD, GR_UNSPROLEI_ACL_MSG);
			error = -EAGAIN;
			break;
		}

		if (current->role->roletype & GR_ROLE_SPECIAL) {
			char *p = "";
			int i = 0;

			read_lock(&tasklist_lock);
			if (current->parent) {
				p = current->parent->role->rolename;
				i = current->parent->acl_role_id;
			}
			read_unlock(&tasklist_lock);

			gr_log_str_int(GR_DONT_AUDIT_GOOD, GR_UNSPROLES_ACL_MSG, p, i);
			gr_set_acls(1);
		} else {
			error = -EPERM;
			goto out;
		}
		break;
	default:
		gr_log_int(GR_DONT_AUDIT, GR_INVMODE_ACL_MSG, gr_usermode->mode);
		error = -EINVAL;
		break;
	}

	if (error != -EPERM)
		goto out;

	if(!(gr_auth_attempts++))
		gr_auth_expires = get_seconds() + CONFIG_GRKERNSEC_ACL_TIMEOUT;

      out:
	up(&gr_dev_sem);
	return error;
}

int
gr_set_acls(const int type)
{
	struct acl_object_label *obj;
	struct task_struct *task, *task2;
	struct file *filp;
	struct acl_role_label *role = current->role;
	__u16 acl_role_id = current->acl_role_id;
	const struct cred *cred;
	char *tmpname;
	struct name_entry *nmatch;
	struct acl_subject_label *tmpsubj;

	rcu_read_lock();
	read_lock(&tasklist_lock);
	read_lock(&grsec_exec_file_lock);
	do_each_thread(task2, task) {
		/* check to see if we're called from the exit handler,
		   if so, only replace ACLs that have inherited the admin
		   ACL */

		if (type && (task->role != role ||
			     task->acl_role_id != acl_role_id))
			continue;

		task->acl_role_id = 0;
		task->acl_sp_role = 0;

		if ((filp = task->exec_file)) {
			cred = __task_cred(task);
			task->role = lookup_acl_role_label(task, cred->uid, cred->gid);

			/* the following is to apply the correct subject 
			   on binaries running when the RBAC system 
			   is enabled, when the binaries have been 
			   replaced or deleted since their execution
			   -----
			   when the RBAC system starts, the inode/dev
			   from exec_file will be one the RBAC system
			   is unaware of.  It only knows the inode/dev
			   of the present file on disk, or the absence
			   of it.
			*/
			preempt_disable();
			tmpname = gr_to_filename_rbac(filp->f_path.dentry, filp->f_path.mnt);
			
			nmatch = lookup_name_entry(tmpname);
			preempt_enable();
			tmpsubj = NULL;
			if (nmatch) {
				if (nmatch->deleted)
					tmpsubj = lookup_acl_subj_label_deleted(nmatch->inode, nmatch->device, task->role);
				else
					tmpsubj = lookup_acl_subj_label(nmatch->inode, nmatch->device, task->role);
				if (tmpsubj != NULL)
					task->acl = tmpsubj;
			}
			if (tmpsubj == NULL)
				task->acl = chk_subj_label(filp->f_path.dentry, filp->f_path.mnt,
							   task->role);
			if (task->acl) {
				struct acl_subject_label *curr;
				curr = task->acl;

				task->is_writable = 0;
				/* ignore additional mmap checks for processes that are writable 
				   by the default ACL */
				obj = chk_obj_label(filp->f_path.dentry, filp->f_path.mnt, default_role->root_label);
				if (unlikely(obj->mode & GR_WRITE))
					task->is_writable = 1;
				obj = chk_obj_label(filp->f_path.dentry, filp->f_path.mnt, task->role->root_label);
				if (unlikely(obj->mode & GR_WRITE))
					task->is_writable = 1;

				gr_set_proc_res(task);

#ifdef CONFIG_GRKERNSEC_ACL_DEBUG
				printk(KERN_ALERT "gr_set_acls for (%s:%d): role:%s, subject:%s\n", task->comm, task->pid, task->role->rolename, task->acl->filename);
#endif
			} else {
				read_unlock(&grsec_exec_file_lock);
				read_unlock(&tasklist_lock);
				rcu_read_unlock();
				gr_log_str_int(GR_DONT_AUDIT_GOOD, GR_DEFACL_MSG, task->comm, task->pid);
				return 1;
			}
		} else {
			// it's a kernel process
			task->role = kernel_role;
			task->acl = kernel_role->root_label;
#ifdef CONFIG_GRKERNSEC_ACL_HIDEKERN
			task->acl->mode &= ~GR_PROCFIND;
#endif
		}
	} while_each_thread(task2, task);
	read_unlock(&grsec_exec_file_lock);
	read_unlock(&tasklist_lock);
	rcu_read_unlock();

	return 0;
}

void
gr_learn_resource(const struct task_struct *task,
		  const int res, const unsigned long wanted, const int gt)
{
	struct acl_subject_label *acl;
	const struct cred *cred;

	if (unlikely((gr_status & GR_READY) &&
		     task->acl && (task->acl->mode & (GR_LEARN | GR_INHERITLEARN))))
		goto skip_reslog;

#ifdef CONFIG_GRKERNSEC_RESLOG
	gr_log_resource(task, res, wanted, gt);
#endif
      skip_reslog:

	if (unlikely(!(gr_status & GR_READY) || !wanted || res >= GR_NLIMITS))
		return;

	acl = task->acl;

	if (likely(!acl || !(acl->mode & (GR_LEARN | GR_INHERITLEARN)) ||
		   !(acl->resmask & (1 << (unsigned short) res))))
		return;

	if (wanted >= acl->res[res].rlim_cur) {
		unsigned long res_add;

		res_add = wanted;
		switch (res) {
		case RLIMIT_CPU:
			res_add += GR_RLIM_CPU_BUMP;
			break;
		case RLIMIT_FSIZE:
			res_add += GR_RLIM_FSIZE_BUMP;
			break;
		case RLIMIT_DATA:
			res_add += GR_RLIM_DATA_BUMP;
			break;
		case RLIMIT_STACK:
			res_add += GR_RLIM_STACK_BUMP;
			break;
		case RLIMIT_CORE:
			res_add += GR_RLIM_CORE_BUMP;
			break;
		case RLIMIT_RSS:
			res_add += GR_RLIM_RSS_BUMP;
			break;
		case RLIMIT_NPROC:
			res_add += GR_RLIM_NPROC_BUMP;
			break;
		case RLIMIT_NOFILE:
			res_add += GR_RLIM_NOFILE_BUMP;
			break;
		case RLIMIT_MEMLOCK:
			res_add += GR_RLIM_MEMLOCK_BUMP;
			break;
		case RLIMIT_AS:
			res_add += GR_RLIM_AS_BUMP;
			break;
		case RLIMIT_LOCKS:
			res_add += GR_RLIM_LOCKS_BUMP;
			break;
		case RLIMIT_SIGPENDING:
			res_add += GR_RLIM_SIGPENDING_BUMP;
			break;
		case RLIMIT_MSGQUEUE:
			res_add += GR_RLIM_MSGQUEUE_BUMP;
			break;
		case RLIMIT_NICE:
			res_add += GR_RLIM_NICE_BUMP;
			break;
		case RLIMIT_RTPRIO:
			res_add += GR_RLIM_RTPRIO_BUMP;
			break;
		case RLIMIT_RTTIME:
			res_add += GR_RLIM_RTTIME_BUMP;
			break;
		}

		acl->res[res].rlim_cur = res_add;

		if (wanted > acl->res[res].rlim_max)
			acl->res[res].rlim_max = res_add;

		/* only log the subject filename, since resource logging is supported for
		   single-subject learning only */
		rcu_read_lock();
		cred = __task_cred(task);
		security_learn(GR_LEARN_AUDIT_MSG, task->role->rolename,
			       task->role->roletype, cred->uid, cred->gid, acl->filename,
			       acl->filename, acl->res[res].rlim_cur, acl->res[res].rlim_max,
			       "", (unsigned long) res, &task->signal->curr_ip);
		rcu_read_unlock();
	}

	return;
}

#if defined(CONFIG_PAX_HAVE_ACL_FLAGS) && (defined(CONFIG_PAX_NOEXEC) || defined(CONFIG_PAX_ASLR))
void
pax_set_initial_flags(struct linux_binprm *bprm)
{
	struct task_struct *task = current;
        struct acl_subject_label *proc;
	unsigned long flags;

        if (unlikely(!(gr_status & GR_READY)))
                return;

	flags = pax_get_flags(task);

        proc = task->acl;

	if (proc->pax_flags & GR_PAX_DISABLE_PAGEEXEC)
		flags &= ~MF_PAX_PAGEEXEC;
	if (proc->pax_flags & GR_PAX_DISABLE_SEGMEXEC)
		flags &= ~MF_PAX_SEGMEXEC;
	if (proc->pax_flags & GR_PAX_DISABLE_RANDMMAP)
		flags &= ~MF_PAX_RANDMMAP;
	if (proc->pax_flags & GR_PAX_DISABLE_EMUTRAMP)
		flags &= ~MF_PAX_EMUTRAMP;
	if (proc->pax_flags & GR_PAX_DISABLE_MPROTECT)
		flags &= ~MF_PAX_MPROTECT;

	if (proc->pax_flags & GR_PAX_ENABLE_PAGEEXEC)
		flags |= MF_PAX_PAGEEXEC;
	if (proc->pax_flags & GR_PAX_ENABLE_SEGMEXEC)
		flags |= MF_PAX_SEGMEXEC;
	if (proc->pax_flags & GR_PAX_ENABLE_RANDMMAP)
		flags |= MF_PAX_RANDMMAP;
	if (proc->pax_flags & GR_PAX_ENABLE_EMUTRAMP)
		flags |= MF_PAX_EMUTRAMP;
	if (proc->pax_flags & GR_PAX_ENABLE_MPROTECT)
		flags |= MF_PAX_MPROTECT;

	pax_set_flags(task, flags);

        return;
}
#endif

#ifdef CONFIG_SYSCTL
/* Eric Biederman likes breaking userland ABI and every inode-based security
   system to save 35kb of memory */

/* we modify the passed in filename, but adjust it back before returning */
static struct acl_object_label *gr_lookup_by_name(char *name, unsigned int len)
{
	struct name_entry *nmatch;
	char *p, *lastp = NULL;
	struct acl_object_label *obj = NULL, *tmp;
	struct acl_subject_label *tmpsubj;
	char c = '\0';

	read_lock(&gr_inode_lock);

	p = name + len - 1;
	do {
		nmatch = lookup_name_entry(name);
		if (lastp != NULL)
			*lastp = c;

		if (nmatch == NULL)
			goto next_component;
		tmpsubj = current->acl;
		do {
			obj = lookup_acl_obj_label(nmatch->inode, nmatch->device, tmpsubj);
			if (obj != NULL) {
				tmp = obj->globbed;
				while (tmp) {
					if (!glob_match(tmp->filename, name)) {
						obj = tmp;
						goto found_obj;
					}
					tmp = tmp->next;
				}
				goto found_obj;
			}
		} while ((tmpsubj = tmpsubj->parent_subject));
next_component:
		/* end case */
		if (p == name)
			break;

		while (*p != '/')
			p--;
		if (p == name)
			lastp = p + 1;
		else {
			lastp = p;
			p--;
		}
		c = *lastp;
		*lastp = '\0';
	} while (1);
found_obj:
	read_unlock(&gr_inode_lock);
	/* obj returned will always be non-null */
	return obj;
}

/* returns 0 when allowing, non-zero on error
   op of 0 is used for readdir, so we don't log the names of hidden files
*/
__u32
gr_handle_sysctl(const struct ctl_table *table, const int op)
{
	ctl_table *tmp;
	const char *proc_sys = "/proc/sys";
	char *path;
	struct acl_object_label *obj;
	unsigned short len = 0, pos = 0, depth = 0, i;
	__u32 err = 0;
	__u32 mode = 0;

	if (unlikely(!(gr_status & GR_READY)))
		return 0;

	/* for now, ignore operations on non-sysctl entries if it's not a
	   readdir*/
	if (table->child != NULL && op != 0)
		return 0;

	mode |= GR_FIND;
	/* it's only a read if it's an entry, read on dirs is for readdir */
	if (op & MAY_READ)
		mode |= GR_READ;
	if (op & MAY_WRITE)
		mode |= GR_WRITE;

	preempt_disable();

	path = per_cpu_ptr(gr_shared_page[0], smp_processor_id());

	/* it's only a read/write if it's an actual entry, not a dir
	   (which are opened for readdir)
	*/

	/* convert the requested sysctl entry into a pathname */

	for (tmp = (ctl_table *)table; tmp != NULL; tmp = tmp->parent) {
		len += strlen(tmp->procname);
		len++;
		depth++;
	}

	if ((len + depth + strlen(proc_sys) + 1) > PAGE_SIZE) {
		/* deny */
		goto out;
	}

	memset(path, 0, PAGE_SIZE);

	memcpy(path, proc_sys, strlen(proc_sys));

	pos += strlen(proc_sys);

	for (; depth > 0; depth--) {
		path[pos] = '/';
		pos++;
		for (i = 1, tmp = (ctl_table *)table; tmp != NULL; tmp = tmp->parent) {
			if (depth == i) {
				memcpy(path + pos, tmp->procname,
				       strlen(tmp->procname));
				pos += strlen(tmp->procname);
			}
			i++;
		}
	}

	obj = gr_lookup_by_name(path, pos);
	err = obj->mode & (mode | to_gr_audit(mode) | GR_SUPPRESS);

	if (unlikely((current->acl->mode & (GR_LEARN | GR_INHERITLEARN)) &&
		     ((err & mode) != mode))) {
		__u32 new_mode = mode;

		new_mode &= ~(GR_AUDITS | GR_SUPPRESS);

		err = 0;
		gr_log_learn_sysctl(path, new_mode);
	} else if (!(err & GR_FIND) && !(err & GR_SUPPRESS) && op != 0) {
		gr_log_hidden_sysctl(GR_DONT_AUDIT, GR_HIDDEN_ACL_MSG, path);
		err = -ENOENT;
	} else if (!(err & GR_FIND)) {
		err = -ENOENT;
	} else if (((err & mode) & ~GR_FIND) != (mode & ~GR_FIND) && !(err & GR_SUPPRESS)) {
		gr_log_str4(GR_DONT_AUDIT, GR_SYSCTL_ACL_MSG, "denied",
			       path, (mode & GR_READ) ? " reading" : "",
			       (mode & GR_WRITE) ? " writing" : "");
		err = -EACCES;
	} else if ((err & mode) != mode) {
		err = -EACCES;
	} else if ((((err & mode) & ~GR_FIND) == (mode & ~GR_FIND)) && (err & GR_AUDITS)) {
		gr_log_str4(GR_DO_AUDIT, GR_SYSCTL_ACL_MSG, "successful",
			       path, (mode & GR_READ) ? " reading" : "",
			       (mode & GR_WRITE) ? " writing" : "");
		err = 0;
	} else
		err = 0;

      out:
	preempt_enable();

	return err;
}
#endif

int
gr_handle_proc_ptrace(struct task_struct *task)
{
	struct file *filp;
	struct task_struct *tmp = task;
	struct task_struct *curtemp = current;
	__u32 retmode;

#ifndef CONFIG_GRKERNSEC_HARDEN_PTRACE
	if (unlikely(!(gr_status & GR_READY)))
		return 0;
#endif

	read_lock(&tasklist_lock);
	read_lock(&grsec_exec_file_lock);
	filp = task->exec_file;

	while (tmp->pid > 0) {
		if (tmp == curtemp)
			break;
		tmp = tmp->parent;
	}

	if (!filp || (tmp->pid == 0 && ((grsec_enable_harden_ptrace && current_uid() && !(gr_status & GR_READY)) ||
				((gr_status & GR_READY)	&& !(current->acl->mode & GR_RELAXPTRACE))))) {
		read_unlock(&grsec_exec_file_lock);
		read_unlock(&tasklist_lock);
		return 1;
	}

#ifdef CONFIG_GRKERNSEC_HARDEN_PTRACE
	if (!(gr_status & GR_READY)) {
		read_unlock(&grsec_exec_file_lock);
		read_unlock(&tasklist_lock);
		return 0;
	}
#endif

	retmode = gr_search_file(filp->f_path.dentry, GR_NOPTRACE, filp->f_path.mnt);
	read_unlock(&grsec_exec_file_lock);
	read_unlock(&tasklist_lock);

	if (retmode & GR_NOPTRACE)
		return 1;

	if (!(current->acl->mode & GR_POVERRIDE) && !(current->role->roletype & GR_ROLE_GOD)
	    && (current->acl != task->acl || (current->acl != current->role->root_label
	    && current->pid != task->pid)))
		return 1;

	return 0;
}

int
gr_handle_ptrace(struct task_struct *task, const long request)
{
	struct task_struct *tmp = task;
	struct task_struct *curtemp = current;
	__u32 retmode;

#ifndef CONFIG_GRKERNSEC_HARDEN_PTRACE
	if (unlikely(!(gr_status & GR_READY)))
		return 0;
#endif

	read_lock(&tasklist_lock);
	while (tmp->pid > 0) {
		if (tmp == curtemp)
			break;
		tmp = tmp->parent;
	}

	if (tmp->pid == 0 && ((grsec_enable_harden_ptrace && current_uid() && !(gr_status & GR_READY)) ||
				((gr_status & GR_READY)	&& !(current->acl->mode & GR_RELAXPTRACE)))) {
		read_unlock(&tasklist_lock);
		gr_log_ptrace(GR_DONT_AUDIT, GR_PTRACE_ACL_MSG, task);
		return 1;
	}
	read_unlock(&tasklist_lock);

#ifdef CONFIG_GRKERNSEC_HARDEN_PTRACE
	if (!(gr_status & GR_READY))
		return 0;
#endif

	read_lock(&grsec_exec_file_lock);
	if (unlikely(!task->exec_file)) {
		read_unlock(&grsec_exec_file_lock);
		return 0;
	}

	retmode = gr_search_file(task->exec_file->f_path.dentry, GR_PTRACERD | GR_NOPTRACE, task->exec_file->f_path.mnt);
	read_unlock(&grsec_exec_file_lock);

	if (retmode & GR_NOPTRACE) {
		gr_log_ptrace(GR_DONT_AUDIT, GR_PTRACE_ACL_MSG, task);
		return 1;
	}
		
	if (retmode & GR_PTRACERD) {
		switch (request) {
		case PTRACE_POKETEXT:
		case PTRACE_POKEDATA:
		case PTRACE_POKEUSR:
#if !defined(CONFIG_PPC32) && !defined(CONFIG_PPC64) && !defined(CONFIG_PARISC) && !defined(CONFIG_ALPHA) && !defined(CONFIG_IA64)
		case PTRACE_SETREGS:
		case PTRACE_SETFPREGS:
#endif
#ifdef CONFIG_X86
		case PTRACE_SETFPXREGS:
#endif
#ifdef CONFIG_ALTIVEC
		case PTRACE_SETVRREGS:
#endif
			return 1;
		default:
			return 0;
		}
	} else if (!(current->acl->mode & GR_POVERRIDE) &&
		   !(current->role->roletype & GR_ROLE_GOD) &&
		   (current->acl != task->acl)) {
		gr_log_ptrace(GR_DONT_AUDIT, GR_PTRACE_ACL_MSG, task);
		return 1;
	}

	return 0;
}

static int is_writable_mmap(const struct file *filp)
{
	struct task_struct *task = current;
	struct acl_object_label *obj, *obj2;

	if (gr_status & GR_READY && !(task->acl->mode & GR_OVERRIDE) &&
	    !task->is_writable && S_ISREG(filp->f_path.dentry->d_inode->i_mode)) {
		obj = chk_obj_label(filp->f_path.dentry, filp->f_path.mnt, default_role->root_label);
		obj2 = chk_obj_label(filp->f_path.dentry, filp->f_path.mnt,
				     task->role->root_label);
		if (unlikely((obj->mode & GR_WRITE) || (obj2->mode & GR_WRITE))) {
			gr_log_fs_generic(GR_DONT_AUDIT, GR_WRITLIB_ACL_MSG, filp->f_path.dentry, filp->f_path.mnt);
			return 1;
		}
	}
	return 0;
}

int
gr_acl_handle_mmap(const struct file *file, const unsigned long prot)
{
	__u32 mode;

	if (unlikely(!file || !(prot & PROT_EXEC)))
		return 1;

	if (is_writable_mmap(file))
		return 0;

	mode =
	    gr_search_file(file->f_path.dentry,
			   GR_EXEC | GR_AUDIT_EXEC | GR_SUPPRESS,
			   file->f_path.mnt);

	if (!gr_tpe_allow(file))
		return 0;

	if (unlikely(!(mode & GR_EXEC) && !(mode & GR_SUPPRESS))) {
		gr_log_fs_rbac_generic(GR_DONT_AUDIT, GR_MMAP_ACL_MSG, file->f_path.dentry, file->f_path.mnt);
		return 0;
	} else if (unlikely(!(mode & GR_EXEC))) {
		return 0;
	} else if (unlikely(mode & GR_EXEC && mode & GR_AUDIT_EXEC)) {
		gr_log_fs_rbac_generic(GR_DO_AUDIT, GR_MMAP_ACL_MSG, file->f_path.dentry, file->f_path.mnt);
		return 1;
	}

	return 1;
}

int
gr_acl_handle_mprotect(const struct file *file, const unsigned long prot)
{
	__u32 mode;

	if (unlikely(!file || !(prot & PROT_EXEC)))
		return 1;

	if (is_writable_mmap(file))
		return 0;

	mode =
	    gr_search_file(file->f_path.dentry,
			   GR_EXEC | GR_AUDIT_EXEC | GR_SUPPRESS,
			   file->f_path.mnt);

	if (!gr_tpe_allow(file))
		return 0;

	if (unlikely(!(mode & GR_EXEC) && !(mode & GR_SUPPRESS))) {
		gr_log_fs_rbac_generic(GR_DONT_AUDIT, GR_MPROTECT_ACL_MSG, file->f_path.dentry, file->f_path.mnt);
		return 0;
	} else if (unlikely(!(mode & GR_EXEC))) {
		return 0;
	} else if (unlikely(mode & GR_EXEC && mode & GR_AUDIT_EXEC)) {
		gr_log_fs_rbac_generic(GR_DO_AUDIT, GR_MPROTECT_ACL_MSG, file->f_path.dentry, file->f_path.mnt);
		return 1;
	}

	return 1;
}

void
gr_acl_handle_psacct(struct task_struct *task, const long code)
{
	unsigned long runtime;
	unsigned long cputime;
	unsigned int wday, cday;
	__u8 whr, chr;
	__u8 wmin, cmin;
	__u8 wsec, csec;
	struct timespec timeval;

	if (unlikely(!(gr_status & GR_READY) || !task->acl ||
		     !(task->acl->mode & GR_PROCACCT)))
		return;

	do_posix_clock_monotonic_gettime(&timeval);
	runtime = timeval.tv_sec - task->start_time.tv_sec;
	wday = runtime / (3600 * 24);
	runtime -= wday * (3600 * 24);
	whr = runtime / 3600;
	runtime -= whr * 3600;
	wmin = runtime / 60;
	runtime -= wmin * 60;
	wsec = runtime;

	cputime = (task->utime + task->stime) / HZ;
	cday = cputime / (3600 * 24);
	cputime -= cday * (3600 * 24);
	chr = cputime / 3600;
	cputime -= chr * 3600;
	cmin = cputime / 60;
	cputime -= cmin * 60;
	csec = cputime;

	gr_log_procacct(GR_DO_AUDIT, GR_ACL_PROCACCT_MSG, task, wday, whr, wmin, wsec, cday, chr, cmin, csec, code);

	return;
}

void gr_set_kernel_label(struct task_struct *task)
{
	if (gr_status & GR_READY) {
		task->role = kernel_role;
		task->acl = kernel_role->root_label;
	}
	return;
}

#ifdef CONFIG_TASKSTATS
int gr_is_taskstats_denied(int pid)
{
	struct task_struct *task;
#if defined(CONFIG_GRKERNSEC_PROC_USER) || defined(CONFIG_GRKERNSEC_PROC_USERGROUP)
	const struct cred *cred;
#endif
	int ret = 0;

	/* restrict taskstats viewing to un-chrooted root users
	   who have the 'view' subject flag if the RBAC system is enabled
	*/

	read_lock(&tasklist_lock);
	task = find_task_by_vpid(pid);
	if (task) {
		gr_fs_read_lock(task);
#ifdef CONFIG_GRKERNSEC_CHROOT
		if (proc_is_chrooted(task))
			ret = -EACCES;
#endif
#if defined(CONFIG_GRKERNSEC_PROC_USER) || defined(CONFIG_GRKERNSEC_PROC_USERGROUP)
		cred = __task_cred(task);
#ifdef CONFIG_GRKERNSEC_PROC_USER
		if (cred->uid != 0)
			ret = -EACCES;
#elif defined(CONFIG_GRKERNSEC_PROC_USERGROUP)
		if (cred->uid != 0 && !groups_search(cred->group_info, CONFIG_GRKERNSEC_PROC_GID))
			ret = -EACCES;
#endif
#endif
		if (gr_status & GR_READY) {
			if (!(task->acl->mode & GR_VIEW))
				ret = -EACCES;
		}
		
		gr_fs_read_unlock(task);
	} else
		ret = -ENOENT;

	read_unlock(&tasklist_lock);

	return ret;
}
#endif

int gr_acl_handle_filldir(const struct file *file, const char *name, const unsigned int namelen, const ino_t ino)
{
	struct task_struct *task = current;
	struct dentry *dentry = file->f_path.dentry;
	struct vfsmount *mnt = file->f_path.mnt;
	struct acl_object_label *obj, *tmp;
	struct acl_subject_label *subj;
	unsigned int bufsize;
	int is_not_root;
	char *path;

	if (unlikely(!(gr_status & GR_READY)))
		return 1;

	if (task->acl->mode & (GR_LEARN | GR_INHERITLEARN))
		return 1;

	/* ignore Eric Biederman */
	if (IS_PRIVATE(dentry->d_inode))
		return 1;

	subj = task->acl;
	do {
		obj = lookup_acl_obj_label(ino, dentry->d_inode->i_sb->s_dev, subj);
		if (obj != NULL)
			return (obj->mode & GR_FIND) ? 1 : 0;
	} while ((subj = subj->parent_subject));
	
	/* this is purely an optimization since we're looking for an object
	   for the directory we're doing a readdir on
	   if it's possible for any globbed object to match the entry we're
	   filling into the directory, then the object we find here will be
	   an anchor point with attached globbed objects
	*/
	obj = chk_obj_label_noglob(dentry, mnt, task->acl);
	if (obj->globbed == NULL)
		return (obj->mode & GR_FIND) ? 1 : 0;

	is_not_root = ((obj->filename[0] == '/') &&
		   (obj->filename[1] == '\0')) ? 0 : 1;
	bufsize = PAGE_SIZE - namelen - is_not_root;

	/* check bufsize > PAGE_SIZE || bufsize == 0 */
	if (unlikely((bufsize - 1) > (PAGE_SIZE - 1)))
		return 1;

	preempt_disable();
	path = d_real_path(dentry, mnt, per_cpu_ptr(gr_shared_page[0], smp_processor_id()),
			   bufsize);

	bufsize = strlen(path);

	/* if base is "/", don't append an additional slash */
	if (is_not_root)
		*(path + bufsize) = '/';
	memcpy(path + bufsize + is_not_root, name, namelen);
	*(path + bufsize + namelen + is_not_root) = '\0';

	tmp = obj->globbed;
	while (tmp) {
		if (!glob_match(tmp->filename, path)) {
			preempt_enable();
			return (tmp->mode & GR_FIND) ? 1 : 0;
		}
		tmp = tmp->next;
	}
	preempt_enable();
	return (obj->mode & GR_FIND) ? 1 : 0;
}

EXPORT_SYMBOL(gr_learn_resource);
EXPORT_SYMBOL(gr_set_kernel_label);
#ifdef CONFIG_SECURITY
EXPORT_SYMBOL(gr_check_user_change);
EXPORT_SYMBOL(gr_check_group_change);
#endif

