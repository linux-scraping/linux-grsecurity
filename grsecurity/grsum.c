#include <linux/err.h>
#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/mm.h>
#include <linux/scatterlist.h>
#include <linux/crypto.h>
#include <linux/gracl.h>


#if !defined(CONFIG_CRYPTO) || defined(CONFIG_CRYPTO_MODULE) || !defined(CONFIG_CRYPTO_SHA256) || defined(CONFIG_CRYPTO_SHA256_MODULE)
#error "crypto and sha256 must be built into the kernel"
#endif

int
chkpw(struct gr_arg *entry, unsigned char *salt, unsigned char *sum)
{
	struct crypto_hash *tfm;
	struct hash_desc desc;
	struct scatterlist sg[2];
	unsigned char temp_sum[GR_SHA_LEN] __attribute__((aligned(__alignof__(unsigned long))));
	unsigned long *tmpsumptr = (unsigned long *)temp_sum;
	unsigned long *sumptr = (unsigned long *)sum;
	int cryptres;
	int retval = 1;
	volatile int mismatched = 0;
	volatile int dummy = 0;
	unsigned int i;

	tfm = crypto_alloc_hash("sha256", 0, CRYPTO_ALG_ASYNC);
	if (IS_ERR(tfm)) {
		/* should never happen, since sha256 should be built in */
		memset(entry->pw, 0, GR_PW_LEN);
		return 1;
	}

	sg_init_table(sg, 2);
	sg_set_buf(&sg[0], salt, GR_SALT_LEN);
	sg_set_buf(&sg[1], entry->pw, strlen(entry->pw));

	desc.tfm = tfm;
	desc.flags = 0;

	cryptres = crypto_hash_digest(&desc, sg, GR_SALT_LEN + strlen(entry->pw),
					temp_sum);

	memset(entry->pw, 0, GR_PW_LEN);

	if (cryptres)
		goto out;

	for (i = 0; i < GR_SHA_LEN/sizeof(tmpsumptr[0]); i++)
		if (sumptr[i] != tmpsumptr[i])
			mismatched = 1;
		else
			dummy = 1;	// waste a cycle

	if (!mismatched)
		retval = dummy - 1;

out:
	crypto_free_hash(tfm);

	return retval;
}
