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
	char *p;
	struct crypto_hash *tfm;
	struct hash_desc desc;
	struct scatterlist sg;
	unsigned char temp_sum[GR_SHA_LEN];
	volatile int retval = 0;
	volatile int dummy = 0;
	unsigned int i;

	sg_init_table(&sg, 1);

	tfm = crypto_alloc_hash("sha256", 0, CRYPTO_ALG_ASYNC);
	if (IS_ERR(tfm)) {
		/* should never happen, since sha256 should be built in */
		return 1;
	}

	desc.tfm = tfm;
	desc.flags = 0;

	crypto_hash_init(&desc);

	p = salt;
	sg_set_buf(&sg, p, GR_SALT_LEN);
	crypto_hash_update(&desc, &sg, sg.length);

	p = entry->pw;
	sg_set_buf(&sg, p, strlen(p));
	
	crypto_hash_update(&desc, &sg, sg.length);

	crypto_hash_final(&desc, temp_sum);

	memset(entry->pw, 0, GR_PW_LEN);

	for (i = 0; i < GR_SHA_LEN; i++)
		if (sum[i] != temp_sum[i])
			retval = 1;
		else
			dummy = 1;	// waste a cycle

	crypto_free_hash(tfm);

	return retval;
}
