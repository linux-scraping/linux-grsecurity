#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/mm.h>
#include <asm/scatterlist.h>
#include <linux/crypto.h>
#include <linux/gracl.h>


#if !defined(CONFIG_CRYPTO) || defined(CONFIG_CRYPTO_MODULE) || !defined(CONFIG_CRYPTO_SHA256) || defined(CONFIG_CRYPTO_SHA256_MODULE)
#error "crypto and sha256 must be built into the kernel"
#endif

int
chkpw(struct gr_arg *entry, unsigned char *salt, unsigned char *sum)
{
	char *p;
	struct crypto_tfm *tfm;
	unsigned char temp_sum[GR_SHA_LEN];
	struct scatterlist sg[2];
	volatile int retval = 0;
	volatile int dummy = 0;
	unsigned int i;

	tfm = crypto_alloc_tfm("sha256", 0);
	if (tfm == NULL) {
		/* should never happen, since sha256 should be built in */
		return 1;
	}

	crypto_digest_init(tfm);

	p = salt;
	sg[0].page = virt_to_page(p);
	sg[0].offset = ((long) p & ~PAGE_MASK);
	sg[0].length = GR_SALT_LEN;
	
	crypto_digest_update(tfm, sg, 1);

	p = entry->pw;
	sg[0].page = virt_to_page(p);
	sg[0].offset = ((long) p & ~PAGE_MASK);
	sg[0].length = strlen(entry->pw);

	crypto_digest_update(tfm, sg, 1);

	crypto_digest_final(tfm, temp_sum);

	memset(entry->pw, 0, GR_PW_LEN);

	for (i = 0; i < GR_SHA_LEN; i++)
		if (sum[i] != temp_sum[i])
			retval = 1;
		else
			dummy = 1;	// waste a cycle

	crypto_free_tfm(tfm);

	return retval;
}
