// SPDX-License-Identifier: GPL-2.0-only
/*
 * AEAD scatterlist layout test
 *
 * Check that an AEAD implementation gives the same result whatever the layout
 * of the request: random messages are processed once with the associated data
 * and the payload in a single entry each (contiguous buffers that may span
 * several pages, in place and out of place), and once scattered over many
 * small entries in separate pages.  Ciphertexts and tags must match, the
 * contiguous layout must decrypt back to the original message and a tampered
 * message must be rejected.
 *
 * Drivers often have a fast path for contiguous requests and a generic one
 * driven by skcipher_walk, and test vectors are too short to exercise
 * contiguous entries larger than a page.
 *
 * Copyright (c) 2026 Antonio Quartulli <antonio@mandelbit.com>
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <crypto/aead.h>
#include <linux/module.h>
#include <linux/random.h>
#include <linux/scatterlist.h>
#include <linux/sizes.h>
#include <linux/slab.h>
#include <linux/string.h>

#define TEST_MAX_AD		512
/* above SZ_64K to cover drivers capping their fast path there */
#define TEST_MAX_LEN		(SZ_64K + SZ_4K)
#define TEST_MAX_TAG		32
#define TEST_MAX_IV		32
#define TEST_MAX_KEY		32
#define TEST_BUF_LEN		(TEST_MAX_AD + TEST_MAX_LEN + TEST_MAX_TAG)
#define TEST_MAX_SG		512

static char *algs = "aegis128x4,gcm(aes),rfc7539(chacha20,poly1305)";
module_param(algs, charp, 0444);
MODULE_PARM_DESC(algs, "comma-separated list of AEAD algorithms to test");

static unsigned int iterations = 5000;
static unsigned int bench;
module_param(bench, uint, 0444);
MODULE_PARM_DESC(bench, "if set, time this many ovpn-like aegis128x4 encryptions per layout");
module_param(iterations, uint, 0444);
MODULE_PARM_DESC(iterations, "number of random messages per algorithm");

struct test_ctx {
	struct crypto_aead *tfm;
	struct aead_request *req;
	struct crypto_wait wait;
	u8 iv[TEST_MAX_IV];
	u8 *ref;	/* original message: AD || plaintext */
	u8 *lin;	/* contiguous layout */
	u8 *oop;	/* contiguous out-of-place destination */
	u8 *frag;	/* scattered layout, gathered back */
	u8 *ctsave;	/* reference ciphertext, kept intact */
	void *pages[TEST_MAX_SG];
	struct scatterlist sg_lin[3];
	struct scatterlist sg_oop[3];
	struct scatterlist sg_frag[TEST_MAX_SG];
	/* AD in the first entry, payload and tag scattered */
	struct scatterlist sg_s[TEST_MAX_SG / 2];
	struct scatterlist sg_d[TEST_MAX_SG / 2];
	unsigned long adfrag_fast;	/* requests within 64 entries */
};

static int test_run(struct test_ctx *t, struct scatterlist *src,
		    struct scatterlist *dst, unsigned int assoclen,
		    unsigned int cryptlen, bool enc)
{
	u8 iv[TEST_MAX_IV];

	/* the request may update the IV */
	memcpy(iv, t->iv, crypto_aead_ivsize(t->tfm));
	aead_request_set_ad(t->req, assoclen);
	aead_request_set_crypt(t->req, src, dst, cryptlen, iv);
	return crypto_wait_req(enc ? crypto_aead_encrypt(t->req) :
				     crypto_aead_decrypt(t->req), &t->wait);
}

/* AD entry, payload entry and tag entry, like a linear network packet */
static void test_sg_lin(struct scatterlist *sg, u8 *buf, unsigned int assoclen,
			unsigned int len, unsigned int authsize)
{
	sg_init_table(sg, 3);
	sg_set_buf(&sg[0], buf, assoclen);
	sg_set_buf(&sg[1], buf + assoclen, len);
	sg_set_buf(&sg[2], buf + assoclen + len, authsize);
}

/* copy @len bytes of @buf over randomly sized entries in separate pages */
static int test_sg_frag(struct test_ctx *t, const u8 *buf, unsigned int len)
{
	unsigned int off = 0, n = 0, l;

	sg_init_table(t->sg_frag, TEST_MAX_SG);
	do {
		/* mostly short entries, sometimes up to a full page */
		if (get_random_u32_below(8))
			l = 1 + get_random_u32_below(256);
		else
			l = 1 + get_random_u32_below(PAGE_SIZE);
		if (n == TEST_MAX_SG - 1)
			l = PAGE_SIZE;
		l = min(l, len - off);
		if (n == TEST_MAX_SG - 1 && off + l < len)
			return -E2BIG;

		/* place the data at a random offset in the page */
		memcpy(t->pages[n] + PAGE_SIZE - l, buf + off, l);
		sg_set_buf(&t->sg_frag[n], t->pages[n] + PAGE_SIZE - l, l);
		off += l;
		n++;
	} while (off < len);

	sg_mark_end(&t->sg_frag[n - 1]);
	return 0;
}

/*
 * Build @sg over @pages with the @assoclen bytes of AD contiguous in the first
 * entry and the following @rest bytes over a few entries of up to a page, each
 * in a separate page: the layout of an skb with page fragments.  Copy @buf, or
 * zero the payload (keeping the AD) if @zero.
 */
static int test_sg_adfrag(struct scatterlist *sg, void **pages, const u8 *buf,
			  unsigned int assoclen, unsigned int rest, bool zero)
{
	const unsigned int max = TEST_MAX_SG / 2;
	unsigned int off = 0, n = 0, l;

	sg_init_table(sg, max);
	if (assoclen) {
		memcpy(pages[0], buf, assoclen);
		sg_set_buf(&sg[0], pages[0], assoclen);
		n = 1;
	}

	while (off < rest) {
		if (n == max)
			return -E2BIG;
		l = get_random_u32_below(2) ? 1 + get_random_u32_below(512) :
					      1 + get_random_u32_below(PAGE_SIZE);
		l = min(l, rest - off);
		if (zero)
			memset(pages[n] + PAGE_SIZE - l, 0, l);
		else
			memcpy(pages[n] + PAGE_SIZE - l, buf + assoclen + off, l);
		sg_set_buf(&sg[n], pages[n] + PAGE_SIZE - l, l);
		off += l;
		n++;
	}

	sg_mark_end(&sg[n - 1]);
	return n;
}

/* scattered payload checks, both directions, in and out of place */
static int test_adfrag(struct test_ctx *t, const u8 *ct, unsigned int assoclen,
		       unsigned int len, unsigned int authsize)
{
	void **sp = t->pages, **dp = t->pages + TEST_MAX_SG / 2;
	const char *drv = crypto_aead_driver_name(t->tfm);
	unsigned int total = assoclen + len + authsize;
	int ns, nd, err, bit;

	/* encryption in place */
	ns = test_sg_adfrag(t->sg_s, sp, t->ref, assoclen, len + authsize,
			    false);
	if (ns < 0)
		return 0;
	if (ns <= 64)
		t->adfrag_fast++;
	err = test_run(t, t->sg_s, t->sg_s, assoclen, len, true);
	sg_copy_to_buffer(t->sg_s, ns, t->frag, total);
	if (err || memcmp(ct + assoclen, t->frag + assoclen, len + authsize)) {
		pr_err("%s: adfrag enc inplace: assoclen=%u len=%u authsize=%u err=%d\n",
		       drv, assoclen, len, authsize, err);
		return err ?: -EINVAL;
	}

	/* encryption out of place: scattered src and dst */
	ns = test_sg_adfrag(t->sg_s, sp, t->ref, assoclen, len, false);
	nd = test_sg_adfrag(t->sg_d, dp, t->ref, assoclen, len + authsize,
			    true);
	if (ns < 0 || nd < 0)
		return 0;
	err = test_run(t, t->sg_s, t->sg_d, assoclen, len, true);
	sg_copy_to_buffer(t->sg_d, nd, t->frag, total);
	if (err || memcmp(ct + assoclen, t->frag + assoclen, len + authsize)) {
		pr_err("%s: adfrag enc oop: assoclen=%u len=%u authsize=%u err=%d\n",
		       drv, assoclen, len, authsize, err);
		return err ?: -EINVAL;
	}

	/* scattered source, contiguous destination, both directions */
	ns = test_sg_adfrag(t->sg_s, sp, t->ref, assoclen, len, false);
	if (ns < 0)
		return 0;
	memcpy(t->oop, t->ref, assoclen);
	memset(t->oop + assoclen, 0, len + authsize);
	test_sg_lin(t->sg_oop, t->oop, assoclen, len, authsize);
	err = test_run(t, t->sg_s, t->sg_oop, assoclen, len, true);
	if (err || memcmp(ct + assoclen, t->oop + assoclen, len + authsize)) {
		pr_err("%s: adfrag enc to linear: assoclen=%u len=%u authsize=%u err=%d\n",
		       drv, assoclen, len, authsize, err);
		return err ?: -EINVAL;
	}
	ns = test_sg_adfrag(t->sg_s, sp, ct, assoclen, len + authsize, false);
	if (ns < 0)
		return 0;
	memset(t->oop + assoclen, 0, len + authsize);
	err = test_run(t, t->sg_s, t->sg_oop, assoclen, len + authsize, false);
	if (err || memcmp(t->ref + assoclen, t->oop + assoclen, len)) {
		pr_err("%s: adfrag dec to linear: assoclen=%u len=%u authsize=%u err=%d\n",
		       drv, assoclen, len, authsize, err);
		return err ?: -EINVAL;
	}

	/* decryption in place */
	ns = test_sg_adfrag(t->sg_s, sp, ct, assoclen, len + authsize, false);
	if (ns < 0)
		return 0;
	err = test_run(t, t->sg_s, t->sg_s, assoclen, len + authsize, false);
	sg_copy_to_buffer(t->sg_s, ns, t->frag, total);
	if (err || memcmp(t->ref, t->frag, assoclen + len)) {
		pr_err("%s: adfrag dec inplace: assoclen=%u len=%u authsize=%u err=%d\n",
		       drv, assoclen, len, authsize, err);
		return err ?: -EINVAL;
	}

	/* decryption out of place */
	ns = test_sg_adfrag(t->sg_s, sp, ct, assoclen, len + authsize, false);
	nd = test_sg_adfrag(t->sg_d, dp, ct, assoclen, len, true);
	if (ns < 0 || nd < 0)
		return 0;
	err = test_run(t, t->sg_s, t->sg_d, assoclen, len + authsize, false);
	sg_copy_to_buffer(t->sg_d, nd, t->frag, assoclen + len);
	if (err || memcmp(t->ref + assoclen, t->frag + assoclen, len)) {
		pr_err("%s: adfrag dec oop: assoclen=%u len=%u authsize=%u err=%d\n",
		       drv, assoclen, len, authsize, err);
		return err ?: -EINVAL;
	}

	/* a flipped bit must be rejected by a scattered decryption too */
	memcpy(t->frag, ct, total);
	bit = get_random_u32_below(total * 8);
	t->frag[bit / 8] ^= BIT(bit % 8);
	ns = test_sg_adfrag(t->sg_s, sp, t->frag, assoclen, len + authsize,
			    false);
	if (ns < 0)
		return 0;
	err = test_run(t, t->sg_s, t->sg_s, assoclen, len + authsize, false);
	if (err != -EBADMSG) {
		pr_err("%s: adfrag tampered message not rejected: assoclen=%u len=%u authsize=%u err=%d\n",
		       drv, assoclen, len, authsize, err);
		return -EINVAL;
	}

	return 0;
}

static unsigned int test_rand_len(unsigned int assoclen)
{
	switch (get_random_u32_below(8)) {
	case 0:
	case 1:
		return get_random_u32_below(PAGE_SIZE + 1);
	case 2:
		/* around the 64KiB boundary */
		return SZ_64K - assoclen - 2 + get_random_u32_below(5);
	case 3:
		return get_random_u32_below(TEST_MAX_LEN + 1);
	default:
		/* jumbo frame sizes, larger than a page */
		return PAGE_SIZE + get_random_u32_below(3 * PAGE_SIZE);
	}
}

static int test_one(struct test_ctx *t, unsigned int authsize)
{
	unsigned int assoclen, len, total;
	bool oop = get_random_u32_below(2);
	u8 *ct;
	int err;

	assoclen = get_random_u32_below(4) ? 8 :
		   get_random_u32_below(TEST_MAX_AD + 1);
	len = test_rand_len(assoclen);
	total = assoclen + len + authsize;

	get_random_bytes(t->iv, crypto_aead_ivsize(t->tfm));
	get_random_bytes(t->ref, assoclen + len);

	/* contiguous layout, in place or out of place */
	memcpy(t->lin, t->ref, assoclen + len);
	test_sg_lin(t->sg_lin, t->lin, assoclen, len, authsize);
	if (oop) {
		memcpy(t->oop, t->ref, assoclen);
		memset(t->oop + assoclen, 0, len + authsize);
		test_sg_lin(t->sg_oop, t->oop, assoclen, len, authsize);
	}
	err = test_run(t, t->sg_lin, oop ? t->sg_oop : t->sg_lin, assoclen,
		       len, true);
	if (err) {
		pr_err("%s: encryption failed: %d\n",
		       crypto_aead_driver_name(t->tfm), err);
		return err;
	}
	ct = oop ? t->oop : t->lin;
	memcpy(t->ctsave, ct, total);

	/* scattered layout, in place */
	err = test_sg_frag(t, t->ref, total);
	if (err)
		return err;
	err = test_run(t, t->sg_frag, t->sg_frag, assoclen, len, true);
	if (err) {
		pr_err("%s: scattered encryption failed: %d\n",
		       crypto_aead_driver_name(t->tfm), err);
		return err;
	}
	sg_copy_to_buffer(t->sg_frag, sg_nents(t->sg_frag), t->frag, total);

	if (memcmp(ct + assoclen, t->frag + assoclen, len + authsize)) {
		pr_err("%s: ciphertext mismatch: assoclen=%u len=%u authsize=%u oop=%d\n",
		       crypto_aead_driver_name(t->tfm), assoclen, len,
		       authsize, oop);
		return -EINVAL;
	}

	/* decrypt the contiguous layout in place */
	memcpy(t->lin, ct, total);
	err = test_run(t, t->sg_lin, t->sg_lin, assoclen, len + authsize,
		       false);
	if (err || memcmp(t->lin, t->ref, assoclen + len)) {
		pr_err("%s: decryption failed: assoclen=%u len=%u authsize=%u err=%d\n",
		       crypto_aead_driver_name(t->tfm), assoclen, len,
		       authsize, err);
		return err ?: -EINVAL;
	}

	/* a single flipped bit anywhere must be detected */
	memcpy(t->lin, ct, total);
	t->lin[get_random_u32_below(total)] ^= BIT(get_random_u32_below(8));
	err = test_run(t, t->sg_lin, t->sg_lin, assoclen, len + authsize,
		       false);
	if (err != -EBADMSG) {
		pr_err("%s: tampered message not rejected: assoclen=%u len=%u authsize=%u err=%d\n",
		       crypto_aead_driver_name(t->tfm), assoclen, len,
		       authsize, err);
		return -EINVAL;
	}

	return test_adfrag(t, t->ctsave, assoclen, len, authsize);
}

static int test_setkey(struct crypto_aead *tfm)
{
	static const unsigned int keylens[] = { 16, 32, 24 };
	u8 key[TEST_MAX_KEY];
	int i, err = -EINVAL;

	get_random_bytes(key, sizeof(key));
	for (i = 0; i < ARRAY_SIZE(keylens); i++) {
		err = crypto_aead_setkey(tfm, key, keylens[i]);
		if (!err)
			break;
	}

	return err;
}

static int test_alg(struct test_ctx *t, const char *alg)
{
	unsigned int authsizes[2], authsize, i, n;
	int err;

	t->tfm = crypto_alloc_aead(alg, 0, 0);
	if (IS_ERR(t->tfm)) {
		err = PTR_ERR(t->tfm);
		if (err == -ENOENT) {
			pr_info("%s: not available, skipping\n", alg);
			return 0;
		}
		pr_err("%s: allocation failed: %d\n", alg, err);
		return err;
	}

	err = -EINVAL;
	if (crypto_aead_ivsize(t->tfm) > TEST_MAX_IV ||
	    crypto_aead_maxauthsize(t->tfm) > TEST_MAX_TAG) {
		pr_err("%s: unsupported IV or tag size\n", alg);
		goto out_tfm;
	}

	t->req = aead_request_alloc(t->tfm, GFP_KERNEL);
	if (!t->req) {
		err = -ENOMEM;
		goto out_tfm;
	}
	crypto_init_wait(&t->wait);
	aead_request_set_callback(t->req, CRYPTO_TFM_REQ_MAY_BACKLOG |
				  CRYPTO_TFM_REQ_MAY_SLEEP, crypto_req_done,
				  &t->wait);

	authsizes[0] = crypto_aead_maxauthsize(t->tfm);
	authsizes[1] = min(16U, authsizes[0]);
	n = authsizes[0] == authsizes[1] ? 1 : 2;

	for (i = 0; i < iterations; i++) {
		/* fresh key for every message */
		err = test_setkey(t->tfm);
		if (err) {
			pr_err("%s: setkey failed: %d\n", alg, err);
			goto out_req;
		}

		authsize = authsizes[i % n];
		err = crypto_aead_setauthsize(t->tfm, authsize);
		if (err) {
			pr_err("%s: setauthsize(%u) failed: %d\n", alg,
			       authsize, err);
			goto out_req;
		}

		err = test_one(t, authsize);
		if (err)
			goto out_req;

		cond_resched();
	}

	pr_info("%s (%s): %u messages OK (%lu scattered-payload requests within 64 entries)\n",
		alg, crypto_aead_driver_name(t->tfm), iterations,
		t->adfrag_fast);
	t->adfrag_fast = 0;
out_req:
	aead_request_free(t->req);
out_tfm:
	crypto_free_aead(t->tfm);
	return err;
}

/*
 * Terminate the first algorithm name of the comma-separated list @alg and
 * return the next one, or NULL.  Commas within parentheses belong to the
 * name, e.g. "rfc7539(chacha20,poly1305)".
 */
static char *test_next_alg(char *alg)
{
	int depth = 0;

	for (; *alg; alg++) {
		if (*alg == '(') {
			depth++;
		} else if (*alg == ')') {
			depth--;
		} else if (*alg == ',' && !depth) {
			*alg = '\0';
			return alg + 1;
		}
	}

	return NULL;
}

static void test_bench_one(struct test_ctx *t, const char *what,
			   struct scatterlist *src, struct scatterlist *dst,
			   unsigned int len)
{
	u64 t0, t1;
	unsigned int i;

	for (i = 0; i < 1000; i++)
		test_run(t, src, dst, 8, len, true);
	t0 = ktime_get_ns();
	for (i = 0; i < bench; i++)
		test_run(t, src, dst, 8, len, true);
	t1 = ktime_get_ns();
	pr_info("bench %s len=%u: %llu ns/op\n", what, len,
		(t1 - t0) / bench);
}

/* ovpn-like layouts: AD entry, 52 bytes of headers, payload, tag entry */
static void test_bench(struct test_ctx *t)
{
	static const unsigned int lens[] = { 1368, 8868 };
	struct scatterlist src[5], dst[3];
	bool *sgp = NULL;
	unsigned int i;
	u8 *out;

	t->tfm = crypto_alloc_aead("aegis128x4", 0, 0);
	if (IS_ERR(t->tfm))
		return;
	t->req = aead_request_alloc(t->tfm, GFP_KERNEL);
	crypto_init_wait(&t->wait);
	aead_request_set_callback(t->req, 0, crypto_req_done, &t->wait);
	test_setkey(t->tfm);
	crypto_aead_setauthsize(t->tfm, 16);
	get_random_bytes(t->iv, 16);
	out = t->oop;
	(void)sgp;

	for (i = 0; i < ARRAY_SIZE(lens); i++) {
		unsigned int len = lens[i], first = PAGE_SIZE - 52;
		u8 *pay = t->frag;

		/* linear: one-shot path */
		test_sg_lin(t->sg_lin, t->lin, 8, len, 16);
		test_bench_one(t, "linear-inplace", t->sg_lin, t->sg_lin, len);

		/* src: AD | 52 B headers | payload in page-sized frags | */
		sg_init_table(src, 5);
		sg_set_buf(&src[0], t->pages[0], 8);
		sg_set_buf(&src[1], t->pages[1] + first, 52);
		if (len - 52 <= PAGE_SIZE) {
			sg_set_buf(&src[2], t->pages[2], len - 52);
			sg_mark_end(&src[2]);
		} else {
			sg_set_buf(&src[2], t->pages[2], PAGE_SIZE);
			sg_set_buf(&src[3], t->pages[3], PAGE_SIZE);
			sg_set_buf(&src[4], t->pages[4], len - 52 - 2 * PAGE_SIZE);
		}
		/* dst: AD | record payload slot | tag, contiguous */
		test_sg_lin(dst, out, 8, len, 16);
		(void)pay;
		test_bench_one(t, "frags-oop", src, dst, len);
	}
	aead_request_free(t->req);
	crypto_free_aead(t->tfm);
}

static int __init test_aead_sg_init(void)
{
	char *list, *alg;
	struct test_ctx *t;
	int i, err = -ENOMEM;

	t = kzalloc_obj(*t);
	if (!t)
		return -ENOMEM;

	t->ref = kmalloc(TEST_BUF_LEN, GFP_KERNEL);
	t->lin = kmalloc(TEST_BUF_LEN, GFP_KERNEL);
	t->oop = kmalloc(TEST_BUF_LEN, GFP_KERNEL);
	t->frag = kmalloc(TEST_BUF_LEN, GFP_KERNEL);
	t->ctsave = kmalloc(TEST_BUF_LEN, GFP_KERNEL);
	if (!t->ref || !t->lin || !t->oop || !t->frag || !t->ctsave)
		goto out;

	for (i = 0; i < TEST_MAX_SG; i++) {
		t->pages[i] = (void *)__get_free_page(GFP_KERNEL);
		if (!t->pages[i])
			goto out;
	}

	if (bench) {
		test_bench(t);
		err = 0;
		goto out;
	}

	list = kstrdup(algs, GFP_KERNEL);
	if (!list)
		goto out;

	err = 0;
	alg = list;
	while (!err && alg) {
		char *next = test_next_alg(alg);

		if (*alg)
			err = test_alg(t, alg);
		alg = next;
	}
	kfree(list);

out:
	for (i = 0; i < TEST_MAX_SG; i++)
		free_page((unsigned long)t->pages[i]);
	kfree(t->ctsave);
	kfree(t->frag);
	kfree(t->oop);
	kfree(t->lin);
	kfree(t->ref);
	kfree(t);

	return err;
}

static void __exit test_aead_sg_exit(void)
{
}

module_init(test_aead_sg_init);
module_exit(test_aead_sg_exit);

MODULE_DESCRIPTION("AEAD scatterlist layout test");
MODULE_AUTHOR("Antonio Quartulli <antonio@mandelbit.com>");
MODULE_LICENSE("GPL");
