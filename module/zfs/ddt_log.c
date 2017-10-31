/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
 *
 * You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
 * or http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at usr/src/OPENSOLARIS.LICENSE.
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 */

/*
 * Copyright (c) 2009, 2010, Oracle and/or its affiliates. All rights reserved.
 */

#include <sys/zfs_context.h>
#include <sys/spa.h>
#include <sys/zio.h>
#include <sys/ddt.h>
#include <sys/zap.h>
#include <sys/dmu_tx.h>
#include <util/sscanf.h>

int ddt_log_blksz = 128*1024;
int ddt_log_maxinflation_pct = 200;

typedef struct ddt_log_phys {
	uint64_t dlp_numents;
} ddt_log_phys_t;

typedef struct ddt_log_entry_phys {
	ddt_key_t dlep_key;
	ddt_phys_t dlep_phys[DDT_PHYS_TYPES];
} ddt_log_entry_phys_t;

typedef struct ddt_tree_entry {
	ddt_log_entry_phys_t	entry;
	avl_node_t		node;
} ddt_tree_entry_t;

typedef struct ddt_log {
	dmu_buf_user_t dl_dbu;
	objset_t *dl_os;
	uint64_t dl_object;
	dmu_buf_t *dl_dbuf;
	avl_tree_t dl_tree;
	kmutex_t dl_lock;
	boolean_t dl_loaded;
} ddt_log_t;

static void ddt_log_evict_func(void *user_ptr)
{
	ddt_log_t *dl = user_ptr;
	ddt_tree_entry_t *dte;
	void *cookie = NULL;

	while ((dte = avl_destroy_nodes(&dl->dl_tree, &cookie)) != NULL) {
		kmem_free(dte, sizeof (*dte));
	}

	avl_destroy(&dl->dl_tree);
	mutex_destroy(&dl->dl_lock);
	kmem_free(dl, sizeof (*dl));
}

static void
assign_phys(ddt_phys_t *dest, const ddt_phys_t *src)
{
	for (int k = 0; k < DDT_PHYS_TYPES; k++)
		dest[k] = src[k];
}

static inline ddt_log_phys_t *
ddt_log_phys(ddt_log_t *dl)
{
	return (dl->dl_dbuf->db_data);
}

static boolean_t
phys_refcount_zero(const ddt_phys_t *dp)
{
	for (int k = 0; k < DDT_PHYS_TYPES; k++) {
		if (dp[k].ddp_refcnt != 0)
			return (B_FALSE);
	}
	return (B_TRUE);
}

static void
ddt_log_load(ddt_log_t *dl)
{
	ASSERT(MUTEX_HELD(&dl->dl_lock));
	for (uint64_t i = 0; i < ddt_log_phys(dl)->dlp_numents; i++) {
		ddt_log_entry_phys_t dlep;

		VERIFY0(dmu_read(dl->dl_os, dl->dl_object, i * sizeof (dlep),
		    sizeof (dlep), &dlep, 0));

		avl_index_t where;
		ddt_tree_entry_t *dte;
		dte = avl_find(&dl->dl_tree, &dlep, &where);

		if (phys_refcount_zero(dlep.dlep_phys)) {
			if (dte != NULL) {
				avl_remove(&dl->dl_tree, dte);
				kmem_free(dte, sizeof (*dte));
			}
			continue;
		}
		if (dte == NULL) {
			dte = kmem_zalloc(sizeof (*dte), KM_SLEEP);
			dte->entry.dlep_key = dlep.dlep_key;
			avl_insert(&dl->dl_tree, dte, where);
		}
		assign_phys(dte->entry.dlep_phys, dlep.dlep_phys);
	}
}

static int
ddt_tree_entry_compare(const void *x1, const void *x2)
{
	const ddt_tree_entry_t *dde1 = x1;
	const ddt_tree_entry_t *dde2 = x2;
	const uint64_t *u1 = (const uint64_t *)&dde1->entry.dlep_key;
	const uint64_t *u2 = (const uint64_t *)&dde2->entry.dlep_key;

	for (int i = 0; i < DDT_KEY_WORDS; i++) {
		if (u1[i] < u2[i])
			return (-1);
		if (u1[i] > u2[i])
			return (1);
	}

	return (0);
}

static ddt_log_t *
ddt_log_hold(objset_t *os, uint64_t object, void *tag)
{
	dmu_buf_t *db;
	ddt_log_t *dl;
	VERIFY0(dmu_bonus_hold(os, object, tag, &db));
	dl = dmu_buf_get_user(db);
	if (dl == NULL) {
		dl = kmem_zalloc(sizeof (struct ddt_log), KM_SLEEP);
		dmu_buf_init_user(&dl->dl_dbu,
		    NULL, ddt_log_evict_func, &dl->dl_dbuf);
		dl->dl_os = os;
		dl->dl_object = object;
		dl->dl_dbuf = db;
		avl_create(&dl->dl_tree, ddt_tree_entry_compare,
		    sizeof (ddt_tree_entry_t),
		    offsetof(ddt_tree_entry_t, node));
		mutex_init(&dl->dl_lock, NULL, MUTEX_DEFAULT, NULL);
		dl->dl_loaded = B_FALSE;
		mutex_enter(&dl->dl_lock);
		ddt_log_t *winner = dmu_buf_set_user(db, &dl->dl_dbu);
		if (winner != NULL) {
			avl_destroy(&dl->dl_tree);
			mutex_exit(&dl->dl_lock);
			mutex_destroy(&dl->dl_lock);
			kmem_free(dl, sizeof (struct ddt_log));
			dl = winner;
		}
	} else {
		mutex_enter(&dl->dl_lock);
	}
	if (!dl->dl_loaded) {
		ddt_log_load(dl);
		dl->dl_loaded = B_TRUE;
	}
	return (dl);
}

static void
ddt_log_rele(ddt_log_t *dl, void *tag)
{
	mutex_exit(&dl->dl_lock);
	dmu_buf_rele(dl->dl_dbuf, tag);
}

/*
 * Open questions: After a certain number of log entries, we want to clear the list and rewrite it.  How/when to do that?
 * dmu_buf_get/set_user : store the in-memory structure in there
 */
/* ARGSUSED */
static int
ddt_log_create(objset_t *os, uint64_t *objectp, dmu_tx_t *tx, boolean_t prehash)
{
	*objectp = dmu_object_alloc(os, DMU_OTN_UINT64_METADATA, ddt_log_blksz,
	    DMU_OTN_UINT64_METADATA, sizeof (ddt_log_phys_t), tx);
	return (0);
}

static int
ddt_log_destroy(objset_t *os, uint64_t object, dmu_tx_t *tx)
{
	return (dmu_object_free(os, object, tx));
}

static int
ddt_log_lookup(objset_t *os, uint64_t object, ddt_entry_t *dde)
{
	struct ddt_log *dl = ddt_log_hold(os, object, FTAG);
	ddt_tree_entry_t seek;
	ddt_tree_entry_t *entry;

	seek.entry.dlep_key = dde->dde_key;
	entry = avl_find(&dl->dl_tree, &seek, NULL);
	if (entry == NULL) {
		ddt_log_rele(dl, FTAG);
		return (ENOENT);
	}
	assign_phys(dde->dde_phys, entry->entry.dlep_phys);
	ddt_log_rele(dl, FTAG);
	return (0);
}

/* ARGSUSED */
static void
ddt_log_prefetch(objset_t *os, uint64_t object, ddt_entry_t *dde)
{
	/* XXX nothing ? */
}

static void
append_entry(ddt_log_t *dl, ddt_log_entry_phys_t *dlep, dmu_tx_t *tx)
{
	uint64_t offset = ddt_log_phys(dl)->dlp_numents *
	    sizeof (ddt_log_entry_phys_t);
	ASSERT(MUTEX_HELD(&dl->dl_lock));
	dmu_buf_will_dirty(dl->dl_dbuf, tx);
	ddt_log_phys(dl)->dlp_numents++;
	dmu_write(dl->dl_os, dl->dl_object, offset, sizeof (*dlep), dlep, tx);
}

static void
ddt_log_condense(ddt_log_t *dl, dmu_tx_t *tx)
{
	ASSERT(MUTEX_HELD(&dl->dl_lock));

	zfs_dbgmsg("txg %llu: condensing ddt log "
	    "with %llu entries in-memory, %llu entries on-disk",
	    (longlong_t)dmu_tx_get_txg(tx),
	    (longlong_t)avl_numnodes(&dl->dl_tree),
	    (longlong_t)ddt_log_phys(dl)->dlp_numents);

	/* clear existing object */
	VERIFY0(dmu_free_range(dl->dl_os, dl->dl_object, 0, DMU_OBJECT_END, tx));
	dmu_buf_will_dirty(dl->dl_dbuf, tx);
	ddt_log_phys(dl)->dlp_numents = 0;

	for (ddt_tree_entry_t *dte = avl_first(&dl->dl_tree);
	    dte != NULL; dte = AVL_NEXT(&dl->dl_tree, dte)) {
		append_entry(dl, &dte->entry, tx);
	}
	ASSERT3U(avl_numnodes(&dl->dl_tree), ==, ddt_log_phys(dl)->dlp_numents);
}

static int
ddt_log_update(objset_t *os, uint64_t object, ddt_entry_t *dde, dmu_tx_t *tx)
{
	struct ddt_log *dl = ddt_log_hold(os, object, FTAG);
	ddt_tree_entry_t *dte;
	ddt_tree_entry_t seek;
	seek.entry.dlep_key = dde->dde_key;
	avl_index_t where;

	/*
	 * Update the entry stored in the in-memory representation.  If there
	 * isn't one, create it.
	 */
	dte = avl_find(&dl->dl_tree, &seek, &where);
	if (dte == NULL) {
		dte = kmem_zalloc(sizeof (*dte), KM_SLEEP);
		dte->entry.dlep_key = dde->dde_key;
		avl_insert(&dl->dl_tree, dte, where);
	}
	assign_phys(dte->entry.dlep_phys, dde->dde_phys);

	append_entry(dl, &dte->entry, tx);

	if (ddt_log_phys(dl)->dlp_numents >
	    avl_numnodes(&dl->dl_tree) * ddt_log_maxinflation_pct / 100 &&
	    ddt_log_phys(dl)->dlp_numents >
	    2 * ddt_log_blksz / sizeof (ddt_log_entry_phys_t)) {
		ddt_log_condense(dl, tx);
	}

	ddt_log_rele(dl, FTAG);
	return (0);
}

static int
ddt_log_remove(objset_t *os, uint64_t object, ddt_entry_t *dde, dmu_tx_t *tx)
{
	ddt_log_t *dl = ddt_log_hold(os, object, FTAG);
	ddt_tree_entry_t *buf, seek;
	seek.entry.dlep_key = dde->dde_key;

	/*
	 * Remove the entry from our in-memory representation.  If it's not
	 * present, return ENOENT.
	 */
	buf = avl_find(&dl->dl_tree, &seek, NULL);
	if (buf == NULL) {
		ddt_log_rele(dl, FTAG);
		return (ENOENT);
	}
	avl_remove(&dl->dl_tree, buf);

	/*
	 * Append a log entry with refcount = 0, so when load the ddt we don't
	 * keep this element in the dl_tree.
	 */
	bzero(buf->entry.dlep_phys, sizeof(buf->entry.dlep_phys));

	append_entry(dl, &buf->entry, tx);
	kmem_free(buf, sizeof (*buf));
	ddt_log_rele(dl, FTAG);
	return (0);
}

/* XXX assumes that first word of hash is unique */
static int
ddt_log_walk(objset_t *os, uint64_t object, ddt_entry_t *dde, uint64_t *walk)
{
	ddt_log_t *dl = ddt_log_hold(os, object, FTAG);
	ddt_tree_entry_t *dte;
	ddt_tree_entry_t seek = { 0 };
	seek.entry.dlep_key.ddk_cksum.zc_word[0] = *walk;
	avl_index_t where;

	/*
	 * Find the next entry in our in-memory representation.  If there
	 * are no more entries, return ENOENT.
	 */
	dte = avl_find(&dl->dl_tree, &seek, &where);
	dte = avl_nearest(&dl->dl_tree, where, AVL_AFTER);
	if (dte == NULL) {
		ddt_log_rele(dl, FTAG);
		return (ENOENT);
	}
	dde->dde_key = dte->entry.dlep_key;
	assign_phys(dde->dde_phys, dte->entry.dlep_phys);
	*walk = dte->entry.dlep_key.ddk_cksum.zc_word[0] + 1;
	ddt_log_rele(dl, FTAG);
	return (0);
}

static int
ddt_log_count(objset_t *os, uint64_t object, uint64_t *count)
{
	ddt_log_t *dl = ddt_log_hold(os, object, FTAG);
	uint64_t ret = avl_numnodes(&dl->dl_tree);
	ddt_log_rele(dl, FTAG);
	*count = ret;
	return (0);
}

const ddt_ops_t ddt_log_ops = {
	"log",
	ddt_log_create,
	ddt_log_destroy,
	ddt_log_lookup,
	ddt_log_prefetch,
	ddt_log_update,
	ddt_log_remove,
	ddt_log_walk,
	ddt_log_count,
};
