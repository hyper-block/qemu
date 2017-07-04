#include "qemu/osdep.h"
#include "qemu-version.h"
#include "qapi/error.h"
#include "qapi-visit.h"
#include "qapi/qobject-output-visitor.h"
#include "qapi/qmp/qerror.h"
#include "qapi/qmp/qjson.h"
#include "qemu/cutils.h"
#include "qemu/config-file.h"
#include "qemu/option.h"
#include "qemu/error-report.h"
#include "qemu/log.h"
#include "qom/object_interfaces.h"
#include "sysemu/sysemu.h"
#include "block/block.h"
#include "sysemu/block-backend.h"
#include "block/block_int.h"
#include "block/blockjob.h"
#include "block/qapi.h"

#include "block/qcow2.h"
#include "crypto/init.h"
#include "trace/control.h"
#include "qcow2-img-utils.h"
#include <getopt.h>

static void set_disk_info(BlockDriverState *bs, Snapshot_cache_t *cache, uint64_t *l1_table_offset, uint32_t *l1_size)
{
    BDRVQcow2State *s = bs->opaque;
    if(cache->snapshot_index != SNAPSHOT_MAX_INDEX){
        QCowSnapshot *snapshot = &s->snapshots[cache->snapshot_index];
        *l1_size = snapshot->l1_size;
        *l1_table_offset = snapshot->l1_table_offset;
    }else{
        *l1_size = s->l1_size;
        *l1_table_offset = s->l1_table_offset;
    }
}

uint64_t get_layer_disk_size(BlockDriverState *bs, int snapshot_index)
{
    BDRVQcow2State *s = bs->opaque;
    if(snapshot_index != SNAPSHOT_MAX_INDEX){
        QCowSnapshot *snapshot = &s->snapshots[snapshot_index];
        return snapshot->disk_size;
    }else{
        return bs->total_sectors<<9;
    }
}

static int get_max_l1_size(BlockDriverState *bs)
{
    BDRVQcow2State *s = bs->opaque;
    int max_l1_size = s->l1_size;
    int i;
    for(i = 0; i < s->nb_snapshots; i++){
        QCowSnapshot *snapshot = &s->snapshots[i];
        max_l1_size = MAX(max_l1_size, snapshot->l1_size);
    }
    return max_l1_size;
}

uint64_t get_layer_cluster_nb(BlockDriverState *bs, int snapshot_index)
{
    return SIZE_TO_CLUSTER_NB(bs, get_layer_disk_size(bs, snapshot_index));
}

#define SNAPSHOT_MAX_INDEX (0x7fffffff)
int get_snapshot_cluster_l2_offset(BlockDriverState *bs, Snapshot_cache_t *cache, int64_t cluster_index, uint64_t* ret_offset)
{
    BDRVQcow2State *s = bs->opaque;
    int64_t cluster_nb;
    uint32_t l1_size = 0;
    uint64_t l1_table_offset = 0, disk_size = DISK_SIZE(bs);

    if(!cache || cache->snapshot_index < 0){
        *ret_offset = 0;
        return 0;
    }

    if(cache->snapshot_index >= (int)s->nb_snapshots && SNAPSHOT_MAX_INDEX != cache->snapshot_index){
        error_report("error cache->snapshot_index is %d, totoal is %d", cache->snapshot_index, s->nb_snapshots);
        goto faild;
    }

    if(cache->sn_l1_table_cache.table == NULL){
        set_disk_info(bs, cache, &l1_table_offset, &l1_size);
        int max_l1_size = get_max_l1_size(bs);
        if (l1_size > 0) {
            cache->sn_l1_table_cache.table = g_malloc0(align_offset(max_l1_size * sizeof(uint64_t), 512));
            cache->sn_l1_be_table_cache.table = g_malloc0(align_offset(max_l1_size * sizeof(uint64_t), 512));
            int ret;
            do{
                ret = bdrv_pread(bs->file, l1_table_offset, cache->sn_l1_table_cache.table, l1_size * sizeof(uint64_t));
            }while(ret == -EINPROGRESS);
            if (ret < 0) {
                error_report("bdrv_pread error ret %d, offset %ld size %ld", ret, l1_table_offset, l1_size * sizeof(uint64_t));
                goto faild;
            }
            cache->l1_size = l1_size;
            cache->l1_size_byte = l1_size * sizeof(uint64_t);
            cache->sn_l1_table_cache.cluster_offset = l1_table_offset;
            cache->sn_l1_be_table_cache.cluster_offset = l1_table_offset;
            memcpy(cache->sn_l1_be_table_cache.table, cache->sn_l1_table_cache.table, l1_size * sizeof(uint64_t));
            uint32_t i;
            for(i = 0;i < l1_size; i++) {
                be64_to_cpus(&cache->sn_l1_table_cache.table[i]);
                cache->sn_l1_table_cache.table[i] &= L1E_OFFSET_MASK;
            }
        }
    }

    cluster_nb = disk_size >> s->cluster_bits;
    if(cluster_index >= cluster_nb){
        error_report("cluster_index >= cluster_nb %ld %ld", cluster_index, cluster_nb);
faild:
        return -1;
    }
    uint64_t l1_index = cluster_index >> s->l2_bits;
    uint64_t l2_offset = cache->sn_l1_table_cache.table[l1_index];
    *ret_offset = l2_offset;

    return 0;
}

/**
 * ret < 0, error
 * ret == 0, l2 not allocated, so cluster is not allocated
 * ret > 0, acturely is 1, l2 is allocated, but cluster maybe not allocated
 */
int get_snapshot_cluster_offset(BlockDriverState *bs, Snapshot_cache_t *cache, int64_t cluster_index, uint64_t *ret_offset)
{
    BDRVQcow2State *s = bs->opaque;
    uint64_t l2_offset;
    int ret = get_snapshot_cluster_l2_offset(bs, cache, cluster_index, &l2_offset);
    if(ret < 0){
        error_report("%s get_snapshot_cluster_l2_offset ret %d", __func__, ret);
        return ret;
    }

    if (!l2_offset) {
        ret = 0;// no l2 allocated
        *ret_offset = 0;
        goto out;
    }

    if(unlikely(!cache->sn_l2_table_cache.table)){
        cache->sn_l2_table_cache.table = g_malloc0(align_offset(s->cluster_size, 512));
    }

    if( l2_offset != cache->sn_l2_table_cache.cluster_offset){
        // LOG_DEBUG("misss cache offset 0x%x", l2_offset);
        ret = bdrv_pread(bs->file, l2_offset, cache->sn_l2_table_cache.table, s->cluster_size);
        if (ret < 0) {
            return ret;
        }
        cache->sn_l2_table_cache.cluster_offset = l2_offset;
        uint32_t i;
        for(i = 0; i < (s->cluster_size / sizeof(uint64_t)); i++){
            be64_to_cpus(&cache->sn_l2_table_cache.table[i]);
        }
    }

    int l2_index = cluster_index & ((1 << s->l2_bits) - 1);
    uint64_t cluster_offset = cache->sn_l2_table_cache.table[l2_index];
    *ret_offset = cluster_offset;

    ret = 1; // l2 is allocated

out:
    return ret;
}

int get_snapshot_cluster_offset_with_zero_flag(BlockDriverState *bs, Snapshot_cache_t *cache, int64_t cluster_index, uint64_t *ret_offset)
{
    int ret = get_snapshot_cluster_offset(bs, cache, cluster_index, ret_offset);
    if(ret < 0)
        return ret;
    *ret_offset &= (L2E_OFFSET_MASK | QCOW_OFLAG_ZERO);
    return ret;
}

int get_snapshot_cluster_pure_offset(BlockDriverState *bs, Snapshot_cache_t *cache, int64_t cluster_index, uint64_t *ret_offset)
{
    int ret = get_snapshot_cluster_offset(bs, cache, cluster_index, ret_offset);
    if(ret < 0)
        return ret;
    *ret_offset &= L2E_OFFSET_MASK;
    return ret;
}

static int __is_backing_file_allocated(BlockDriverState *bs, int64_t cluster_index, int32_t cluster_bits)
{
    uint64_t cluster_offset;
    // unsigned int sector_nb = (1<<cluster_bits)>>9;
    unsigned int bytes = (1<<cluster_bits);
    int64_t offset = cluster_index<<cluster_bits;

    if(!bs){
        return 0;
    }

    int ret = qcow2_get_cluster_offset(bs, offset, &bytes, &cluster_offset);
    if(ret < 0){
        error_report("error is_backing_file_allocated ret %d", ret);
        return ret;
    }
    if(cluster_offset == 0){
        return 0;
    }
    return 1;
}

static int is_backing_file_allocated(BlockDriverState *_backing_bs, int64_t cluster_index, int32_t cluster_bits, BlockDriverState **real_data_backing_bs)
{
    BlockDriverState *backing_bs = _backing_bs;
    *real_data_backing_bs = NULL;
    while(backing_bs){
        int ret = __is_backing_file_allocated(backing_bs, cluster_index, cluster_bits);
        if(ret == 1){
            *real_data_backing_bs = backing_bs;
            return ret;
        }
        if(ret < 0){
            return ret;
        }
        backing_bs = backing_bs->backing? backing_bs->backing->bs : NULL;
    }
    return 0;
}

// a cluster one time, for full read
int read_snapshot_cluster_get_offset(BlockDriverState *bs, Snapshot_cache_t *cache, int64_t cluster_index, ClusterData_t *data,
                                     uint64_t *out_offset, bool* backing_with_data, ClusterData_t *backing_data)
{
    BlockDriverState *backing_bs = bs->backing->bs;
    BlockDriverState *real_data_backing_bs = NULL;
    BDRVQcow2State *s = bs->opaque;
    uint64_t cluster_offset;

    int isbaking_alloc = is_backing_file_allocated(backing_bs, cluster_index, s->cluster_bits, &real_data_backing_bs);
    if(isbaking_alloc < 0){
        return -1;
    }
    if(out_offset)
        *out_offset = 0;
    if(backing_with_data)
        *backing_with_data = !!isbaking_alloc;

    int ret = get_snapshot_cluster_offset(bs, cache, cluster_index, &cluster_offset);
    if(ret < 0){
        error_report("%s get_snapshot_cluster_offset ret %d", __func__, ret);
        return ret;
    }
    bool zero_flag = false;
    int use_backing = 0;
    ret = qcow2_get_cluster_type(cluster_offset);
    switch(ret){
    case QCOW2_CLUSTER_UNALLOCATED:
        if(cache->read_backingfile){
            use_backing = isbaking_alloc;
        }
        if(use_backing == 1){
            // LOG_DEBUG("read snapshot cluster %ld is in backing file", cluster_index);
            break;
        }
        // use_backing == 0, backing al
        goto unalloc;
        break;
    case QCOW2_CLUSTER_ZERO: // zeros treated equal to normal
    case QCOW2_CLUSTER_NORMAL:
        if(out_offset)
            *out_offset = cluster_offset & (L2E_OFFSET_MASK | QCOW_OFLAG_ZERO);
        zero_flag = !!(cluster_offset & QCOW_OFLAG_ZERO);
        cluster_offset &= L2E_OFFSET_MASK;
        break;
    default:
        error_report("error unknown type ret %d", ret);
        return -1;
        break;
    }
    if(!data){
        goto normal;
    }

    data->cluset_index = cluster_index;

    if(isbaking_alloc && backing_data){
        ret = bdrv_pread(real_data_backing_bs->file, cluster_index<<s->cluster_bits, backing_data->buf, s->cluster_size);
        if(ret < 0){
            return -1;
        }
        backing_data->cluset_index = cluster_index;
    }

    if(use_backing){
        if(backing_data){
            memcpy(data->buf, backing_data->buf, s->cluster_size);
            ret = s->cluster_size;
        }else{
            ret = bdrv_pread(real_data_backing_bs->file, cluster_index<<s->cluster_bits, data->buf, s->cluster_size);
        }
    }else{
        if(!zero_flag){
            ret = bdrv_pread(bs->file, cluster_offset, data->buf, s->cluster_size);
        } else { // cluster_offset is zero, just use memset
            ret = s->cluster_size;
            memset(data->buf, 0, s->cluster_size);
        }
    }
    if(ret < 0){
        return -1;
    }
normal:
    if(zero_flag){
        // LOG_INFO("cluster index %ld is zeros", cluster_index);
        return 2;
    }
    return 1;
unalloc:
    return 0;
}

int read_snapshot_cluster(BlockDriverState *bs, Snapshot_cache_t *cache, int64_t cluster_index, ClusterData_t *data)
{
    return read_snapshot_cluster_get_offset(bs, cache, cluster_index, data, NULL, NULL, NULL);
}

// not include None allocated clusters
int count_full_image_clusters(BlockDriverState *bs, Snapshot_cache_t *cache, uint64_t *allocated_cluster_count, uint64_t start_cluster)
{
    uint64_t total_cluster_count;
    *allocated_cluster_count = 0;
    total_cluster_count = TOTAL_CLUSTER_NB(bs);
    uint64_t i;
    for(i = start_cluster; i < total_cluster_count; i ++){
        int ret = read_snapshot_cluster(bs, cache, i, NULL);
        if(ret < 0)
            return ret;

        if(ret == 1 || ret == 2){
            *allocated_cluster_count += 1;
        }
    }
    return 0;
}

// FOR INCREMENT READ, 1 means success, 0 not allocated, -1 error
int read_snapshot_cluster_increment(BlockDriverState *bs, Snapshot_cache_t *self_cache, Snapshot_cache_t *father_cache,
                                    int64_t cluster_index, ClusterData_t *data, bool* is_0_offset)
{
    uint64_t self_cluster_offset, pure_self_cluster_offset, father_cluster_offset;
    int ret1, ret2;
    ret1 = get_snapshot_cluster_offset_with_zero_flag(bs, self_cache, cluster_index, &self_cluster_offset);
    ret2 = get_snapshot_cluster_offset_with_zero_flag(bs, father_cache, cluster_index, &father_cluster_offset);
    if(ret1 < 0 || ret2 < 0){
        return -1; // failed
    }
    // if zeros flag set, self_cluster_offset is |1, if both |1, so self_cluster_offset == father_cluster_offset
    if(self_cluster_offset == father_cluster_offset || self_cluster_offset == 0){
        if(is_0_offset){
            *is_0_offset = (self_cluster_offset == 0);
        }
        return 0; // same as father or not allocated
    }
    // allocated or zeros
    pure_self_cluster_offset = self_cluster_offset & L2E_OFFSET_MASK;
    bool zero_flag = !!(self_cluster_offset & QCOW_OFLAG_ZERO);

    if(!data){
        goto out;
    }
    BDRVQcow2State *s = bs->opaque;
    data->cluset_index = cluster_index;
    if(zero_flag){
        memset(data->buf, 0, s->cluster_size);
    }else{
        int ret = bdrv_pread(bs->file, pure_self_cluster_offset, data->buf, s->cluster_size);
        if(ret < 0){
            return ret;
        }
    }
out:
    if(zero_flag){
        // LOG_INFO("cluster index %ld is zeros", cluster_index);
        return 2;
    }
    return 1;
}

int count_increment_clusters(BlockDriverState *bs, Snapshot_cache_t *self_cache, Snapshot_cache_t *father_cache, uint64_t *increment_cluster_count, uint64_t start_cluster)
{
    uint64_t total_cluster_count;
    *increment_cluster_count = 0;
    total_cluster_count = TOTAL_CLUSTER_NB(bs);
    uint64_t i;
    for(i = start_cluster; i < total_cluster_count; i++){
        int ret = read_snapshot_cluster_increment(bs, self_cache, father_cache, i, NULL, NULL);
        if(ret < 0)
            return ret;

        if(ret == 1 || ret == 2){
            (*increment_cluster_count) += 1;
        }
    }
    return 0;
}

static int _bdrv_pwrite(BlockDriverState *bs, int64_t offset, char *buf, int bytes)
{
	struct iovec iov[1];
	iov[0].iov_base = (void*)buf;
	iov[0].iov_len = bytes;
	QEMUIOVector qiov;
	qemu_iovec_init_external(&qiov, iov, 1);

	int ret = bs->drv->bdrv_co_pwritev(bs, offset, bytes, &qiov, 0);
	if(ret < 0){
		return ret;
	}
	return bytes;
}

static int bdrv_write_zeros(BlockDriverState *bs, int64_t offset, int bytes)
{
	int ret = bs->drv->bdrv_co_pwrite_zeroes(bs, offset>>BDRV_SECTOR_BITS, bytes>>BDRV_SECTOR_BITS, BDRV_REQ_ZERO_WRITE);
	if(ret < 0){
		return ret;
	}
	return bytes;
}

static int allocate_l2(BlockDriverState *bs, uint64_t *l1_table, uint64_t *l1_be_table, int l1_index, Qcow2Cache *l2_table_cache, uint64_t *out_l2_offset, void** l2_table)
{
	int ret = 0;
	uint64_t old_l2_offset = *out_l2_offset;
	struct BDRVQcow2State * s = bs->opaque;
	int64_t l2_offset = qcow2_alloc_clusters(bs, s->l2_size * sizeof(uint64_t));
	if (l2_offset < 0) {
		ret = l2_offset;
		goto out;
	}
	// LOG_INFO("allocate_l2 %d %016lx", l1_index, l2_offset);
	ret = qcow2_cache_flush(bs, s->refcount_block_cache);
	if (ret < 0) {
		goto out;
	}
	ret = qcow2_cache_get_empty(bs, l2_table_cache, l2_offset, l2_table);
	if (ret < 0) {
		goto out;
	}

	if(!old_l2_offset){
		memset(*l2_table, 0, s->l2_size * sizeof(uint64_t));
	}else{
		// LOG_INFO("copy-l2-of l1_index %d", l1_index);
		uint64_t* old_table;
		/* if there was an old l2 table, read it from the disk */
		ret = qcow2_cache_get(bs, l2_table_cache,
			old_l2_offset & L1E_OFFSET_MASK,
			(void**) &old_table);
		if (ret < 0) {
			goto out1;
		}

		memcpy(*l2_table, old_table, s->cluster_size);

		qcow2_cache_put(bs, l2_table_cache, (void**) &old_table);
		qcow2_free_clusters(bs, old_l2_offset & L1E_OFFSET_MASK, s->cluster_size, QCOW2_DISCARD_OTHER);
	}

	qcow2_cache_entry_mark_dirty(bs, l2_table_cache, *l2_table);
	ret = qcow2_cache_flush(bs, l2_table_cache);
	if (ret < 0) {
		goto out1;
	}
	l1_table[l1_index] = l2_offset;
	l1_be_table[l1_index] = cpu_to_be64(l2_offset | QCOW_OFLAG_COPIED);
	*out_l2_offset = l2_offset;
out1:
	qcow2_cache_put(bs, l2_table_cache, l2_table);
out:
	return ret;
}

static int qcow2_write_snapshot_cluster_zero(BlockDriverState *bs, uint64_t *l1_table/*little end with no flag*/,uint64_t *l1_be_table, int l1_table_len, Qcow2Cache *l2_table_cache, uint64_t cluster_index, bool flush)
{
	int ret = 0;
	struct BDRVQcow2State * s = bs->opaque;
	int l1_index = cluster_index >> s->l2_bits;
	int l2_index = cluster_index & ((1 << s->l2_bits) - 1);
	uint64_t l2_offset = l1_table[l1_index];
	l2_offset &= L1E_OFFSET_MASK;
	uint64_t l2_offset_with_flag = be64_to_cpu(l1_be_table[l1_index]);
	uint64_t *l2_table = NULL;

	if(0 == l2_offset || !(l2_offset_with_flag & QCOW_OFLAG_COPIED)){
		ret = allocate_l2(bs, l1_table, l1_be_table, l1_index, l2_table_cache, &l2_offset, (void**)&l2_table);
		if(ret < 0){
			goto out;
		}
	}
	ret = qcow2_cache_get(bs, l2_table_cache, l2_offset, (void**) &l2_table);
	if(ret < 0){
		goto out;
	}

	l2_table[l2_index] |= cpu_to_be64(QCOW_OFLAG_ZERO);
	qcow2_cache_entry_mark_dirty(bs, l2_table_cache, l2_table);
	if(flush){
		ret = qcow2_cache_flush(bs, l2_table_cache);
		if (ret < 0) {
			goto fail;
		}
	}

fail:
	qcow2_cache_put(bs, l2_table_cache, (void**) &l2_table);
out:
	return ret;
}

static inline void * get_l1_table(BlockDriverState *bs, Snapshot_cache_t *cache)
{
	uint64_t offset;
	int ret = get_snapshot_cluster_l2_offset(bs, cache, 0, &offset);
	if(ret < 0)
		return (void *)-1;
	return cache->sn_l1_table_cache.table; // if snapshot index < 0, this will be NULL
}

static inline void * get_l1_be_table(BlockDriverState *bs, Snapshot_cache_t *cache)
{
	uint64_t offset;
	int ret = get_snapshot_cluster_l2_offset(bs, cache, 0, &offset);
	if(ret < 0)
		return (void *)-1;
	return cache->sn_l1_be_table_cache.table; // if snapshot index < 0, this will be NULL
}

static void allocate_caches(Snapshot_cache_t* current_cache, Snapshot_cache_t** out_snapshots_cache, int nb_snapshots)
{
	Snapshot_cache_t *snapshots_cache = zalloc(nb_snapshots*sizeof(Snapshot_cache_t));
	init_cache(current_cache, SNAPSHOT_MAX_INDEX);
	int i;
	for(i = 0; i < nb_snapshots; i++){
		init_cache(&snapshots_cache[i], i);
	}
	*out_snapshots_cache = snapshots_cache;
}

static int allocate_cluster(BlockDriverState *bs, Qcow2Cache *l2_table_cache, uint64_t *l2_table, uint64_t l2_offset, int l2_index, uint64_t *out_cluster_offset, uint64_t *in_cluster_offset)
{
	int ret = 0;
	struct BDRVQcow2State * s = bs->opaque;
	int64_t cluster_offset;
	int ref = 0;
	if(in_cluster_offset && *in_cluster_offset){
		cluster_offset = *in_cluster_offset;
		ref = qcow2_update_cluster_refcount(bs, cluster_offset >> s->cluster_bits, 1, false, QCOW2_DISCARD_SNAPSHOT);
		if(ref < 0){
			error_report("error qcow2_update_cluster_refcount ret %d", ref);
			return ref;
		}
		// error_report("cluster index %ld reference-set to %d", cluster_offset >> s->cluster_bits, ref);
		goto store_offset;
	}

	cluster_offset = qcow2_alloc_clusters(bs, s->cluster_size);
	if(cluster_offset < 0){
		ret = cluster_offset;
		goto out;
	}
	ret = qcow2_cache_flush(bs, s->refcount_block_cache);
	if (ret < 0) {
		goto out;
	}

store_offset:
	error_report("L2 %016lx l2_index %d cluster offset %016lx ref %d", l2_offset, l2_index, cluster_offset, ref);
	l2_table[l2_index] = cpu_to_be64(cluster_offset);
	*out_cluster_offset = cluster_offset;

	qcow2_cache_entry_mark_dirty(bs, l2_table_cache, l2_table);
	ret = qcow2_cache_flush(bs, l2_table_cache);
	if (ret < 0) {
		goto out;
	}
out:
	return ret;
}

static int qcow2_write_snapshot_cluster(BlockDriverState *bs, uint64_t *l1_table/*little end with no flag*/, uint64_t *l1_be_table, int l1_table_len, Qcow2Cache *l2_table_cache,
								 uint64_t cluster_index, char* buf, uint64_t* in_out_cluster_offset)
{
	int ret;
	struct BDRVQcow2State * s = bs->opaque;
	int l1_index = cluster_index >> s->l2_bits;
	int l2_index = cluster_index & ((1 << s->l2_bits) - 1);
	uint64_t l2_offset = l1_table[l1_index];
	l2_offset &= L1E_OFFSET_MASK;
	uint64_t l2_offset_with_flag = be64_to_cpu(l1_be_table[l1_index]);
	uint64_t *l2_table = NULL;
	bool use_exist_cluster = in_out_cluster_offset && *in_out_cluster_offset;

	if(0 == l2_offset || !(l2_offset_with_flag & QCOW_OFLAG_COPIED)){
		ret = allocate_l2(bs, l1_table, l1_be_table, l1_index, l2_table_cache, &l2_offset, (void**)&l2_table);
		if(ret < 0){
			goto out;
		}
	}
	ret = qcow2_cache_get(bs, l2_table_cache, l2_offset, (void**) &l2_table);
	if(ret < 0){
		goto out;
	}

	uint64_t cluster_offset = be64_to_cpu(l2_table[l2_index]);
	cluster_offset &= L2E_OFFSET_MASK;
	if(0 == cluster_offset){
		ret = allocate_cluster(bs, l2_table_cache, l2_table, l2_offset, l2_index, &cluster_offset, in_out_cluster_offset);
		if(ret < 0){
			goto out1;
		}
		if(in_out_cluster_offset){
			*in_out_cluster_offset = cluster_offset;
		}
		if(use_exist_cluster){
			ret = 0;
			goto out1;
		}
	}
	ret = bdrv_pwrite(bs->file, cluster_offset, buf, s->cluster_size);
	if(ret < 0){
		error_report("error bdrv_pwrite cluster index %ld", cluster_index);
		goto out1;
	}

out1:
	qcow2_cache_put(bs, l2_table_cache, (void**) &l2_table);
out:
	return ret;
}

static int mebs_qcow2_free_clusters(BlockDriverState *bs,
							int64_t cluster_index,
							enum qcow2_discard_type type)
{
    int ret;
    ret = qcow2_update_cluster_refcount(bs, cluster_index, 1, true, type);
    if (ret < 0) {
        fprintf(stderr, "qcow2_free_clusters failed: %s\n", strerror(-ret));
        /* TODO Remember the clusters to free them later and avoid leaking */
    }
    // error_report("cluster index %ld reference-set to %d", cluster_index, ret);
    return ret;
}

static int update_all_ref_count(BlockDriverState *bs, Snapshot_cache_t* current_ebs_cache, Snapshot_cache_t* snapshots_ebs_cache, int snapshots_nb)
{
	int ret = qcow2_update_snapshot_refcount(bs, current_ebs_cache->sn_l1_table_cache.cluster_offset, current_ebs_cache->l1_size, 0);
	if(ret < 0){
		error_report("qcow2_update_snapshot_refcount current error");
		return ret;
	}
	int i;
	for(i = 0; i < snapshots_nb; i++){
		ret = qcow2_update_snapshot_refcount(bs, snapshots_ebs_cache[i].sn_l1_table_cache.cluster_offset, snapshots_ebs_cache[i].l1_size, 0);
		if(ret < 0){
			error_report("qcow2_update_snapshot_refcount snapshots_ebs_cache i %d error", ret);
			return ret;
		}
	}
	return 0;
}

static int qcow2_trim_snapshot_cluster(BlockDriverState *bs, uint64_t *l1_table,/*little end with no flag*/ int l1_table_len, Qcow2Cache *l2_table_cache, uint64_t cluster_index, bool flush)
{
	int ret = 0;
	struct BDRVQcow2State * s = bs->opaque;
	int l1_index = cluster_index >> s->l2_bits;
	int l2_index = cluster_index & ((1 << s->l2_bits) - 1);
	uint64_t l2_offset = l1_table[l1_index];
	l2_offset &= L1E_OFFSET_MASK;
	uint64_t *l2_table = NULL;

	if(0 == l2_offset){
		return 0;
	}
	ret = qcow2_cache_get(bs, l2_table_cache, l2_offset, (void**) &l2_table);
	if(ret < 0){
		goto out;
	}
	uint64_t cluster_offset = be64_to_cpu(l2_table[l2_index]);
	cluster_offset &= L2E_OFFSET_MASK;
	if(cluster_offset == 0){
		goto out1;
	}
	l2_table[l2_index] = 0;
	mebs_qcow2_free_clusters(bs, cluster_offset>>s->cluster_bits, QCOW2_DISCARD_SNAPSHOT);
	qcow2_cache_entry_mark_dirty(bs, l2_table_cache, l2_table);
	if(flush){
		ret = qcow2_cache_flush(bs, l2_table_cache);
		if (ret < 0) {
			goto out1;
		}
	}

out1:
	qcow2_cache_put(bs, l2_table_cache, (void**) &l2_table);
out:
	return ret;
}

static int flush_l1_table(BlockDriverState *bs, Snapshot_cache_t* cache)
{
	return bdrv_pwrite(bs->file, cache->sn_l1_table_cache.cluster_offset, cache->sn_l1_be_table_cache.table, cache->l1_size_byte);
}

static int flush_l1_tables(BlockDriverState *bs, Snapshot_cache_t* current_ebs_cache, Snapshot_cache_t* snapshots_ebs_cache, int snapshots_nb)
{
	struct BDRVQcow2State * s = bs->opaque;
	int i;
	for(i = 0; i < s->l1_size; i++){
		// LOG_INFO("l1-iterm old %d %016lx %016lx", i, s->l1_table[i], be64_to_cpu(s->l1_table[i]));
	}

	for(i = 0; i < s->l1_size; i++){
		s->l1_table[i] = be64_to_cpu(current_ebs_cache->sn_l1_be_table_cache.table[i]);
	}

	for(i = 0; i < s->l1_size; i++){
		// LOG_INFO("l1-iterm %d %016lx %016lx", i, s->l1_table[i], be64_to_cpu(s->l1_table[i]));
	}

	int ret = flush_l1_table(bs, current_ebs_cache);
	if(ret < 0){
		error_report("error flush current_ebs_cache l1 table");
		return ret;
	}
	for(i = 0; i < snapshots_nb; i++){
		ret = flush_l1_table(bs, &snapshots_ebs_cache[i]);
		if(ret < 0){
			error_report("error flush snapshots_ebs_cache l1 table index %d", i);
			return ret;
		}
	}
	return 0;
}

// if backing_data is NULL, zeros will be set to snapshots
// else backing_data will be set to snapshot
static int write_snapshots_content(BlockDriverState *bs, Snapshot_cache_t*snapshots_ebs_cache,
								   uint64_t *snapshots_cluster_nbs, uint64_t *snapshots_cluster_offsets,
								   int nb_snapshots, uint64_t cluster_index, uint64_t *current_l1_table, uint64_t *current_l1_be_table, uint64_t **snapshots_l1_tables, uint64_t **snapshots_l1_be_tables,
								   int max_l1_size, Qcow2Cache **qcow2_caches, Qcow2Cache *qcow2_current_cache, uint64_t *counters, ClusterData_t *backing_data, bool just_get_offset, bool write_current)
{
	int ret = 0;
	memset(snapshots_cluster_offsets, 0, sizeof(void*)*nb_snapshots);
	uint64_t data_offset = 0;
	int i;
	for(i = 0; i < nb_snapshots; i++){
		uint64_t snapshot_cluster_offset;
		ret = get_snapshot_cluster_pure_offset(bs, &snapshots_ebs_cache[i], cluster_index, &snapshot_cluster_offset);
		if(ret < 0){
			error_report("error get_snapshot_cluster_pure_offset1 ret %d", ret);
			return ret;
		}
		snapshots_cluster_offsets[i] = snapshot_cluster_offset;
		if(snapshot_cluster_offset){
			continue;
		}
		if(cluster_index > snapshots_cluster_nbs[i]){
			continue;
		}
		if(just_get_offset){
			continue;
		}
		if(!backing_data){
			ret = qcow2_write_snapshot_cluster_zero(bs, snapshots_l1_tables[i], snapshots_l1_be_tables[i], max_l1_size, qcow2_caches[i], cluster_index, false);
			if(ret < 0){
				error_report("qcow2_write_snapshot_cluster_zero ret %d cluster %ld", ret, cluster_index);
				return ret;
			}
		} else {
			ret = qcow2_write_snapshot_cluster(bs, snapshots_l1_tables[i], snapshots_l1_be_tables[i], max_l1_size, qcow2_caches[i], cluster_index, backing_data->buf, &data_offset);
			if(ret < 0){
				error_report("qcow2_write_snapshot_cluster %ld ret %d", cluster_index, ret);
				return ret;
			}
		}
		if(counters)
			counters[i]++;
	}
	if(write_current && backing_data){
		ret = qcow2_write_snapshot_cluster(bs, current_l1_table, current_l1_be_table, max_l1_size, qcow2_current_cache, cluster_index, backing_data->buf, &data_offset);
	}
	return ret;
}

static int deep_trim_current_covered_clusters(BlockDriverState *bs, Snapshot_cache_t* current_ebs_cache, Snapshot_cache_t* snapshots_ebs_cache, int snapshots_nb,
									   Qcow2Cache **qcow2_caches, Qcow2Cache *qcow2_current_cache, uint64_t current_total_cluter_nb,
									   uint64_t *current_l1_table, uint64_t *current_l1_be_table, uint64_t **snapshots_l1_tables, uint64_t **snapshots_l1_be_tables,
									   uint64_t *snapshots_cluster_offsets, uint64_t *snapshots_cluster_nbs, int max_l1_size)
{
	int ret = 0;
	uint64_t cluster_index;
	for(cluster_index = 0; cluster_index < current_total_cluter_nb; cluster_index++){
		uint64_t offset;
		ret = read_snapshot_cluster_get_offset(bs, current_ebs_cache, cluster_index, NULL, &offset, NULL, NULL);
		if(ret == 0 || ret == 2){
			continue;
		}
		if(!offset){
			continue;
		}

		ret = write_snapshots_content(bs, snapshots_ebs_cache, snapshots_cluster_nbs, snapshots_cluster_offsets,
									 snapshots_nb, cluster_index, current_l1_table, current_l1_be_table, snapshots_l1_tables, snapshots_l1_be_tables,
									 max_l1_size, qcow2_caches, qcow2_current_cache, NULL, NULL, true, false);
		if(ret < 0){
			return ret;
		}
		int i;
		for(i = 0; i < snapshots_nb; i++){
			if(offset == snapshots_cluster_offsets[i]){
				// LOG_INFO("snapshot cluster index %ld share with snapshot %d, trim will done both", cluster_index, i);
				ret = qcow2_trim_snapshot_cluster(bs, snapshots_l1_tables[i], max_l1_size, qcow2_caches[i], cluster_index, false);
				if(ret < 0){
					return ret;
				}
			}
		}
		ret = qcow2_trim_snapshot_cluster(bs, current_l1_table, max_l1_size, qcow2_current_cache, cluster_index, false);
		if(ret < 0){
			return ret;
		}
	}
	return 0;
}

static inline void free_cache(Snapshot_cache_t * cache)
{
	free(cache->sn_l1_be_table_cache.table);
	free(cache->sn_l1_table_cache.table);
	free(cache->sn_l2_table_cache.table);
}

static void free_caches(Snapshot_cache_t* current_cache, Snapshot_cache_t* snapshots_cache, int nb_snapshots)
{
	free_cache(current_cache);
	int i;
	for(i = 0; i < nb_snapshots; i++){
		free_cache(&snapshots_cache[i]);
	}
}

#define CHECK_ERROR_RET(p) if(p == (void*)-1){	\
						ret = -1;			\
						goto out;			\
						}


int qcow2_template_clone(BlockDriverState *bs, BlockDriverState *clone_des_bs, bool trim, bool copy_backingfile, out_percent_wrap cb, void* percent_data)
{
	int ret = 0, r = 0;
	struct BDRVQcow2State * s = bs->opaque;
	int max_l1_size = get_max_l1_size(bs);
	int nb_snapshots = s->nb_snapshots;
	Snapshot_cache_t current_ebs_cache, *snapshots_ebs_cache;
	uint64_t *current_l1_table, *current_l1_be_table;
	uint64_t** snapshots_l1_tables = zalloc(sizeof(uint64_t*) * nb_snapshots);
	uint64_t** snapshots_l1_be_tables = zalloc(sizeof(uint64_t*) * nb_snapshots);
	ClusterData_t *data = zalloc(sizeof(*data)+s->cluster_size);
	ClusterData_t *backing_data = zalloc(sizeof(*data)+s->cluster_size);
	allocate_caches(&current_ebs_cache, &snapshots_ebs_cache, nb_snapshots);
	current_ebs_cache.read_backingfile = true;

	current_l1_table = get_l1_table(bs, &current_ebs_cache);
	CHECK_ERROR_RET(current_l1_table);
	current_l1_be_table = get_l1_be_table(bs, &current_ebs_cache);
	int i;
	for(i = 0; i < nb_snapshots; i++){
		snapshots_l1_tables[i] = get_l1_table(bs, &snapshots_ebs_cache[i]);
		CHECK_ERROR_RET(snapshots_l1_tables[i]);
		snapshots_l1_be_tables[i] = get_l1_be_table(bs, &snapshots_ebs_cache[i]);
	}
	Qcow2Cache **qcow2_caches = zalloc(sizeof(void*)*(nb_snapshots+1));
	for(i = 0; i < nb_snapshots; i++){
		qcow2_caches[i] = qcow2_cache_create(bs, 2);
	}
	Qcow2Cache *qcow2_current_cache = s->l2_table_cache;

	uint64_t *counters = zalloc(sizeof(uint64_t)*nb_snapshots);
	uint64_t total_cluster_nb = get_layer_cluster_nb(bs, SNAPSHOT_MAX_INDEX);
	uint64_t *snapshots_cluster_offsets = zalloc(sizeof(uint64_t)*nb_snapshots);
	uint64_t *snapshots_cluster_nbs = zalloc(sizeof(uint64_t)*nb_snapshots);
	for(i = 0; i < nb_snapshots; i++){
		snapshots_cluster_nbs[i] = get_layer_cluster_nb(bs, i);
	}
	uint64_t cluster_index;
	for(cluster_index = 0; cluster_index < total_cluster_nb; cluster_index++){
		bool backing_with_data = false;
		uint64_t current_layer_data_offset;
		ret = read_snapshot_cluster_get_offset(bs, &current_ebs_cache, cluster_index, data,
											   &current_layer_data_offset, &backing_with_data, backing_data);
		if(ret < 0){
			error_report("error read_snapshot_cluster_get_offset ret %d ", ret);
			goto out1;
		}
		int r = ret;
		// clone about, read from current and write in to clone to file
		if(r != 0 && cb){
			cb(percent_data);
		}

		ClusterData_t *backing_data_copy = backing_with_data ? backing_data : NULL;
		if(r != 0 && clone_des_bs && (copy_backingfile || current_layer_data_offset)){// have zero or data
			if(r == 2){
				ret = bdrv_write_zeros(clone_des_bs, cluster_index<<s->cluster_bits, s->cluster_size);
				if(ret < 0){
					error_report("error bdrv_write_zeros is %ld, ret %d", cluster_index, ret);
					goto out1;
				}
			}else{ // r == 1
				ret = _bdrv_pwrite(clone_des_bs, cluster_index<<s->cluster_bits, data->buf, s->cluster_size);
				if(ret < 0){
					error_report("error bdrv_pwrite index is %ld", cluster_index);
					goto out1;
				}
			}
		}
		// clone about end
		// r == 0, backing file and current both unallocated
		// r == 2, current is zero flag
		// r == 1 current or backing file is allocated, if data_offset != 0 data is from current, if backing_with_data backing with data too

		// current is allocated and a new template is creating, then fill snapshots with content or zeros
		// if no new template is creating, this means just put backing content to current volume, then backing file must with data
		if(current_layer_data_offset || (!trim && backing_data_copy)){
			// if data_offset is not 0, it means there has data in current layer
			// then snapshots must be set to zero or backing data
			ret = write_snapshots_content(bs, snapshots_ebs_cache,
										  snapshots_cluster_nbs, snapshots_cluster_offsets,
										  nb_snapshots, cluster_index, current_l1_table, current_l1_be_table, snapshots_l1_tables, snapshots_l1_be_tables,
										  max_l1_size, qcow2_caches, qcow2_current_cache, counters, backing_data_copy, false, !trim && !current_layer_data_offset);
			if(ret < 0){
				goto out1;
			}
		}
	}
	for(i = 0; i < nb_snapshots; i++){
		QCowSnapshot *snapshot = &s->snapshots[i];
		printf("set snapshots zeros counter: %s %ld\n", snapshot->id_str, counters[i]);
	}
out1:
	for(i = 0; i < nb_snapshots; i++){
		r = qcow2_cache_flush(bs, qcow2_caches[i]);
		if(r < 0){
			ret = r;
		}
	}
	qcow2_cache_flush(bs, qcow2_current_cache);
	if(ret >= 0){
		ret = flush_l1_tables(bs, &current_ebs_cache, snapshots_ebs_cache, nb_snapshots);
	}
	if(ret >= 0){
		ret = update_all_ref_count(bs, &current_ebs_cache, snapshots_ebs_cache, nb_snapshots);
	}
	if(ret >= 0 && trim){
		ret = deep_trim_current_covered_clusters(bs, &current_ebs_cache, snapshots_ebs_cache, nb_snapshots,
												qcow2_caches, qcow2_current_cache, total_cluster_nb,
												current_l1_table, current_l1_be_table, snapshots_l1_tables, snapshots_l1_be_tables, snapshots_cluster_offsets,
												snapshots_cluster_nbs, max_l1_size);
		error_report("deep_trim_current_covered_clusters ret %d", ret);
		trim = false;
		goto out1;
	}
	for(i = 0; i < nb_snapshots; i++){
		qcow2_cache_destroy(bs, qcow2_caches[i]);
	}
	free(qcow2_caches);
	free(snapshots_cluster_offsets);
	free(snapshots_cluster_nbs);
	free(counters);
out:
	free(snapshots_l1_tables);
	free(snapshots_l1_be_tables);
	free_caches(&current_ebs_cache, snapshots_ebs_cache, nb_snapshots);
	free(data);
	free(backing_data);
	return ret;
}

#define _1MB (1024*1024)
static void *rate_computer(int byte)
{
	static char outbuf[32];
	static time_t current_time = 0;
	static uint64_t total_byte_in_a_second = 0;
	time_t now = time(0);
	if(now != current_time){
		if(total_byte_in_a_second > _1MB){
			sprintf(outbuf, "%8ldMB/s", total_byte_in_a_second / _1MB);
		}else if(total_byte_in_a_second < _1MB && total_byte_in_a_second > 1024){
			sprintf(outbuf, "%8ldKB/s", total_byte_in_a_second / 1024);
		}else{
			sprintf(outbuf, "%9ldB/s", total_byte_in_a_second);
		}
		total_byte_in_a_second = 0;
		current_time = now;
	}
	total_byte_in_a_second += byte;
	return outbuf;
}

static void print_percent(int percent, uint64_t done_size_byte, uint64_t total_size_byte, int unit_percent, char *rate_str)
{
	char buf[1024];
	int size;
	size = sprintf(buf, "\rdone %3d%% ", percent);
	size += sprintf(buf + size, "%s %ld %ld [", rate_str, done_size_byte, total_size_byte);
	int i;
	for(i = 0; i < (percent / unit_percent); i++){
		size += sprintf(buf + size, "#");
	}
	for(i = 0; i < ((100 - percent + (unit_percent - 1)) / unit_percent); i++){
		size += sprintf(buf + size, " ");
	}
	size += sprintf(buf + size, "]");
	if(100 == percent)
		size += sprintf(buf + size, "\n");

	fprintf(stderr, "%s", buf);fflush(stderr);
}

void out_percent(int add_inc, uint64_t total, int unit_percent, int unit_size_byte)
{
	static uint64_t done_size = 0;
	static int last_showed_percent = 0; // x / 100
	static uint32_t last_print_time = 0;
	uint32_t now = time(0);
	if(total == 0){
		done_size = 0;
		last_showed_percent = 0;
		fprintf(stderr, "\n");
		print_percent(0, 0, 0, unit_percent, rate_computer(0));
		return;
	}
	done_size += add_inc;
	int percent = done_size * 100 / total;

	rate_computer(unit_size_byte * add_inc);
	if(percent > last_showed_percent || now - last_print_time >= 1){
		last_print_time = now;
		print_percent(percent, done_size*unit_size_byte, total*unit_size_byte, unit_percent, rate_computer(0));
		last_showed_percent = percent;
	}
}

