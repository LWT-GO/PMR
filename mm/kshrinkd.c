// SPDX-License-Identifier: GPL-2.0


 #define pr_fmt(fmt) KBUILD_MODNAME ": " fmt


 #include <linux/mm.h>
 #include <linux/sched/mm.h>
 #include <linux/module.h>
 #include <linux/gfp.h>
 #include <linux/kernel_stat.h>
 #include <linux/swap.h>
 #include <linux/pagemap.h>
 #include <linux/init.h>
 #include <linux/highmem.h>
 #include <linux/kernel.h>
 #include <linux/time.h>
 #include <linux/time64.h>
 #include <linux/vmpressure.h>
 #include <linux/vmstat.h>
 #include <linux/file.h>
 #include <linux/writeback.h>
 #include <linux/blkdev.h>
 #include <linux/buffer_head.h>	/* for try_to_release_page(),
                     buffer_heads_over_limit */
 #include <linux/mm_inline.h>
 #include <linux/backing-dev.h>
 #include <linux/rmap.h>
 #include <linux/topology.h>
 #include <linux/cpu.h>
 #include <linux/cpuset.h>
 #include <linux/compaction.h>
 #include <linux/notifier.h>
 #include <linux/rwsem.h>
 #include <linux/delay.h>
 #include <linux/kthread.h>
 #include <linux/freezer.h>
 #include <linux/memcontrol.h>
 #include <linux/delayacct.h>
 #include <linux/sysctl.h>
 #include <linux/oom.h>
 #include <linux/pagevec.h>
 #include <linux/prefetch.h>
 #include <linux/printk.h>
 #include <linux/dax.h>
 #include <linux/psi.h>
 #include <linux/pagewalk.h>
 #include <linux/shmem_fs.h>
 #include <linux/ctype.h>
 #include <linux/debugfs.h>
 
 #include <asm/tlbflush.h>
 #include <asm/div64.h>
 
 #include <linux/swapops.h>
 #include <linux/balloon_compaction.h>
 
 #include <linux/timer.h>
 #include <linux/timex.h>
 #include <linux/rtc.h>
 
 #include "internal.h" 

 
 unsigned long direct_count=0;
 
 struct scan_control {
     /* How many pages kshrink_list() should reclaim */
     unsigned long nr_to_reclaim;
 
     /*
      * Nodemask of nodes allowed by the caller. If NULL, all nodes
      * are scanned.
      */
     nodemask_t	*nodemask;
 
     /*
      * The memory cgroup that hit its limit and as a result is the
      * primary target of this reclaim invocation.
      */
     struct mem_cgroup *target_mem_cgroup;
 
     /*
      * Scan pressure balancing between anon and file LRUs
      */
     unsigned long	anon_cost;
     unsigned long	file_cost;
 
     /* Can active pages be deactivated as part of reclaim? */
 #define DEACTIVATE_ANON 1
 #define DEACTIVATE_FILE 2
     unsigned int may_deactivate:2;
     unsigned int force_deactivate:1;
     unsigned int skipped_deactivate:1;
 
     /* Writepage batching in laptop mode; RECLAIM_WRITE */
     unsigned int may_writepage:1;
 
     /* Can mapped pages be reclaimed? */
     unsigned int may_unmap:1;
 
     /* Can pages be swapped as part of reclaim? */
     unsigned int may_swap:1;
 
     /*
      * Cgroup memory below memory.low is protected as long as we
      * don't threaten to OOM. If any cgroup is reclaimed at
      * reduced force or passed over entirely due to its memory.low
      * setting (memcg_low_skipped), and nothing is reclaimed as a
      * result, then go back for one more cycle that reclaims the protected
      * memory (memcg_low_reclaim) to avert OOM.
      */
     unsigned int memcg_low_reclaim:1;
     unsigned int memcg_low_skipped:1;
 
     unsigned int hibernation_mode:1;
 
     /* One of the zones is ready for compaction */
     unsigned int compaction_ready:1;
 
     /* There is easily reclaimable cold cache in the current node */
     unsigned int cache_trim_mode:1;
 
     /* The file pages on the current node are dangerously low */
     unsigned int file_is_tiny:1;

 
     /* Allocation order */
     s8 order;
 
     /* Scan (total_size >> priority) pages at once */
     s8 priority;
 
     /* The highest zone to isolate pages for reclaim from */
     s8 reclaim_idx;
 
     /* This context's GFP mask */
     gfp_t gfp_mask;
 
     /* Incremented by the number of inactive pages that were scanned */
     unsigned long nr_scanned;
 
     /* Number of pages freed so far during a call to shrink_zones() */
     unsigned long nr_reclaimed;
 
     struct {
         unsigned int dirty;
         unsigned int unqueued_dirty;
         unsigned int congested;
         unsigned int writeback;
         unsigned int immediate;
         unsigned int file_taken;
         unsigned int taken;
     } nr;
 
     /* for recording the reclaimed slab by now */
     struct reclaim_state reclaim_state;
 };
 
 
 /*
  * From 0 .. 200.  Higher means more swappy.
  */
 int vm_swappiness = 60;
 
 #define DEF_KSHRINKD_THREADS_PER_NODE 1
 static int kshrinkd_threads = DEF_KSHRINKD_THREADS_PER_NODE;
 static int __init kshrinkd_per_node_setup(char *str)
 {
     int tmp;
 
     if (kstrtoint(str, 0, &tmp) < 0)
         return 0;
 
     if (tmp > MAX_KSHRINKD_THREADS || tmp <= 0)
         return 0;
 
     kshrinkd_threads = tmp;
     return 1;
 }
 __setup("kshrinkd_per_node=", kshrinkd_per_node_setup);
 
 static void set_task_reclaim_state(struct task_struct *task,
                    struct reclaim_state *rs)
 {
     /* Check for an overwrite */
     WARN_ON_ONCE(rs && task->reclaim_state);
 
     /* Check for the nulling of an already-nulled member */
     WARN_ON_ONCE(!rs && !task->reclaim_state);
 
     task->reclaim_state = rs;
 }
 
 static LIST_HEAD(shrinker_list);
 static DECLARE_RWSEM(shrinker_rwsem);
 
 

 
 /*
  * This misses isolated pages which are not accounted for to save counters.
  * As the data only determines if reclaim or compaction continues, it is
  * not expected that isolated pages will be a dominating factor.
  */
 unsigned long zone_reclaimable_pages(struct zone *zone)
 {
     unsigned long nr;
 
     nr = zone_page_state_snapshot(zone, NR_ZONE_INACTIVE_FILE) +
         zone_page_state_snapshot(zone, NR_ZONE_ACTIVE_FILE);
     if (get_nr_swap_pages() > 0)
         nr += zone_page_state_snapshot(zone, NR_ZONE_INACTIVE_ANON) +
             zone_page_state_snapshot(zone, NR_ZONE_ACTIVE_ANON);
 
     return nr;
 }
 
 /**
  * lruvec_lru_size -  Returns the number of pages on the given LRU list.
  * @lruvec: lru vector
  * @lru: lru to use
  * @zone_idx: zones to consider (use MAX_NR_ZONES for the whole LRU list)
  */
 unsigned long lruvec_lru_size(struct lruvec *lruvec, enum lru_list lru, int zone_idx)
 {
     unsigned long size = 0;
     int zid;
 
     for (zid = 0; zid <= zone_idx && zid < MAX_NR_ZONES; zid++) {
         struct zone *zone = &lruvec_pgdat(lruvec)->node_zones[zid];
 
         if (!managed_zone(zone))
             continue;
 
         if (!mem_cgroup_disabled())
             size += mem_cgroup_get_zone_lru_size(lruvec, lru, zid);
         else
             size += zone_page_state(zone, NR_ZONE_LRU_BASE + lru);
     }
     return size;
 }
 
 /*
  * Add a shrinker callback to be called from the vm.
  */
 int prealloc_shrinker(struct shrinker *shrinker)
 {
     unsigned int size = sizeof(*shrinker->nr_deferred);
 
     if (shrinker->flags & SHRINKER_NUMA_AWARE)
         size *= nr_node_ids;
 
     shrinker->nr_deferred = kzalloc(size, GFP_KERNEL);
     if (!shrinker->nr_deferred)
         return -ENOMEM;
 
     if (shrinker->flags & SHRINKER_MEMCG_AWARE) {
         if (prealloc_memcg_shrinker(shrinker))
             goto free_deferred;
     }
 
     return 0;
 
 free_deferred:
     kfree(shrinker->nr_deferred);
     shrinker->nr_deferred = NULL;
     return -ENOMEM;
 }
 
 void free_prealloced_shrinker(struct shrinker *shrinker)
 {
     if (!shrinker->nr_deferred)
         return;
 
     if (shrinker->flags & SHRINKER_MEMCG_AWARE)
         unregister_memcg_shrinker(shrinker);
 
     kfree(shrinker->nr_deferred);
     shrinker->nr_deferred = NULL;
 }
 
 void register_shrinker_prepared(struct shrinker *shrinker)
 {
     down_write(&shrinker_rwsem);
     list_add_tail(&shrinker->list, &shrinker_list);
     up_write(&shrinker_rwsem);
 }
 
 int register_shrinker(struct shrinker *shrinker)
 {
     int err = prealloc_shrinker(shrinker);
 
     if (err)
         return err;
     register_shrinker_prepared(shrinker);
     return 0;
 }
 EXPORT_SYMBOL(register_shrinker);
 
 /*
  * Remove one
  */
 void unregister_shrinker(struct shrinker *shrinker)
 {
     if (!shrinker->nr_deferred)
         return;
     if (shrinker->flags & SHRINKER_MEMCG_AWARE)
         unregister_memcg_shrinker(shrinker);
     down_write(&shrinker_rwsem);
     list_del(&shrinker->list);
     up_write(&shrinker_rwsem);
     kfree(shrinker->nr_deferred);
     shrinker->nr_deferred = NULL;
 }
 EXPORT_SYMBOL(unregister_shrinker);
 
 #define SHRINK_BATCH 128
 
 static unsigned long do_shrink_slab(struct shrink_control *shrinkctl,
                     struct shrinker *shrinker, int priority)
 {
     unsigned long freed = 0;
     unsigned long long delta;
     long total_scan;
     long freeable;
     long nr;
     long new_nr;
     int nid = shrinkctl->nid;
     long batch_size = shrinker->batch ? shrinker->batch
                       : SHRINK_BATCH;
     long scanned = 0, next_deferred;
 
     trace_android_vh_do_shrink_slab(shrinker, shrinkctl, priority);
 
     if (!(shrinker->flags & SHRINKER_NUMA_AWARE))
         nid = 0;
 
     freeable = shrinker->count_objects(shrinker, shrinkctl);
     if (freeable == 0 || freeable == SHRINK_EMPTY)
         return freeable;
 
     /*
      * copy the current shrinker scan count into a local variable
      * and zero it so that other concurrent shrinker invocations
      * don't also do this scanning work.
      */
     nr = atomic_long_xchg(&shrinker->nr_deferred[nid], 0);
 
     total_scan = nr;
     if (shrinker->seeks) {
         delta = freeable >> priority;
         delta *= 4;
         do_div(delta, shrinker->seeks);
     } else {
         /*
          * These objects don't require any IO to create. Trim
          * them aggressively under memory pressure to keep
          * them from causing refetches in the IO caches.
          */
         delta = freeable / 2;
     }
 
     total_scan += delta;
     if (total_scan < 0) {
         pr_err("shrink_slab: %pS negative objects to delete nr=%ld\n",
                shrinker->scan_objects, total_scan);
         total_scan = freeable;
         next_deferred = nr;
     } else
         next_deferred = total_scan;
 
     /*
      * We need to avoid excessive windup on filesystem shrinkers
      * due to large numbers of GFP_NOFS allocations causing the
      * shrinkers to return -1 all the time. This results in a large
      * nr being built up so when a shrink that can do some work
      * comes along it empties the entire cache due to nr >>>
      * freeable. This is bad for sustaining a working set in
      * memory.
      *
      * Hence only allow the shrinker to scan the entire cache when
      * a large delta change is calculated directly.
      */
     if (delta < freeable / 4)
         total_scan = min(total_scan, freeable / 2);
 
     /*
      * Avoid risking looping forever due to too large nr value:
      * never try to free more than twice the estimate number of
      * freeable entries.
      */
     if (total_scan > freeable * 2)
         total_scan = freeable * 2;
 
     trace_mm_shrink_slab_start(shrinker, shrinkctl, nr,
                    freeable, delta, total_scan, priority);
 
     /*
      * Normally, we should not scan less than batch_size objects in one
      * pass to avoid too frequent shrinker calls, but if the slab has less
      * than batch_size objects in total and we are really tight on memory,
      * we will try to reclaim all available objects, otherwise we can end
      * up failing allocations although there are plenty of reclaimable
      * objects spread over several slabs with usage less than the
      * batch_size.
      *
      * We detect the "tight on memory" situations by looking at the total
      * number of objects we want to scan (total_scan). If it is greater
      * than the total number of objects on slab (freeable), we must be
      * scanning at high prio and therefore should try to reclaim as much as
      * possible.
      */
     while (total_scan >= batch_size ||
            total_scan >= freeable) {
         unsigned long ret;
         unsigned long nr_to_scan = min(batch_size, total_scan);
 
         shrinkctl->nr_to_scan = nr_to_scan;
         shrinkctl->nr_scanned = nr_to_scan;
         ret = shrinker->scan_objects(shrinker, shrinkctl);
         if (ret == SHRINK_STOP)
             break;
         freed += ret;
 
         count_vm_events(SLABS_SCANNED, shrinkctl->nr_scanned);
         total_scan -= shrinkctl->nr_scanned;
         scanned += shrinkctl->nr_scanned;
 
         cond_resched();
     }
 
     if (next_deferred >= scanned)
         next_deferred -= scanned;
     else
         next_deferred = 0;
     /*
      * move the unused scan count back into the shrinker in a
      * manner that handles concurrent updates. If we exhausted the
      * scan, there is no need to do an update.
      */
     if (next_deferred > 0)
         new_nr = atomic_long_add_return(next_deferred,
                         &shrinker->nr_deferred[nid]);
     else
         new_nr = atomic_long_read(&shrinker->nr_deferred[nid]);
 
     trace_mm_shrink_slab_end(shrinker, nid, freed, nr, new_nr, total_scan);
     return freed;
 }



 
 /**
  * shrink_slab - shrink slab caches
  * @gfp_mask: allocation context
  * @nid: node whose slab caches to target
  * @memcg: memory cgroup whose slab caches to target
  * @priority: the reclaim priority
  *
  * Call the shrink functions to age shrinkable caches.
  *
  * @nid is passed along to shrinkers with SHRINKER_NUMA_AWARE set,
  * unaware shrinkers will receive a node id of 0 instead.
  *
  * @memcg specifies the memory cgroup to target. Unaware shrinkers
  * are called only if it is the root cgroup.
  *
  * @priority is sc->priority, we take the number of objects and >> by priority
  * in order to get the scan target.
  *
  * Returns the number of reclaimed slab objects.
  */
 static unsigned long shrink_slab(gfp_t gfp_mask, int nid,
                  struct mem_cgroup *memcg,
                  int priority)
 {
     unsigned long ret, freed = 0;
     struct shrinker *shrinker;
     bool bypass = false;
 
     trace_android_vh_shrink_slab_bypass(gfp_mask, nid, memcg, priority, &bypass);
     if (bypass)
         return 0;
 
     /*
      * The root memcg might be allocated even though memcg is disabled
      * via "cgroup_disable=memory" boot parameter.  This could make
      * mem_cgroup_is_root() return false, then just run memcg slab
      * shrink, but skip global shrink.  This may result in premature
      * oom.
      */
     if (!mem_cgroup_disabled() && !mem_cgroup_is_root(memcg))
         return shrink_slab_memcg(gfp_mask, nid, memcg, priority);
 
     if (!down_read_trylock(&shrinker_rwsem))
         goto out;
 
     list_for_each_entry(shrinker, &shrinker_list, list) {
         struct shrink_control sc = {
             .gfp_mask = gfp_mask,
             .nid = nid,
             .memcg = memcg,
         };
 
         ret = do_shrink_slab(&sc, shrinker, priority);
         if (ret == SHRINK_EMPTY)
             ret = 0;
         freed += ret;
         /*
          * Bail out if someone want to register a new shrinker to
          * prevent the registration from being stalled for long periods
          * by parallel ongoing shrinking.
          */
         if (rwsem_is_contended(&shrinker_rwsem)) {
             freed = freed ? : 1;
             break;
         }
     }
 
     up_read(&shrinker_rwsem);
 out:
     cond_resched();
     return freed;
 }
 
 void drop_slab_node(int nid)
 {
     unsigned long freed;
 
     do {
         struct mem_cgroup *memcg = NULL;
 
         if (fatal_signal_pending(current))
             return;
 
         freed = 0;
         memcg = mem_cgroup_iter(NULL, NULL, NULL);
         do {
             freed += shrink_slab(GFP_KERNEL, nid, memcg, 0);
         } while ((memcg = mem_cgroup_iter(NULL, memcg, NULL)) != NULL);
     } while (freed > 10);
 }
 
 void drop_slab(void)
 {
     int nid;
 
     for_each_online_node(nid)
         drop_slab_node(nid);
 }
 
 static inline int is_page_cache_freeable(struct page *page)
 {
     /*
      * A freeable page cache page is referenced only by the caller
      * that isolated the page, the page cache and optional buffer
      * heads at page->private.
      */
     int page_cache_pins = thp_nr_pages(page);
     return page_count(page) - page_has_private(page) == 1 + page_cache_pins;
 }
 
 static int may_write_to_inode(struct inode *inode)
 {
     if (current->flags & PF_SWAPWRITE)
         return 1;
     if (!inode_write_congested(inode))
         return 1;
     if (inode_to_bdi(inode) == current->backing_dev_info)
         return 1;
     return 0;
 }
 
 /*
  * We detected a synchronous write error writing a page out.  Probably
  * -ENOSPC.  We need to propagate that into the address_space for a subsequent
  * fsync(), msync() or close().
  *
  * The tricky part is that after writepage we cannot touch the mapping: nothing
  * prevents it from being freed up.  But we have a ref on the page and once
  * that page is locked, the mapping is pinned.
  *
  * We're allowed to run sleeping lock_page() here because we know the caller has
  * __GFP_FS.
  */
 static void handle_write_error(struct address_space *mapping,
                 struct page *page, int error)
 {
     lock_page(page);
     if (page_mapping(page) == mapping)
         mapping_set_error(mapping, error);
     unlock_page(page);
 }
 
 /* possible outcome of pageout() */
 typedef enum {
     /* failed to write page out, page is locked */
     PAGE_KEEP,
     /* move page to the active list, page is locked */
     PAGE_ACTIVATE,
     /* page has been sent to the disk successfully, page is unlocked */
     PAGE_SUCCESS,
     /* page is clean and locked */
     PAGE_CLEAN,
 } pageout_t;
 
 /*
  * pageout is called by shrink_page_list() for each dirty page.
  * Calls ->writepage().
  */
 static pageout_t pageout(struct page *page, struct address_space *mapping)
 {
     /*
      * If the page is dirty, only perform writeback if that write
      * will be non-blocking.  To prevent this allocation from being
      * stalled by pagecache activity.  But note that there may be
      * stalls if we need to run get_block().  We could test
      * PagePrivate for that.
      *
      * If this process is currently in __generic_file_write_iter() against
      * this page's queue, we can perform writeback even if that
      * will block.
      *
      * If the page is swapcache, write it back even if that would
      * block, for some throttling. This happens by accident, because
      * swap_backing_dev_info is bust: it doesn't reflect the
      * congestion state of the swapdevs.  Easy to fix, if needed.
      */
     // ktime_t starttime, delta, pageout_time;
     // unsigned long long duration;
     // starttime = ktime_get();
 
     
     if (!is_page_cache_freeable(page))
         return PAGE_KEEP;
     if (!mapping) {
         /*
          * Some data journaling orphaned pages can have
          * page->mapping == NULL while being dirty with clean buffers.
          */
         if (page_has_private(page)) {
             if (try_to_free_buffers(page)) {
                 ClearPageDirty(page);
                 pr_info("%s: orphaned page\n", __func__);
                 return PAGE_CLEAN;
             }
         }
         return PAGE_KEEP;
     }
     if (mapping->a_ops->writepage == NULL)
         return PAGE_ACTIVATE;
     if (!may_write_to_inode(mapping->host))
         return PAGE_KEEP;
 
     if (clear_page_dirty_for_io(page)) {
         int res;
         struct writeback_control wbc = {
             .sync_mode = WB_SYNC_NONE,
             .nr_to_write = SWAP_CLUSTER_MAX,
             .range_start = 0,
             .range_end = LLONG_MAX,
             .for_reclaim = 1,
         };
 
         SetPageReclaim(page);
         res = mapping->a_ops->writepage(page, &wbc);
         if (res < 0)
             handle_write_error(mapping, page, res);
         if (res == AOP_WRITEPAGE_ACTIVATE) {
             ClearPageReclaim(page);
             return PAGE_ACTIVATE;
         }
 
         if (!PageWriteback(page)) {
             /* synchronous write or broken a_ops? */
             ClearPageReclaim(page);
         }
         trace_mm_vmscan_writepage(page);
         inc_node_page_state(page, NR_VMSCAN_WRITE);
         return PAGE_SUCCESS;
     }
 
     // pageout_time = ktime_get();
 
     // delta = ktime_sub(pageout_time, starttime);
 
     // duration = (unsigned long long) ktime_to_us(delta);//΢��
     // printk("lwt:%s pageout_time %lld usecs",__FUNCTION__, duration);
     return PAGE_CLEAN;
 }
 
 /*
  * Same as remove_mapping, but if the page is removed from the mapping, it
  * gets returned with a refcount of 0.
  */
 static int __remove_mapping(struct address_space *mapping, struct page *page,
                 bool reclaimed, struct mem_cgroup *target_memcg)
 {
     unsigned long flags;
     int refcount;
     void *shadow = NULL;
 
     BUG_ON(!PageLocked(page));
     BUG_ON(mapping != page_mapping(page));
 
     //printk("lwt:%s, %d,",__func__,__LINE__);
 
     xa_lock_irqsave(&mapping->i_pages, flags);
     /*
      * The non racy check for a busy page.
      *
      * Must be careful with the order of the tests. When someone has
      * a ref to the page, it may be possible that they dirty it then
      * drop the reference. So if PageDirty is tested before page_count
      * here, then the following race may occur:
      *
      * get_user_pages(&page);
      * [user mapping goes away]
      * write_to(page);
      *				!PageDirty(page)    [good]
      * SetPageDirty(page);
      * put_page(page);
      *				!page_count(page)   [good, discard it]
      *
      * [oops, our write_to data is lost]
      *
      * Reversing the order of the tests ensures such a situation cannot
      * escape unnoticed. The smp_rmb is needed to ensure the page->flags
      * load is not satisfied before that of page->_refcount.
      *
      * Note that if SetPageDirty is always performed via set_page_dirty,
      * and thus under the i_pages lock, then this ordering is not required.
      */
     refcount = 1 + compound_nr(page);
     if (!page_ref_freeze(page, refcount))
         goto cannot_free;
     /* note: atomic_cmpxchg in page_ref_freeze provides the smp_rmb */
     if (unlikely(PageDirty(page))) {
         page_ref_unfreeze(page, refcount);
         goto cannot_free;
     }
 
     if (PageSwapCache(page)) {
         swp_entry_t swap = { .val = page_private(page) };
 
         /* get a shadow entry before mem_cgroup_swapout() clears page_memcg() */
         if (reclaimed && !mapping_exiting(mapping))
             shadow = workingset_eviction(page, target_memcg);
         mem_cgroup_swapout(page, swap);
         __delete_from_swap_cache(page, swap, shadow);
         xa_unlock_irqrestore(&mapping->i_pages, flags);
         //printk("lwt:%s, %d,",__func__,__LINE__);
         put_swap_page(page, swap);
     } else {
         void (*freepage)(struct page *);
 
         freepage = mapping->a_ops->freepage;
         /*
          * Remember a shadow entry for reclaimed file cache in
          * order to detect refaults, thus thrashing, later on.
          *
          * But don't store shadows in an address space that is
          * already exiting.  This is not just an optimization,
          * inode reclaim needs to empty out the radix tree or
          * the nodes are lost.  Don't plant shadows behind its
          * back.
          *
          * We also don't store shadows for DAX mappings because the
          * only page cache pages found in these are zero pages
          * covering holes, and because we don't want to mix DAX
          * exceptional entries and shadow exceptional entries in the
          * same address_space.
          */
         if (reclaimed && page_is_file_lru(page) &&
             !mapping_exiting(mapping) && !dax_mapping(mapping))
             shadow = workingset_eviction(page, target_memcg);
         __delete_from_page_cache(page, shadow);
         xa_unlock_irqrestore(&mapping->i_pages, flags);
 
         if (freepage != NULL)
             freepage(page);
     }
 
     return 1;
 
 cannot_free:
     xa_unlock_irqrestore(&mapping->i_pages, flags);
     return 0;
 }
 
 /*
  * Attempt to detach a locked page from its ->mapping.  If it is dirty or if
  * someone else has a ref on the page, abort and return 0.  If it was
  * successfully detached, return 1.  Assumes the caller has a single ref on
  * this page.
  */
 int remove_mapping(struct address_space *mapping, struct page *page)
 {
     //printk("lwt:%s, %d,",__func__,__LINE__);
 
     if (__remove_mapping(mapping, page, false, NULL)) {
         /*
          * Unfreezing the refcount with 1 rather than 2 effectively
          * drops the pagecache ref for us without requiring another
          * atomic operation.
          */
         page_ref_unfreeze(page, 1);
         return 1;
     }
     return 0;
 }
 
 /**
  * putback_lru_page - put previously isolated page onto appropriate LRU list
  * @page: page to be put back to appropriate lru list
  *
  * Add previously isolated @page to appropriate LRU list.
  * Page may still be unevictable for other reasons.
  *
  * lru_lock must not be held, interrupts must be enabled.
  */
 void putback_lru_page(struct page *page)
 {
     lru_cache_add(page);
     put_page(page);		/* drop ref from isolate */
 }
 
 enum page_references {
     PAGEREF_RECLAIM,
     PAGEREF_RECLAIM_CLEAN,
     PAGEREF_KEEP,
     PAGEREF_ACTIVATE,
 };
 
 static enum page_references page_check_references(struct page *page,
                           struct scan_control *sc)
 {
     int referenced_ptes, referenced_page;
     unsigned long vm_flags;
 
     referenced_ptes = page_referenced(page, 1, sc->target_mem_cgroup,
                       &vm_flags);
     referenced_page = TestClearPageReferenced(page);
 
     /*
      * Mlock lost the isolation race with us.  Let try_to_unmap()
      * move the page to the unevictable list.
      */
     if (vm_flags & VM_LOCKED)
         return PAGEREF_RECLAIM;
 
     /* rmap lock contention: rotate */
     if (referenced_ptes == -1)
         return PAGEREF_KEEP;
 
     if (referenced_ptes) {
         /*
          * All mapped pages start out with page table
          * references from the instantiating fault, so we need
          * to look twice if a mapped file page is used more
          * than once.
          *
          * Mark it and spare it for another trip around the
          * inactive list.  Another page table reference will
          * lead to its activation.
          *
          * Note: the mark is set for activated pages as well
          * so that recently deactivated but used pages are
          * quickly recovered.
          */
         SetPageReferenced(page);
 
         if (referenced_page || referenced_ptes > 1)
             return PAGEREF_ACTIVATE;
 
         /*
          * Activate file-backed executable pages after first usage.
          */
         if ((vm_flags & VM_EXEC) && !PageSwapBacked(page))
             return PAGEREF_ACTIVATE;
 
         return PAGEREF_KEEP;
     }
 
     /* Reclaim if clean, defer dirty pages to writeback */
     if (referenced_page && !PageSwapBacked(page))
         return PAGEREF_RECLAIM_CLEAN;
 
     return PAGEREF_RECLAIM;
 }
 
 /* Check if a page is dirty or under writeback */
 static void page_check_dirty_writeback(struct page *page,
                        bool *dirty, bool *writeback)
 {
     struct address_space *mapping;
 
     /*
      * Anonymous pages are not handled by flushers and must be written
      * from reclaim context. Do not stall reclaim based on them
      */
     if (!page_is_file_lru(page) ||
         (PageAnon(page) && !PageSwapBacked(page))) {
         *dirty = false;
         *writeback = false;
         return;
     }
 
     /* By default assume that the page flags are accurate */
     *dirty = PageDirty(page);
     *writeback = PageWriteback(page);
 
     /* Verify dirty/writeback state if the filesystem supports it */
     if (!page_has_private(page))
         return;
 
     mapping = page_mapping(page);
     if (mapping && mapping->a_ops->is_dirty_writeback)
         mapping->a_ops->is_dirty_writeback(page, dirty, writeback);
 }
 
 /*
  * shrink_page_list() returns the number of reclaimed pages
  */
 static unsigned int kshrinkd_page_list(struct list_head *page_list)
 {
     LIST_HEAD(ret_pages);
     LIST_HEAD(free_pages);
     unsigned int nr_reclaimed = 0;
     unsigned int pgactivate = 0;
     struct page = lru_to_page(page_list);
     struct pglist_data *pgdat = page_pgdat(page);
     unsigned int nr_swappage = 0;
     unsigned int nr_pageout = 0;

     struct scan_control sc = {
		.gfp_mask = GFP_KERNEL,
		.order = order,
		.may_unmap = 1,
	};

 
     memset(stat, 0, sizeof(*stat));
     cond_resched();
 
 
     while (!list_empty(page_list)) {
         struct address_space *mapping;
         struct page *page;
         enum page_references references = PAGEREF_RECLAIM;
         bool dirty, writeback, may_enter_fs;
         unsigned int nr_pages;
 
         calltime = ktime_get();
 
         cond_resched();
 
         
         page = lru_to_page(page_list);
         list_del(&page->lru);
         
 
         if (!trylock_page(page))
             goto keep;
 
         VM_BUG_ON_PAGE(PageActive(page), page);
 
         nr_pages = compound_nr(page);
 
         /* Account the number of base pages even though THP */
         sc->nr_scanned += nr_pages;
 
         if (unlikely(!page_evictable(page)))
             goto activate_locked;
 
         if (!sc->may_unmap && page_mapped(page))
             goto keep_locked;
 
         /* page_update_gen() tried to promote this page? */
         if (lru_gen_enabled() && !ignore_references &&
             page_mapped(page) && PageReferenced(page))
             goto keep_locked;
 
         may_enter_fs = (sc->gfp_mask & __GFP_FS) ||
             (PageSwapCache(page) && (sc->gfp_mask & __GFP_IO));
 
         /*
          * The number of dirty pages determines if a node is marked
          * reclaim_congested which affects wait_iff_congested. kshrinkd
          * will stall and start writing pages if the tail of the LRU
          * is all dirty unqueued pages.
          */
         page_check_dirty_writeback(page, &dirty, &writeback);
         if (dirty || writeback)
             stat->nr_dirty++;
 
         if (dirty && !writeback)
             stat->nr_unqueued_dirty++;
 
         /*
          * Treat this page as congested if the underlying BDI is or if
          * pages are cycling through the LRU so quickly that the
          * pages marked for immediate reclaim are making it to the
          * end of the LRU a second time.
          */
         mapping = page_mapping(page);
         if (((dirty || writeback) && mapping &&
              inode_write_congested(mapping->host)) ||
             (writeback && PageReclaim(page)))
             stat->nr_congested++;
 
         
         // delta = ktime_sub(beforetime,calltime2);
         // duration = (unsigned long long) ktime_to_us(delta);//΢��
         // total_beforetime2 = total_beforetime2 + duration;
         /*
          * If a page at the tail of the LRU is under writeback, there
          * are three cases to consider.
          *
          * 1) If reclaim is encountering an excessive number of pages
          *    under writeback and this page is both under writeback and
          *    PageReclaim then it indicates that pages are being queued
          *    for IO but are being recycled through the LRU before the
          *    IO can complete. Waiting on the page itself risks an
          *    indefinite stall if it is impossible to writeback the
          *    page due to IO error or disconnected storage so instead
          *    note that the LRU is being scanned too quickly and the
          *    caller can stall after page list has been processed.
          *
          * 2) Global or new memcg reclaim encounters a page that is
          *    not marked for immediate reclaim, or the caller does not
          *    have __GFP_FS (or __GFP_IO if it's simply going to swap,
          *    not to fs). In this case mark the page for immediate
          *    reclaim and continue scanning.
          *
          *    Require may_enter_fs because we would wait on fs, which
          *    may not have submitted IO yet. And the loop driver might
          *    enter reclaim, and deadlock if it waits on a page for
          *    which it is needed to do the write (loop masks off
          *    __GFP_IO|__GFP_FS for this reason); but more thought
          *    would probably show more reasons.
          *
          * 3) Legacy memcg encounters a page that is already marked
          *    PageReclaim. memcg does not have any dirty pages
          *    throttling so we could easily OOM just because too many
          *    pages are in writeback and there is nothing else to
          *    reclaim. Wait for the writeback to complete.
          *
          * In cases 1) and 2) we activate the pages to get them out of
          * the way while we continue scanning for clean pages on the
          * inactive list and refilling from the active list. The
          * observation here is that waiting for disk writes is more
          * expensive than potentially causing reloads down the line.
          * Since they're marked for immediate reclaim, they won't put
          * memory pressure on the cache working set any longer than it
          * takes to write them to disk.
          */
         
 
         if (PageWriteback(page)) {
             /* Case 1 above */
             if (current_is_kshrinkd() &&
                 PageReclaim(page) &&
                 test_bit(PGDAT_WRITEBACK, &pgdat->flags)) {
                 stat->nr_immediate++;
                 goto activate_locked;
 
             /* Case 2 above */
             } else if (writeback_throttling_sane(sc) ||
                 !PageReclaim(page) || !may_enter_fs) {
                 /*
                  * This is slightly racy - end_page_writeback()
                  * might have just cleared PageReclaim, then
                  * setting PageReclaim here end up interpreted
                  * as PageReadahead - but that does not matter
                  * enough to care.  What we do want is for this
                  * page to have PageReclaim set next time memcg
                  * reclaim reaches the tests above, so it will
                  * then wait_on_page_writeback() to avoid OOM;
                  * and it's also appropriate in global reclaim.
                  */
                 SetPageReclaim(page);
                 stat->nr_writeback++;
                 goto activate_locked;
 
             /* Case 3 above */
             } else {
                 unlock_page(page);
                 wait_on_page_writeback(page);
                 /* then go back and try same page again */
                 list_add_tail(&page->lru, page_list);
                 continue;
             }
         }
 
       
         if (!ignore_references)
             references = page_check_references(page, sc);
 
         switch (references) {
         case PAGEREF_ACTIVATE:
             goto activate_locked;
         case PAGEREF_KEEP:
             stat->nr_ref_keep += nr_pages;
             goto keep_locked;
         case PAGEREF_RECLAIM:
         case PAGEREF_RECLAIM_CLEAN:
             ; /* try to reclaim the page below */
         }
 
         /*
          * Anonymous process memory has backing store?
          * Try to allocate it some swap space here.
          * Lazyfree page could be freed directly
          */
         
 
         if (PageAnon(page) && PageSwapBacked(page)) {
             nr_swappage++;
             if (!PageSwapCache(page)) {
                 if (!(sc->gfp_mask & __GFP_IO))
                     goto keep_locked;
                 if (page_maybe_dma_pinned(page))
                     goto keep_locked;
                 if (PageTransHuge(page)) {
                     /* cannot split THP, skip it */
                     if (!can_split_huge_page(page, NULL))
                         goto activate_locked;
                     /*
                      * Split pages without a PMD map right
                      * away. Chances are some or all of the
                      * tail pages can be freed without IO.
                      */
                     if (!compound_mapcount(page) &&
                         split_huge_page_to_list(page,
                                     page_list))
                         goto activate_locked;
                 }
                 if (!add_to_swap(page)) {
                     if (!PageTransHuge(page))
                         goto activate_locked_split;
                     /* Fallback to swap normal pages */
                     if (split_huge_page_to_list(page,
                                     page_list))
                         goto activate_locked;
 #ifdef CONFIG_TRANSPARENT_HUGEPAGE
                     count_vm_event(THP_SWPOUT_FALLBACK);
 #endif
                     if (!add_to_swap(page))
                         goto activate_locked_split;
                 }
 
                 may_enter_fs = true;
 
                 /* Adding to swap updated mapping */
                 mapping = page_mapping(page);
             }
         } else if (unlikely(PageTransHuge(page))) {
             /* Split file THP */
             if (split_huge_page_to_list(page, page_list))
                 goto keep_locked;
         }
 
 
         /*
          * THP may get split above, need minus tail pages and update
          * nr_pages to avoid accounting tail pages twice.
          *
          * The tail pages that are added into swap cache successfully
          * reach here.
          */
         if ((nr_pages > 1) && !PageTransHuge(page)) {
             sc->nr_scanned -= (nr_pages - 1);
             nr_pages = 1;
         }
 
         /*
          * The page is mapped into the page tables of one or more
          * processes. Try to unmap it here.
          */
 
         if (page_mapped(page)) {
             enum ttu_flags flags = TTU_BATCH_FLUSH;
             bool was_swapbacked = PageSwapBacked(page);
 
             if (unlikely(PageTransHuge(page)))
                 flags |= TTU_SPLIT_HUGE_PMD;
             //printk("lwt:%s, %d,",__func__,__LINE__);
             if (!try_to_unmap(page, flags)) {
                 stat->nr_unmap_fail += nr_pages;
                 if (!was_swapbacked && PageSwapBacked(page))
                     stat->nr_lazyfree_fail += nr_pages;
                 goto activate_locked;
             }
         }
     
        
         if (PageDirty(page)) {
             /*
              * Only kshrinkd can writeback filesystem pages
              * to avoid risk of stack overflow. But avoid
              * injecting inefficient single-page IO into
              * flusher writeback as much as possible: only
              * write pages when we've encountered many
              * dirty pages, and when we've already scanned
              * the rest of the LRU for clean pages and see
              * the same dirty pages again (PageReclaim).
              */
             if (page_is_file_lru(page) &&
                 (!current_is_kshrinkd() || !PageReclaim(page) ||
                  !test_bit(PGDAT_DIRTY, &pgdat->flags))) {
                 /*
                  * Immediately reclaim when written back.
                  * Similar in principal to deactivate_page()
                  * except we already have the page isolated
                  * and know it's dirty
                  */
                 inc_node_page_state(page, NR_VMSCAN_IMMEDIATE);
                 SetPageReclaim(page);
 
                 goto activate_locked;
             }
 
             if (references == PAGEREF_RECLAIM_CLEAN)
                 goto keep_locked;
             if (!may_enter_fs)
                 goto keep_locked;
             if (!sc->may_writepage)
                 goto keep_locked;
 
             /*
              * Page is dirty. Flush the TLB if a writable entry
              * potentially exists to avoid CPU writes after IO
              * starts and then write it out here.
              */
             try_to_unmap_flush_dirty();
             if (PageAnon(page)) {
                     nr_pageout++;
             }
             switch (pageout(page, mapping)) {
             case PAGE_KEEP:
                 goto keep_locked;
             case PAGE_ACTIVATE:
                 goto activate_locked;
             case PAGE_SUCCESS:
                 stat->nr_pageout += thp_nr_pages(page);
 
                 if (PageWriteback(page))
                     goto keep;
                 if (PageDirty(page))
                     goto keep;
 
                 /*
                  * A synchronous write - probably a ramdisk.  Go
                  * ahead and try to reclaim the page.
                  */
                 if (!trylock_page(page))
                     goto keep;
                 if (PageDirty(page) || PageWriteback(page))
                     goto keep_locked;
                 mapping = page_mapping(page);
             case PAGE_CLEAN:
                 ; /* try to free the page below */
             }
         }
 
     
         
         /*
          * If the page has buffers, try to free the buffer mappings
          * associated with this page. If we succeed we try to free
          * the page as well.
          *
          * We do this even if the page is PageDirty().
          * try_to_release_page() does not perform I/O, but it is
          * possible for a page to have PageDirty set, but it is actually
          * clean (all its buffers are clean).  This happens if the
          * buffers were written out directly, with submit_bh(). ext3
          * will do this, as well as the blockdev mapping.
          * try_to_release_page() will discover that cleanness and will
          * drop the buffers and mark the page clean - it can be freed.
          *
          * Rarely, pages can have buffers and no ->mapping.  These are
          * the pages which were not successfully invalidated in
          * truncate_complete_page().  We try to drop those buffers here
          * and if that worked, and the page is no longer mapped into
          * process address space (page_count == 1) it can be freed.
          * Otherwise, leave the page on the LRU so it is swappable.
          */
 
         //calltime = ktime_get();
         if (page_has_private(page)) {
             if (!try_to_release_page(page, sc->gfp_mask))
                 goto activate_locked;
             if (!mapping && page_count(page) == 1) {
                 unlock_page(page);
                 if (put_page_testzero(page))
                     goto free_it;
                 else {
                     /*
                      * rare race with speculative reference.
                      * the speculative reference will free
                      * this page shortly, so we may
                      * increment nr_reclaimed here (and
                      * leave it off the LRU).
                      */
                     nr_reclaimed++;
                     continue;
                 }
             }
         }
 
 
         if (PageAnon(page) && !PageSwapBacked(page)) {
             /* follow __remove_mapping for reference */
             if (!page_ref_freeze(page, 1))
                 goto keep_locked;
             if (PageDirty(page)) {
                 page_ref_unfreeze(page, 1);
                 goto keep_locked;
             }
 
             count_vm_event(PGLAZYFREED);
             count_memcg_page_event(page, PGLAZYFREED);
         } else if (!mapping || !__remove_mapping(mapping, page, true,
                              sc->target_mem_cgroup))
             goto keep_locked;
 
         unlock_page(page);
 
 
 free_it:
         // printk("lwt:%s free_it %d\n",__FUNCTION__, while_count);
         /*
          * THP may get swapped out in a whole, need account
          * all base pages.
          */
         nr_reclaimed += nr_pages;
 
         /*
          * Is there need to periodically free_page_list? It would
          * appear not as the counts should be low
          */
         if (unlikely(PageTransHuge(page)))
             destroy_compound_page(page);
         else
             list_add(&page->lru, &free_pages);
         continue;
 
 
 activate_locked_split:
         //printk("lwt:%s activate_locked_split %d\n",__FUNCTION__, while_count);
         /*
          * The tail pages that are failed to add into swap cache
          * reach here.  Fixup nr_scanned and nr_pages.
          */
         if (nr_pages > 1) {
             sc->nr_scanned -= (nr_pages - 1);
             nr_pages = 1;
         }
 activate_locked:
         //printk("lwt:%s activate_locked %d\n",__FUNCTION__, while_count);
         /* Not a candidate for swapping, so reclaim swap space. */
         if (PageSwapCache(page) && (mem_cgroup_swap_full(page) ||
                         PageMlocked(page)))
             try_to_free_swap(page);
         VM_BUG_ON_PAGE(PageActive(page), page);
         if (!PageMlocked(page)) {
             int type = page_is_file_lru(page);
             SetPageActive(page);
             stat->nr_activate[type] += nr_pages;
             count_memcg_page_event(page, PGACTIVATE);
         }
 keep_locked:
         //printk("lwt:%s keep_locked %d\n",__FUNCTION__, while_count);
         unlock_page(page);
 keep:
         //printk("lwt:%s keep %d\n",__FUNCTION__, while_count);
         list_add(&page->lru, &ret_pages);
         VM_BUG_ON_PAGE(PageLRU(page) || PageUnevictable(page), page);
     
     }
 
 
     pgactivate = stat->nr_activate[0] + stat->nr_activate[1];
 
     mem_cgroup_uncharge_list(&free_pages);
     try_to_unmap_flush();
     free_unref_page_list(&free_pages);
 
     list_splice(&ret_pages, page_list);
     count_vm_events(PGACTIVATE, pgactivate);

     return nr_reclaimed;
 }

 EXPORT_SYMBOL(kshrinkd_page_list)

 
 unsigned int reclaim_clean_pages_from_list(struct zone *zone,
                         struct list_head *page_list)
 {
     struct scan_control sc = {
         .gfp_mask = GFP_KERNEL,
         .priority = DEF_PRIORITY,
         .may_unmap = 1,
     };
     struct reclaim_stat stat;
     unsigned int nr_reclaimed;
     struct page *page, *next;
     LIST_HEAD(clean_pages);
     printk("lwt:%s satrt!\n",__FUNCTION__);
     list_for_each_entry_safe(page, next, page_list, lru) {
         if (page_is_file_lru(page) && !PageDirty(page) &&
             !__PageMovable(page) && !PageUnevictable(page)) {
             ClearPageActive(page);
             list_move(&page->lru, &clean_pages);
         }
     }
 
     nr_reclaimed = shrink_page_list(&clean_pages, zone->zone_pgdat, &sc,
                     &stat, true,NULL);
     list_splice(&clean_pages, page_list);
     mod_node_page_state(zone->zone_pgdat, NR_ISOLATED_FILE,
                 -(long)nr_reclaimed);
     /*
      * Since lazyfree pages are isolated from file LRU from the beginning,
      * they will rotate back to anonymous LRU in the end if it failed to
      * discard so isolated count will be mismatched.
      * Compensate the isolated count for both LRU lists.
      */
     mod_node_page_state(zone->zone_pgdat, NR_ISOLATED_ANON,
                 stat.nr_lazyfree_fail);
     mod_node_page_state(zone->zone_pgdat, NR_ISOLATED_FILE,
                 -(long)stat.nr_lazyfree_fail);
     return nr_reclaimed;
 }
 
 int reclaim_pages_from_list(struct list_head *page_list)
 {
     struct scan_control sc = {
         .gfp_mask = GFP_KERNEL,
         .priority = DEF_PRIORITY,
         .may_writepage = 1,
         .may_unmap = 1,
         .may_swap = 1,
     };
     unsigned long nr_reclaimed;
     struct reclaim_stat dummy_stat;
     struct page *page;
     printk("lwt:%s satrt!\n",__FUNCTION__);
     list_for_each_entry(page, page_list, lru)
         ClearPageActive(page);
 
     nr_reclaimed = shrink_page_list(page_list, NULL, &sc,
                 &dummy_stat, false,NULL);
     while (!list_empty(page_list)) {
 
         page = lru_to_page(page_list);
         list_del(&page->lru);
         dec_node_page_state(page, NR_ISOLATED_ANON +
                 page_is_file_lru(page));
         putback_lru_page(page);
     }
 
     return nr_reclaimed;
 }
 
 /*
  * Attempt to remove the specified page from its LRU.  Only take this page
  * if it is of the appropriate PageActive status.  Pages which are being
  * freed elsewhere are also ignored.
  *
  * page:	page to consider
  * mode:	one of the LRU isolation modes defined above
  *
  * returns 0 on success, -ve errno on failure.
  */
 int __isolate_lru_page(struct page *page, isolate_mode_t mode)
 {
     int ret = -EINVAL;
 
     /* Only take pages on the LRU. */
     if (!PageLRU(page))
         return ret;
 
     /* Compaction should not handle unevictable pages but CMA can do so */
     if (PageUnevictable(page) && !(mode & ISOLATE_UNEVICTABLE))
         return ret;
 
     ret = -EBUSY;
 
     /*
      * To minimise LRU disruption, the caller can indicate that it only
      * wants to isolate pages it will be able to operate on without
      * blocking - clean pages for the most part.
      *
      * ISOLATE_ASYNC_MIGRATE is used to indicate that it only wants to pages
      * that it is possible to migrate without blocking
      */
     if (mode & ISOLATE_ASYNC_MIGRATE) {
         /* All the caller can do on PageWriteback is block */
         if (PageWriteback(page))
             return ret;
 
         if (PageDirty(page)) {
             struct address_space *mapping;
             bool migrate_dirty;
 
             /*
              * Only pages without mappings or that have a
              * ->migratepage callback are possible to migrate
              * without blocking. However, we can be racing with
              * truncation so it's necessary to lock the page
              * to stabilise the mapping as truncation holds
              * the page lock until after the page is removed
              * from the page cache.
              */
             if (!trylock_page(page))
                 return ret;
 
             mapping = page_mapping(page);
             migrate_dirty = !mapping || mapping->a_ops->migratepage;
             unlock_page(page);
             if (!migrate_dirty)
                 return ret;
         }
     }
 
     if ((mode & ISOLATE_UNMAPPED) && page_mapped(page))
         return ret;
 
     if (likely(get_page_unless_zero(page))) {
         /*
          * Be careful not to clear PageLRU until after we're
          * sure the page is not being freed elsewhere -- the
          * page release code relies on it.
          */
         ClearPageLRU(page);
         ret = 0;
     }
 
     return ret;
 }
 
 
 /*
  * Update LRU sizes after isolating pages. The LRU size updates must
  * be complete before mem_cgroup_update_lru_size due to a sanity check.
  */
 static __always_inline void update_lru_sizes(struct lruvec *lruvec,
             enum lru_list lru, unsigned long *nr_zone_taken)
 {
     int zid;
 
     for (zid = 0; zid < MAX_NR_ZONES; zid++) {
         if (!nr_zone_taken[zid])
             continue;
 
         update_lru_size(lruvec, lru, zid, -nr_zone_taken[zid]);
     }
 
 }
 
 /**
  * pgdat->lru_lock is heavily contended.  Some of the functions that
  * shrink the lists perform better by taking out a batch of pages
  * and working on them outside the LRU lock.
  *
  * For pagecache intensive workloads, this function is the hottest
  * spot in the kernel (apart from copy_*_user functions).
  *
  * Appropriate locks must be held before calling this function.
  *
  * @nr_to_scan:	The number of eligible pages to look through on the list.
  * @lruvec:	The LRU vector to pull pages from.
  * @dst:	The temp list to put pages on to.
  * @nr_scanned:	The number of pages that were scanned.
  * @sc:		The scan_control struct for this reclaim session
  * @lru:	LRU list id for isolating
  *
  * returns how many pages were moved onto *@dst.
  */
 static unsigned long kisolate_lru_pages(unsigned long nr_to_scan,
         struct lruvec *lruvec, struct list_head *dst,
         unsigned long *nr_scanned, struct scan_control *sc,
         enum lru_list lru)
 {
     struct list_head *src = &lruvec->lists[lru];
     unsigned long nr_taken = 0;
     unsigned long nr_zone_taken[MAX_NR_ZONES] = { 0 };
     unsigned long nr_skipped[MAX_NR_ZONES] = { 0, };
     unsigned long skipped = 0;
     unsigned long scan, total_scan, nr_pages;
     LIST_HEAD(pages_skipped);
     isolate_mode_t mode = (sc->may_unmap ? 0 : ISOLATE_UNMAPPED);
 
     total_scan = 0;
     scan = 0;
     while (scan < nr_to_scan && !list_empty(src)) {
         struct page *page;
 
         page = lru_to_page(src);
         prefetchw_prev_lru_page(page, src, flags);
 
         VM_BUG_ON_PAGE(!PageLRU(page), page);
 
         nr_pages = compound_nr(page);
         total_scan += nr_pages;
 
         if (page_zonenum(page) > sc->reclaim_idx) {
             list_move(&page->lru, &pages_skipped);
             nr_skipped[page_zonenum(page)] += nr_pages;
             continue;
         }
 
         /*
          * Do not count skipped pages because that makes the function
          * return with no isolated pages if the LRU mostly contains
          * ineligible pages.  This causes the VM to not reclaim any
          * pages, triggering a premature OOM.
          *
          * Account all tail pages of THP.  This would not cause
          * premature OOM since __isolate_lru_page() returns -EBUSY
          * only when the page is being freed somewhere else.
          */
         scan += nr_pages;
         switch (__isolate_lru_page(page, mode)) {
         case 0:
             nr_taken += nr_pages;
             nr_zone_taken[page_zonenum(page)] += nr_pages;
             list_move(&page->lru, dst);
             break;
 
         case -EBUSY:
             /* else it is being freed elsewhere */
             list_move(&page->lru, src);
             continue;
 
         default:
             BUG();
         }
     }
 
     /*
      * Splice any skipped pages to the start of the LRU list. Note that
      * this disrupts the LRU order when reclaiming for lower zones but
      * we cannot splice to the tail. If we did then the SWAP_CLUSTER_MAX
      * scanning would soon rescan the same pages to skip and put the
      * system at risk of premature OOM.
      */
     if (!list_empty(&pages_skipped)) {
         int zid;
 
         list_splice(&pages_skipped, src);
         for (zid = 0; zid < MAX_NR_ZONES; zid++) {
             if (!nr_skipped[zid])
                 continue;
 
             __count_zid_vm_events(PGSCAN_SKIP, zid, nr_skipped[zid]);
             skipped += nr_skipped[zid];
         }
     }
     *nr_scanned = total_scan;
     trace_mm_vmscan_lru_isolate(sc->reclaim_idx, sc->order, nr_to_scan,
                     total_scan, skipped, nr_taken, mode, lru);
     update_lru_sizes(lruvec, lru, nr_zone_taken);
     return nr_taken;
 }
 
 /**
  * isolate_lru_page - tries to isolate a page from its LRU list
  * @page: page to isolate from its LRU list
  *
  * Isolates a @page from an LRU list, clears PageLRU and adjusts the
  * vmstat statistic corresponding to whatever LRU list the page was on.
  *
  * Returns 0 if the page was removed from an LRU list.
  * Returns -EBUSY if the page was not on an LRU list.
  *
  * The returned page will have PageLRU() cleared.  If it was found on
  * the active list, it will have PageActive set.  If it was found on
  * the unevictable list, it will have the PageUnevictable bit set. That flag
  * may need to be cleared by the caller before letting the page go.
  *
  * The vmstat statistic corresponding to the list on which the page was
  * found will be decremented.
  *
  * Restrictions:
  *
  * (1) Must be called with an elevated refcount on the page. This is a
  *     fundamental difference from kisolate_lru_pages (which is called
  *     without a stable reference).
  * (2) the lru_lock must not be held.
  * (3) interrupts must be enabled.
  */
 int isolate_lru_page(struct page *page)
 {
     int ret = -EBUSY;
 
     VM_BUG_ON_PAGE(!page_count(page), page);
     WARN_RATELIMIT(PageTail(page), "trying to isolate tail page");
 
     if (PageLRU(page)) {
         pg_data_t *pgdat = page_pgdat(page);
         struct lruvec *lruvec;
 
         spin_lock_irq(&pgdat->lru_lock);
         lruvec = mem_cgroup_page_lruvec(page, pgdat);
         if (PageLRU(page)) {
             get_page(page);
             ClearPageLRU(page);
             del_page_from_lru_list(page, lruvec);
             ret = 0;
         }
         spin_unlock_irq(&pgdat->lru_lock);
     }
     return ret;
 }
 
 /*
  * A direct reclaimer may isolate SWAP_CLUSTER_MAX pages from the LRU list and
  * then get rescheduled. When there are massive number of tasks doing page
  * allocation, such sleeping direct reclaimers may keep piling up on each CPU,
  * the LRU list will go small and be scanned faster than necessary, leading to
  * unnecessary swapping, thrashing and OOM.
  */
 static int too_many_isolated(struct pglist_data *pgdat, int file,
         struct scan_control *sc)
 {
     unsigned long inactive, isolated;
 
     if (current_is_kshrinkd())
         return 0;
 
     if (!writeback_throttling_sane(sc))
         return 0;
 
     if (file) {
         inactive = node_page_state(pgdat, NR_INACTIVE_FILE);
         isolated = node_page_state(pgdat, NR_ISOLATED_FILE);
     } else {
         inactive = node_page_state(pgdat, NR_INACTIVE_ANON);
         isolated = node_page_state(pgdat, NR_ISOLATED_ANON);
     }
 
     /*
      * GFP_NOIO/GFP_NOFS callers are allowed to isolate more pages, so they
      * won't get blocked by normal direct-reclaimers, forming a circular
      * deadlock.
      */
     if ((sc->gfp_mask & (__GFP_IO | __GFP_FS)) == (__GFP_IO | __GFP_FS))
         inactive >>= 3;
 
     return isolated > inactive;
 }
 
 /*
  * This moves pages from @list to corresponding LRU list.
  *
  * We move them the other way if the page is referenced by one or more
  * processes, from rmap.
  *
  * If the pages are mostly unmapped, the processing is fast and it is
  * appropriate to hold zone_lru_lock across the whole operation.  But if
  * the pages are mapped, the processing is slow (page_referenced()) so we
  * should drop zone_lru_lock around each page.  It's impossible to balance
  * this, so instead we remove the pages from the LRU while processing them.
  * It is safe to rely on PG_active against the non-LRU pages in here because
  * nobody will play with that bit on a non-LRU page.
  *
  * The downside is that we have to touch page->_refcount against each page.
  * But we had to alter page->flags anyway.
  *
  * Returns the number of pages moved to the given lruvec.
  */
 
 static unsigned noinline_for_stack move_pages_to_lru(struct lruvec *lruvec,
                              struct list_head *list)
 {
     struct pglist_data *pgdat = lruvec_pgdat(lruvec);
     int nr_pages, nr_moved = 0;
     LIST_HEAD(pages_to_free);
     struct page *page;
 
     while (!list_empty(list)) {
         page = lru_to_page(list);
         VM_BUG_ON_PAGE(PageLRU(page), page);
         list_del(&page->lru);
         if (unlikely(!page_evictable(page))) {
             spin_unlock_irq(&pgdat->lru_lock);
             putback_lru_page(page);
             spin_lock_irq(&pgdat->lru_lock);
             continue;
         }
         lruvec = mem_cgroup_page_lruvec(page, pgdat);
 
         SetPageLRU(page);
         add_page_to_lru_list(page, lruvec);
 
         if (put_page_testzero(page)) {
             del_page_from_lru_list(page, lruvec);
             __clear_page_lru_flags(page);
 
             if (unlikely(PageCompound(page))) {
                 spin_unlock_irq(&pgdat->lru_lock);
                 destroy_compound_page(page);
                 spin_lock_irq(&pgdat->lru_lock);
             } else
                 list_add(&page->lru, &pages_to_free);
         } else {
             nr_pages = thp_nr_pages(page);
             nr_moved += nr_pages;
             if (PageActive(page))
                 workingset_age_nonresident(lruvec, nr_pages);
         }
     }
 
     /*
      * To save our caller's stack, now use input list for pages to free.
      */
     list_splice(&pages_to_free, list);
 
     return nr_moved;
 }
 
 /*
  * If a kernel thread (such as nfsd for loop-back mounts) services
  * a backing device by writing to the page cache it sets PF_LOCAL_THROTTLE.
  * In that case we should only throttle if the backing device it is
  * writing to is congested.  In other cases it is safe to throttle.
  */
 static int current_may_throttle(void)
 {
     return !(current->flags & PF_LOCAL_THROTTLE) ||
         current->backing_dev_info == NULL ||
         bdi_write_congested(current->backing_dev_info);
 }
 
 /*
  * kshrink_inactive_list() is a helper for shrink_node().  It returns the number
  * of reclaimed pages
  */
 static noinline_for_stack unsigned long
 kshrink_inactive_list(unsigned long nr_to_scan, struct lruvec *lruvec,
              struct scan_control *sc, enum lru_list lru, unsigned long long *tar)
 {
     LIST_HEAD(page_list);
     unsigned long nr_scanned;
     unsigned long isolated;
     bool file = is_file_lru(lru);
     struct pglist_data *pgdat = lruvec_pgdat(lruvec);
     bool stalled = false;
     struct page *page, *tmp;
     
     while (unlikely(too_many_isolated(pgdat, file, sc))) {
         if (stalled)
             return 0;
 
         /* wait a bit for the reclaimer. */
         msleep(100);
         stalled = true;
 
         /* We are about to die and free our memory. Return now. */
         if (fatal_signal_pending(current))
             return SWAP_CLUSTER_MAX;
     }
 
     lru_add_drain();

     spin_lock_irq(&pgdat->lru_lock);
    
     nr_taken = kisolate_lru_pages(nr_to_scan, lruvec, &page_list,
                  &nr_scanned, lru, sc);
     
    spin_unlock_irq(&pgdat->lru_lock);
    
    if (nr_taken == 0)
         return 0;
 
     /* 处理隔离的页面 */
     list_for_each_entry_safe(page, tmp, &page_list, lru) {
         /* 检查是否达到上限 */
         if (atomic_read(&victim_page_count) >= VICTIM_LIST_MAX_PAGES)
             break;
 
         list_del(&page->lru);
         
         /* 添加到受害者列表 */
         spin_lock_irqsave(&victim_list_lock, flags);
         list_add_tail(&page->lru, &victim_page_list);
         SetPageVictim(page);
         atomic_inc(&victim_page_count);
         spin_unlock_irqrestore(&victim_list_lock, flags);
     }
 
     /* 将剩余页面放回 LRU */
     if (!list_empty(&page_list)) {
         spin_lock_irqsave(&lruvec->lru_lock, flags);
         putback_lru_pages(&page_list);
         spin_unlock_irqrestore(&lruvec->lru_lock, flags);
     }

     lru_add_drain();
 
     
     __mod_node_page_state(pgdat, NR_ISOLATED_ANON + file, nr_taken);
 
    return nr_pages;
 }
 
 static void kshrink_active_list(unsigned long nr_to_scan,
                    struct lruvec *lruvec,
                    struct scan_control *sc,
                    enum lru_list lru)
 {
     unsigned long nr_taken;
     unsigned long nr_scanned;
     unsigned long vm_flags;
     LIST_HEAD(l_hold);	/* The pages which were snipped off */
     LIST_HEAD(l_active);
     LIST_HEAD(l_inactive);
     struct page *page;
     unsigned nr_deactivate, nr_activate;
     unsigned nr_rotated = 0;
     int file = is_file_lru(lru);
     struct pglist_data *pgdat = lruvec_pgdat(lruvec);
 
     // ktime_t starttime, delta, shrinkactive_time;
     // unsigned long long duration;
     // starttime = ktime_get();
 
     lru_add_drain();
 
     spin_lock_irq(&pgdat->lru_lock);
 
     nr_taken = kisolate_lru_pages(nr_to_scan, lruvec, &l_hold,
                      &nr_scanned, sc, lru);
 
     // isolate_time = ktime_get();
     // delta = ktime_sub(isolate_time, starttime);
     // duration = (unsigned long long) ktime_to_us(delta);//΢��
     // printk("lwt:%s isolate_time %lld usecs\n",__FUNCTION__, duration);
 
 
     __mod_node_page_state(pgdat, NR_ISOLATED_ANON + file, nr_taken);
 
     if (!cgroup_reclaim(sc))
         __count_vm_events(PGREFILL, nr_scanned);
     __count_memcg_events(lruvec_memcg(lruvec), PGREFILL, nr_scanned);
 
     spin_unlock_irq(&pgdat->lru_lock);
 
     while (!list_empty(&l_hold)) {
         cond_resched();
         page = lru_to_page(&l_hold);
         list_del(&page->lru);
 
         if (unlikely(!page_evictable(page))) {
             putback_lru_page(page);
             continue;
         }
 
         if (unlikely(buffer_heads_over_limit)) {
             if (page_has_private(page) && trylock_page(page)) {
                 if (page_has_private(page))
                     try_to_release_page(page, 0);
                 unlock_page(page);
             }
         }
 
         /* Referenced or rmap lock contention: rotate */
         if (page_referenced(page, 0, sc->target_mem_cgroup,
                      &vm_flags) != 0) {
             /*
              * Identify referenced, file-backed active pages and
              * give them one more trip around the active list. So
              * that executable code get better chances to stay in
              * memory under moderate memory pressure.  Anon pages
              * are not likely to be evicted by use-once streaming
              * IO, plus JVM can create lots of anon VM_EXEC pages,
              * so we ignore them here.
              */
             if ((vm_flags & VM_EXEC) && page_is_file_lru(page)) {
                 nr_rotated += thp_nr_pages(page);
                 list_add(&page->lru, &l_active);
                 continue;
             }
         }
 
         ClearPageActive(page);	/* we are de-activating */
         SetPageWorkingset(page);
         list_add(&page->lru, &l_inactive);
     }
 
     /*
      * Move pages back to the lru list.
      */
     spin_lock_irq(&pgdat->lru_lock);
 
     nr_activate = move_pages_to_lru(lruvec, &l_active);
     nr_deactivate = move_pages_to_lru(lruvec, &l_inactive);
     /* Keep all free pages in l_active list */
     list_splice(&l_inactive, &l_active);
 
     __count_vm_events(PGDEACTIVATE, nr_deactivate);
     __count_memcg_events(lruvec_memcg(lruvec), PGDEACTIVATE, nr_deactivate);
 
     __mod_node_page_state(pgdat, NR_ISOLATED_ANON + file, -nr_taken);
     spin_unlock_irq(&pgdat->lru_lock);
 
     mem_cgroup_uncharge_list(&l_active);
     free_unref_page_list(&l_active);
     trace_mm_vmscan_lru_shrink_active(pgdat->node_id, nr_taken, nr_activate,
             nr_deactivate, nr_rotated, sc->priority, file);
     
 }
 
 unsigned long reclaim_pages(struct list_head *page_list)
 {
     int nid = NUMA_NO_NODE;
     unsigned int nr_reclaimed = 0;
     LIST_HEAD(node_page_list);
     struct reclaim_stat dummy_stat;
     struct page *page;
     struct blk_plug plug;
     bool do_plug = false;
     struct scan_control sc = {
         .gfp_mask = GFP_KERNEL,
         .priority = DEF_PRIORITY,
         .may_writepage = 1,
         .may_unmap = 1,
         .may_swap = 1,
     };
     printk("lwt:%s satrt!\n",__FUNCTION__);
     trace_android_vh_reclaim_pages_plug(&do_plug);
     if (do_plug)
         blk_start_plug(&plug);
 
     while (!list_empty(page_list)) {
         page = lru_to_page(page_list);
         if (nid == NUMA_NO_NODE) {
             nid = page_to_nid(page);
             INIT_LIST_HEAD(&node_page_list);
         }
 
         if (nid == page_to_nid(page)) {
             ClearPageActive(page);
             list_move(&page->lru, &node_page_list);
             continue;
         }
 
         nr_reclaimed += shrink_page_list(&node_page_list,
                         NODE_DATA(nid),
                         &sc, &dummy_stat, false,NULL);
         while (!list_empty(&node_page_list)) {
             page = lru_to_page(&node_page_list);
             list_del(&page->lru);
             putback_lru_page(page);
         }
 
         nid = NUMA_NO_NODE;
     }
 
     if (!list_empty(&node_page_list)) {
         nr_reclaimed += shrink_page_list(&node_page_list,
                         NODE_DATA(nid),
                         &sc, &dummy_stat, false,NULL);
         while (!list_empty(&node_page_list)) {
             page = lru_to_page(&node_page_list);
             list_del(&page->lru);
             putback_lru_page(page);
         }
     }
     if (do_plug)
         blk_finish_plug(&plug);
 
     return nr_reclaimed;
 }
 
 static unsigned long kshrink_list(enum lru_list lru, unsigned long nr_to_scan,
                  struct lruvec *lruvec, struct scan_control *sc, unsigned long long *par)
 {
     unsigned int tmp;
     unsigned long long x_time=0;
     ktime_t starttime, delta, shrinklist_time;
     unsigned long long duration=0;
     starttime = ktime_get();
     //printk("lwt:%s start!\n",__FUNCTION__);
     if (is_active_lru(lru)) {
         if (sc->may_deactivate & (1 << is_file_lru(lru)))
             kshrink_active_list(nr_to_scan, lruvec, sc, lru);
         else
             sc->skipped_deactivate = 1;
         return 0;
     }
     tmp = kshrink_inactive_list(nr_to_scan, lruvec, sc, lru, &x_time);
     *par = x_time;
 
     shrinklist_time = ktime_get();
     delta = ktime_sub(shrinklist_time, starttime);
     duration = (unsigned long long) ktime_to_us(delta);//΢��
     //printk("lwt:%s shrinklist_time %lld usecs\n",__FUNCTION__, duration);
     return tmp;
     // return kshrink_inactive_list(nr_to_scan, lruvec, sc, lru);
 }
 
 /*
  * The inactive anon list should be small enough that the VM never has
  * to do too much work.
  *
  * The inactive file list should be small enough to leave most memory
  * to the established workingset on the scan-resistant active list,
  * but large enough to avoid thrashing the aggregate readahead window.
  *
  * Both inactive lists should also be large enough that each inactive
  * page has a chance to be referenced again before it is reclaimed.
  *
  * If that fails and refaulting is observed, the inactive list grows.
  *
  * The inactive_ratio is the target ratio of ACTIVE to INACTIVE pages
  * on this LRU, maintained by the pageout code. An inactive_ratio
  * of 3 means 3:1 or 25% of the pages are kept on the inactive list.
  *
  * total     target    max
  * memory    ratio     inactive
  * -------------------------------------
  *   10MB       1         5MB
  *  100MB       1        50MB
  *    1GB       3       250MB
  *   10GB      10       0.9GB
  *  100GB      31         3GB
  *    1TB     101        10GB
  *   10TB     320        32GB
  */
 static bool inactive_is_low(struct lruvec *lruvec, enum lru_list inactive_lru)
 {
     enum lru_list active_lru = inactive_lru + LRU_ACTIVE;
     unsigned long inactive, active;
     unsigned long inactive_ratio;
     unsigned long gb;
 
     inactive = lruvec_page_state(lruvec, NR_LRU_BASE + inactive_lru);
     active = lruvec_page_state(lruvec, NR_LRU_BASE + active_lru);
 
     gb = (inactive + active) >> (30 - PAGE_SHIFT);
     if (gb)
         inactive_ratio = int_sqrt(10 * gb);
     else
         inactive_ratio = 1;
 
     trace_android_vh_tune_inactive_ratio(&inactive_ratio, is_file_lru(inactive_lru));
 
     return inactive * inactive_ratio < active;
 }
 
 enum scan_balance {
     SCAN_EQUAL,
     SCAN_FRACT,
     SCAN_ANON,
     SCAN_FILE,
 };
 
 static void prepare_scan_count(pg_data_t *pgdat, struct scan_control *sc)
 {
     unsigned long file;
     struct lruvec *target_lruvec;
 
     if (lru_gen_enabled())
         return;
 
     target_lruvec = mem_cgroup_lruvec(sc->target_mem_cgroup, pgdat);
 
     /*
      * Determine the scan balance between anon and file LRUs.
      */
     spin_lock_irq(&pgdat->lru_lock);
     sc->anon_cost = target_lruvec->anon_cost;
     sc->file_cost = target_lruvec->file_cost;
     spin_unlock_irq(&pgdat->lru_lock);
 
     /*
      * Target desirable inactive:active list ratios for the anon
      * and file LRU lists.
      */
     if (!sc->force_deactivate) {
         unsigned long refaults;
 
         refaults = lruvec_page_state(target_lruvec,
                 WORKINGSET_ACTIVATE_ANON);
         if (refaults != target_lruvec->refaults[0] ||
             inactive_is_low(target_lruvec, LRU_INACTIVE_ANON))
             sc->may_deactivate |= DEACTIVATE_ANON;
         else
             sc->may_deactivate &= ~DEACTIVATE_ANON;
 
         /*
          * When refaults are being observed, it means a new
          * workingset is being established. Deactivate to get
          * rid of any stale active pages quickly.
          */
         refaults = lruvec_page_state(target_lruvec,
                 WORKINGSET_ACTIVATE_FILE);
         if (refaults != target_lruvec->refaults[1] ||
             inactive_is_low(target_lruvec, LRU_INACTIVE_FILE))
             sc->may_deactivate |= DEACTIVATE_FILE;
         else
             sc->may_deactivate &= ~DEACTIVATE_FILE;
     } else
         sc->may_deactivate = DEACTIVATE_ANON | DEACTIVATE_FILE;
 
     /*
      * If we have plenty of inactive file pages that aren't
      * thrashing, try to reclaim those first before touching
      * anonymous pages.
      */
     file = lruvec_page_state(target_lruvec, NR_INACTIVE_FILE);
     if (file >> sc->priority && !(sc->may_deactivate & DEACTIVATE_FILE))
         sc->cache_trim_mode = 1;
     else
         sc->cache_trim_mode = 0;
 
     /*
      * Prevent the reclaimer from falling into the cache trap: as
      * cache pages start out inactive, every cache fault will tip
      * the scan balance towards the file LRU.  And as the file LRU
      * shrinks, so does the window for rotation from references.
      * This means we have a runaway feedback loop where a tiny
      * thrashing file LRU becomes infinitely more attractive than
      * anon pages.  Try to detect this based on file LRU size.
      */
     if (!cgroup_reclaim(sc)) {
         unsigned long total_high_wmark = 0;
         unsigned long free, anon;
         int z;
 
         free = sum_zone_node_page_state(pgdat->node_id, NR_FREE_PAGES);
         file = node_page_state(pgdat, NR_ACTIVE_FILE) +
                node_page_state(pgdat, NR_INACTIVE_FILE);
 
         for (z = 0; z < MAX_NR_ZONES; z++) {
             struct zone *zone = &pgdat->node_zones[z];
 
             if (!managed_zone(zone))
                 continue;
 
             total_high_wmark += high_wmark_pages(zone);
         }
 
         /*
          * Consider anon: if that's low too, this isn't a
          * runaway file reclaim problem, but rather just
          * extreme pressure. Reclaim as per usual then.
          */
         anon = node_page_state(pgdat, NR_INACTIVE_ANON);
 
         sc->file_is_tiny =
             file + free <= total_high_wmark &&
             !(sc->may_deactivate & DEACTIVATE_ANON) &&
             anon >> sc->priority;
     }
 }
 
 /*
  * Determine how aggressively the anon and file LRU lists should be
  * scanned.  The relative value of each set of LRU lists is determined
  * by looking at the fraction of the pages scanned we did rotate back
  * onto the active list instead of evict.
  *
  * nr[0] = anon inactive pages to scan; nr[1] = anon active pages to scan
  * nr[2] = file inactive pages to scan; nr[3] = file active pages to scan
  */
 static void get_scan_count(struct lruvec *lruvec, struct scan_control *sc,
                unsigned long *nr)
 {
     struct mem_cgroup *memcg = lruvec_memcg(lruvec);
     unsigned long anon_cost, file_cost, total_cost;
     int swappiness = mem_cgroup_swappiness(memcg);
     u64 fraction[ANON_AND_FILE];
     u64 denominator = 0;	/* gcc */
     enum scan_balance scan_balance;
     unsigned long ap, fp;
     enum lru_list lru;
     bool balance_anon_file_reclaim = false;
     
 
     /* If we have no swap space, do not bother scanning anon pages. */
     if (!sc->may_swap || mem_cgroup_get_nr_swap_pages(memcg) <= 0) {
         scan_balance = SCAN_FILE;
         goto out;
     }
 
     trace_android_vh_tune_swappiness(&swappiness);
     /*
      * Global reclaim will swap to prevent OOM even with no
      * swappiness, but memcg users want to use this knob to
      * disable swapping for individual groups completely when
      * using the memory controller's swap limit feature would be
      * too expensive.
      */
     if (cgroup_reclaim(sc) && !swappiness) {
         scan_balance = SCAN_FILE;
         goto out;
     }
 
     /*
      * Do not apply any pressure balancing cleverness when the
      * system is close to OOM, scan both anon and file equally
      * (unless the swappiness setting disagrees with swapping).
      */
     if (!sc->priority && swappiness) {
         scan_balance = SCAN_EQUAL;
         goto out;
     }
 
     /*
      * If the system is almost out of file pages, force-scan anon.
      */
     if (sc->file_is_tiny) {
         scan_balance = SCAN_ANON;
         goto out;
     }
 
     trace_android_rvh_set_balance_anon_file_reclaim(&balance_anon_file_reclaim);
 
     /*
      * If there is enough inactive page cache, we do not reclaim
      * anything from the anonymous working right now. But when balancing
      * anon and page cache files for reclaim, allow swapping of anon pages
      * even if there are a number of inactive file cache pages.
      */
     if (!balance_anon_file_reclaim && sc->cache_trim_mode) {
         scan_balance = SCAN_FILE;
         goto out;
     }
 
     scan_balance = SCAN_FRACT;
     /*
      * Calculate the pressure balance between anon and file pages.
      *
      * The amount of pressure we put on each LRU is inversely
      * proportional to the cost of reclaiming each list, as
      * determined by the share of pages that are refaulting, times
      * the relative IO cost of bringing back a swapped out
      * anonymous page vs reloading a filesystem page (swappiness).
      *
      * Although we limit that influence to ensure no list gets
      * left behind completely: at least a third of the pressure is
      * applied, before swappiness.
      *
      * With swappiness at 100, anon and file have equal IO cost.
      */
     total_cost = sc->anon_cost + sc->file_cost;
     anon_cost = total_cost + sc->anon_cost;
     file_cost = total_cost + sc->file_cost;
     total_cost = anon_cost + file_cost;
 
     ap = swappiness * (total_cost + 1);
     ap /= anon_cost + 1;
 
     fp = (200 - swappiness) * (total_cost + 1);
     fp /= file_cost + 1;
 
     fraction[0] = ap;
     fraction[1] = fp;
     denominator = ap + fp;
 out:
     trace_android_vh_tune_scan_type((char *)(&scan_balance));
     trace_android_vh_tune_memcg_scan_type(memcg, (char *)(&scan_balance));
     for_each_evictable_lru(lru) {
         int file = is_file_lru(lru);
         unsigned long lruvec_size;
         unsigned long low, min;
         unsigned long scan;
 
         lruvec_size = lruvec_lru_size(lruvec, lru, sc->reclaim_idx);
         mem_cgroup_protection(sc->target_mem_cgroup, memcg,
                       &min, &low);
 
         if (min || low) {
             /*
              * Scale a cgroup's reclaim pressure by proportioning
              * its current usage to its memory.low or memory.min
              * setting.
              *
              * This is important, as otherwise scanning aggression
              * becomes extremely binary -- from nothing as we
              * approach the memory protection threshold, to totally
              * nominal as we exceed it.  This results in requiring
              * setting extremely liberal protection thresholds. It
              * also means we simply get no protection at all if we
              * set it too low, which is not ideal.
              *
              * If there is any protection in place, we reduce scan
              * pressure by how much of the total memory used is
              * within protection thresholds.
              *
              * There is one special case: in the first reclaim pass,
              * we skip over all groups that are within their low
              * protection. If that fails to reclaim enough pages to
              * satisfy the reclaim goal, we come back and override
              * the best-effort low protection. However, we still
              * ideally want to honor how well-behaved groups are in
              * that case instead of simply punishing them all
              * equally. As such, we reclaim them based on how much
              * memory they are using, reducing the scan pressure
              * again by how much of the total memory used is under
              * hard protection.
              */
             unsigned long cgroup_size = mem_cgroup_size(memcg);
             unsigned long protection;
 
             /* memory.low scaling, make sure we retry before OOM */
             if (!sc->memcg_low_reclaim && low > min) {
                 protection = low;
                 sc->memcg_low_skipped = 1;
             } else {
                 protection = min;
             }
 
             /* Avoid TOCTOU with earlier protection check */
             cgroup_size = max(cgroup_size, protection);
 
             scan = lruvec_size - lruvec_size * protection /
                 (cgroup_size + 1);
 
             /*
              * Minimally target SWAP_CLUSTER_MAX pages to keep
              * reclaim moving forwards, avoiding decrementing
              * sc->priority further than desirable.
              */
             scan = max(scan, SWAP_CLUSTER_MAX);
         } else {
             scan = lruvec_size;
         }
 
         scan >>= sc->priority;
 
         /*
          * If the cgroup's already been deleted, make sure to
          * scrape out the remaining cache.
          */
         if (!scan && !mem_cgroup_online(memcg))
             scan = min(lruvec_size, SWAP_CLUSTER_MAX);
 
         switch (scan_balance) {
         case SCAN_EQUAL:
             /* Scan lists relative to size */
             break;
         case SCAN_FRACT:
             /*
              * Scan types proportional to swappiness and
              * their relative recent reclaim efficiency.
              * Make sure we don't miss the last page on
              * the offlined memory cgroups because of a
              * round-off error.
              */
             scan = mem_cgroup_online(memcg) ?
                    div64_u64(scan * fraction[file], denominator) :
                    DIV64_U64_ROUND_UP(scan * fraction[file],
                           denominator);
             break;
         case SCAN_FILE:
         case SCAN_ANON:
             /* Scan one type exclusively */
             if ((scan_balance == SCAN_FILE) != file)
                 scan = 0;
             break;
         default:
             /* Look ma, no brain */
             BUG();
         }
 
         nr[lru] = scan;
     }
 }
 

 
   

static void kshrink_lruvec(struct lruvec *lruvec, struct scan_control *sc, unsigned long long *lwt2)
 {
     // struct timeval tv_begin1;
     // struct timeval tv_begin2;
     // struct timeval tv_end;
     unsigned long nr[NR_LRU_LISTS];
     unsigned long targets[NR_LRU_LISTS];
     unsigned long nr_to_scan;
     unsigned long total_scan = 0;
     enum lru_list lru;
     unsigned long nr_reclaimed = 0;
     unsigned long nr_to_reclaim = sc->nr_to_reclaim;
     bool proportional_reclaim;
     struct blk_plug plug;
     bool do_plug = true;
 
     
     printk("lwt:%s start!\n",__FUNCTION__);
 
     satrt_time = ktime_get();
 
     if (lru_gen_enabled()) {
         lru_gen_kshrink_lruvec(lruvec, sc);
         return;
     }
 
 
     get_scan_count(lruvec, sc, nr);
 

 
     /* Record the original scan target for proportional adjustments later */
     memcpy(targets, nr, sizeof(nr));
 
     /*
      * Global reclaiming within direct reclaim at DEF_PRIORITY is a normal
      * event that can occur when there is little memory pressure e.g.
      * multiple streaming readers/writers. Hence, we do not abort scanning
      * when the requested number of pages are reclaimed when scanning at
      * DEF_PRIORITY on the assumption that the fact we are direct
      * reclaiming implies that kshrinkd is not keeping up and it is best to
      * do a batch of work at once. For memcg reclaim one check is made to
      * abort proportional reclaim if either the file or anon lru has already
      * dropped to zero at the first pass.
      */
     proportional_reclaim = (!cgroup_reclaim(sc) && !current_is_kshrinkd() &&
                 sc->priority == DEF_PRIORITY);
 
     trace_android_vh_kshrink_lruvec_blk_plug(&do_plug);
     if (do_plug)
         blk_start_plug(&plug);
     while (nr[LRU_INACTIVE_ANON] || nr[LRU_ACTIVE_FILE] ||
                     nr[LRU_INACTIVE_FILE]) {
         unsigned long nr_anon, nr_file, percentage;
         unsigned long nr_scanned;
 
         for_each_evictable_lru(lru) {
             if (nr[lru]) {
                 nr_to_scan = min(nr[lru], SWAP_CLUSTER_MAX);
                 total_scan = total_scan + nr_to_scan;
                 nr[lru] -= nr_to_scan;
 
                 nr_reclaimed += kshrink_list(lru, nr_to_scan,
                                 lruvec, sc, &every_time);
         
             }
         }
 
         cond_resched();
 
         if (nr_reclaimed < nr_to_reclaim || proportional_reclaim)
             continue;
 
         /*
          * For kshrinkd and memcg, reclaim at least the number of pages
          * requested. Ensure that the anon and file LRUs are scanned
          * proportionally what was requested by get_scan_count(). We
          * stop reclaiming one LRU and reduce the amount scanning
          * proportional to the original scan target.
          */
         nr_file = nr[LRU_INACTIVE_FILE] + nr[LRU_ACTIVE_FILE];
         nr_anon = nr[LRU_INACTIVE_ANON] + nr[LRU_ACTIVE_ANON];
 
         /*
          * It's just vindictive to attack the larger once the smaller
          * has gone to zero.  And given the way we stop scanning the
          * smaller below, this makes sure that we only make one nudge
          * towards proportionality once we've got nr_to_reclaim.
          */
         if (!nr_file || !nr_anon)
         {
             printk("lwt:%s, break!\n", __FUNCTION__);
             break;
         }
 
         if (nr_file > nr_anon) {
             unsigned long scan_target = targets[LRU_INACTIVE_ANON] +
                         targets[LRU_ACTIVE_ANON] + 1;
             lru = LRU_BASE;
             percentage = nr_anon * 100 / scan_target;
         } else {
             unsigned long scan_target = targets[LRU_INACTIVE_FILE] +
                         targets[LRU_ACTIVE_FILE] + 1;
             lru = LRU_FILE;
             percentage = nr_file * 100 / scan_target;
         }
 
         /* Stop scanning the smaller of the LRU */
         nr[lru] = 0;
         nr[lru + LRU_ACTIVE] = 0;
 
         /*
          * Recalculate the other LRU scan count based on its original
          * scan target and the percentage scanning already complete
          */
         lru = (lru == LRU_FILE) ? LRU_BASE : LRU_FILE;
         nr_scanned = targets[lru] - nr[lru];
         nr[lru] = targets[lru] * (100 - percentage) / 100;
         nr[lru] -= min(nr[lru], nr_scanned);
 
         lru += LRU_ACTIVE;
         nr_scanned = targets[lru] - nr[lru];
         nr[lru] = targets[lru] * (100 - percentage) / 100;
         nr[lru] -= min(nr[lru], nr_scanned);
     }
     if (do_plug)
         blk_finish_plug(&plug);
     sc->nr_reclaimed += nr_reclaimed;
 
   
     /*
      * Even if we did not try to evict anon pages at all, we want to
      * rebalance the anon lru active/inactive ratio.
      */
     if (total_swap_pages && inactive_is_low(lruvec, LRU_INACTIVE_ANON))
         kshrink_active_list(SWAP_CLUSTER_MAX, lruvec,
                    sc, LRU_ACTIVE_ANON);
 
 }
 
 /* Use reclaim/compaction for costly allocs or under memory pressure */
 static bool in_reclaim_compaction(struct scan_control *sc)
 {
     if (IS_ENABLED(CONFIG_COMPACTION) && sc->order &&
             (sc->order > PAGE_ALLOC_COSTLY_ORDER ||
              sc->priority < DEF_PRIORITY - 2))
         return true;
 
     return false;
 }
 
 /*
  * Reclaim/compaction is used for high-order allocation requests. It reclaims
  * order-0 pages before compacting the zone. should_continue_reclaim() returns
  * true if more pages should be reclaimed such that when the page allocator
  * calls try_to_compact_pages() that it will have enough free pages to succeed.
  * It will give up earlier than that if there is difficulty reclaiming pages.
  */
 static inline bool should_continue_reclaim(struct pglist_data *pgdat,
                     unsigned long nr_reclaimed,
                     struct scan_control *sc)
 {
     unsigned long pages_for_compaction;
     unsigned long inactive_lru_pages;
     int z;
 
     /* If not in reclaim/compaction mode, stop */
     if (!in_reclaim_compaction(sc))
         return false;
 
     /*
      * Stop if we failed to reclaim any pages from the last SWAP_CLUSTER_MAX
      * number of pages that were scanned. This will return to the caller
      * with the risk reclaim/compaction and the resulting allocation attempt
      * fails. In the past we have tried harder for __GFP_RETRY_MAYFAIL
      * allocations through requiring that the full LRU list has been scanned
      * first, by assuming that zero delta of sc->nr_scanned means full LRU
      * scan, but that approximation was wrong, and there were corner cases
      * where always a non-zero amount of pages were scanned.
      */
     if (!nr_reclaimed)
         return false;
 
     /* If compaction would go ahead or the allocation would succeed, stop */
     for (z = 0; z <= sc->reclaim_idx; z++) {
         struct zone *zone = &pgdat->node_zones[z];
         if (!managed_zone(zone))
             continue;
 
         switch (compaction_suitable(zone, sc->order, 0, sc->reclaim_idx)) {
         case COMPACT_SUCCESS:
         case COMPACT_CONTINUE:
             return false;
         default:
             /* check next zone */
             ;
         }
     }
 
     /*
      * If we have not reclaimed enough pages for compaction and the
      * inactive lists are large enough, continue reclaiming
      */
     pages_for_compaction = compact_gap(sc->order);
     inactive_lru_pages = node_page_state(pgdat, NR_INACTIVE_FILE);
     if (get_nr_swap_pages() > 0)
         inactive_lru_pages += node_page_state(pgdat, NR_INACTIVE_ANON);
 
     return inactive_lru_pages > pages_for_compaction;
 }
 
 static void kshrink_node_memcgs(pg_data_t *pgdat, struct scan_control *sc, unsigned long long *lwt1)
 {
     struct mem_cgroup *target_memcg = sc->target_mem_cgroup;
     struct mem_cgroup *memcg;
     
     ktime_t starttime, delta, shrinkmemcgs_time;
     unsigned long long duration;
     unsigned long long mid_time;
     starttime = ktime_get();
     printk("lwt:%s start!\n",__FUNCTION__);
     memcg = mem_cgroup_iter(target_memcg, NULL, NULL);
     do {
         struct lruvec *lruvec = mem_cgroup_lruvec(memcg, pgdat);
         unsigned long reclaimed;
         unsigned long scanned;
 
         /*
          * This loop can become CPU-bound when target memcgs
          * aren't eligible for reclaim - either because they
          * don't have any reclaimable pages, or because their
          * memory is explicitly protected. Avoid soft lockups.
          */
         cond_resched();
 
         mem_cgroup_calculate_protection(target_memcg, memcg);
 
         if (mem_cgroup_below_min(memcg)) {
             /*
              * Hard protection.
              * If there is no reclaimable memory, OOM.
              */
             continue;
         } else if (mem_cgroup_below_low(memcg)) {
             /*
              * Soft protection.
              * Respect the protection only as long as
              * there is an unprotected supply
              * of reclaimable memory from other cgroups.
              */
             if (!sc->memcg_low_reclaim) {
                 sc->memcg_low_skipped = 1;
                 continue;
             }
             memcg_memory_event(memcg, MEMCG_LOW);
         }
 
         reclaimed = sc->nr_reclaimed;
         scanned = sc->nr_scanned;
 
         kshrink_lruvec(lruvec, sc, &mid_time);
 
         shrink_slab(sc->gfp_mask, pgdat->node_id, memcg,
                 sc->priority);
 
         /* Record the group's reclaim efficiency */
         vmpressure(sc->gfp_mask, memcg, false,
                sc->nr_scanned - scanned,
                sc->nr_reclaimed - reclaimed);
 
     } while ((memcg = mem_cgroup_iter(target_memcg, memcg, NULL)));
 
     shrinkmemcgs_time = ktime_get();
     delta = ktime_sub(shrinkmemcgs_time, starttime);
     duration = (unsigned long long) ktime_to_us(delta);//΢��
     *lwt1 = mid_time;
    // printk("lwt:%s shrinkmemcgs_time %lld usecs\n",__FUNCTION__, duration);
 }
 
 static void kshrink_node(pg_data_t *pgdat, struct scan_control *sc)
 {
     struct reclaim_state *reclaim_state = current->reclaim_state;
     unsigned long nr_reclaimed, nr_scanned;
     struct lruvec *target_lruvec;
     bool reclaimable = false;
     ktime_t starttime, delta, shrinknode_time;
     unsigned long long duration;
     unsigned long long tmp;
     starttime = ktime_get();
     printk("lwt:%s start!\n",__FUNCTION__);
     target_lruvec = mem_cgroup_lruvec(sc->target_mem_cgroup, pgdat);
 
 again:
     memset(&sc->nr, 0, sizeof(sc->nr));
 
     nr_reclaimed = sc->nr_reclaimed;
     nr_scanned = sc->nr_scanned;
 
     prepare_scan_count(pgdat, sc);
 
     kshrink_node_memcgs(pgdat, sc, &tmp);
 
     if (reclaim_state) {
         sc->nr_reclaimed += reclaim_state->reclaimed_slab;
         reclaim_state->reclaimed_slab = 0;
     }
 
     /* Record the subtree's reclaim efficiency */
     vmpressure(sc->gfp_mask, sc->target_mem_cgroup, true,
            sc->nr_scanned - nr_scanned,
            sc->nr_reclaimed - nr_reclaimed);
 
     if (sc->nr_reclaimed - nr_reclaimed)
         reclaimable = true;
 
     if (current_is_kshrinkd()) {
         /*
          * If reclaim is isolating dirty pages under writeback,
          * it implies that the long-lived page allocation rate
          * is exceeding the page laundering rate. Either the
          * global limits are not being effective at throttling
          * processes due to the page distribution throughout
          * zones or there is heavy usage of a slow backing
          * device. The only option is to throttle from reclaim
          * context which is not ideal as there is no guarantee
          * the dirtying process is throttled in the same way
          * balance_dirty_pages() manages.
          *
          * Once a node is flagged PGDAT_WRITEBACK, kshrinkd will
          * count the number of pages under pages flagged for
          * immediate reclaim and stall if any are encountered
          * in the nr_immediate check below.
          */
         if (sc->nr.writeback && sc->nr.writeback == sc->nr.taken)
             set_bit(PGDAT_WRITEBACK, &pgdat->flags);
 
         /* Allow kshrinkd to start writing pages during reclaim.*/
         if (sc->nr.unqueued_dirty == sc->nr.file_taken)
             set_bit(PGDAT_DIRTY, &pgdat->flags);
 
         /*
          * If kshrinkd scans pages marked for immediate
          * reclaim and under writeback (nr_immediate), it
          * implies that pages are cycling through the LRU
          * faster than they are written so also forcibly stall.
          */
         if (sc->nr.immediate)
             congestion_wait(BLK_RW_ASYNC, HZ/10);
     }
 
     /*
      * Tag a node/memcg as congested if all the dirty pages
      * scanned were backed by a congested BDI and
      * wait_iff_congested will stall.
      *
      * Legacy memcg will stall in page writeback so avoid forcibly
      * stalling in wait_iff_congested().
      */
     if ((current_is_kshrinkd() ||
          (cgroup_reclaim(sc) && writeback_throttling_sane(sc))) &&
         sc->nr.dirty && sc->nr.dirty == sc->nr.congested){
         printk("lwt: LRUVEC_CONGESTED\n");
         set_bit(LRUVEC_CONGESTED, &target_lruvec->flags);}
 
     /*
      * Stall direct reclaim for IO completions if underlying BDIs
      * and node is congested. Allow kshrinkd to continue until it
      * starts encountering unqueued dirty pages or cycling through
      * the LRU too quickly.
      */
     if (!current_is_kshrinkd() && current_may_throttle() &&
         !sc->hibernation_mode &&
         test_bit(LRUVEC_CONGESTED, &target_lruvec->flags)){
         printk("lwt: wait_iff_congested\n");
         wait_iff_congested(BLK_RW_ASYNC, HZ/10);}
 
     if (should_continue_reclaim(pgdat, sc->nr_reclaimed - nr_reclaimed,
                     sc))
         goto again;
 
     /*
      * kshrinkd gives up on balancing particular nodes after too
      * many failures to reclaim anything from them and goes to
      * sleep. On reclaim progress, reset the failure counter. A
      * successful direct reclaim run will revive a dormant kshrinkd.
      */
     if (reclaimable)
         pgdat->kshrinkd_failures = 0;
 
}
 
 /*
  * Returns true if compaction should go ahead for a costly-order request, or
  * the allocation would already succeed without compaction. Return false if we
  * should reclaim first.
  */
 static inline bool compaction_ready(struct zone *zone, struct scan_control *sc)
 {
     unsigned long watermark;
     enum compact_result suitable;
 
     suitable = compaction_suitable(zone, sc->order, 0, sc->reclaim_idx);
     if (suitable == COMPACT_SUCCESS)
         /* Allocation should succeed already. Don't reclaim. */
         return true;
     if (suitable == COMPACT_SKIPPED)
         /* Compaction cannot yet proceed. Do reclaim. */
         return false;
 
     /*
      * Compaction is already possible, but it takes time to run and there
      * are potentially other callers using the pages just freed. So proceed
      * with reclaim to make a buffer of free pages available to give
      * compaction a reasonable chance of completing and allocating the page.
      * Note that we won't actually reclaim the whole buffer in one attempt
      * as the target watermark in should_continue_reclaim() is lower. But if
      * we are already above the high+gap watermark, don't reclaim at all.
      */
     watermark = high_wmark_pages(zone) + compact_gap(sc->order);
 
     return zone_watermark_ok_safe(zone, 0, watermark, sc->reclaim_idx);
 }
 

 static void snapshot_refaults(struct mem_cgroup *target_memcg, pg_data_t *pgdat)
 {
     struct lruvec *target_lruvec;
     unsigned long refaults;
 
     if (lru_gen_enabled())
         return;
 
     target_lruvec = mem_cgroup_lruvec(target_memcg, pgdat);
     refaults = lruvec_page_state(target_lruvec, WORKINGSET_ACTIVATE_ANON);
     target_lruvec->refaults[0] = refaults;
     refaults = lruvec_page_state(target_lruvec, WORKINGSET_ACTIVATE_FILE);
     target_lruvec->refaults[1] = refaults;
 }
 

 
 static void kshrinkd_age_node(struct pglist_data *pgdat, struct scan_control *sc)
 {
     struct mem_cgroup *memcg;
     struct lruvec *lruvec;
 
     if (lru_gen_enabled()) {
         lru_gen_age_node(pgdat, sc);
         return;
     }
 
     if (!total_swap_pages)
         return;
 
     lruvec = mem_cgroup_lruvec(NULL, pgdat);
     if (!inactive_is_low(lruvec, LRU_INACTIVE_ANON))
         return;
 
     memcg = mem_cgroup_iter(NULL, NULL, NULL);
     do {
         lruvec = mem_cgroup_lruvec(memcg, pgdat);
         kshrink_active_list(SWAP_CLUSTER_MAX, lruvec,
                    sc, LRU_ACTIVE_ANON);
         memcg = mem_cgroup_iter(NULL, memcg, NULL);
     } while (memcg);
 }
 
 static bool pgdat_watermark_boosted(pg_data_t *pgdat, int highest_zoneidx)
 {
     int i;
     struct zone *zone;
 
     /*
      * Check for watermark boosts top-down as the higher zones
      * are more likely to be boosted. Both watermarks and boosts
      * should not be checked at the same time as reclaim would
      * start prematurely when there is no boosting and a lower
      * zone is balanced.
      */
     for (i = highest_zoneidx; i >= 0; i--) {
         zone = pgdat->node_zones + i;
         if (!managed_zone(zone))
             continue;
 
         if (zone->watermark_boost)
             return true;
     }
 
     return false;
 }
 
 /*
  * Returns true if there is an eligible zone balanced for the request order
  * and highest_zoneidx
  */
 static bool pgdat_balanced(pg_data_t *pgdat, int order, int highest_zoneidx)
 {
     int i;
     unsigned long mark = -1;
     struct zone *zone;
 
     /*
      * Check watermarks bottom-up as lower zones are more likely to
      * meet watermarks.
      */
     for (i = 0; i <= highest_zoneidx; i++) {
         zone = pgdat->node_zones + i;
 
         if (!managed_zone(zone))
             continue;
 
         mark = high_wmark_pages(zone);
         if (zone_watermark_ok_safe(zone, order, mark, highest_zoneidx))
             return true;
     }
 
     /*
      * If a node has no populated zone within highest_zoneidx, it does not
      * need balancing by definition. This can happen if a zone-restricted
      * allocation tries to wake a remote kshrinkd.
      */
     if (mark == -1)
         return true;
 
     return false;
 }
 
 /* Clear pgdat state for congested, dirty or under writeback. */
 static void clear_pgdat_congested(pg_data_t *pgdat)
 {
     struct lruvec *lruvec = mem_cgroup_lruvec(NULL, pgdat);
 
     clear_bit(LRUVEC_CONGESTED, &lruvec->flags);
     clear_bit(PGDAT_DIRTY, &pgdat->flags);
     clear_bit(PGDAT_WRITEBACK, &pgdat->flags);
 }
 
 /*
  * Prepare kshrinkd for sleeping. This verifies that there are no processes
  * waiting in throttle_direct_reclaim() and that watermarks have been met.
  *
  * Returns true if kshrinkd is ready to sleep
  */
 static bool prepare_kshrinkd_sleep(pg_data_t *pgdat, int order,
                 int highest_zoneidx)
 {
     /*
      * The throttled processes are normally woken up in kbalance_pgdat() as
      * soon as allow_direct_reclaim() is true. But there is a potential
      * race between when kshrinkd checks the watermarks and a process gets
      * throttled. There is also a potential race if processes get
      * throttled, kshrinkd wakes, a large process exits thereby balancing the
      * zones, which causes kshrinkd to exit kbalance_pgdat() before reaching
      * the wake up checks. If kshrinkd is going to sleep, no process should
      * be sleeping on pfmemalloc_wait, so wake them now if necessary. If
      * the wake up is premature, processes will wake kshrinkd and get
      * throttled again. The difference from wake ups in kbalance_pgdat() is
      * that here we are under prepare_to_wait().
      */
     if (waitqueue_active(&pgdat->pfmemalloc_wait))
         wake_up_all(&pgdat->pfmemalloc_wait);
 
     /* Hopeless node, leave it to direct reclaim */
     if (pgdat->kshrinkd_failures >= MAX_RECLAIM_RETRIES)
         return true;
 
     if (pgdat_balanced(pgdat, order, highest_zoneidx)) {
         clear_pgdat_congested(pgdat);
         return true;
     }
 
     return false;
 }
 
 /*
  * kshrinkd shrinks a node of pages that are at or below the highest usable
  * zone that is currently unbalanced.
  *
  * Returns true if kshrinkd scanned at least the requested number of pages to
  * reclaim or if the lack of progress was due to pages under writeback.
  * This is used to determine if the scanning priority needs to be raised.
  */
 static bool kshrinkd_shrink_node(pg_data_t *pgdat,
                    struct scan_control *sc)
 {
     struct zone *zone;
     int z;
     // ktime_t starttime, delta, shrinknode_time;
     // unsigned long long duration;
     // starttime = ktime_get();
     // printk("lwt:%s start",__FUNCTION__);
     /* Reclaim a number of pages proportional to the number of zones */
     sc->nr_to_reclaim = 0;
     for (z = 0; z <= sc->reclaim_idx; z++) {
         zone = pgdat->node_zones + z;
         if (!managed_zone(zone))
             continue;
 
         sc->nr_to_reclaim += max(high_wmark_pages(zone), SWAP_CLUSTER_MAX);
         //printk("lwt:%s, sc->high_wmark_pages is %d", __FUNCTION__,high_wmark_pages(zone));
     }
 
     /*
      * Historically care was taken to put equal pressure on all zones but
      * now pressure is applied based on node LRU order.
      */
     //printk("lwt:%s, sc->nr_to_reclaim is %d", __FUNCTION__,sc->nr_to_reclaim);
     kshrink_node(pgdat, sc);
 
     /*
      * Fragmentation may mean that the system cannot be rebalanced for
      * high-order allocations. If twice the allocation size has been
      * reclaimed then recheck watermarks only at order-0 to prevent
      * excessive reclaim. Assume that a process requested a high-order
      * can direct reclaim/compact.
      */
     if (sc->order && sc->nr_reclaimed >= compact_gap(sc->order))
         sc->order = 0;
     
     // shrinknode_time = ktime_get();
     // delta = ktime_sub(shrinknode_time, starttime);
     // duration = (unsigned long long) ktime_to_us(delta);//΢��
     // printk("lwt:%s shrinknode_time %lld usecs",__FUNCTION__, duration);
 
     return sc->nr_scanned >= sc->nr_to_reclaim;
 }
 
 /*
  * For kshrinkd, kbalance_pgdat() will reclaim pages across a node from zones
  * that are eligible for use by the caller until at least one zone is
  * balanced.
  *
  * Returns the order kshrinkd finished reclaiming at.
  *
  * kshrinkd scans the zones in the highmem->normal->dma direction.  It skips
  * zones which have free_pages > high_wmark_pages(zone), but once a zone is
  * found to have free_pages <= high_wmark_pages(zone), any page in that zone
  * or lower is eligible for reclaim until at least one usable zone is
  * balanced.
  */
 static int kbalance_pgdat(pg_data_t *pgdat, int order, int highest_zoneidx)
 {
     int i;
     unsigned long nr_soft_reclaimed;
     unsigned long nr_soft_scanned;
     unsigned long pflags;
     unsigned long nr_boost_reclaim;
     unsigned long zone_boosts[MAX_NR_ZONES] = { 0, };
     bool boosted;
     struct zone *zone;
     struct scan_control sc = {
         .gfp_mask = GFP_KERNEL,
         .order = order,
         .may_unmap = 1,
     };
 
     // ktime_t starttime, delta, balance_time;
     // unsigned long long duration;
 
     //printk("lwt:%s start",__FUNCTION__);
     // starttime = ktime_get();
 
     set_task_reclaim_state(current, &sc.reclaim_state);
     psi_memstall_enter(&pflags);
     __fs_reclaim_acquire();
 
     count_vm_event(PAGEOUTRUN);
 
     /*
      * Account for the reclaim boost. Note that the zone boost is left in
      * place so that parallel allocations that are near the watermark will
      * stall or direct reclaim until kshrinkd is finished.
      */
     nr_boost_reclaim = 0;
     for (i = 0; i <= highest_zoneidx; i++) {
         zone = pgdat->node_zones + i;
         if (!managed_zone(zone))
             continue;
 
         nr_boost_reclaim += zone->watermark_boost;
         zone_boosts[i] = zone->watermark_boost;
     }
     boosted = nr_boost_reclaim;
 
 restart:
     sc.priority = DEF_PRIORITY;
     do {
         unsigned long nr_reclaimed = sc.nr_reclaimed;
         bool raise_priority = true;
         bool balanced;
         bool ret;
 
         sc.reclaim_idx = highest_zoneidx;
 
         /*
          * If the number of buffer_heads exceeds the maximum allowed
          * then consider reclaiming from all zones. This has a dual
          * purpose -- on 64-bit systems it is expected that
          * buffer_heads are stripped during active rotation. On 32-bit
          * systems, highmem pages can pin lowmem memory and shrinking
          * buffers can relieve lowmem pressure. Reclaim may still not
          * go ahead if all eligible zones for the original allocation
          * request are balanced to avoid excessive reclaim from kshrinkd.
          */
         if (buffer_heads_over_limit) {
             for (i = MAX_NR_ZONES - 1; i >= 0; i--) {
                 zone = pgdat->node_zones + i;
                 if (!managed_zone(zone))
                     continue;
 
                 sc.reclaim_idx = i;
                 break;
             }
         }
 
         /*
          * If the pgdat is imbalanced then ignore boosting and preserve
          * the watermarks for a later time and restart. Note that the
          * zone watermarks will be still reset at the end of balancing
          * on the grounds that the normal reclaim should be enough to
          * re-evaluate if boosting is required when kshrinkd next wakes.
          */
         balanced = pgdat_balanced(pgdat, sc.order, highest_zoneidx);
         if (!balanced && nr_boost_reclaim) {
             nr_boost_reclaim = 0;
             goto restart;
         }
 
         /*
          * If boosting is not active then only reclaim if there are no
          * eligible zones. Note that sc.reclaim_idx is not used as
          * buffer_heads_over_limit may have adjusted it.
          */
         if (!nr_boost_reclaim && balanced)
             goto out;
 
         /* Limit the priority of boosting to avoid reclaim writeback */
         if (nr_boost_reclaim && sc.priority == DEF_PRIORITY - 2)
             raise_priority = false;
 
         /*
          * Do not writeback or swap pages for boosted reclaim. The
          * intent is to relieve pressure not issue sub-optimal IO
          * from reclaim context. If no pages are reclaimed, the
          * reclaim will be aborted.
          */
         sc.may_writepage = !laptop_mode && !nr_boost_reclaim;
         sc.may_swap = !nr_boost_reclaim;
 
         /*
          * Do some background aging, to give pages a chance to be
          * referenced before reclaiming. All pages are rotated
          * regardless of classzone as this is about consistent aging.
          */
         kshrinkd_age_node(pgdat, &sc);
 
         /*
          * If we're getting trouble reclaiming, start doing writepage
          * even in laptop mode.
          */
         if (sc.priority < DEF_PRIORITY - 2)
             sc.may_writepage = 1;
 
         /* Call soft limit reclaim before calling shrink_node. */
         sc.nr_scanned = 0;
         nr_soft_scanned = 0;
         nr_soft_reclaimed = mem_cgroup_soft_limit_reclaim(pgdat, sc.order,
                         sc.gfp_mask, &nr_soft_scanned);
         sc.nr_reclaimed += nr_soft_reclaimed;
 
         /*
          * There should be no need to raise the scanning priority if
          * enough pages are already being scanned that that high
          * watermark would be met at 100% efficiency.
          */
         if (kshrinkd_shrink_node(pgdat, &sc))
             raise_priority = false;
 
         /*
          * If the low watermark is met there is no need for processes
          * to be throttled on pfmemalloc_wait as they should not be
          * able to safely make forward progress. Wake them
          */
         if (waitqueue_active(&pgdat->pfmemalloc_wait) &&
                 allow_direct_reclaim(pgdat))
             wake_up_all(&pgdat->pfmemalloc_wait);
 
         /* Check if kshrinkd should be suspending */
         __fs_reclaim_release();
         ret = try_to_freeze();
         __fs_reclaim_acquire();
         if (ret || kthread_should_stop())
             break;
 
         /*
          * Raise priority if scanning rate is too low or there was no
          * progress in reclaiming pages
          */
         nr_reclaimed = sc.nr_reclaimed - nr_reclaimed;
         nr_boost_reclaim -= min(nr_boost_reclaim, nr_reclaimed);
 
         /*
          * If reclaim made no progress for a boost, stop reclaim as
          * IO cannot be queued and it could be an infinite loop in
          * extreme circumstances.
          */
         if (nr_boost_reclaim && !nr_reclaimed)
             break;
 
         if (raise_priority || !nr_reclaimed)
             sc.priority--;
     } while (sc.priority >= 1);
 
     if (!sc.nr_reclaimed)
         pgdat->kshrinkd_failures++;
 
 out:
     /* If reclaim was boosted, account for the reclaim done in this pass */
     if (boosted) {
         unsigned long flags;
 
         for (i = 0; i <= highest_zoneidx; i++) {
             if (!zone_boosts[i])
                 continue;
 
             /* Increments are under the zone lock */
             zone = pgdat->node_zones + i;
             spin_lock_irqsave(&zone->lock, flags);
             zone->watermark_boost -= min(zone->watermark_boost, zone_boosts[i]);
             spin_unlock_irqrestore(&zone->lock, flags);
         }
 
         /*
          * As there is now likely space, wakeup kcompact to defragment
          * pageblocks.
          */
         wakeup_kcompactd(pgdat, pageblock_order, highest_zoneidx);
     }
 
     snapshot_refaults(NULL, pgdat);
     __fs_reclaim_release();
     psi_memstall_leave(&pflags);
     set_task_reclaim_state(current, NULL);
 
     /*
      * Return the order kshrinkd stopped reclaiming at as
      * prepare_kshrinkd_sleep() takes it into account. If another caller
      * entered the allocator slow path while kshrinkd was awake, order will
      * remain at the higher level.
      */
 
     // balance_time = ktime_get();
     // delta = ktime_sub(balance_time, starttime);
     // duration = (unsigned long long) ktime_to_us(delta);//΢��
     // printk("lwt:%s balance_time %lld usecs",__FUNCTION__, duration);
 
     return sc.order;
 }
 
 /*
  * The pgdat->kshrinkd_highest_zoneidx is used to pass the highest zone index to
  * be reclaimed by kshrinkd from the waker. If the value is MAX_NR_ZONES which is
  * not a valid index then either kshrinkd runs for first time or kshrinkd couldn't
  * sleep after previous reclaim attempt (node is still unbalanced). In that
  * case return the zone index of the previous kshrinkd reclaim cycle.
  */
 static enum zone_type kshrinkd_highest_zoneidx(pg_data_t *pgdat,
                        enum zone_type prev_highest_zoneidx)
 {
     enum zone_type curr_idx = READ_ONCE(pgdat->kshrinkd_highest_zoneidx);
 
     return curr_idx == MAX_NR_ZONES ? prev_highest_zoneidx : curr_idx;
 }
 
 static void kshrinkd_try_to_sleep(pg_data_t *pgdat, int alloc_order, int reclaim_order,
                 unsigned int highest_zoneidx)
 {
     long remaining = 0;
     DEFINE_WAIT(wait);
 
     if (freezing(current) || kthread_should_stop())
         return;
 
     prepare_to_wait(&pgdat->kshrinkd_wait, &wait, TASK_INTERRUPTIBLE);
 
     /*
      * Try to sleep for a short interval. Note that kcompactd will only be
      * woken if it is possible to sleep for a short interval. This is
      * deliberate on the assumption that if reclaim cannot keep an
      * eligible zone balanced that it's also unlikely that compaction will
      * succeed.
      */
     if (prepare_kshrinkd_sleep(pgdat, reclaim_order, highest_zoneidx)) {
         /*
          * Compaction records what page blocks it recently failed to
          * isolate pages from and skips them in the future scanning.
          * When kshrinkd is going to sleep, it is reasonable to assume
          * that pages and compaction may succeed so reset the cache.
          */
         reset_isolation_suitable(pgdat);
 
         /*
          * We have freed the memory, now we should compact it to make
          * allocation of the requested order possible.
          */
         wakeup_kcompactd(pgdat, alloc_order, highest_zoneidx);
 
         remaining = schedule_timeout(HZ/10);
 
         /*
          * If woken prematurely then reset kshrinkd_highest_zoneidx and
          * order. The values will either be from a wakeup request or
          * the previous request that slept prematurely.
          */
         if (remaining) {
             WRITE_ONCE(pgdat->kshrinkd_highest_zoneidx,
                     kshrinkd_highest_zoneidx(pgdat,
                             highest_zoneidx));
 
             if (READ_ONCE(pgdat->kshrinkd_order) < reclaim_order)
                 WRITE_ONCE(pgdat->kshrinkd_order, reclaim_order);
         }
 
         finish_wait(&pgdat->kshrinkd_wait, &wait);
         prepare_to_wait(&pgdat->kshrinkd_wait, &wait, TASK_INTERRUPTIBLE);
     }
 
     /*
      * After a short sleep, check if it was a premature sleep. If not, then
      * go fully to sleep until explicitly woken up.
      */
     if (!remaining &&
         prepare_kshrinkd_sleep(pgdat, reclaim_order, highest_zoneidx)) {
    
 
         /*
          * vmstat counters are not perfectly accurate and the estimated
          * value for counters such as NR_FREE_PAGES can deviate from the
          * true value by nr_online_cpus * threshold. To avoid the zone
          * watermarks being breached while under pressure, we reduce the
          * per-cpu vmstat threshold while kshrinkd is awake and restore
          * them before going back to sleep.
          */
         set_pgdat_percpu_threshold(pgdat, calculate_normal_threshold);
 
         if (!kthread_should_stop())
             schedule();
 
         set_pgdat_percpu_threshold(pgdat, calculate_pressure_threshold);
     } else {
         if (remaining)
             count_vm_event(kshrinkd_LOW_WMARK_HIT_QUICKLY);
         else
             count_vm_event(kshrinkd_HIGH_WMARK_HIT_QUICKLY);
     }
     finish_wait(&pgdat->kshrinkd_wait, &wait);
 }
 
 /*
  * The background pageout daemon, started as a kernel thread
  * from the init process.
  *
  * This basically trickles out pages so that we have _some_
  * free memory available even if there is no other activity
  * that frees anything up. This is needed for things like routing
  * etc, where we otherwise might have all activity going on in
  * asynchronous contexts that cannot page things out.
  *
  * If there are applications that are active memory-allocators
  * (most normal use), this basically shouldn't matter.
  */
 static int kshrinkd(void *p)
 {
     unsigned int alloc_order, reclaim_order;
     unsigned int highest_zoneidx = MAX_NR_ZONES - 1;
     pg_data_t *pgdat = (pg_data_t*)p;
     struct task_struct *tsk = current;
     const struct cpumask *cpumask = cpumask_of_node(pgdat->node_id);
     
 
     if (!cpumask_empty(cpumask))
         set_cpus_allowed_ptr(tsk, cpumask);
 
     /*
      * Tell the memory management that we're a "memory allocator",
      * and that if we need more memory we should get access to it
      * regardless (see "__alloc_pages()"). "kshrinkd" should
      * never get caught in the normal page freeing logic.
      *
      * (kshrinkd normally doesn't need memory anyway, but sometimes
      * you need a small amount of memory in order to be able to
      * page out something else, and this flag essentially protects
      * us from recursively trying to free more memory as we're
      * trying to free the first piece of memory in the first place).
      */
     tsk->flags |= PF_MEMALLOC | PF_SWAPWRITE | PF_kshrinkd;
     set_freezable();
 
     WRITE_ONCE(pgdat->kshrinkd_order, 0);
     WRITE_ONCE(pgdat->kshrinkd_highest_zoneidx, MAX_NR_ZONES);


    while (!kthread_should_stop()) {
 
         alloc_order = reclaim_order = READ_ONCE(pgdat->kshrinkd_order);
         highest_zoneidx = kshrinkd_highest_zoneidx(pgdat,
                             highest_zoneidx);
 
 kshrinkd_try_sleep:
         kshrinkd_try_to_sleep(pgdat, alloc_order, reclaim_order,
                     highest_zoneidx);
 
         /* Read the new order and highest_zoneidx */
         alloc_order = reclaim_order = READ_ONCE(pgdat->kshrinkd_order);
         highest_zoneidx = kshrinkd_highest_zoneidx(pgdat,
                             highest_zoneidx);
         WRITE_ONCE(pgdat->kshrinkd_order, 0);
         WRITE_ONCE(pgdat->kshrinkd_highest_zoneidx, MAX_NR_ZONES);
 
         ret = try_to_freeze();
         if (kthread_should_stop())
             break;
 
         /*
          * We can speed up thawing tasks if we don't call kbalance_pgdat
          * after returning from the refrigerator
          */
         if (ret)
             continue;
 
         /*
          * Reclaim begins at the requested order but if a high-order
          * reclaim fails then kshrinkd falls back to reclaiming for
          * order-0. If that happens, kshrinkd will consider sleeping
          * for the order it finished reclaiming at (reclaim_order)
          * but kcompactd is woken to compact for the original
          * request (alloc_order).
          */
        kbalance_pgdat(pgdat, alloc_order,
                         highest_zoneidx);
        if (atomic_read(&victim_page_count) < VICTIM_LIST_MAX_PAGES) {
                goto kshrinkd_try_sleep;
        }
    
        cond_resched();
    }
 
     return 0;
 }
 
 static int kshrinkd_per_node_run(int nid)
 {
     pg_data_t *pgdat = NODE_DATA(nid);
     int hid;
     int ret = 0;
 
     for (hid = 0; hid < kshrinkd_threads; ++hid) {
         pgdat->mkshrinkd[hid] = kthread_run(kshrinkd, pgdat, "kshrinkd%d:%d",
                                 nid, hid);
         if (IS_ERR(pgdat->mkshrinkd[hid])) {
             /* failure at boot is fatal */
             WARN_ON(system_state < SYSTEM_RUNNING);
             pr_err("Failed to start kshrinkd%d on node %d\n",
                 hid, nid);
             ret = PTR_ERR(pgdat->mkshrinkd[hid]);
             pgdat->mkshrinkd[hid] = NULL;
             continue;
         }
         if (!pgdat->kshrinkd)
             pgdat->kshrinkd = pgdat->mkshrinkd[hid];
     }
 
     return ret;
 }
 
 static void kshrinkd_per_node_stop(int nid)
 {
     int hid = 0;
     struct task_struct *kshrinkd;
 
     for (hid = 0; hid < kshrinkd_threads; hid++) {
         kshrinkd = NODE_DATA(nid)->mkshrinkd[hid];
         if (kshrinkd) {
             kthread_stop(kshrinkd);
             NODE_DATA(nid)->mkshrinkd[hid] = NULL;
         }
     }
     NODE_DATA(nid)->kshrinkd = NULL;
 }
 
 /*
  * A zone is low on free memory or too fragmented for high-order memory.  If
  * kshrinkd should reclaim (direct reclaim is deferred), wake it up for the zone's
  * pgdat.  It will wake up kcompactd after reclaiming memory.  If kshrinkd reclaim
  * has failed or is not needed, still wake up kcompactd if only compaction is
  * needed.
  */
 void wakeup_kshrinkd(struct zone *zone, gfp_t gfp_flags, int order,
            enum zone_type highest_zoneidx)
 {
     pg_data_t *pgdat;
     enum zone_type curr_idx;
 
     if (!managed_zone(zone))
         return;
 
     if (!cpuset_zone_allowed(zone, gfp_flags))
         return;
 
     pgdat = zone->zone_pgdat;
     curr_idx = READ_ONCE(pgdat->kshrinkd_highest_zoneidx);
 
     if (curr_idx == MAX_NR_ZONES || curr_idx < highest_zoneidx)
         WRITE_ONCE(pgdat->kshrinkd_highest_zoneidx, highest_zoneidx);
 
     if (READ_ONCE(pgdat->kshrinkd_order) < order)
         WRITE_ONCE(pgdat->kshrinkd_order, order);
 
     if (!waitqueue_active(&pgdat->kshrinkd_wait))
         return;
 
     /* Hopeless node, leave it to direct reclaim if possible */
     if (pgdat->kshrinkd_failures >= MAX_RECLAIM_RETRIES ||
         (pgdat_balanced(pgdat, order, highest_zoneidx) &&
          !pgdat_watermark_boosted(pgdat, highest_zoneidx))) {
         /*
          * There may be plenty of free memory available, but it's too
          * fragmented for high-order allocations.  Wake up kcompactd
          * and rely on compaction_suitable() to determine if it's
          * needed.  If it fails, it will defer subsequent attempts to
          * ratelimit its work.
          */
         if (!(gfp_flags & __GFP_DIRECT_RECLAIM))
             wakeup_kcompactd(pgdat, order, highest_zoneidx);
         return;
     }
 
     wake_up_interruptible(&pgdat->kshrinkd_wait);
 }
 
 

int kshrinkd_run(int nid)
{
	const unsigned int priority_less = 5;
	struct sched_param param = {
		.sched_priority = MAX_PRIO - priority_less,
	};
	pg_data_t *pgdat = NODE_DATA(nid);

	if (pgdat->kshrinkd)
		return 0;

	
	pgdat->kshrinkd = kthread_create(kshrinkd, pgdat, "kshrinkd%d", nid);
	if (IS_ERR(pgdat->kshrinkd)) {
		pr_err("Failed to start kshrinkd on node %d\n", nid);
		return PTR_ERR(pgdat->kshrinkd);
	}

	sched_setscheduler_nocheck(pgdat->kshrinkd, SCHED_NORMAL, &param);
	set_user_nice(pgdat->kshrinkd, PRIO_TO_NICE(param.sched_priority));
	wake_up_process(pgdat->kshrinkd);

	return 0;
}


void kshrinkd_stop(int nid)
{
	struct task_struct *kshrinkd = NODE_DATA(nid)->kshrinkd;

    if (kshrinkd_threads > 1) {
        kshrinkd_per_node_stop(nid);
        return;
    }

	if (kshrinkd) {
		kthread_stop(kshrinkd);
		NODE_DATA(nid)->kshrinkd = NULL;
	}

	kshrinkd_pid = -1;
}


static int kshrinkd_cpu_online(unsigned int cpu)
{
	int nid;

	for_each_node_state (nid, N_MEMORY) {
		pg_data_t *pgdat = NODE_DATA(nid);
		const struct cpumask *mask;

		mask = cpumask_of_node(pgdat->node_id);
		if (cpumask_any_and(cpu_online_mask, mask) < nr_cpu_ids)
			/* One of our CPUs online: restore mask */
			set_cpus_allowed_ptr(pgdat->kshrinkd, mask);
	}

	return 0;
}

static int __init kshrinkd_init(void)
{
	int nid;
	int ret;

    swap_setup();

	ret = cpuhp_setup_state_nocalls(CPUHP_AP_ONLINE_DYN, "mm/kshrinkd:online",
					kshrinkd_cpu_online, NULL);
	if (ret < 0) {
		pr_err("kshrinkd: failed to register hotplug callbacks.\n");
		return ret;
	}

	for_each_node_state (nid, N_MEMORY)
		kshrinkd_run(nid);

	return 0;
}
module_init(kshrinkd_init)