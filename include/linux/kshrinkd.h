/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_KSHRINKD_H
#define _LINUX_KSHRINKD_H

#include <linux/list.h>
#include <linux/spinlock.h>
#include <linux/types.h>
#include <linux/wait.h>

extern struct list_head victim_page_list;

extern void wake_all_kshrinkd(void);

extern unsigned int kshrinkd_page_list(struct list_head *page_list)

#endif /* _LINUX_KSHRINKD_H */
