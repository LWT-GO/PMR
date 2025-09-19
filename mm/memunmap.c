
#define KMSG_COMPONENT "mem_unmap"
#define pr_fmt(fmt) KMSG_COMPONENT ": " fmt

#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/sysfs.h>
#include <linux/kobject.h>
#include <linux/string.h>
#include <linux/memunmap.h>

unsigned long mem_unmap_unit_size = 1;
 
static struct kobject *mem_unmap_kobj;
 

static ssize_t mem_unmap_unit_show(struct kobject *kobj,
                    struct kobj_attribute *attr,
                    char *buf)
{
    return sysfs_emit(buf, "%lu\n", mem_unmap_unit_size);
}
 
static ssize_t mem_unmap_unit_store(struct kobject *kobj,
                     struct kobj_attribute *attr,
                     const char *buf, size_t count)
{
     unsigned long val;
     int ret;
 
     ret = kstrtoul(buf, 0, &val);
     if (ret)
         return ret;
 
     if (val < 1)
         return -EINVAL;
 
     mem_unmap_unit_size = val;
 
     pr_info("mem_unmap_unit: set to %lu\n", val);
     return count;
}
 
static struct kobj_attribute mem_unmap_unit_attr =
     __ATTR(mem_unmap_unit, 0644, mem_unmap_unit_show, mem_unmap_unit_store);
 
static struct attribute *mem_unmap_attrs[] = {
    &mem_unmap_unit_attr.attr,
    NULL,
};

static struct attribute_group mem_unmap_attr_group = {
    .attrs = mem_unmap_attrs,
};

static int __init memunmap_init(void)
{
     int ret;
 
     mem_unmap_kobj = kobject_create_and_add("mem_unmap", kernel_kobj);
     if (!mem_unmap_kobj) {
         pr_err("Failed to create kobject\n");
         return -ENOMEM;
     }
 
     ret = sysfs_create_file(mem_unmap_kobj, &mem_unmap_attr_group);
     if (ret) {
         pr_err("Failed to create sysfs attribute: %d\n", ret);
         goto err_kobj;
     }
 
 
     return 0;
 
 err_kobj:
     kobject_put(mem_unmap_kobj);
     return ret;
}
 

static void __exit memunmap_exit(void)
{
     if (mem_unmap_kobj) {
         sysfs_remove_file(mem_unmap_kobj, &mem_unmap_unit_attr.attr);
         kobject_put(mem_unmap_kobj);
         pr_info("/sys/kernel/mem_unmap/ removed\n");
     }
}
 
module_init(memunmap_init);
module_exit(memunmap_exit);
MODULE_LICENSE("GPL");

 