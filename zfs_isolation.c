#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/list.h>
#include <linux/rculist.h>
#include <linux/rcupdate.h>
#include <linux/uaccess.h>
#include <linux/fs.h>
#include <linux/cred.h>
#include <linux/version.h>
#include <linux/audit.h>
#include <linux/lsm_hooks.h>

#define ZFS_ISOLATION_VERSION "3.0"

struct zfs_dataset;
int zfs_dataset_hold(const char *name, void *tag, struct zfs_dataset **dsp);
void zfs_dataset_rele(struct zfs_dataset *ds, void *tag);
const char *zfs_dataset_name(struct zfs_dataset *ds);

enum zfs_access_mode {
    ZFS_ACCESS_NONE = 0,
    ZFS_ACCESS_READ = (1 << 0),
    ZFS_ACCESS_WRITE = (1 << 1),
    ZFS_ACCESS_EXECUTE = (1 << 2),
    ZFS_ACCESS_ALL = ZFS_ACCESS_READ | ZFS_ACCESS_WRITE | ZFS_ACCESS_EXECUTE
};

struct zfs_isolation_dataset {
    char name[ZFS_MAX_DATASET_NAME_LEN];
    enum zfs_access_mode mode;
    struct list_head list;
    struct rcu_head rcu;
};

struct zfs_container_isolation {
    pid_t container_pid;
    uid_t isolation_uid;
    struct list_head datasets;
    spinlock_t lock;
    atomic64_t total_read_ops;
    atomic64_t total_write_ops;
    atomic64_t total_exec_ops;
    atomic64_t denied_access_attempts;
};

static struct zfs_container_isolation *isolation_data;

static int zfs_dataset_access_control(const char *dataset_name, int access_mask)
{
    struct zfs_isolation_dataset *dataset;
    int ret = -EACCES;

    rcu_read_lock();
    list_for_each_entry_rcu(dataset, &isolation_data->datasets, list) {
        if (strcmp(dataset->name, dataset_name) == 0) {
            if ((dataset->mode & access_mask) == access_mask) {
                ret = 0;
                if (access_mask & ZFS_ACCESS_READ)
                    atomic64_inc(&isolation_data->total_read_ops);
                if (access_mask & ZFS_ACCESS_WRITE)
                    atomic64_inc(&isolation_data->total_write_ops);
                if (access_mask & ZFS_ACCESS_EXECUTE)
                    atomic64_inc(&isolation_data->total_exec_ops);
            } else {
                atomic64_inc(&isolation_data->denied_access_attempts);
            }
            break;
        }
    }
    rcu_read_unlock();

    return ret;
}

static void zfs_isolation_audit_log(const char *event, const char *dataset_name, int result)
{
    struct audit_buffer *ab;
    uid_t uid = from_kuid(&init_user_ns, current_uid());

    ab = audit_log_start(NULL, GFP_KERNEL, AUDIT_SYSTEM_SECCOMP);
    if (ab) {
        audit_log_format(ab, "zfs_isolation: event=%s dataset=%s uid=%u pid=%d result=%d",
                         event, dataset_name, uid, task_pid_nr(current), result);
        audit_log_end(ab);
    }
}

static int zfs_security_inode_permission(struct inode *inode, int mask)
{
    struct zfs_dataset *zd;
    const char *dataset_name;
    int access_mask = 0, ret;

    if (!S_ISREG(inode->i_mode) && !S_ISDIR(inode->i_mode))
        return 0;

    if (zfs_dataset_hold(inode->i_sb->s_id, NULL, &zd))
        return 0;

    dataset_name = zfs_dataset_name(zd);

    if (mask & MAY_READ)
        access_mask |= ZFS_ACCESS_READ;
    if (mask & MAY_WRITE)
        access_mask |= ZFS_ACCESS_WRITE;
    if (mask & MAY_EXEC)
        access_mask |= ZFS_ACCESS_EXECUTE;

    ret = zfs_dataset_access_control(dataset_name, access_mask);
    zfs_isolation_audit_log(ret ? "access_denied" : "access_granted", dataset_name, ret);

    zfs_dataset_rele(zd, NULL);
    return ret;
}

static struct security_hook_list zfs_isolation_hooks[] __lsm_ro_after_init = {
    LSM_HOOK_INIT(inode_permission, zfs_security_inode_permission),
};

static int __init zfs_container_isolation_init(void)
{
    int ret;

    isolation_data = kzalloc(sizeof(*isolation_data), GFP_KERNEL);
    if (!isolation_data)
        return -ENOMEM;

    spin_lock_init(&isolation_data->lock);
    INIT_LIST_HEAD(&isolation_data->datasets);

    security_add_hooks(zfs_isolation_hooks, ARRAY_SIZE(zfs_isolation_hooks), "zfs_isolation");

    pr_info("ZFS Container Isolation v%s Initialized\n", ZFS_ISOLATION_VERSION);
    return 0;
}

static void __exit zfs_container_isolation_exit(void)
{
    struct zfs_isolation_dataset *dataset, *tmp;

    list_for_each_entry_safe(dataset, tmp, &isolation_data->datasets, list) {
        list_del_rcu(&dataset->list);
        kfree_rcu(dataset, rcu);
    }

    kfree(isolation_data);
    pr_info("ZFS Container Isolation Module Safely Unloaded\n");
}

module_init(zfs_container_isolation_init);
module_exit(zfs_container_isolation_exit);

MODULE_AUTHOR("John");
MODULE_VERSION(ZFS_ISOLATION_VERSION);
MODULE_LICENSE("GPL");
