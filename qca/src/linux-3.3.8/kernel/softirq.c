/*
 *	linux/kernel/softirq.c
 *
 *	Copyright (C) 1992 Linus Torvalds
 *
 *	Distribute under GPLv2.
 *
 *	Rewritten. Old one was good in 2.2, but in 2.3 it was immoral. --ANK (990903)
 *
 *	Remote softirq infrastructure is by Jens Axboe.
 */

#include <linux/export.h>
#include <linux/kernel_stat.h>
#include <linux/interrupt.h>
#include <linux/init.h>
#include <linux/mm.h>
#include <linux/notifier.h>
#include <linux/percpu.h>
#include <linux/cpu.h>
#include <linux/freezer.h>
#include <linux/kthread.h>
#include <linux/rcupdate.h>
#include <linux/ftrace.h>
#include <linux/smp.h>
#include <linux/tick.h>

#define CREATE_TRACE_POINTS
#include <trace/events/irq.h>

#include <asm/irq.h>
/*
   - No shared variables, all the data are CPU local.
   - If a softirq needs serialization, let it serialize itself
     by its own spinlocks.
   - Even if softirq is serialized, only local cpu is marked for
     execution. Hence, we get something sort of weak cpu binding.
     Though it is still not clear, will it result in better locality
     or will not.

   Examples:
   - NET RX softirq. It is multithreaded and does not require
     any global serialization.
   - NET TX softirq. It kicks software netdevice queues, hence
     it is logically serialized per device, but this serialization
     is invisible to common code.
   - Tasklets: serialized wrt itself.
 */

#ifndef __ARCH_IRQ_STAT
irq_cpustat_t irq_stat[NR_CPUS] ____cacheline_aligned;
EXPORT_SYMBOL(irq_stat);
#endif

static struct softirq_action softirq_vec[NR_SOFTIRQS] __cacheline_aligned_in_smp;

DEFINE_PER_CPU(struct task_struct *, ksoftirqd);

char *softirq_to_name[NR_SOFTIRQS] = {
	"HI", "TIMER", "NET_TX", "NET_RX", "BLOCK", "BLOCK_IOPOLL",
	"TASKLET", "SCHED", "HRTIMER", "RCU"
};

/*
 * we cannot loop indefinitely here to avoid userspace starvation,
 * but we also don't want to introduce a worst case 1/HZ latency
 * to the pending events, so lets the scheduler to balance
 * the softirq load for us.
 */
static void wakeup_softirqd(void)
{
	/* Interrupts are disabled: no need to stop preemption */
	struct task_struct *tsk = __this_cpu_read(ksoftirqd);

	if (tsk && tsk->state != TASK_RUNNING)
		wake_up_process(tsk);
}

/*
 * preempt_count and SOFTIRQ_OFFSET usage:
 * - preempt_count is changed by SOFTIRQ_OFFSET on entering or leaving
 *   softirq processing.
 * - preempt_count is changed by SOFTIRQ_DISABLE_OFFSET (= 2 * SOFTIRQ_OFFSET)
 *   on local_bh_disable or local_bh_enable.
 * This lets us distinguish between whether we are currently processing
 * softirq and whether we just have bh disabled.
 */

/*
 * This one is for softirq.c-internal use,
 * where hardirqs are disabled legitimately:
 */
#ifdef CONFIG_TRACE_IRQFLAGS
static void __local_bh_disable(unsigned long ip, unsigned int cnt)
{
	unsigned long flags;

	WARN_ON_ONCE(in_irq());

	raw_local_irq_save(flags);
	/*
	 * The preempt tracer hooks into add_preempt_count and will break
	 * lockdep because it calls back into lockdep after SOFTIRQ_OFFSET
	 * is set and before current->softirq_enabled is cleared.
	 * We must manually increment preempt_count here and manually
	 * call the trace_preempt_off later.
	 */
	preempt_count() += cnt;
	/*
	 * Were softirqs turned off above:
	 */
	if (softirq_count() == cnt)
		trace_softirqs_off(ip);
	raw_local_irq_restore(flags);

	if (preempt_count() == cnt)
		trace_preempt_off(CALLER_ADDR0, get_parent_ip(CALLER_ADDR1));
}
#else /* !CONFIG_TRACE_IRQFLAGS */
static inline void __local_bh_disable(unsigned long ip, unsigned int cnt)
{
	add_preempt_count(cnt);
	barrier();
}
#endif /* CONFIG_TRACE_IRQFLAGS */

void local_bh_disable(void)
{
	__local_bh_disable((unsigned long)__builtin_return_address(0),
				SOFTIRQ_DISABLE_OFFSET);
}

EXPORT_SYMBOL(local_bh_disable);

static void __local_bh_enable(unsigned int cnt)
{
	WARN_ON_ONCE(in_irq());
	WARN_ON_ONCE(!irqs_disabled());

	if (softirq_count() == cnt)
		trace_softirqs_on((unsigned long)__builtin_return_address(0));
	sub_preempt_count(cnt);
}

/*
 * Special-case - softirqs can safely be enabled in
 * cond_resched_softirq(), or by __do_softirq(),
 * without processing still-pending softirqs:
 */
void _local_bh_enable(void)
{
	__local_bh_enable(SOFTIRQ_DISABLE_OFFSET);
}

EXPORT_SYMBOL(_local_bh_enable);

static inline void _local_bh_enable_ip(unsigned long ip)
{
	WARN_ON_ONCE(in_irq() || irqs_disabled());
#ifdef CONFIG_TRACE_IRQFLAGS
	local_irq_disable();
#endif
	/*
	 * Are softirqs going to be turned on now:
	 */
	if (softirq_count() == SOFTIRQ_DISABLE_OFFSET)
		trace_softirqs_on(ip);
	/*
	 * Keep preemption disabled until we are done with
	 * softirq processing:
 	 */
	sub_preempt_count(SOFTIRQ_DISABLE_OFFSET - 1);

	if (unlikely(!in_interrupt() && local_softirq_pending()))
		do_softirq();

	dec_preempt_count();
#ifdef CONFIG_TRACE_IRQFLAGS
	local_irq_enable();
#endif
	preempt_check_resched();
}

void local_bh_enable(void)
{
	_local_bh_enable_ip((unsigned long)__builtin_return_address(0));
}
EXPORT_SYMBOL(local_bh_enable);

void local_bh_enable_ip(unsigned long ip)
{
	_local_bh_enable_ip(ip);
}
EXPORT_SYMBOL(local_bh_enable_ip);

/*
 * We restart softirq processing for at most MAX_SOFTIRQ_RESTART times,
 * but break the loop if need_resched() is set or after 2 ms.
 * The MAX_SOFTIRQ_TIME provides a nice upper bound in most cases, but in
 * certain cases, such as stop_machine(), jiffies may cease to
 * increment and so we need the MAX_SOFTIRQ_RESTART limit as
 * well to make sure we eventually return from this method.
 *
 * These limits have been established via experimentation.
 * The two things to balance is latency against fairness -
 * we want to handle softirqs as soon as possible, but they
 * should not be able to lock up the box.
 */
#define MAX_SOFTIRQ_TIME  msecs_to_jiffies(2)
#define MAX_SOFTIRQ_RESTART 10

#define CONFIG_SOFTIRQ_DYNAMIC_TUNNING y
/* add by wanghao  */
#ifdef CONFIG_SOFTIRQ_DYNAMIC_TUNNING

static int maxSoftirqRestart = MAX_SOFTIRQ_RESTART;
static unsigned long maxSoftirqTime = 0;
static int currentLevel = 0;

struct softirqLevel
{
	int loop;
	unsigned long time;//unit:ms
};

struct softirqLevel level[] = {
	{10,  1},
	//{50,  0},
	{10,  0},
	{8,  0},
	{7,  0},
	{4,  0},
	//{2,  0},
	//{1,  0},
	{NULL, NULL}
};
#endif
/* add end  */



asmlinkage void __do_softirq(void)
{
	struct softirq_action *h;
	__u32 pending;
#ifdef CONFIG_SOFTIRQ_DYNAMIC_TUNNING
	int max_restart = maxSoftirqRestart;
#else
	int max_restart = MAX_SOFTIRQ_RESTART;
#endif
	int cpu;
#ifdef CONFIG_SOFTIRQ_DYNAMIC_TUNNING
	unsigned long end = jiffies + maxSoftirqTime;
#else
    unsigned long end = jiffies + MAX_SOFTIRQ_TIME;
#endif

	pending = local_softirq_pending();
	account_system_vtime(current);

	__local_bh_disable((unsigned long)__builtin_return_address(0),
				SOFTIRQ_OFFSET);
	lockdep_softirq_enter();

	cpu = smp_processor_id();
restart:
	/* Reset the pending bitmask before enabling irqs */
	set_softirq_pending(0);

	local_irq_enable();

	h = softirq_vec;

	do {
		if (pending & 1) {
			unsigned int vec_nr = h - softirq_vec;
			int prev_count = preempt_count();

			kstat_incr_softirqs_this_cpu(vec_nr);

			trace_softirq_entry(vec_nr);
			h->action(h);
			trace_softirq_exit(vec_nr);
			if (unlikely(prev_count != preempt_count())) {
				printk(KERN_ERR "huh, entered softirq %u %s %p"
				       "with preempt_count %08x,"
				       " exited with %08x?\n", vec_nr,
				       softirq_to_name[vec_nr], h->action,
				       prev_count, preempt_count());
				preempt_count() = prev_count;
			}

			rcu_bh_qs(cpu);
		}
		h++;
		pending >>= 1;
	} while (pending);

	local_irq_disable();

	pending = local_softirq_pending();
	if (pending) {
		if (time_before(jiffies, end) && !need_resched() &&
		    --max_restart)
			goto restart;

		wakeup_softirqd();
	}

	lockdep_softirq_exit();

	account_system_vtime(current);
	__local_bh_enable(SOFTIRQ_OFFSET);
}

#ifndef __ARCH_HAS_DO_SOFTIRQ

/* add by wanghao  */
#ifdef CONFIG_SOFTIRQ_DYNAMIC_TUNNING
#define MAX_SOFTIRQ_HANDLE_TIME		msecs_to_jiffies(500)
#define MAX_HIGH_LOAD_COUNT			1
#define MAX_LOW_LOAD_COUNT			3
#define HIGH_LOAD_THRESHOLD			85//scheduler will tell us this value now.
#define LOAD_COUNT_TIME				msecs_to_jiffies(200)
#define MAX_LOAD						100
#define LOAD_INTERVAL					20
#define printErr(fmt, args...) printk("\033[1m[ %s ] %03d: "fmt"\033[0m", __FUNCTION__, __LINE__, ##args)
#define printWar(fmt, args...) printk("\033[4m[ %s ] %03d: "fmt"\033[0m", __FUNCTION__, __LINE__, ##args)

static unsigned long softirqTime = 0;
static unsigned long loadCountTime = 0;
static int highLoadCount = 0;
static int lowLoadCount = 0;

/*static unsigned int netrxCounter = 0;
static unsigned int taskletCounter = 0;
static unsigned int timerCounter = 0;
static unsigned int nettxCounter = 0;
static unsigned int blockCounter = 0;
static unsigned int blockpollCounter = 0;
static unsigned int schedCounter = 0;
static unsigned int hrtimerCounter = 0;
static unsigned int rcuCounter = 0;*/

static unsigned long testJiffies = 0;

unsigned long loadReserved = 0;
#endif
/* add end  */

asmlinkage void do_softirq(void)
{
	__u32 pending;
	unsigned long flags;

	/* add by wanghao  */
#ifdef CONFIG_SOFTIRQ_DYNAMIC_TUNNING
	unsigned long jiffiesCounter = 0;
	unsigned long softirqJiffies = 0;
#endif
	/* add end  */

	if (in_interrupt())
		return;

	local_irq_save(flags);

	pending = local_softirq_pending();

	if (pending)
	{
#ifdef CONFIG_SOFTIRQ_DYNAMIC_TUNNING
		jiffiesCounter = jiffies;
#endif
		__do_softirq();
	/* add by wanghao  */
#ifdef CONFIG_SOFTIRQ_DYNAMIC_TUNNING
		testJiffies += jiffies - jiffiesCounter;
		if (time_after_eq(jiffies, softirqTime))
		{
			softirqJiffies = testJiffies * 100 / MAX_SOFTIRQ_HANDLE_TIME;//t'/T
			if (softirqJiffies > (MAX_LOAD - loadReserved))//HIGH_LOAD_THRESHOLD)
			{
				lowLoadCount = 0;
				if (time_after(jiffies, loadCountTime))
				{
					highLoadCount++;
					loadCountTime = jiffies + LOAD_COUNT_TIME;
				}
				/* pull level  */
				if (highLoadCount >= MAX_HIGH_LOAD_COUNT)
				{
					highLoadCount = 0;
					if (maxSoftirqRestart > 1)
					{
						//maxSoftirqRestart = maxSoftirqRestart / 2;
						maxSoftirqRestart = 1;//maxSoftirqRestart ? maxSoftirqRestart : 1;
						printWar("decrease softirq level!	%d %d %d\n", maxSoftirqRestart, maxSoftirqTime, loadReserved);
					}
					/*if (level[currentLevel + 1].loop != NULL)
					{
						currentLevel++;
						maxSoftirqRestart = level[currentLevel].loop;
						maxSoftirqTime = level[currentLevel].time ? MAX_SOFTIRQ_TIME : 0;
						printWar("decrease softirq level!	%d %d index=%d\n", maxSoftirqRestart, maxSoftirqTime, currentLevel);
					}*/
				}
				/*if (printk_ratelimit())
				{
					printk("ksoftirq is high loading...time last %d	highLoadCount is %d\n", softirqTime - jiffies, highLoadCount);
				}*/
			}
			else if (softirqJiffies < (MAX_LOAD - LOAD_INTERVAL - loadReserved))
			{
				highLoadCount = 0;
				if (time_after(jiffies, loadCountTime))
				{
					lowLoadCount++;
					loadCountTime = jiffies + LOAD_COUNT_TIME;
				}
				/* push level  */
				if (lowLoadCount >= MAX_LOW_LOAD_COUNT)
				{
					lowLoadCount = 0;
					if (maxSoftirqRestart < MAX_SOFTIRQ_RESTART)
					{
						maxSoftirqRestart = maxSoftirqRestart + 2;
						maxSoftirqRestart = maxSoftirqRestart > MAX_SOFTIRQ_RESTART ? MAX_SOFTIRQ_RESTART : maxSoftirqRestart;
						printWar("increase softirq level!	%d %d %d\n", maxSoftirqRestart, maxSoftirqTime, loadReserved);
					}
					/*if (currentLevel > 0)
					{
						currentLevel--;
						maxSoftirqRestart = level[currentLevel].loop;
						maxSoftirqTime = level[currentLevel].time ? MAX_SOFTIRQ_TIME : 0;
						printWar("increase softirq level!	%d %d index=%d\n", maxSoftirqRestart, maxSoftirqTime, currentLevel);
					}*/
				}
				/*if (printk_ratelimit())
				{
					printk("time cost: %d	lowLoadCount is %d\n", jiffies - softirqTime, lowLoadCount);
				}*/
			}
			softirqTime = jiffies + MAX_SOFTIRQ_HANDLE_TIME;
			testJiffies = 0;
			/*if (printk_ratelimit())
			{
				printWar("softirqJiffies is %u\n", softirqJiffies);
			}*/
		}
		/*if (printk_ratelimit())
		{
			printWar("NET_RX:%u TASKLET:%u TIMER:%u NET_TX:%u BLOCK:%u BLOCK_IOPOLL:%u SCHED:%u HRTIMER:%u RCU:%u\n", 
				kstat_softirqs_cpu(NET_RX_SOFTIRQ, 0) - netrxCounter, 
				kstat_softirqs_cpu(TASKLET_SOFTIRQ, 0) - taskletCounter,
				kstat_softirqs_cpu(TIMER_SOFTIRQ, 0) - timerCounter,
				kstat_softirqs_cpu(NET_TX_SOFTIRQ, 0) - nettxCounter,
				kstat_softirqs_cpu(BLOCK_SOFTIRQ, 0) - blockCounter,
				kstat_softirqs_cpu(BLOCK_IOPOLL_SOFTIRQ, 0) - blockpollCounter,
				kstat_softirqs_cpu(SCHED_SOFTIRQ, 0) - schedCounter,
				kstat_softirqs_cpu(HRTIMER_SOFTIRQ, 0) - hrtimerCounter,
				kstat_softirqs_cpu(RCU_SOFTIRQ, 0) - rcuCounter);
			netrxCounter = kstat_softirqs_cpu(NET_RX_SOFTIRQ, 0);
			taskletCounter = kstat_softirqs_cpu(TASKLET_SOFTIRQ, 0);
			timerCounter = kstat_softirqs_cpu(TIMER_SOFTIRQ, 0);
			nettxCounter = kstat_softirqs_cpu(NET_TX_SOFTIRQ, 0);
			blockCounter = kstat_softirqs_cpu(BLOCK_SOFTIRQ, 0);
			blockpollCounter = kstat_softirqs_cpu(BLOCK_IOPOLL_SOFTIRQ, 0);
			schedCounter = kstat_softirqs_cpu(SCHED_SOFTIRQ, 0);
			hrtimerCounter = kstat_softirqs_cpu(HRTIMER_SOFTIRQ, 0);
			rcuCounter = kstat_softirqs_cpu(RCU_SOFTIRQ, 0);
		}*/
#endif
	}
#ifdef CONFIG_SOFTIRQ_DYNAMIC_TUNNING
	else
	{
		highLoadCount = 0;
		if (time_after(jiffies, loadCountTime))
		{
			lowLoadCount++;
			loadCountTime = jiffies + LOAD_COUNT_TIME;
		}
		/* push level  */
		if (lowLoadCount >= MAX_LOW_LOAD_COUNT)
		{
			lowLoadCount = 0;
			if (maxSoftirqRestart < MAX_SOFTIRQ_RESTART)
			{
				maxSoftirqRestart = maxSoftirqRestart + 1;
				maxSoftirqRestart = maxSoftirqRestart > MAX_SOFTIRQ_RESTART ? MAX_SOFTIRQ_RESTART : maxSoftirqRestart;
				printWar("increase softirq level!	%d %d %d\n", maxSoftirqRestart, maxSoftirqTime, loadReserved);
			}
			/*if (currentLevel > 0)
			{
				currentLevel--;
				maxSoftirqRestart = level[currentLevel].loop;
				maxSoftirqTime = level[currentLevel].time ? MAX_SOFTIRQ_TIME : 0;
				printWar("increase softirq level!	%d %d index=%d\n", maxSoftirqRestart, maxSoftirqTime, currentLevel);
			}*/
		}
		softirqTime = jiffies + MAX_SOFTIRQ_HANDLE_TIME;
		testJiffies = 0;
	}
#endif
	/* add end  */

	local_irq_restore(flags);
}

#endif

/*
 * Enter an interrupt context.
 */
void irq_enter(void)
{
	int cpu = smp_processor_id();

	rcu_irq_enter();
	if (idle_cpu(cpu) && !in_interrupt()) {
		/*
		 * Prevent raise_softirq from needlessly waking up ksoftirqd
		 * here, as softirq will be serviced on return from interrupt.
		 */
		local_bh_disable();
		tick_check_idle(cpu);
		_local_bh_enable();
	}

	__irq_enter();
}

#ifdef __ARCH_IRQ_EXIT_IRQS_DISABLED
static inline void invoke_softirq(void)
{
	if (!force_irqthreads)
		__do_softirq();
	else {
		__local_bh_disable((unsigned long)__builtin_return_address(0),
				SOFTIRQ_OFFSET);
		wakeup_softirqd();
		__local_bh_enable(SOFTIRQ_OFFSET);
	}
}
#else
static inline void invoke_softirq(void)
{
	if (!force_irqthreads)
		do_softirq();
	else {
		__local_bh_disable((unsigned long)__builtin_return_address(0),
				SOFTIRQ_OFFSET);
		wakeup_softirqd();
		__local_bh_enable(SOFTIRQ_OFFSET);
	}
}
#endif

/*
 * Exit an interrupt context. Process softirqs if needed and possible:
 */
void irq_exit(void)
{
	account_system_vtime(current);
	trace_hardirq_exit();
	sub_preempt_count(IRQ_EXIT_OFFSET);
	if (!in_interrupt() && local_softirq_pending())
		invoke_softirq();

#ifdef CONFIG_NO_HZ
	/* Make sure that timer wheel updates are propagated */
	if (idle_cpu(smp_processor_id()) && !in_interrupt() && !need_resched())
		tick_nohz_irq_exit();
#endif
	rcu_irq_exit();
	preempt_enable_no_resched();
}

/*
 * This function must run with irqs disabled!
 */
inline void raise_softirq_irqoff(unsigned int nr)
{
	__raise_softirq_irqoff(nr);

	/*
	 * If we're in an interrupt or softirq, we're done
	 * (this also catches softirq-disabled code). We will
	 * actually run the softirq once we return from
	 * the irq or softirq.
	 *
	 * Otherwise we wake up ksoftirqd to make sure we
	 * schedule the softirq soon.
	 */
	if (!in_interrupt())
		wakeup_softirqd();
}

void raise_softirq(unsigned int nr)
{
	unsigned long flags;

	local_irq_save(flags);
	raise_softirq_irqoff(nr);
	local_irq_restore(flags);
}

void open_softirq(int nr, void (*action)(struct softirq_action *))
{
	softirq_vec[nr].action = action;
}

/*
 * Tasklets
 */
struct tasklet_head
{
	struct tasklet_struct *head;
	struct tasklet_struct **tail;
};

static DEFINE_PER_CPU(struct tasklet_head, tasklet_vec);
static DEFINE_PER_CPU(struct tasklet_head, tasklet_hi_vec);

void __tasklet_schedule(struct tasklet_struct *t)
{
	unsigned long flags;

	local_irq_save(flags);
	t->next = NULL;
	*__this_cpu_read(tasklet_vec.tail) = t;
	__this_cpu_write(tasklet_vec.tail, &(t->next));
	raise_softirq_irqoff(TASKLET_SOFTIRQ);
	local_irq_restore(flags);
}

EXPORT_SYMBOL(__tasklet_schedule);

void __tasklet_hi_schedule(struct tasklet_struct *t)
{
	unsigned long flags;

	local_irq_save(flags);
	t->next = NULL;
	*__this_cpu_read(tasklet_hi_vec.tail) = t;
	__this_cpu_write(tasklet_hi_vec.tail,  &(t->next));
	raise_softirq_irqoff(HI_SOFTIRQ);
	local_irq_restore(flags);
}

EXPORT_SYMBOL(__tasklet_hi_schedule);

void __tasklet_hi_schedule_first(struct tasklet_struct *t)
{
	BUG_ON(!irqs_disabled());

	t->next = __this_cpu_read(tasklet_hi_vec.head);
	__this_cpu_write(tasklet_hi_vec.head, t);
	__raise_softirq_irqoff(HI_SOFTIRQ);
}

EXPORT_SYMBOL(__tasklet_hi_schedule_first);

static void tasklet_action(struct softirq_action *a)
{
	struct tasklet_struct *list;

	local_irq_disable();
	list = __this_cpu_read(tasklet_vec.head);
	__this_cpu_write(tasklet_vec.head, NULL);
	__this_cpu_write(tasklet_vec.tail, &__get_cpu_var(tasklet_vec).head);
	local_irq_enable();

	while (list) {
		struct tasklet_struct *t = list;

		list = list->next;

		if (tasklet_trylock(t)) {
			if (!atomic_read(&t->count)) {
				if (!test_and_clear_bit(TASKLET_STATE_SCHED, &t->state))
					BUG();
				trace_tlet_entry(t);
				t->func(t->data);
				trace_tlet_exit(t);
				tasklet_unlock(t);
				continue;
			}
			tasklet_unlock(t);
		}

		local_irq_disable();
		t->next = NULL;
		*__this_cpu_read(tasklet_vec.tail) = t;
		__this_cpu_write(tasklet_vec.tail, &(t->next));
		__raise_softirq_irqoff(TASKLET_SOFTIRQ);
		local_irq_enable();
	}
}

static void tasklet_hi_action(struct softirq_action *a)
{
	struct tasklet_struct *list;

	local_irq_disable();
	list = __this_cpu_read(tasklet_hi_vec.head);
	__this_cpu_write(tasklet_hi_vec.head, NULL);
	__this_cpu_write(tasklet_hi_vec.tail, &__get_cpu_var(tasklet_hi_vec).head);
	local_irq_enable();

	while (list) {
		struct tasklet_struct *t = list;

		list = list->next;

		if (tasklet_trylock(t)) {
			if (!atomic_read(&t->count)) {
				if (!test_and_clear_bit(TASKLET_STATE_SCHED, &t->state))
					BUG();
				trace_tlet_entry(t);
				t->func(t->data);
				trace_tlet_exit(t);
				tasklet_unlock(t);
				continue;
			}
			tasklet_unlock(t);
		}

		local_irq_disable();
		t->next = NULL;
		*__this_cpu_read(tasklet_hi_vec.tail) = t;
		__this_cpu_write(tasklet_hi_vec.tail, &(t->next));
		__raise_softirq_irqoff(HI_SOFTIRQ);
		local_irq_enable();
	}
}


void tasklet_init(struct tasklet_struct *t,
		  void (*func)(unsigned long), unsigned long data)
{
	t->next = NULL;
	t->state = 0;
	atomic_set(&t->count, 0);
	t->func = func;
	t->data = data;
}

EXPORT_SYMBOL(tasklet_init);

void tasklet_kill(struct tasklet_struct *t)
{
	if (in_interrupt())
		printk("Attempt to kill tasklet from interrupt\n");

	while (test_and_set_bit(TASKLET_STATE_SCHED, &t->state)) {
		do {
			yield();
		} while (test_bit(TASKLET_STATE_SCHED, &t->state));
	}
	tasklet_unlock_wait(t);
	clear_bit(TASKLET_STATE_SCHED, &t->state);
}

EXPORT_SYMBOL(tasklet_kill);

/*
 * tasklet_hrtimer
 */

/*
 * The trampoline is called when the hrtimer expires. It schedules a tasklet
 * to run __tasklet_hrtimer_trampoline() which in turn will call the intended
 * hrtimer callback, but from softirq context.
 */
static enum hrtimer_restart __hrtimer_tasklet_trampoline(struct hrtimer *timer)
{
	struct tasklet_hrtimer *ttimer =
		container_of(timer, struct tasklet_hrtimer, timer);

	tasklet_hi_schedule(&ttimer->tasklet);
	return HRTIMER_NORESTART;
}

/*
 * Helper function which calls the hrtimer callback from
 * tasklet/softirq context
 */
static void __tasklet_hrtimer_trampoline(unsigned long data)
{
	struct tasklet_hrtimer *ttimer = (void *)data;
	enum hrtimer_restart restart;

	restart = ttimer->function(&ttimer->timer);
	if (restart != HRTIMER_NORESTART)
		hrtimer_restart(&ttimer->timer);
}

/**
 * tasklet_hrtimer_init - Init a tasklet/hrtimer combo for softirq callbacks
 * @ttimer:	 tasklet_hrtimer which is initialized
 * @function:	 hrtimer callback function which gets called from softirq context
 * @which_clock: clock id (CLOCK_MONOTONIC/CLOCK_REALTIME)
 * @mode:	 hrtimer mode (HRTIMER_MODE_ABS/HRTIMER_MODE_REL)
 */
void tasklet_hrtimer_init(struct tasklet_hrtimer *ttimer,
			  enum hrtimer_restart (*function)(struct hrtimer *),
			  clockid_t which_clock, enum hrtimer_mode mode)
{
	hrtimer_init(&ttimer->timer, which_clock, mode);
	ttimer->timer.function = __hrtimer_tasklet_trampoline;
	tasklet_init(&ttimer->tasklet, __tasklet_hrtimer_trampoline,
		     (unsigned long)ttimer);
	ttimer->function = function;
}
EXPORT_SYMBOL_GPL(tasklet_hrtimer_init);

/*
 * Remote softirq bits
 */

DEFINE_PER_CPU(struct list_head [NR_SOFTIRQS], softirq_work_list);
EXPORT_PER_CPU_SYMBOL(softirq_work_list);

static void __local_trigger(struct call_single_data *cp, int softirq)
{
	struct list_head *head = &__get_cpu_var(softirq_work_list[softirq]);

	list_add_tail(&cp->list, head);

	/* Trigger the softirq only if the list was previously empty.  */
	if (head->next == &cp->list)
		raise_softirq_irqoff(softirq);
}

#ifdef CONFIG_USE_GENERIC_SMP_HELPERS
static void remote_softirq_receive(void *data)
{
	struct call_single_data *cp = data;
	unsigned long flags;
	int softirq;

	softirq = cp->priv;

	local_irq_save(flags);
	__local_trigger(cp, softirq);
	local_irq_restore(flags);
}

static int __try_remote_softirq(struct call_single_data *cp, int cpu, int softirq)
{
	if (cpu_online(cpu)) {
		cp->func = remote_softirq_receive;
		cp->info = cp;
		cp->flags = 0;
		cp->priv = softirq;

		__smp_call_function_single(cpu, cp, 0);
		return 0;
	}
	return 1;
}
#else /* CONFIG_USE_GENERIC_SMP_HELPERS */
static int __try_remote_softirq(struct call_single_data *cp, int cpu, int softirq)
{
	return 1;
}
#endif

/**
 * __send_remote_softirq - try to schedule softirq work on a remote cpu
 * @cp: private SMP call function data area
 * @cpu: the remote cpu
 * @this_cpu: the currently executing cpu
 * @softirq: the softirq for the work
 *
 * Attempt to schedule softirq work on a remote cpu.  If this cannot be
 * done, the work is instead queued up on the local cpu.
 *
 * Interrupts must be disabled.
 */
void __send_remote_softirq(struct call_single_data *cp, int cpu, int this_cpu, int softirq)
{
	if (cpu == this_cpu || __try_remote_softirq(cp, cpu, softirq))
		__local_trigger(cp, softirq);
}
EXPORT_SYMBOL(__send_remote_softirq);

/**
 * send_remote_softirq - try to schedule softirq work on a remote cpu
 * @cp: private SMP call function data area
 * @cpu: the remote cpu
 * @softirq: the softirq for the work
 *
 * Like __send_remote_softirq except that disabling interrupts and
 * computing the current cpu is done for the caller.
 */
void send_remote_softirq(struct call_single_data *cp, int cpu, int softirq)
{
	unsigned long flags;
	int this_cpu;

	local_irq_save(flags);
	this_cpu = smp_processor_id();
	__send_remote_softirq(cp, cpu, this_cpu, softirq);
	local_irq_restore(flags);
}
EXPORT_SYMBOL(send_remote_softirq);

static int __cpuinit remote_softirq_cpu_notify(struct notifier_block *self,
					       unsigned long action, void *hcpu)
{
	/*
	 * If a CPU goes away, splice its entries to the current CPU
	 * and trigger a run of the softirq
	 */
	if (action == CPU_DEAD || action == CPU_DEAD_FROZEN) {
		int cpu = (unsigned long) hcpu;
		int i;

		local_irq_disable();
		for (i = 0; i < NR_SOFTIRQS; i++) {
			struct list_head *head = &per_cpu(softirq_work_list[i], cpu);
			struct list_head *local_head;

			if (list_empty(head))
				continue;

			local_head = &__get_cpu_var(softirq_work_list[i]);
			list_splice_init(head, local_head);
			raise_softirq_irqoff(i);
		}
		local_irq_enable();
	}

	return NOTIFY_OK;
}

static struct notifier_block __cpuinitdata remote_softirq_cpu_notifier = {
	.notifier_call	= remote_softirq_cpu_notify,
};

void __init softirq_init(void)
{
	int cpu;

	for_each_possible_cpu(cpu) {
		int i;

		per_cpu(tasklet_vec, cpu).tail =
			&per_cpu(tasklet_vec, cpu).head;
		per_cpu(tasklet_hi_vec, cpu).tail =
			&per_cpu(tasklet_hi_vec, cpu).head;
		for (i = 0; i < NR_SOFTIRQS; i++)
			INIT_LIST_HEAD(&per_cpu(softirq_work_list[i], cpu));
	}

	register_hotcpu_notifier(&remote_softirq_cpu_notifier);

	open_softirq(TASKLET_SOFTIRQ, tasklet_action);
	open_softirq(HI_SOFTIRQ, tasklet_hi_action);
}

static int run_ksoftirqd(void * __bind_cpu)
{

	/* add by wanghao  */
#ifdef CONFIG_SOFTIRQ_DYNAMIC_TUNNING
	softirqTime = jiffies + MAX_SOFTIRQ_HANDLE_TIME;
	loadCountTime = jiffies + LOAD_COUNT_TIME;
#endif
	/* add end*/

	set_current_state(TASK_INTERRUPTIBLE);

	while (!kthread_should_stop()) {
		preempt_disable();
		if (!local_softirq_pending()) {
			preempt_enable_no_resched();
			schedule();
			preempt_disable();
		}

		__set_current_state(TASK_RUNNING);

		while (local_softirq_pending()) {
			/* Preempt disable stops cpu going offline.
			   If already offline, we'll be on wrong CPU:
			   don't process */
			if (cpu_is_offline((long)__bind_cpu))
				goto wait_to_die;
			local_irq_disable();
			if (local_softirq_pending())
				__do_softirq();
			local_irq_enable();
			preempt_enable_no_resched();
			cond_resched();
			preempt_disable();
			rcu_note_context_switch((long)__bind_cpu);
		}
		preempt_enable();
		set_current_state(TASK_INTERRUPTIBLE);
	}
	__set_current_state(TASK_RUNNING);
	return 0;

wait_to_die:
	preempt_enable();
	/* Wait for kthread_stop */
	set_current_state(TASK_INTERRUPTIBLE);
	while (!kthread_should_stop()) {
		schedule();
		set_current_state(TASK_INTERRUPTIBLE);
	}
	__set_current_state(TASK_RUNNING);
	return 0;
}

#ifdef CONFIG_HOTPLUG_CPU
/*
 * tasklet_kill_immediate is called to remove a tasklet which can already be
 * scheduled for execution on @cpu.
 *
 * Unlike tasklet_kill, this function removes the tasklet
 * _immediately_, even if the tasklet is in TASKLET_STATE_SCHED state.
 *
 * When this function is called, @cpu must be in the CPU_DEAD state.
 */
void tasklet_kill_immediate(struct tasklet_struct *t, unsigned int cpu)
{
	struct tasklet_struct **i;

	BUG_ON(cpu_online(cpu));
	BUG_ON(test_bit(TASKLET_STATE_RUN, &t->state));

	if (!test_bit(TASKLET_STATE_SCHED, &t->state))
		return;

	/* CPU is dead, so no lock needed. */
	for (i = &per_cpu(tasklet_vec, cpu).head; *i; i = &(*i)->next) {
		if (*i == t) {
			*i = t->next;
			/* If this was the tail element, move the tail ptr */
			if (*i == NULL)
				per_cpu(tasklet_vec, cpu).tail = i;
			return;
		}
	}
	BUG();
}

static void takeover_tasklets(unsigned int cpu)
{
	/* CPU is dead, so no lock needed. */
	local_irq_disable();

	/* Find end, append list for that CPU. */
	if (&per_cpu(tasklet_vec, cpu).head != per_cpu(tasklet_vec, cpu).tail) {
		*__this_cpu_read(tasklet_vec.tail) = per_cpu(tasklet_vec, cpu).head;
		this_cpu_write(tasklet_vec.tail, per_cpu(tasklet_vec, cpu).tail);
		per_cpu(tasklet_vec, cpu).head = NULL;
		per_cpu(tasklet_vec, cpu).tail = &per_cpu(tasklet_vec, cpu).head;
	}
	raise_softirq_irqoff(TASKLET_SOFTIRQ);

	if (&per_cpu(tasklet_hi_vec, cpu).head != per_cpu(tasklet_hi_vec, cpu).tail) {
		*__this_cpu_read(tasklet_hi_vec.tail) = per_cpu(tasklet_hi_vec, cpu).head;
		__this_cpu_write(tasklet_hi_vec.tail, per_cpu(tasklet_hi_vec, cpu).tail);
		per_cpu(tasklet_hi_vec, cpu).head = NULL;
		per_cpu(tasklet_hi_vec, cpu).tail = &per_cpu(tasklet_hi_vec, cpu).head;
	}
	raise_softirq_irqoff(HI_SOFTIRQ);

	local_irq_enable();
}
#endif /* CONFIG_HOTPLUG_CPU */

static int __cpuinit cpu_callback(struct notifier_block *nfb,
				  unsigned long action,
				  void *hcpu)
{
	int hotcpu = (unsigned long)hcpu;
	struct task_struct *p;

	switch (action) {
	case CPU_UP_PREPARE:
	case CPU_UP_PREPARE_FROZEN:
#ifdef CONFIG_SOFTIRQ_DYNAMIC_TUNNING
		maxSoftirqTime = MAX_SOFTIRQ_TIME;//add by wanghao
#endif
		p = kthread_create_on_node(run_ksoftirqd,
					   hcpu,
					   cpu_to_node(hotcpu),
					   "ksoftirqd/%d", hotcpu);
		if (IS_ERR(p)) {
			printk("ksoftirqd for %i failed\n", hotcpu);
			return notifier_from_errno(PTR_ERR(p));
		}
		kthread_bind(p, hotcpu);
  		per_cpu(ksoftirqd, hotcpu) = p;
 		break;
	case CPU_ONLINE:
	case CPU_ONLINE_FROZEN:
		wake_up_process(per_cpu(ksoftirqd, hotcpu));
		break;
#ifdef CONFIG_HOTPLUG_CPU
	case CPU_UP_CANCELED:
	case CPU_UP_CANCELED_FROZEN:
		if (!per_cpu(ksoftirqd, hotcpu))
			break;
		/* Unbind so it can run.  Fall thru. */
		kthread_bind(per_cpu(ksoftirqd, hotcpu),
			     cpumask_any(cpu_online_mask));
	case CPU_DEAD:
	case CPU_DEAD_FROZEN: {
		static const struct sched_param param = {
			.sched_priority = MAX_RT_PRIO-1
		};

		p = per_cpu(ksoftirqd, hotcpu);
		per_cpu(ksoftirqd, hotcpu) = NULL;
		sched_setscheduler_nocheck(p, SCHED_FIFO, &param);
		kthread_stop(p);
		takeover_tasklets(hotcpu);
		break;
	}
#endif /* CONFIG_HOTPLUG_CPU */
 	}
	return NOTIFY_OK;
}

static struct notifier_block __cpuinitdata cpu_nfb = {
	.notifier_call = cpu_callback
};

static __init int spawn_ksoftirqd(void)
{
	void *cpu = (void *)(long)smp_processor_id();
	int err = cpu_callback(&cpu_nfb, CPU_UP_PREPARE, cpu);

	BUG_ON(err != NOTIFY_OK);
	cpu_callback(&cpu_nfb, CPU_ONLINE, cpu);
	register_cpu_notifier(&cpu_nfb);
	return 0;
}
early_initcall(spawn_ksoftirqd);

/*
 * [ These __weak aliases are kept in a separate compilation unit, so that
 *   GCC does not inline them incorrectly. ]
 */

int __init __weak early_irq_init(void)
{
	return 0;
}

#ifdef CONFIG_GENERIC_HARDIRQS
int __init __weak arch_probe_nr_irqs(void)
{
	return NR_IRQS_LEGACY;
}

int __init __weak arch_early_irq_init(void)
{
	return 0;
}
#endif
