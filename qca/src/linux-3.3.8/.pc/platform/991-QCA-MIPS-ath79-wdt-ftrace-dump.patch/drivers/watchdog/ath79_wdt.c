/*
 * Atheros AR71XX/AR724X/AR913X built-in hardware watchdog timer.
 *
 * Copyright (C) 2008-2011 Gabor Juhos <juhosg@openwrt.org>
 * Copyright (C) 2008 Imre Kaloz <kaloz@openwrt.org>
 *
 * This driver was based on: drivers/watchdog/ixp4xx_wdt.c
 *	Author: Deepak Saxena <dsaxena@plexity.net>
 *	Copyright 2004 (c) MontaVista, Software, Inc.
 *
 * which again was based on sa1100 driver,
 *	Copyright (C) 2000 Oleg Drokin <green@crimea.edu>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 as published
 * by the Free Software Foundation.
 *
 */

#include <linux/bitops.h>
#include <linux/delay.h>
#include <linux/errno.h>
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/miscdevice.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/platform_device.h>
#include <linux/types.h>
#include <linux/watchdog.h>
#include <linux/clk.h>
#include <linux/err.h>
#include <linux/interrupt.h>
#include <linux/jiffies.h>
#include <linux/sched.h>
#include <linux/debugfs.h>

#include <asm/mach-ath79/ath79.h>
#include <asm/mach-ath79/ar71xx_regs.h>
#include <asm/mach-ath79/irq.h>

#define DRIVER_NAME	"ath79-wdt"

#define WDT_TIMEOUT	15	/* seconds */

#define WDOG_CTRL_LAST_RESET	BIT(31)
#define WDOG_CTRL_ACTION_MASK	3
#define WDOG_CTRL_ACTION_NONE	0	/* no action */
#define WDOG_CTRL_ACTION_GPI	1	/* general purpose interrupt */
#define WDOG_CTRL_ACTION_NMI	2	/* NMI */
#define WDOG_CTRL_ACTION_FCR	3	/* full chip reset */

static int nowayout = WATCHDOG_NOWAYOUT;
module_param(nowayout, int, 0);
MODULE_PARM_DESC(nowayout, "Watchdog cannot be stopped once started "
			   "(default=" __MODULE_STRING(WATCHDOG_NOWAYOUT) ")");

static int timeout = WDT_TIMEOUT;
module_param(timeout, int, 0);
MODULE_PARM_DESC(timeout, "Watchdog timeout in seconds "
			  "(default=" __MODULE_STRING(WDT_TIMEOUT) "s)");

static unsigned long wdt_flags;

#define WDT_FLAGS_BUSY		0
#define WDT_FLAGS_EXPECT_CLOSE	1

static struct clk *wdt_clk;
static unsigned long wdt_freq;
static int boot_status;
static int max_timeout;
static unsigned long long last_pet;
static struct dentry *ath79_wdt_dbg_dir;

static inline void ath79_wdt_keepalive(void)
{
	ath79_reset_wr(AR71XX_RESET_REG_WDOG, wdt_freq * timeout);
	/* flush write */
	ath79_reset_rr(AR71XX_RESET_REG_WDOG);
	last_pet = sched_clock();
}

static inline void ath79_wdt_enable(void)
{
	ath79_wdt_keepalive();

	/*
	 * Updating the TIMER register requires a few microseconds
	 * on the AR934x SoCs at least. Use a small delay to ensure
	 * that the TIMER register is updated within the hardware
	 * before enabling the watchdog.
	 */
	udelay(2);

#ifdef CONFIG_KEXEC
	ath79_reset_wr(AR71XX_RESET_REG_WDOG_CTRL, WDOG_CTRL_ACTION_GPI);
#else
	ath79_reset_wr(AR71XX_RESET_REG_WDOG_CTRL, WDOG_CTRL_ACTION_FCR);
#endif
	/* flush write */
	ath79_reset_rr(AR71XX_RESET_REG_WDOG_CTRL);

}

static irqreturn_t ath79_wdt_irq_handler(int irq, void *dev_id)
{
	unsigned long nanosec_rem;
	unsigned long long t = sched_clock();
	struct task_struct *tsk;

	ath79_reset_wr(AR71XX_RESET_REG_WDOG_CTRL, WDOG_CTRL_ACTION_NONE);
	pr_info("Watchdog bark! Now = %llu \n", t);
	pr_info("Watchdog last pet at %llu \n", last_pet);
	pr_info("\n ================================== \n");
	panic("BUG :  ATH_WDT_TIMEOUT ");

	return IRQ_HANDLED;
}

static inline void ath79_wdt_disable(void)
{
	ath79_reset_wr(AR71XX_RESET_REG_WDOG_CTRL, WDOG_CTRL_ACTION_NONE);
	/* flush write */
	ath79_reset_rr(AR71XX_RESET_REG_WDOG_CTRL);
}

static int ath79_wdt_set_timeout(int val)
{
	if (val < 1 || val > max_timeout)
		return -EINVAL;

	timeout = val;
	ath79_wdt_keepalive();

	return 0;
}

static int ath79_wdt_open(struct inode *inode, struct file *file)
{
	int ret;

	if (test_and_set_bit(WDT_FLAGS_BUSY, &wdt_flags))
		return -EBUSY;

	clear_bit(WDT_FLAGS_EXPECT_CLOSE, &wdt_flags);

	ret = request_irq(ATH79_MISC_IRQ_WDOG,ath79_wdt_irq_handler,0,"ath79_wdt_irq",NULL);
	if(ret)
	{
		pr_err("ATH79 WDT IRQ Request failed! err %d\n",ret);
		return -EBUSY;
	}

	ath79_wdt_enable();

	return nonseekable_open(inode, file);
}

static int ath79_wdt_release(struct inode *inode, struct file *file)
{
	if (test_bit(WDT_FLAGS_EXPECT_CLOSE, &wdt_flags))
		ath79_wdt_disable();
	else {
		pr_crit(DRIVER_NAME ": device closed unexpectedly, "
			"watchdog timer will not stop!\n");
		ath79_wdt_keepalive();
	}

	clear_bit(WDT_FLAGS_BUSY, &wdt_flags);
	clear_bit(WDT_FLAGS_EXPECT_CLOSE, &wdt_flags);
	free_irq(ATH79_MISC_IRQ_WDOG,NULL);

	return 0;
}

static ssize_t ath79_wdt_write(struct file *file, const char *data,
				size_t len, loff_t *ppos)
{
	if (len) {
		if (!nowayout) {
			size_t i;

			clear_bit(WDT_FLAGS_EXPECT_CLOSE, &wdt_flags);

			for (i = 0; i != len; i++) {
				char c;

				if (get_user(c, data + i))
					return -EFAULT;

				if (c == 'V')
					set_bit(WDT_FLAGS_EXPECT_CLOSE,
						&wdt_flags);
			}
		}

		ath79_wdt_keepalive();
	}

	return len;
}

static const struct watchdog_info ath79_wdt_info = {
	.options		= WDIOF_SETTIMEOUT | WDIOF_KEEPALIVEPING |
				  WDIOF_MAGICCLOSE | WDIOF_CARDRESET,
	.firmware_version	= 0,
	.identity		= "ATH79 watchdog",
};

static long ath79_wdt_ioctl(struct file *file, unsigned int cmd,
			    unsigned long arg)
{
	void __user *argp = (void __user *)arg;
	int __user *p = argp;
	int err;
	int t;

	switch (cmd) {
	case WDIOC_GETSUPPORT:
		err = copy_to_user(argp, &ath79_wdt_info,
				   sizeof(ath79_wdt_info)) ? -EFAULT : 0;
		break;

	case WDIOC_GETSTATUS:
		err = put_user(0, p);
		break;

	case WDIOC_GETBOOTSTATUS:
		err = put_user(boot_status, p);
		break;

	case WDIOC_KEEPALIVE:
		ath79_wdt_keepalive();
		err = 0;
		break;

	case WDIOC_SETTIMEOUT:
		err = get_user(t, p);
		if (err)
			break;

		err = ath79_wdt_set_timeout(t);
		if (err)
			break;

		/* fallthrough */
	case WDIOC_GETTIMEOUT:
		err = put_user(timeout, p);
		break;

	default:
		err = -ENOTTY;
		break;
	}

	return err;
}

static const struct file_operations ath79_wdt_fops = {
	.owner		= THIS_MODULE,
	.llseek		= no_llseek,
	.write		= ath79_wdt_write,
	.unlocked_ioctl	= ath79_wdt_ioctl,
	.open		= ath79_wdt_open,
	.release	= ath79_wdt_release,
};

static struct miscdevice ath79_wdt_miscdev = {
	.minor = WATCHDOG_MINOR,
	.name = "watchdog",
	.fops = &ath79_wdt_fops,
};

static int __devinit ath79_wdt_probe(struct platform_device *pdev)
{
	u32 ctrl;
	int err;
	u8 wdtboot;

	wdt_clk = clk_get(&pdev->dev, "wdt");
	if (IS_ERR(wdt_clk))
		return PTR_ERR(wdt_clk);

	err = clk_enable(wdt_clk);
	if (err)
		goto err_clk_put;

	wdt_freq = clk_get_rate(wdt_clk);
	if (!wdt_freq) {
		err = -EINVAL;
		goto err_clk_disable;
	}

	max_timeout = (0xfffffffful / wdt_freq);
	if (timeout < 1 || timeout > max_timeout) {
		timeout = max_timeout;
		dev_info(&pdev->dev,
			"timeout value must be 0 < timeout < %d, using %d\n",
			max_timeout, timeout);
	}

	ctrl = ath79_reset_rr(AR71XX_RESET_REG_WDOG_CTRL);
	boot_status = (ctrl & WDOG_CTRL_LAST_RESET) ? WDIOF_CARDRESET : 0;
	wdtboot = (ctrl & WDOG_CTRL_LAST_RESET)? 1:0;
	pr_info("AR71XX_RESET_REG_WDOG_CTRL: 0x%x\n ", ctrl);
	if (wdtboot)
		pr_info("Last system reboot was due to WDOG\n");

	err = misc_register(&ath79_wdt_miscdev);
	if (err) {
		dev_err(&pdev->dev,
			"unable to register misc device, err=%d\n", err);
		goto err_clk_disable;
	}

	return 0;

err_clk_disable:
	clk_disable(wdt_clk);
err_clk_put:
	clk_put(wdt_clk);
	return err;
}

static int __devexit ath79_wdt_remove(struct platform_device *pdev)
{
	misc_deregister(&ath79_wdt_miscdev);
	clk_disable(wdt_clk);
	clk_put(wdt_clk);
	return 0;
}

static void ath79_wdt_shutdown(struct platform_device *pdev)
{
	ath79_wdt_disable();
}

static struct platform_driver ath79_wdt_driver = {
	.remove		= __devexit_p(ath79_wdt_remove),
	.shutdown	= ath79_wdt_shutdown,
	.driver		= {
		.name	= DRIVER_NAME,
		.owner	= THIS_MODULE,
	},
};

static int ath79_wdt_debugfs_read(void *data, u64 *val)
{
	pr_info(" ath79_wdt ::Action = %d \n",
		ath79_reset_rr(AR71XX_RESET_REG_WDOG_CTRL));
	return 0;
}

static int ath79_wdt_debugfs_write(void *data, u64 val)
{
	/* check for validity of the option for action. valid range is 0 till 3 */
	if (val < WDOG_CTRL_ACTION_NONE || val > WDOG_CTRL_ACTION_FCR)
		return -EINVAL;

	ath79_reset_wr(AR71XX_RESET_REG_WDOG_CTRL, val);
	/* flush write */
	ath79_reset_rr(AR71XX_RESET_REG_WDOG_CTRL);
	return 0;
}
DEFINE_SIMPLE_ATTRIBUTE(ath79_wdt_dbg_fops,ath79_wdt_debugfs_read,
			ath79_wdt_debugfs_write, "%llu\n");

static int __init ath79_wdt_init(void)
{
	ath79_wdt_dbg_dir = debugfs_create_dir("ath79_wdt", NULL);
	if (IS_ERR_OR_NULL(ath79_wdt_dbg_dir)) {
		pr_err("%s: ath79_wdt_dbg_dir  debugfs dir creation failed\n", __func__);
		return -EINVAL;
	}

	(void) debugfs_create_file("action", S_IRUGO | S_IWUSR,
		ath79_wdt_dbg_dir, NULL, &ath79_wdt_dbg_fops);

	return platform_driver_probe(&ath79_wdt_driver, ath79_wdt_probe);
}
module_init(ath79_wdt_init);

static void __exit ath79_wdt_exit(void)
{
	platform_driver_unregister(&ath79_wdt_driver);
}
module_exit(ath79_wdt_exit);

MODULE_DESCRIPTION("Atheros AR71XX/AR724X/AR913X hardware watchdog driver");
MODULE_AUTHOR("Gabor Juhos <juhosg@openwrt.org");
MODULE_AUTHOR("Imre Kaloz <kaloz@openwrt.org");
MODULE_LICENSE("GPL v2");
MODULE_ALIAS("platform:" DRIVER_NAME);
MODULE_ALIAS_MISCDEV(WATCHDOG_MINOR);
