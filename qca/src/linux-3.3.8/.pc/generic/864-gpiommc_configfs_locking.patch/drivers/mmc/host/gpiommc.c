/*
 * Driver an MMC/SD card on a bitbanging GPIO SPI bus.
 * This module hooks up the mmc_spi and spi_gpio modules and also
 * provides a configfs interface.
 *
 * Copyright 2008 Michael Buesch <mb@bu3sch.de>
 *
 * Licensed under the GNU/GPL. See COPYING for details.
 */

#include <linux/module.h>
#include <linux/mmc/gpiommc.h>
#include <linux/platform_device.h>
#include <linux/list.h>
#include <linux/mutex.h>
#include <linux/spi/spi_gpio_old.h>
#include <linux/configfs.h>
#include <linux/gpio.h>
#include <asm/atomic.h>


#define PFX				"gpio-mmc: "


struct gpiommc_device {
	struct platform_device *pdev;
	struct platform_device *spi_pdev;
	struct spi_board_info boardinfo;
};


MODULE_DESCRIPTION("GPIO based MMC driver");
MODULE_AUTHOR("Michael Buesch");
MODULE_LICENSE("GPL");


static int gpiommc_boardinfo_setup(struct spi_board_info *bi,
				   struct spi_master *master,
				   void *data)
{
	struct gpiommc_device *d = data;
	struct gpiommc_platform_data *pdata = d->pdev->dev.platform_data;

	/* Bind the SPI master to the MMC-SPI host driver. */
	strlcpy(bi->modalias, "mmc_spi", sizeof(bi->modalias));

	bi->max_speed_hz = pdata->max_bus_speed;
	bi->bus_num = master->bus_num;
	bi->mode = pdata->mode;

	return 0;
}

static int gpiommc_probe(struct platform_device *pdev)
{
	struct gpiommc_platform_data *mmc_pdata = pdev->dev.platform_data;
	struct spi_gpio_platform_data spi_pdata;
	struct gpiommc_device *d;
	int err;

	err = -ENXIO;
	if (!mmc_pdata)
		goto error;

#ifdef CONFIG_MMC_SPI_MODULE
	err = request_module("mmc_spi");
	if (err) {
		printk(KERN_WARNING PFX
		       "Failed to request mmc_spi module.\n");
	}
#endif /* CONFIG_MMC_SPI_MODULE */

	/* Allocate the GPIO-MMC device */
	err = -ENOMEM;
	d = kzalloc(sizeof(*d), GFP_KERNEL);
	if (!d)
		goto error;
	d->pdev = pdev;

	/* Create the SPI-GPIO device */
	d->spi_pdev = platform_device_alloc(SPI_GPIO_PLATDEV_NAME,
					    spi_gpio_next_id());
	if (!d->spi_pdev)
		goto err_free_d;

	memset(&spi_pdata, 0, sizeof(spi_pdata));
	spi_pdata.pin_clk = mmc_pdata->pins.gpio_clk;
	spi_pdata.pin_miso = mmc_pdata->pins.gpio_do;
	spi_pdata.pin_mosi = mmc_pdata->pins.gpio_di;
	spi_pdata.pin_cs = mmc_pdata->pins.gpio_cs;
	spi_pdata.cs_activelow = mmc_pdata->pins.cs_activelow;
	spi_pdata.no_spi_delay = mmc_pdata->no_spi_delay;
	spi_pdata.boardinfo_setup = gpiommc_boardinfo_setup;
	spi_pdata.boardinfo_setup_data = d;

	err = platform_device_add_data(d->spi_pdev, &spi_pdata,
				       sizeof(spi_pdata));
	if (err)
		goto err_free_pdev;
	err = platform_device_add(d->spi_pdev);
	if (err)
		goto err_free_pdata;
	platform_set_drvdata(pdev, d);

	printk(KERN_INFO PFX "MMC-Card \"%s\" "
	       "attached to GPIO pins di=%u, do=%u, clk=%u, cs=%u\n",
	       mmc_pdata->name, mmc_pdata->pins.gpio_di,
	       mmc_pdata->pins.gpio_do,
	       mmc_pdata->pins.gpio_clk,
	       mmc_pdata->pins.gpio_cs);

	return 0;

err_free_pdata:
	kfree(d->spi_pdev->dev.platform_data);
	d->spi_pdev->dev.platform_data = NULL;
err_free_pdev:
	platform_device_put(d->spi_pdev);
err_free_d:
	kfree(d);
error:
	return err;
}

static int gpiommc_remove(struct platform_device *pdev)
{
	struct gpiommc_device *d = platform_get_drvdata(pdev);
	struct gpiommc_platform_data *pdata = d->pdev->dev.platform_data;

	platform_device_unregister(d->spi_pdev);
	printk(KERN_INFO PFX "GPIO based MMC-Card \"%s\" removed\n",
	       pdata->name);
	platform_device_put(d->spi_pdev);

	return 0;
}

#ifdef CONFIG_GPIOMMC_CONFIGFS

/* A device that was created through configfs */
struct gpiommc_configfs_device {
	struct config_item item;
	/* The platform device, after registration. */
	struct platform_device *pdev;
	/* The configuration */
	struct gpiommc_platform_data pdata;
};

#define GPIO_INVALID	-1

static inline bool gpiommc_is_registered(struct gpiommc_configfs_device *dev)
{
	return (dev->pdev != NULL);
}

static inline struct gpiommc_configfs_device *ci_to_gpiommc(struct config_item *item)
{
	return item ? container_of(item, struct gpiommc_configfs_device, item) : NULL;
}

static struct configfs_attribute gpiommc_attr_DI = {
	.ca_owner = THIS_MODULE,
	.ca_name = "gpio_data_in",
	.ca_mode = S_IRUGO | S_IWUSR,
};

static struct configfs_attribute gpiommc_attr_DO = {
	.ca_owner = THIS_MODULE,
	.ca_name = "gpio_data_out",
	.ca_mode = S_IRUGO | S_IWUSR,
};

static struct configfs_attribute gpiommc_attr_CLK = {
	.ca_owner = THIS_MODULE,
	.ca_name = "gpio_clock",
	.ca_mode = S_IRUGO | S_IWUSR,
};

static struct configfs_attribute gpiommc_attr_CS = {
	.ca_owner = THIS_MODULE,
	.ca_name = "gpio_chipselect",
	.ca_mode = S_IRUGO | S_IWUSR,
};

static struct configfs_attribute gpiommc_attr_CS_activelow = {
	.ca_owner = THIS_MODULE,
	.ca_name = "gpio_chipselect_activelow",
	.ca_mode = S_IRUGO | S_IWUSR,
};

static struct configfs_attribute gpiommc_attr_spimode = {
	.ca_owner = THIS_MODULE,
	.ca_name = "spi_mode",
	.ca_mode = S_IRUGO | S_IWUSR,
};

static struct configfs_attribute gpiommc_attr_spidelay = {
	.ca_owner = THIS_MODULE,
	.ca_name = "spi_delay",
	.ca_mode = S_IRUGO | S_IWUSR,
};

static struct configfs_attribute gpiommc_attr_max_bus_speed = {
	.ca_owner = THIS_MODULE,
	.ca_name = "max_bus_speed",
	.ca_mode = S_IRUGO | S_IWUSR,
};

static struct configfs_attribute gpiommc_attr_register = {
	.ca_owner = THIS_MODULE,
	.ca_name = "register",
	.ca_mode = S_IRUGO | S_IWUSR,
};

static struct configfs_attribute *gpiommc_config_attrs[] = {
	&gpiommc_attr_DI,
	&gpiommc_attr_DO,
	&gpiommc_attr_CLK,
	&gpiommc_attr_CS,
	&gpiommc_attr_CS_activelow,
	&gpiommc_attr_spimode,
	&gpiommc_attr_spidelay,
	&gpiommc_attr_max_bus_speed,
	&gpiommc_attr_register,
	NULL,
};

static ssize_t gpiommc_config_attr_show(struct config_item *item,
					struct configfs_attribute *attr,
					char *page)
{
	struct gpiommc_configfs_device *dev = ci_to_gpiommc(item);
	ssize_t count = 0;
	unsigned int gpio;
	int err = 0;

	if (attr == &gpiommc_attr_DI) {
		gpio = dev->pdata.pins.gpio_di;
		if (gpio == GPIO_INVALID)
			count = snprintf(page, PAGE_SIZE, "not configured\n");
		else
			count = snprintf(page, PAGE_SIZE, "%u\n", gpio);
		goto out;
	}
	if (attr == &gpiommc_attr_DO) {
		gpio = dev->pdata.pins.gpio_do;
		if (gpio == GPIO_INVALID)
			count = snprintf(page, PAGE_SIZE, "not configured\n");
		else
			count = snprintf(page, PAGE_SIZE, "%u\n", gpio);
		goto out;
	}
	if (attr == &gpiommc_attr_CLK) {
		gpio = dev->pdata.pins.gpio_clk;
		if (gpio == GPIO_INVALID)
			count = snprintf(page, PAGE_SIZE, "not configured\n");
		else
			count = snprintf(page, PAGE_SIZE, "%u\n", gpio);
		goto out;
	}
	if (attr == &gpiommc_attr_CS) {
		gpio = dev->pdata.pins.gpio_cs;
		if (gpio == GPIO_INVALID)
			count = snprintf(page, PAGE_SIZE, "not configured\n");
		else
			count = snprintf(page, PAGE_SIZE, "%u\n", gpio);
		goto out;
	}
	if (attr == &gpiommc_attr_CS_activelow) {
		count = snprintf(page, PAGE_SIZE, "%u\n",
				 dev->pdata.pins.cs_activelow);
		goto out;
	}
	if (attr == &gpiommc_attr_spimode) {
		count = snprintf(page, PAGE_SIZE, "%u\n",
				 dev->pdata.mode);
		goto out;
	}
	if (attr == &gpiommc_attr_spidelay) {
		count = snprintf(page, PAGE_SIZE, "%u\n",
				 !dev->pdata.no_spi_delay);
		goto out;
	}
	if (attr == &gpiommc_attr_max_bus_speed) {
		count = snprintf(page, PAGE_SIZE, "%u\n",
				 dev->pdata.max_bus_speed);
		goto out;
	}
	if (attr == &gpiommc_attr_register) {
		count = snprintf(page, PAGE_SIZE, "%u\n",
				 gpiommc_is_registered(dev));
		goto out;
	}
	WARN_ON(1);
	err = -ENOSYS;
out:
	return err ? err : count;
}

static int gpiommc_do_register(struct gpiommc_configfs_device *dev,
			       const char *name)
{
	int err;

	if (gpiommc_is_registered(dev))
		return 0;

	if (!gpio_is_valid(dev->pdata.pins.gpio_di) ||
	    !gpio_is_valid(dev->pdata.pins.gpio_do) ||
	    !gpio_is_valid(dev->pdata.pins.gpio_clk) ||
	    !gpio_is_valid(dev->pdata.pins.gpio_cs)) {
		printk(KERN_ERR PFX
		       "configfs: Invalid GPIO pin number(s)\n");
		return -EINVAL;
	}

	strlcpy(dev->pdata.name, name,
		sizeof(dev->pdata.name));

	dev->pdev = platform_device_alloc(GPIOMMC_PLATDEV_NAME,
					  gpiommc_next_id());
	if (!dev->pdev)
		return -ENOMEM;
	err = platform_device_add_data(dev->pdev, &dev->pdata,
				       sizeof(dev->pdata));
	if (err) {
		platform_device_put(dev->pdev);
		return err;
	}
	err = platform_device_add(dev->pdev);
	if (err) {
		platform_device_put(dev->pdev);
		return err;
	}

	return 0;
}

static void gpiommc_do_unregister(struct gpiommc_configfs_device *dev)
{
	if (!gpiommc_is_registered(dev))
		return;

	platform_device_unregister(dev->pdev);
	dev->pdev = NULL;
}

static ssize_t gpiommc_config_attr_store(struct config_item *item,
					 struct configfs_attribute *attr,
					 const char *page, size_t count)
{
	struct gpiommc_configfs_device *dev = ci_to_gpiommc(item);
	int err = -EINVAL;
	unsigned long data;

	if (attr == &gpiommc_attr_register) {
		err = strict_strtoul(page, 10, &data);
		if (err)
			goto out;
		err = -EINVAL;
		if (data == 1)
			err = gpiommc_do_register(dev, item->ci_name);
		if (data == 0) {
			gpiommc_do_unregister(dev);
			err = 0;
		}
		goto out;
	}

	if (gpiommc_is_registered(dev)) {
		/* The rest of the config parameters can only be set
		 * as long as the device is not registered, yet. */
		err = -EBUSY;
		goto out;
	}

	if (attr == &gpiommc_attr_DI) {
		err = strict_strtoul(page, 10, &data);
		if (err)
			goto out;
		err = -EINVAL;
		if (!gpio_is_valid(data))
			goto out;
		dev->pdata.pins.gpio_di = data;
		err = 0;
		goto out;
	}
	if (attr == &gpiommc_attr_DO) {
		err = strict_strtoul(page, 10, &data);
		if (err)
			goto out;
		err = -EINVAL;
		if (!gpio_is_valid(data))
			goto out;
		dev->pdata.pins.gpio_do = data;
		err = 0;
		goto out;
	}
	if (attr == &gpiommc_attr_CLK) {
		err = strict_strtoul(page, 10, &data);
		if (err)
			goto out;
		err = -EINVAL;
		if (!gpio_is_valid(data))
			goto out;
		dev->pdata.pins.gpio_clk = data;
		err = 0;
		goto out;
	}
	if (attr == &gpiommc_attr_CS) {
		err = strict_strtoul(page, 10, &data);
		if (err)
			goto out;
		err = -EINVAL;
		if (!gpio_is_valid(data))
			goto out;
		dev->pdata.pins.gpio_cs = data;
		err = 0;
		goto out;
	}
	if (attr == &gpiommc_attr_CS_activelow) {
		err = strict_strtoul(page, 10, &data);
		if (err)
			goto out;
		err = -EINVAL;
		if (data != 0 && data != 1)
			goto out;
		dev->pdata.pins.cs_activelow = data;
		err = 0;
		goto out;
	}
	if (attr == &gpiommc_attr_spimode) {
		err = strict_strtoul(page, 10, &data);
		if (err)
			goto out;
		err = -EINVAL;
		switch (data) {
		case 0:
			dev->pdata.mode = SPI_MODE_0;
			break;
		case 1:
			dev->pdata.mode = SPI_MODE_1;
			break;
		case 2:
			dev->pdata.mode = SPI_MODE_2;
			break;
		case 3:
			dev->pdata.mode = SPI_MODE_3;
			break;
		default:
			goto out;
		}
		err = 0;
		goto out;
	}
	if (attr == &gpiommc_attr_spidelay) {
		err = strict_strtoul(page, 10, &data);
		if (err)
			goto out;
		err = -EINVAL;
		if (data != 0 && data != 1)
			goto out;
		dev->pdata.no_spi_delay = !data;
		err = 0;
		goto out;
	}
	if (attr == &gpiommc_attr_max_bus_speed) {
		err = strict_strtoul(page, 10, &data);
		if (err)
			goto out;
		err = -EINVAL;
		if (data > UINT_MAX)
			goto out;
		dev->pdata.max_bus_speed = data;
		err = 0;
		goto out;
	}
	WARN_ON(1);
	err = -ENOSYS;
out:
	return err ? err : count;
}

static void gpiommc_config_item_release(struct config_item *item)
{
	struct gpiommc_configfs_device *dev = ci_to_gpiommc(item);

	kfree(dev);
}

static struct configfs_item_operations gpiommc_config_item_ops = {
	.release		= gpiommc_config_item_release,
	.show_attribute		= gpiommc_config_attr_show,
	.store_attribute	= gpiommc_config_attr_store,
};

static struct config_item_type gpiommc_dev_ci_type = {
	.ct_item_ops	= &gpiommc_config_item_ops,
	.ct_attrs	= gpiommc_config_attrs,
	.ct_owner	= THIS_MODULE,
};

static struct config_item *gpiommc_make_item(struct config_group *group,
					     const char *name)
{
	struct gpiommc_configfs_device *dev;

	if (strlen(name) > GPIOMMC_MAX_NAMELEN) {
		printk(KERN_ERR PFX "configfs: device name too long\n");
		return NULL;
	}

	dev = kzalloc(sizeof(*dev), GFP_KERNEL);
	if (!dev)
		return NULL;

	config_item_init_type_name(&dev->item, name,
				   &gpiommc_dev_ci_type);

	/* Assign default configuration */
	dev->pdata.pins.gpio_di = GPIO_INVALID;
	dev->pdata.pins.gpio_do = GPIO_INVALID;
	dev->pdata.pins.gpio_clk = GPIO_INVALID;
	dev->pdata.pins.gpio_cs = GPIO_INVALID;
	dev->pdata.pins.cs_activelow = 1;
	dev->pdata.mode = SPI_MODE_0;
	dev->pdata.no_spi_delay = 0;
	dev->pdata.max_bus_speed = 5000000; /* 5 MHz */

	return &(dev->item);
}

static void gpiommc_drop_item(struct config_group *group,
			      struct config_item *item)
{
	struct gpiommc_configfs_device *dev = ci_to_gpiommc(item);

	gpiommc_do_unregister(dev);
	kfree(dev);
}

static struct configfs_group_operations gpiommc_ct_group_ops = {
	.make_item	= gpiommc_make_item,
	.drop_item	= gpiommc_drop_item,
};

static struct config_item_type gpiommc_ci_type = {
	.ct_group_ops	= &gpiommc_ct_group_ops,
	.ct_owner	= THIS_MODULE,
};

static struct configfs_subsystem gpiommc_subsys = {
	.su_group = {
		.cg_item = {
			.ci_namebuf = GPIOMMC_PLATDEV_NAME,
			.ci_type = &gpiommc_ci_type,
		},
	},
	.su_mutex = __MUTEX_INITIALIZER(gpiommc_subsys.su_mutex),
};

#endif /* CONFIG_GPIOMMC_CONFIGFS */

static struct platform_driver gpiommc_plat_driver = {
	.probe	= gpiommc_probe,
	.remove	= gpiommc_remove,
	.driver	= {
		.name	= GPIOMMC_PLATDEV_NAME,
		.owner	= THIS_MODULE,
	},
};

int gpiommc_next_id(void)
{
	static atomic_t counter = ATOMIC_INIT(-1);

	return atomic_inc_return(&counter);
}
EXPORT_SYMBOL(gpiommc_next_id);

static int __init gpiommc_modinit(void)
{
	int err;

	err = platform_driver_register(&gpiommc_plat_driver);
	if (err)
		return err;

#ifdef CONFIG_GPIOMMC_CONFIGFS
	config_group_init(&gpiommc_subsys.su_group);
	err = configfs_register_subsystem(&gpiommc_subsys);
	if (err) {
		platform_driver_unregister(&gpiommc_plat_driver);
		return err;
	}
#endif /* CONFIG_GPIOMMC_CONFIGFS */

	return 0;
}
module_init(gpiommc_modinit);

static void __exit gpiommc_modexit(void)
{
#ifdef CONFIG_GPIOMMC_CONFIGFS
	configfs_unregister_subsystem(&gpiommc_subsys);
#endif
	platform_driver_unregister(&gpiommc_plat_driver);
}
module_exit(gpiommc_modexit);
