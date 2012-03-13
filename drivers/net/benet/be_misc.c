/*
 * Copyright (C) 2005 - 2011 Emulex
 * All rights reserved.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License version 2
 * as published by the Free Software Foundation. The full GNU General
 * Public License is included in this distribution in the file called COPYING.
 *
 * Contact Information:
 * linux-drivers@emulex.com
 *
 * Emulex
 * 3333 Susan Street
 * Costa Mesa, CA 92626
 */
#include "be.h"

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 24)
static ssize_t
flash_fw_store(struct class_device *cd, const char *buf, size_t len)
{
	struct be_adapter *adapter =
		netdev_priv(container_of(cd, struct net_device, class_dev));
	char file_name[ETHTOOL_FLASH_MAX_FILENAME];
	int status;

	if (!capable(CAP_NET_ADMIN))
		return -EPERM;

	file_name[ETHTOOL_FLASH_MAX_FILENAME - 1] = 0;
	strncpy(file_name, buf, (ETHTOOL_FLASH_MAX_FILENAME - 1));

	/* Removing new-line char given by sysfs */
	file_name[strlen(file_name) - 1] = '\0';

	status = be_load_fw(adapter, file_name);
	if (!status)
		return len;
	else
		return status;
}

static CLASS_DEVICE_ATTR(flash_fw, S_IWUSR, NULL, flash_fw_store);

static struct attribute *benet_attrs[] = {
	&class_device_attr_flash_fw.attr,
	NULL,
};
#else

static ssize_t
flash_fw_store(struct device *dev, struct device_attribute *attr,
		const char *buf, size_t len)
{
	struct be_adapter *adapter =
		netdev_priv(container_of(dev, struct net_device, dev));
	char file_name[ETHTOOL_FLASH_MAX_FILENAME];
	int status;

	if (!capable(CAP_NET_ADMIN))
		return -EPERM;

	file_name[ETHTOOL_FLASH_MAX_FILENAME - 1] = 0;
	strncpy(file_name, buf, (ETHTOOL_FLASH_MAX_FILENAME - 1));

	/* Removing new-line char given by sysfs */
	file_name[strlen(file_name) - 1] = '\0';

	status = be_load_fw(adapter, file_name);
	if (!status)
		return len;
	else
		return status;
}

static DEVICE_ATTR(flash_fw, S_IWUSR, NULL, flash_fw_store);

static struct attribute *benet_attrs[] = {
	&dev_attr_flash_fw.attr,
	NULL,
};
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 24)
#define CLASS_DEV		class_dev
#else
#define CLASS_DEV		dev
#endif

static struct attribute_group benet_attr_group = {.attrs = benet_attrs };

void be_sysfs_create_group(struct be_adapter *adapter)
{
	int status;

	status = sysfs_create_group(&adapter->netdev->CLASS_DEV.kobj,
			&benet_attr_group);
	if (status)
		dev_err(&adapter->pdev->dev, "Could not create sysfs group\n");
}

void be_sysfs_remove_group(struct be_adapter *adapter)
{
	sysfs_remove_group(&adapter->netdev->CLASS_DEV.kobj, &benet_attr_group);
}
