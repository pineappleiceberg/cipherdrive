#include <zephyr/device.h>
#include <zephyr/disk/disk_access.h>
#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>
#include <string.h>

LOG_MODULE_REGISTER(encryption_driver, LOG_LEVEL_INF);

static const struct device *underlying_dev;

/* forward declarations */
static int enc_init(const struct device *dev);
static int enc_status(const struct device *dev);
static int enc_read(const struct device *dev, uint8_t *data_buf,
                    uint32_t start_sector, uint32_t sector_count);
static int enc_write(const struct device *dev, const uint8_t *data_buf,
                     uint32_t start_sector, uint32_t sector_count);
static int enc_ioctl(const struct device *dev, uint8_t cmd, void *buff);

/* Our new disk driver API structure */
static const struct disk_driver_api enc_disk_api = {
    .init   = enc_init,
    .status = enc_status,
    .read   = enc_read,
    .write  = enc_write,
    .ioctl  = enc_ioctl,
};

static int enc_init(const struct device *dev)
{
    LOG_INF("enc_init called for %s", dev->name);

    underlying_dev = device_get_binding("RAM_0");  /* or "SDMMC_0" */
    if (!underlying_dev) {
        LOG_ERR("Failed to get underlying device!");
        return -ENODEV;
    }

    /* If underlying dev has an init() method, call it */
    const struct disk_driver_api *api = underlying_dev->api;
    if (api->init) {
        int ret = api->init(underlying_dev);
        if (ret < 0) {
            LOG_ERR("underlying init failed: %d", ret);
            return ret;
        }
    }
    return 0;
}

static int enc_status(const struct device *dev)
{
    if (!underlying_dev) {
        return -ENODEV;
    }

    const struct disk_driver_api *api = underlying_dev->api;
    if (api->status) {
        return api->status(underlying_dev);
    }
    return -ENOTSUP;
}

static int enc_read(const struct device *dev, uint8_t *data_buf,
                    uint32_t start_sector, uint32_t sector_count)
{
    if (!underlying_dev) {
        return -ENODEV;
    }
    const struct disk_driver_api *api = underlying_dev->api;

    /* For simplicity, assume 512B sectors. 
       (You can do an ioctl to find real sector size.) */
    uint32_t sector_size = 512;
    size_t total_bytes = sector_size * sector_count;
    uint8_t *tmp = k_malloc(total_bytes);
    if (!tmp) {
        return -ENOMEM;
    }

    /* Read from underlying driver (its .read method) */
    int ret = api->read(underlying_dev, tmp, start_sector, sector_count);
    if (ret < 0) {
        LOG_ERR("underlying read failed: %d", ret);
        k_free(tmp);
        return ret;
    }

    /* Decrypt (for real use AES-XTS, etc.). We'll just copy. */
    memcpy(data_buf, tmp, total_bytes);

    k_free(tmp);
    return 0;
}

static int enc_write(const struct device *dev, const uint8_t *data_buf,
                     uint32_t start_sector, uint32_t sector_count)
{
    if (!underlying_dev) {
        return -ENODEV;
    }
    const struct disk_driver_api *api = underlying_dev->api;

    uint32_t sector_size = 512;
    size_t total_bytes = sector_size * sector_count;
    uint8_t *tmp = k_malloc(total_bytes);
    if (!tmp) {
        return -ENOMEM;
    }

    /* Encrypt. Real code uses AES-XTS, etc. For now, just copy. */
    memcpy(tmp, data_buf, total_bytes);

    int ret = api->write(underlying_dev, tmp, start_sector, sector_count);
    if (ret < 0) {
        LOG_ERR("underlying write failed: %d", ret);
    }

    k_free(tmp);
    return ret;
}

static int enc_ioctl(const struct device *dev, uint8_t cmd, void *buff)
{
    if (!underlying_dev) {
        return -ENODEV;
    }
    const struct disk_driver_api *api = underlying_dev->api;
    if (api->ioctl) {
        return api->ioctl(underlying_dev, cmd, buff);
    }
    return -ENOTSUP;
}

/* Register as a disk named "ENC" */
DISK_ACCESS_REGISTER(ENC, enc_disk_api);
