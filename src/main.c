/* main.c */

#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>

LOG_MODULE_REGISTER(cipher_app, LOG_LEVEL_INF);

void main(void)
{
    LOG_INF("Hello from our encrypted disk proxy example!");
    /* 
     * On real hardware, you might do something like:
     *   - Wait for the underlying disk device to be ready
     *   - Possibly do your own test calls to read/write
     */
    while (1) {
        k_sleep(K_SECONDS(5));
    }
}
