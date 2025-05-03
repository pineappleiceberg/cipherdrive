#define _GNU_SOURCE
#define NBDKIT_API_VERSION 2
#define THREAD_MODEL NBDKIT_THREAD_MODEL_PARALLEL   /* <-- simplest v2 form */  /* :contentReference[oaicite:3]{index=3} */

#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sodium.h>
#include <nbdkit-plugin.h>

#define SECTOR 512
static FILE *fh;

/* --------------- key & nonce (replace for production) ---------------- */
static const unsigned char key[crypto_stream_chacha20_KEYBYTES] =
  "\x00\x01\x02\x03\x04\x05\x06\x07"
  "\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f"
  "\x10\x11\x12\x13\x14\x15\x16\x17"
  "\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f";
static const unsigned char nonce[8] = "\xde\xad\xbe\xef\xba\xad\xf0\x0d";

/* --------------- small helper --------------------------------------- */
static void crypt_sector(void *buf, uint64_t blk)
{
  /* libsodium lets us specify the counter (blk) directly */            /* :contentReference[oaicite:4]{index=4} */
  crypto_stream_chacha20_xor_ic(buf, buf, SECTOR, nonce, blk, key);
}


/* --------------- nbdkit v2 callbacks -------------------------------- */
static void *open_fn(int readonly)
{
  (void) readonly;
  return fopen("/srv/piusb.img", "r+b");           /* handle == FILE* */
}
static void close_fn(void *h) { fclose(h); }

static int64_t get_size_fn(void *h)
{
  fseeko(h, 0, SEEK_END);
  return ftello(h);
}

static int pread_fn(void *h, void *buf,
                    uint32_t cnt, uint64_t off, uint32_t flags)
{
  (void) flags;
  fseeko(h, off, SEEK_SET);
  if (fread(buf, 1, cnt, h) != cnt) return -1;
  for (uint32_t i = 0; i < cnt; i += SECTOR)
    crypt_sector((char*)buf + i, (off + i) / SECTOR);
  return 0;
}

static int pwrite_fn(void *h, const void *buf,
                     uint32_t cnt, uint64_t off, uint32_t flags)
{
  (void) flags;
  unsigned char tmp[128*SECTOR];
  memcpy(tmp, buf, cnt);
  for (uint32_t i = 0; i < cnt; i += SECTOR)
    crypt_sector(tmp + i, (off + i) / SECTOR);
  fseeko(h, off, SEEK_SET);
  return fwrite(tmp, 1, cnt, h) == cnt ? 0 : -1;
}

/* --------------- plugin struct (notice: no .thread_model field) ----- */
static struct nbdkit_plugin plugin = {
  .name     = "chacha20",
  .longname = "ChaCha20 sector-cipher plugin",
  .open     = open_fn,
  .close    = close_fn,
  .get_size = get_size_fn,
  .pread    = pread_fn,
  .pwrite   = pwrite_fn,
};
NBDKIT_REGISTER_PLUGIN(plugin)

/*export PKG_CONFIG_PATH=/usr/local/lib/pkgconfig:$PKG_CONFIG_PATH   # if not already
gcc -O3 -shared -fPIC -std=c11 \
    $(pkg-config --cflags libsodium)  $(pkg-config --cflags nbdkit) \
    /usr/local/src/nbd_chacha.c -o /usr/local/lib/nbd_chacha.so \
    $(pkg-config --libs libsodium)    $(pkg-config --libs nbdkit)
	
	validation command: /usr/local/bin/nbdkit --dump-plugin /usr/local/lib/nbd_chacha.so*/