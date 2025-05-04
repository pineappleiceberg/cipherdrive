#define _GNU_SOURCE
#define NBDKIT_API_VERSION 2
#define THREAD_MODEL NBDKIT_THREAD_MODEL_PARALLEL
#include <sodium.h>
#include <nbdkit-plugin.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>

#define PLAIN 512 //512 byte block size
#define TAG   16 // tag for poly1305
#define SECT  (PLAIN + TAG) //528 bytes stored for 512 bytes of data


static unsigned char key[crypto_aead_chacha20poly1305_IETF_KEYBYTES];
static FILE *img, *logf;

//last variable is if we are encrypting or decrypting
static int xcrypt(void *buf, uint64_t blk, int enc)
{
  unsigned char nonce[12] = {0}; //chacha needs a 12 byte nonce
  memcpy(nonce + 4, &blk, 8); //some of the nonce is for a counter
  unsigned long long out = 0;
  return enc
  //chachapoly because it is authenticated as well as encrypted
    ? crypto_aead_chacha20poly1305_ietf_encrypt(
        buf, &out, buf, PLAIN, NULL, 0, NULL, nonce, key) == 0
    : crypto_aead_chacha20poly1305_ietf_decrypt(
        buf, &out, NULL, buf, SECT, NULL, 0, nonce, key) == 0;
}

static void log_rw(const char *op, uint64_t off, uint32_t len)
{
  fprintf(logf, "%s off=%llu len=%u\n", op, (unsigned long long)off, len);
  fflush(logf);
}

static void *open_fn(int ro)
{
  (void) ro;
  logf = fopen("/var/log/encdrive.log", "a");
  img  = fopen("/srv/piusb.img", "r+b"); //backing file, can be on NVMe
  return img;
}
static void close_fn(void *h){
    fclose(img);
    fclose(logf);
}

static int64_t get_size(void *h)
{
  fseeko(img, 0, SEEK_END);
  return ftello(img) / SECT * PLAIN;
}

static int pread_fn(void *h, void *buf,
                    uint32_t cnt, uint64_t off, uint32_t f)
{
  (void) f;  uint8_t *p = buf;
  log_rw("R", off, cnt);
  for (uint32_t i=0; i<cnt; i+=PLAIN) {
    unsigned char t[SECT];
    fseeko(img, ((off+i)/PLAIN)*SECT, SEEK_SET);
    if (fread(t,1,SECT,img)!=SECT) return -1;
    if (!xcrypt(t,(off+i)/PLAIN,0)) {
		memset(p+i, 0, PLAIN);             //if our auth tag fails, we can return all zeros without failing
		fprintf(logf,
			"AUTH-FAIL blk=%llu  ➜ zero-filled sector returned\n",
			(unsigned long long)((off+i)/PLAIN));
	} else {
		memcpy(p+i, t, PLAIN);             //sector with passing auth tag
	}
  }
  return 0;
}

static int pwrite_fn(void *h, const void *buf,
                     uint32_t cnt, uint64_t off, uint32_t f)
{
  (void) f;  const uint8_t *p = buf;  log_rw("W", off, cnt);
  for (uint32_t i=0; i<cnt; i+=PLAIN) {
    unsigned char t[SECT];
    memcpy(t,p+i,PLAIN);
    if (!xcrypt(t,(off+i)/PLAIN,1)) return -1;
    fseeko(img, ((off+i)/PLAIN)*SECT, SEEK_SET);
    if (fwrite(t,1,SECT,img)!=SECT) return -1;
  }
  return 0;
}

//AI generated hex print function
static int hex2bin(const char *hex, unsigned char *out, size_t max)
{
  size_t len = strlen(hex);
  if (len % 2 || len/2 > max) return -1;
  for (size_t i=0;i<len;i+=2){unsigned int b; if (sscanf(hex+i,"%2x",&b)!=1) return -1; out[i/2] = b;}
  return len/2;
}

static int config(const char *k,const char *v)
{
  if (strcmp(k,"key") == 0) {
    char *pw = NULL;
    if (nbdkit_read_password(v,&pw)==-1) return -1;

    if (hex2bin(pw,key,sizeof key)!=32){
      nbdkit_error("key must be 64-hex-chars (32 bytes)");
      free(pw); return -1;
    }

    free(pw); return 0;
  }

  nbdkit_error("unknown parameter %s",k);
  return -1;
}


static struct nbdkit_plugin plugin = {
  .name        = "aead-logfile",
  .longname    = "ChaCha20-Poly1305 sector plug-in (logs)",
  .config      = config,
  .open        = open_fn,  .close  = close_fn,
  .get_size    = get_size,
  .pread       = pread_fn, .pwrite = pwrite_fn,
};
NBDKIT_REGISTER_PLUGIN(plugin)
///usr/local/src/nbd_aead_logfile.c
