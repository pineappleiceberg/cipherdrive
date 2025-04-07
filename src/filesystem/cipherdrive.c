#define FUSE_USE_VERSION 31

#include <fuse.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <pthread.h>
#include <limits.h>
#include <time.h>

#include "aes.h"

#define BLOCK_SIZE 4096
#define IV_SIZE AES_BLOCKLEN

static int backing_fd = -1;
static char* backing_file_path = NULL;
static uint8_t master_key[AES_KEYLEN];
static pthread_mutex_t crypto_mutex = PTHREAD_MUTEX_INITIALIZER;
static off_t file_size = 0;

static int load_master_key() {
    uint8_t static_dev_key[AES_KEYLEN] = {0};

    if (sizeof(static_dev_key) != AES_KEYLEN) {
        fprintf(stderr, "Error: AES_KEYLEN mismatch for static key. Check aes.h\n");
        return -1;
    }
    printf("WARNING: Using static development key!\n");
    memcpy(master_key, static_dev_key, AES_KEYLEN);
    return 0;
}

static void derive_block_iv(uint64_t block_num, uint8_t* iv) {
    memset(iv, 0, IV_SIZE);
    memcpy(iv, &block_num, sizeof(block_num));
}

static int read_and_decrypt_block(uint64_t block_num, uint8_t* block_buffer) {
    uint8_t iv[IV_SIZE];
    struct AES_ctx ctx;
    off_t offset = (off_t)block_num * BLOCK_SIZE;
    ssize_t res;

    res = pread(backing_fd, block_buffer, BLOCK_SIZE, offset);
    if (res == -1) {
        perror("pread failed in read_and_decrypt_block");
        return -errno;
    }
    if (res < BLOCK_SIZE) {
        memset(block_buffer + res, 0, BLOCK_SIZE - res);
    }

    pthread_mutex_lock(&crypto_mutex);
    derive_block_iv(block_num, iv);
    AES_init_ctx_iv(&ctx, master_key, iv);
    AES_CTR_xcrypt_buffer(&ctx, block_buffer, BLOCK_SIZE);
    pthread_mutex_unlock(&crypto_mutex);

    return 0;
}

static int encrypt_and_write_block(uint64_t block_num, uint8_t* block_buffer) {
    uint8_t iv[IV_SIZE];
    struct AES_ctx ctx;
    off_t offset = (off_t)block_num * BLOCK_SIZE;
    ssize_t res;

    pthread_mutex_lock(&crypto_mutex);
    derive_block_iv(block_num, iv);
    AES_init_ctx_iv(&ctx, master_key, iv);
    AES_CTR_xcrypt_buffer(&ctx, block_buffer, BLOCK_SIZE);
    pthread_mutex_unlock(&crypto_mutex);

    res = pwrite(backing_fd, block_buffer, BLOCK_SIZE, offset);
    if (res == -1) {
        perror("pwrite failed in encrypt_and_write_block");
        return -errno;
    }
    if (res < BLOCK_SIZE) {
         fprintf(stderr, "Error: Partial write (%zd bytes) occurred for block %llu\n", res, block_num);
         return -EIO;
    }

    return 0;
}


static void* cipherdrive_init(struct fuse_conn_info *conn,
                             struct fuse_config *cfg)
{
    (void) conn;
    cfg->use_ino = 1;
    cfg->attr_timeout = 1.0;
    cfg->entry_timeout = 1.0;
    cfg->negative_timeout = 0.0;

    if (!backing_file_path) {
        fprintf(stderr, "Error: Backing file path not set in init!\n");
        return NULL;
    }
    backing_fd = open(backing_file_path, O_RDWR | O_CREAT, 0600);
    if (backing_fd < 0) {
        perror("Failed to open backing file in init");
        return NULL;
    }

    struct stat st;
    if (fstat(backing_fd, &st) == -1) {
        perror("Failed to fstat backing file in init");
        close(backing_fd);
        backing_fd = -1;
        return NULL;
    }
    file_size = st.st_size;

    if (load_master_key() != 0) {
         fprintf(stderr, "Failed to load master key in init\n");
         close(backing_fd);
         backing_fd = -1;
         return NULL;
    }

    printf("CipherDrive initialized. Backing file: %s, Size: %ld\n", backing_file_path, file_size);
    return NULL;
}

static void cipherdrive_destroy(void *private_data)
{
    (void)private_data;
    if (backing_fd >= 0) {
        printf("CipherDrive destroying. Closing backing file (fd=%d).\n", backing_fd);
        if (close(backing_fd) == -1) {
             perror("Error closing backing file in destroy");
        }
        backing_fd = -1;
    }
    if (backing_file_path) {
        backing_file_path = NULL;
    }
}


static int cipherdrive_getattr(const char* path, struct stat* stbuf,
                              struct fuse_file_info *fi) {
    (void) fi;
    memset(stbuf, 0, sizeof(struct stat));

    if (strcmp(path, "/") == 0) {
        stbuf->st_mode = S_IFDIR | 0755;
        stbuf->st_nlink = 2;
        return 0;
    }

     if (strcmp(path, "/storage.img") == 0) {
        stbuf->st_mode = S_IFREG | 0644;
        stbuf->st_nlink = 1;
        stbuf->st_size = file_size;
        stbuf->st_blksize = BLOCK_SIZE;
        stbuf->st_blocks = (file_size + BLOCK_SIZE - 1) / BLOCK_SIZE;

        if (backing_fd >= 0) {
            struct stat backing_st;
            if (fstat(backing_fd, &backing_st) == 0) {
                 stbuf->st_atim = backing_st.st_atim;
                 stbuf->st_mtim = backing_st.st_mtim;
                 stbuf->st_ctim = backing_st.st_ctim;
                 stbuf->st_uid = backing_st.st_uid;
                 stbuf->st_gid = backing_st.st_gid;
            } else {
                 perror("fstat failed in getattr");
                 time_t now = time(NULL);
                 stbuf->st_atim.tv_sec = now;
                 stbuf->st_mtim.tv_sec = now;
                 stbuf->st_ctim.tv_sec = now;
                 stbuf->st_uid = getuid();
                 stbuf->st_gid = getgid();
            }
        } else {
             time_t now = time(NULL);
             stbuf->st_atim.tv_sec = now;
             stbuf->st_mtim.tv_sec = now;
             stbuf->st_ctim.tv_sec = now;
             stbuf->st_uid = getuid();
             stbuf->st_gid = getgid();
        }
        return 0;
    }

    return -ENOENT;
}

static int cipherdrive_readdir(const char* path, void* buf, fuse_fill_dir_t filler,
                             off_t offset, struct fuse_file_info* fi,
                             enum fuse_readdir_flags flags) {
    (void) offset;
    (void) fi;
    (void) flags;

    if (strcmp(path, "/") != 0) {
        return -ENOENT;
    }

    filler(buf, ".", NULL, 0, 0);
    filler(buf, "..", NULL, 0, 0);
    filler(buf, "storage.img", NULL, 0, 0);

    return 0;
}


static int cipherdrive_open(const char* path, struct fuse_file_info* fi) {
    if (strcmp(path, "/storage.img") != 0) {
        return -ENOENT;
    }

    if (backing_fd < 0) {
        fprintf(stderr, "Error: Attempt to open %s, but backing_fd is invalid.\n", path);
        return -EIO;
    }


    fi->fh = backing_fd;

    return 0;
}

static int cipherdrive_release(const char *path, struct fuse_file_info *fi) {
    (void) path;
    (void) fi;
    return 0;
}
/*
We need to treat the data as disk blocks instead of bytes because our
target when we get it from linux will be a single disk image file 
so we wont get the granularity of bytes, we will get the granularity of disk blocks
*/
static int cipherdrive_read(const char* path, char* buf, size_t size, off_t offset,
                          struct fuse_file_info* fi) {
    (void)fi;
    if (strcmp(path, "/storage.img") != 0) {
        return -ENOENT;
    }
     if (backing_fd < 0) {
        return -EIO;
    }

    if (offset >= file_size) {
        return 0;
    }

    if (offset + size > file_size) {
        size = file_size - offset;
    }

    size_t total_read = 0;
    uint8_t *block_buffer = malloc(BLOCK_SIZE);
    if (!block_buffer) {
        perror("Failed to allocate block buffer in read");
        return -ENOMEM;
    }

    while (total_read < size) {
        off_t current_offset = offset + total_read;

        uint64_t block_num = current_offset / BLOCK_SIZE;
        off_t offset_in_block = current_offset % BLOCK_SIZE;
        size_t bytes_to_read_from_block = BLOCK_SIZE - offset_in_block;

        if (bytes_to_read_from_block > (size - total_read)) {
            bytes_to_read_from_block = size - total_read;
        }

         if (bytes_to_read_from_block == 0) {
            break;
        }

        if (read_and_decrypt_block(block_num, block_buffer) != 0) {
            fprintf(stderr, "Error decrypting block %llu during read\n", block_num);
            free(block_buffer);
            return -EIO;
        }

        memcpy(buf + total_read, block_buffer + offset_in_block, bytes_to_read_from_block);
        total_read += bytes_to_read_from_block;
    }

    free(block_buffer);
    return total_read;
}


static int cipherdrive_write(const char* path, const char* buf, size_t size, off_t offset,
                           struct fuse_file_info* fi) {
    (void)fi;
     if (strcmp(path, "/storage.img") != 0) {
        return -ENOENT;
    }
     if (backing_fd < 0) {
        return -EIO;
    }

    size_t total_written = 0;
    uint8_t *block_buffer = malloc(BLOCK_SIZE);
    if (!block_buffer) {
        perror("Failed to allocate block buffer in write");
        return -ENOMEM;
    }

    while (total_written < size) {
        off_t current_offset = offset + total_written;
        uint64_t block_num = current_offset / BLOCK_SIZE;
        off_t offset_in_block = current_offset % BLOCK_SIZE;
        size_t bytes_to_write_to_block = BLOCK_SIZE - offset_in_block;

        if (bytes_to_write_to_block > (size - total_written)) {
            bytes_to_write_to_block = size - total_written;
        }

        int is_partial_write = (offset_in_block != 0 || bytes_to_write_to_block != BLOCK_SIZE);

        if (is_partial_write) {
             off_t read_offset = (off_t)block_num * BLOCK_SIZE;
             if (read_offset < file_size) {
                if (read_and_decrypt_block(block_num, block_buffer) != 0) {
                    fprintf(stderr, "Error reading block %llu for partial write\n", block_num);
                    free(block_buffer);
                    return -EIO;
                }
             } else {
                 memset(block_buffer, 0, BLOCK_SIZE);
             }
        }

        memcpy(block_buffer + offset_in_block, buf + total_written, bytes_to_write_to_block);

        if (encrypt_and_write_block(block_num, block_buffer) != 0) {
            fprintf(stderr, "Error encrypting block %llu during write\n", block_num);
            free(block_buffer);
             if (errno == ENOSPC) return -ENOSPC;
            return -EIO;
        }

        total_written += bytes_to_write_to_block;

        if (current_offset + bytes_to_write_to_block > file_size) {
            file_size = current_offset + bytes_to_write_to_block;
        }
    }

    free(block_buffer);
    return total_written;
}


static int cipherdrive_truncate(const char* path, off_t size, struct fuse_file_info *fi) {
    (void) fi;
    if (strcmp(path, "/storage.img") != 0) {
        return -ENOENT;
    }
     if (backing_fd < 0) {
        return -EIO;
    }

    if (size > file_size) {
        uint8_t *zero_block = calloc(1, BLOCK_SIZE);
        if (!zero_block) return -ENOMEM;

        off_t current_end = file_size;
        while (current_end < size) {
            uint64_t block_num = current_end / BLOCK_SIZE;
            off_t offset_in_block = current_end % BLOCK_SIZE;
            size_t bytes_to_zero = BLOCK_SIZE - offset_in_block;
            if (current_end + bytes_to_zero > size) {
                bytes_to_zero = size - current_end;
            }

            if (offset_in_block != 0 || bytes_to_zero != BLOCK_SIZE) {
                if (read_and_decrypt_block(block_num, zero_block) != 0) {
                    memset(zero_block, 0, BLOCK_SIZE);
                }
                memset(zero_block + offset_in_block, 0, bytes_to_zero);
            } else {
            }

            if (encrypt_and_write_block(block_num, zero_block) != 0) {
                fprintf(stderr, "Error writing zero block %llu during truncate\n", block_num);
                free(zero_block);
                 return -EIO;
            }
            current_end += bytes_to_zero;
        }
        free(zero_block);
    }

    int res = ftruncate(backing_fd, size);
    if (res == -1) {
        return -errno;
    }
    file_size = size;

    return 0;
}


static int cipherdrive_fsync(const char* path, int isdatasync, struct fuse_file_info* fi) {
     (void) path;
     if (backing_fd < 0) {
        return -EIO;
    }

    int res;
    int fd_to_sync = (fi && fi->fh > 0) ? fi->fh : backing_fd;

    if (isdatasync) {
        #ifdef HAVE_FDATASYNC
        res = fdatasync(fd_to_sync);
        #else
        res = fsync(fd_to_sync);
        #endif
    } else {
        res = fsync(fd_to_sync);
    }

    if (res == -1) {
        return -errno;
    }
    return 0;
}

static int cipherdrive_other_unsupported() {
    return -EOPNOTSUPP;
}


static struct fuse_operations cipherdrive_oper = {
    .init       = cipherdrive_init,
    .destroy    = cipherdrive_destroy,
    .getattr    = cipherdrive_getattr,
    .readdir    = cipherdrive_readdir,
    .open       = cipherdrive_open,
    .release    = cipherdrive_release,
    .read       = cipherdrive_read,
    .write      = cipherdrive_write,
    .truncate   = cipherdrive_truncate,
    .fsync      = cipherdrive_fsync,
    .mkdir      = (void*)cipherdrive_other_unsupported,
    .unlink     = (void*)cipherdrive_other_unsupported,
    .rmdir      = (void*)cipherdrive_other_unsupported,
    .rename     = (void*)cipherdrive_other_unsupported,
    .link       = (void*)cipherdrive_other_unsupported,
    .chmod      = (void*)cipherdrive_other_unsupported,
    .chown      = (void*)cipherdrive_other_unsupported,
    .create     = (void*)cipherdrive_other_unsupported,
    .utimens    = (void*)cipherdrive_other_unsupported,
};

static char* allocated_backing_path = NULL;

int main(int argc, char* argv[]) {
    struct fuse_args args = FUSE_ARGS_INIT(argc, argv);

    if (argc < 3) {
        fprintf(stderr, "Usage: %s <backing_file> <mount_point> [FUSE options]\n", argv[0]);
        return 1;
    }

    backing_file_path = argv[1];

    for (int i = 1; i < argc - 1; ++i) {
        argv[i] = argv[i+1];
    }
    argc--;
    args.argc = argc;

    printf("Starting CipherDrive FUSE...\n");
    printf("  Backing File: %s\n", backing_file_path);
    printf("  Mount Point:  %s\n", argv[1]);

    int ret = fuse_main(args.argc, args.argv, &cipherdrive_oper, NULL);


    printf("CipherDrive FUSE finished with exit code %d.\n", ret);
    return ret;
} 
