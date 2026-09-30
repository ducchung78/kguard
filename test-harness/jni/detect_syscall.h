/*
 * detect_syscall.h — Direct syscall wrappers (ARM64)
 */
#ifndef KGUARD_DETECT_SYSCALL_H
#define KGUARD_DETECT_SYSCALL_H

#include <stddef.h>
#include <stdint.h>

/* Direct ARM64 syscall wrappers — bypass libc entirely */
long direct_openat(int dfd, const char *path, int flags, int mode);
long direct_read(int fd, void *buf, size_t count);
long direct_close(int fd);
long direct_write(int fd, const void *buf, size_t count);
long direct_faccessat(int dfd, const char *path, int mode, int flags);
long direct_readlinkat(int dfd, const char *path, char *buf, int bufsiz);
long direct_newfstatat(int dfd, const char *path, void *statbuf, int flag);
long direct_getdents64(int fd, void *dirp, unsigned int count);
long direct_mincore(void *addr, size_t length, unsigned char *vec);
long direct_prctl(int option, unsigned long a2, unsigned long a3,
                  unsigned long a4, unsigned long a5);

#endif
