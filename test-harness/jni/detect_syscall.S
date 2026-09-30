/*
 * detect_syscall.S — Pure ARM64 (AArch64) direct syscall stubs
 *
 * These bypass Bionic libc entirely — arguments go straight from
 * registers to the kernel via SVC #0.  If libc functions are hooked
 * (GOT/PLT or inline), these wrappers remain unaffected.
 *
 * ARM64 Linux syscall ABI:
 *   X8  = syscall number
 *   X0-X5 = arguments (same as C calling convention)
 *   X0  = return value (negative = -errno)
 */

.text
.arch armv8-a

/* ────────────────────────────────────────────
 * long direct_openat(int dfd, const char *path, int flags, int mode)
 * __NR_openat = 56
 * ──────────────────────────────────────────── */
.global direct_openat
.type   direct_openat, %function
direct_openat:
    mov     x8, #56
    svc     #0
    ret
.size   direct_openat, .-direct_openat

/* ────────────────────────────────────────────
 * long direct_read(int fd, void *buf, size_t count)
 * __NR_read = 63
 * ──────────────────────────────────────────── */
.global direct_read
.type   direct_read, %function
direct_read:
    mov     x8, #63
    svc     #0
    ret
.size   direct_read, .-direct_read

/* ────────────────────────────────────────────
 * long direct_close(int fd)
 * __NR_close = 57
 * ──────────────────────────────────────────── */
.global direct_close
.type   direct_close, %function
direct_close:
    mov     x8, #57
    svc     #0
    ret
.size   direct_close, .-direct_close

/* ────────────────────────────────────────────
 * long direct_write(int fd, const void *buf, size_t count)
 * __NR_write = 64
 * ──────────────────────────────────────────── */
.global direct_write
.type   direct_write, %function
direct_write:
    mov     x8, #64
    svc     #0
    ret
.size   direct_write, .-direct_write

/* ────────────────────────────────────────────
 * long direct_faccessat(int dfd, const char *path, int mode, int flags)
 * __NR_faccessat = 48
 * ──────────────────────────────────────────── */
.global direct_faccessat
.type   direct_faccessat, %function
direct_faccessat:
    mov     x8, #48
    svc     #0
    ret
.size   direct_faccessat, .-direct_faccessat

/* ────────────────────────────────────────────
 * long direct_readlinkat(int dfd, const char *path, char *buf, int bufsiz)
 * __NR_readlinkat = 78
 * ──────────────────────────────────────────── */
.global direct_readlinkat
.type   direct_readlinkat, %function
direct_readlinkat:
    mov     x8, #78
    svc     #0
    ret
.size   direct_readlinkat, .-direct_readlinkat

/* ────────────────────────────────────────────
 * long direct_newfstatat(int dfd, const char *path, void *statbuf, int flag)
 * __NR_newfstatat = 79
 * ──────────────────────────────────────────── */
.global direct_newfstatat
.type   direct_newfstatat, %function
direct_newfstatat:
    mov     x8, #79
    svc     #0
    ret
.size   direct_newfstatat, .-direct_newfstatat

/* ────────────────────────────────────────────
 * long direct_getdents64(int fd, void *dirp, unsigned int count)
 * __NR_getdents64 = 61
 * ──────────────────────────────────────────── */
.global direct_getdents64
.type   direct_getdents64, %function
direct_getdents64:
    mov     x8, #61
    svc     #0
    ret
.size   direct_getdents64, .-direct_getdents64

/* ────────────────────────────────────────────
 * long direct_mincore(void *addr, size_t length, unsigned char *vec)
 * __NR_mincore = 232
 * ──────────────────────────────────────────── */
.global direct_mincore
.type   direct_mincore, %function
direct_mincore:
    mov     x8, #232
    svc     #0
    ret
.size   direct_mincore, .-direct_mincore

/* ────────────────────────────────────────────
 * long direct_prctl(int option, ulong a2, ulong a3, ulong a4, ulong a5)
 * __NR_prctl = 167
 * ──────────────────────────────────────────── */
.global direct_prctl
.type   direct_prctl, %function
direct_prctl:
    mov     x8, #167
    svc     #0
    ret
.size   direct_prctl, .-direct_prctl
