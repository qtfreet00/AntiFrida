#include <jni.h>
#include <sys/types.h>
#include <cstring>
#include <cstdio>
#include <android/log.h>
#include <unistd.h>
#include <android/log.h>
#include <pthread.h>
#include <cstdlib>
#include <elf.h>
#include <link.h>
#include <fcntl.h>

extern "C" int wrap_openat(int, const char *, int, ...);

extern "C" ssize_t wrap_read(int __fd, void *__buf, size_t __count);

extern "C" int wrap_close(int __fd);

extern "C" int wrap_kill(pid_t, int);

#define BUFFER_LEN 512

#define TAG "carleen"

#define DEBUG

#ifdef DEBUG
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, TAG, __VA_ARGS__)
#define LOGW(...) __android_log_print(ANDROID_LOG_WARN, TAG, __VA_ARGS__)
#else
#define LOGW(...) ((void)0)
#define LOGI(...) ((void)0)
#endif

int
wrap_memcmp(const unsigned char *s1, const unsigned char *s2, size_t n) {
    if (n != 0) {
        const unsigned char *p1 = s1;
        const unsigned char *p2 = s2;

        do {
            if (*p1++ != *p2++)
                return (*--p1 - *--p2);
        } while (--n != 0);
    }
    return (0);
}


int find_mem_string(long long base, long long end, unsigned char *ptr, unsigned int len) {

    unsigned char *rc = (unsigned char *) base;

    while ((long long) rc < end - len) {
        if (*rc == *ptr) {
            if (wrap_memcmp(rc, ptr, len) == 0) {
                return 1;
            }
        }

        rc++;

    }
    return 0;
}

int read_line(int fd, char *ptr, unsigned int maxlen) {
    int n;
    int rc;
    char c;

    for (n = 1; n < maxlen; n++) {
        if ((rc = wrap_read(fd, &c, 1)) == 1) {
            *ptr++ = c;
            if (c == '\n')
                break;
        } else if (rc == 0) {
            if (n == 1)
                return 0;    /* EOF no data read */
            else
                break;    /* EOF, some data read */
        } else
            return (-1);    /* error */
    }
    *ptr = 0;
    return (n);
}

int elf_check_header(uintptr_t base_addr) {
    ElfW(Ehdr) *ehdr = (ElfW(Ehdr) *) base_addr;
    if (0 != memcmp(ehdr->e_ident, ELFMAG, SELFMAG)) return 0;
#if defined(__LP64__)
    if(ELFCLASS64 != ehdr->e_ident[EI_CLASS]) return 0;
#else
    if (ELFCLASS32 != ehdr->e_ident[EI_CLASS]) return 0;
#endif
    if (ELFDATA2LSB != ehdr->e_ident[EI_DATA]) return 0;
    if (EV_CURRENT != ehdr->e_ident[EI_VERSION]) return 0;
    if (ET_EXEC != ehdr->e_type && ET_DYN != ehdr->e_type) return 0;
    if (EV_CURRENT != ehdr->e_version) return 0;
    return 1;
}

int wrap_endsWith(const char *str, const char *suffix) {
    if (!str || !suffix)
        return 0;
    size_t lenA = strlen(str);
    size_t lenB = strlen(suffix);
    if (lenB > lenA)
        return 0;
    return strncmp(str + lenA - lenB, suffix, lenB) == 0;
}


void *check_loop(void *) {
    int fd;
    char path[256];
    char perm[5];
    unsigned long offset;
    unsigned int base;
    long end;
    char buffer[BUFFER_LEN];
    int loop = 0;
    unsigned int length = 11;
    //"frida:rpc"
    unsigned char frida_rpc[] =
            {

                    0xfe, 0xba, 0xfb, 0x4a, 0x9a, 0xca, 0x7f, 0xfb,
                    0xdb, 0xea, 0xfe, 0xdc
            };

    for (unsigned char &m : frida_rpc) {
        unsigned char c = m;
        c = ~c;
        c ^= 0xb1;
        c = (c >> 0x6) | (c << 0x2);
        c ^= 0x4a;
        c = (c >> 0x6) | (c << 0x2);
        m = c;
    }
    LOGI("start check frida loop");
    while (loop < 10) {
        fd = wrap_openat(AT_FDCWD, "/proc/self/maps", O_RDONLY, 0);
        if (fd > 0) {
            while ((read_line(fd, buffer, BUFFER_LEN)) > 0) {

                if (sscanf(buffer, "%x-%lx %4s %lx %*s %*s %s", &base, &end, perm, &offset, path) !=
                    5) {
                    continue;
                }
                if (perm[0] != 'r') continue;
                if (perm[3] != 'p') continue; //do not touch the shared memory
                if (0 != offset) continue;
                if (strlen(path) == 0) continue;
                if ('[' == path[0]) continue;
                if (end - base <= 1000000) continue;
                if (wrap_endsWith(path, ".oat")) continue;
                if (elf_check_header(base) != 1) continue;
                if (find_mem_string(base, end, frida_rpc, length) == 1) {
                    LOGI("frida found in memory!");
#ifndef DEBUG
                    wrap_kill(wrap_getpid(),SIGKILL);
#endif
                    break;
                }
            }
        } else {
            LOGI("open maps error");
        }
        wrap_close(fd);
        loop++;
        sleep(3);
    }
    return nullptr;
}


void anti_frida_loop() {
    pthread_t t;
    if (pthread_create(&t, nullptr, check_loop, (void *) nullptr) != 0) {
        exit(-1);
    };
    pthread_detach(t);
}


extern "C"
JNIEXPORT void JNICALL
Java_com_qtfreet_antifrida_MainActivity_startCheck(JNIEnv *env, jobject thiz) {
    anti_frida_loop();
}