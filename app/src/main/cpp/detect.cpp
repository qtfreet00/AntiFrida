#include <jni.h>
#include <sys/types.h>
#include <cstring>
#include <cstdio>
#include <android/log.h>
#include <unistd.h>
#include <android/log.h>
#include <pthread.h>
#include <cstdlib>
#include <fcntl.h>

extern "C" int wrap_openat(int, const char *, int, ...);

extern "C" ssize_t wrap_read(int __fd, void *__buf, size_t __count);

extern "C" int wrap_close(int __fd);

extern "C" int wrap_kill(pid_t, int);

#define TAG "carleen"

#define DEBUG

#define BUFFER_LEN 512


#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, TAG, __VA_ARGS__)


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

int scan_executes(char *buffer) {
    char mode[10];
    char path[256];
    long long base;
    long long end;
    // "frida:rpc"
    unsigned char s[] =
            {

                    0xfe, 0xba, 0xfb, 0x4a, 0x9a, 0xca, 0x7f, 0xfb,
                    0xdb, 0xea, 0xfe, 0xdc
            };

    for (unsigned char &m : s) {
        unsigned char c = m;
        c = ~c;
        c ^= 0xb1;
        c = (c >> 0x6) | (c << 0x2);
        c ^= 0x4a;
        c = (c >> 0x6) | (c << 0x2);
        m = c;
    }

    unsigned int length = 11;

    if (sscanf(buffer, "%llx-%llx %s %*s %*s %*s %s", &base, &end, mode, path) != 4) {
        return 0;
    }

    if (wrap_memcmp((unsigned char *) mode, (unsigned char *) "r-xp", 4) == 0 && path[0] != '[' &&
        end - base > 1000000) {

        return (find_mem_string(base, end, s, length) == 1);

    } else {
        return 0;
    }
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

void *check_loop(void *) {
    int fd;
    char buffer[BUFFER_LEN];
    int loop = 0;
#ifdef DEBUG
    LOGI("start check frida loop");
#endif
    while (loop < 10) {
        fd = wrap_openat(AT_FDCWD, "/proc/self/maps", O_RDONLY, 0);
        if (fd > 0) {
            while ((read_line(fd, buffer, BUFFER_LEN)) > 0) {

                if (scan_executes(buffer) == 1) {
#ifdef DEBUG
                    LOGI("frida found in memory!");
#else
                    wrap_kill(wrap_getpid(),SIGKILL);
#endif
                    break;
                }
            }
        } else {
#ifdef DEBUG
            LOGI("open maps error");
#endif
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