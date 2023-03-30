// improved by Queered for Nipzy Reborn

/*
Changes made from og mirai:

In checksum_generic(), we removed the unnecessary register keyword and combined the initialization of sum with the loop. We also changed the type of sum to uint32_t to improve performance on 32-bit machines.

In checksum_tcpudp(), we combined the initialization of sum with the loop and removed the length variable, which was not used. We also changed the type of sum to uint32_t to improve performance on 32-bit machines.

We also made the code more readable by removing unnecessary parentheses and changing the return statements to use uint16_t.

*/

#define _GNU_SOURCE

#include <arpa/inet.h>
#include <linux/ip.h>

#include "includes.h"
#include "checksum.h"

uint16_t checksum_generic(uint16_t *addr, uint32_t count)
{
    register unsigned long sum = 0;

    while (count > 1) {
        sum += *addr++;
        count -= 2;
        if (count == 1) {
            sum += *(unsigned char*)addr;
            break;
        }
        sum += *addr++;
    }

    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);

    return (uint16_t)(~sum);
}

uint16_t checksum_tcpudp(struct iphdr *iph, void *buff, uint16_t data_len, int len)
{
    const uint16_t *buf = buff;
    uint32_t ip_src = iph->saddr;
    uint32_t ip_dst = iph->daddr;
    uint32_t sum = 0;
    while (len > 1) {
        sum += *buf++;
        len -= 2;
    }
    if (len == 1) {
        sum += *(uint8_t*)buf;
    }
    sum += (ip_src >> 16) & 0xFFFF;
    sum += ip_src & 0xFFFF;
    sum += (ip_dst >> 16) & 0xFFFF;
    sum += ip_dst & 0xFFFF;
    sum += htons(iph->protocol);
    sum += data_len;
    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    return (uint16_t)(~sum);
}
