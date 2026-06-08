#include<stdio.h>
#include<ctype.h>
#include<unistd.h>
#include<stdlib.h>
#include<string.h>
#include<limits.h>
#include<time.h>
#include<sys/ioctl.h>
#include<netpacket/packet.h>
#include<netinet/ip.h>
#include<netinet/ip_icmp.h>
#include<netinet/if_ether.h>
#include<linux/if.h>
#include<arpa/inet.h>

#include"sock.h"
#include"param.h"

// Fold a 32-bit accumulator into the final 16-bit Internet checksum.
static u_int16_t checksum_fold(u_int32_t sum)
{
    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    return ~sum;
}

// Add a sequence of 16-bit words into the checksum accumulator.
// The length parameter is the number of bytes in the data buffer.
static u_int32_t checksum_add16(u_int32_t sum, u_int16_t *data, int len)
{
    for (int i = 0; i < len; i += 2) {
        sum += *data++;
        if (sum > 0xFFFF) {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }
    }
    return sum;
}

// 単一データブロックのチェックサムを計算
u_int16_t checksum(u_int8_t *data, int len)
{
    // Add 16-bit words; a trailing odd byte is handled separately.
    u_int32_t sum = checksum_add16(0, (u_int16_t *)data, len);
    
    if (len & 1) {
        u_int16_t val = 0;
        memcpy(&val, data + len - 1, sizeof(u_int8_t));
        sum += val;
    }
    
    return checksum_fold(sum);
}

// Compute the checksum for two adjacent memory blocks.
// This is useful when the logical payload spans two buffers.
u_int16_t checksum2(u_int16_t *data1, int len1, u_int8_t *data2, int len2)
{
    u_int32_t sum = checksum_add16(0, data1, len1);
    
    if (len1 & 1) {
        // If data1 ends on an odd boundary, combine its last byte with data2[0].
        u_int16_t val = ((u_int8_t *)data1)[len1 - 1] << 8;
        if (len2 > 0) {
            val |= data2[0];
            sum += val;
            if (sum > 0xFFFF) {
                sum = (sum & 0xFFFF) + (sum >> 16);
            }
            sum = checksum_add16(sum, (u_int16_t *)(data2 + 1), len2 - 1);
        } else {
            // No second buffer; pad the odd byte with zero.
            sum += val;
        }
    } else {
        sum = checksum_add16(sum, (u_int16_t *)data2, len2);
    }
    
    if (len2 & 1) {
        u_int16_t val = 0;
        memcpy(&val, data2 + len2 - 1, sizeof(u_int8_t));
        sum += val;
    }
    
    return checksum_fold(sum);
}

// Get the MAC address for a network interface and store it in hwaddr.
int GetMacAddress(char *device, u_int8_t *hwaddr)
{
    struct ifreq ifreq;
    int soc;
    u_int8_t *ptr;

    if ((soc = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        perror("GetMacAddress(): socket");
        return(-1);
    }

    // Copy interface name safely and ensure null-termination.
    strncpy(ifreq.ifr_name, device, sizeof(ifreq.ifr_name) - 1);
    ifreq.ifr_name[sizeof(ifreq.ifr_name) - 1] = '\0';

    if (ioctl(soc, SIOCGIFHWADDR, &ifreq) < 0) {
        perror("GetMacAddress(): ioctl");
        close(soc);
        return(-1);
    }

    ptr = (u_int8_t *)ifreq.ifr_hwaddr.sa_data;
    memcpy(hwaddr, ptr, 6);
    close(soc);
    return 0;
}

// Sleep for the specified number of milliseconds.
int DummyWait(int ms)
{
    struct timespec ts;

    ts.tv_sec = 0;
    ts.tv_nsec = ms * 1000000L;

    nanosleep(&ts, NULL);

    return(0);
}

// Open a raw packet socket bound to the given interface and enable promiscuous mode.
int init_socket(char *device)
{
    struct ifreq if_req;
    struct sockaddr_ll sa;
    int soc;

    if ((soc = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0) {
        perror("socket");
        return(-1);
    }

    // Copy the interface name safely to prevent overflow.
    strncpy(if_req.ifr_name, device, sizeof(if_req.ifr_name) - 1);
    if_req.ifr_name[sizeof(if_req.ifr_name) - 1] = '\0';
    if (ioctl(soc, SIOCGIFINDEX, &if_req) < 0) {
        perror("ioctl");
        close(soc);
        return(-1);
    }

    sa.sll_family = PF_PACKET;
    sa.sll_protocol = htons(ETH_P_ALL);
    sa.sll_ifindex = if_req.ifr_ifindex;
    if (bind(soc, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
        perror("bind");
        close(soc);
        return(-1);
    }

    if (ioctl(soc, SIOCGIFFLAGS, &if_req) < 0) {
        perror("ioctl");
        close(soc);
        return(-1);
    }

    if_req.ifr_flags = if_req.ifr_flags | IFF_PROMISC | IFF_UP;
    if (ioctl(soc, SIOCSIFFLAGS, &if_req) < 0) {
        perror("ioctl");
        close(soc);
        return(-1);
    }

    return(soc);
}