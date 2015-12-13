/*
 * Copyright (c) 2015 Mike Maraya <mike[dot]maraya[at]gmail[dot]com>
 * All rights reserved.
 *
 * This file is subject to the terms and conditions defined in
 * https://github.com/mmaraya/port-mirroring/blob/master/LICENSE,
 * which is part of this software package.
 *
 */

#include "net.h"

char * printMACStr(const char* mac)
{
    static char macStr[20]={0};
    sprintf(macStr, "%02x%02x%02x%02x%02x%02x",
            (unsigned char)mac[0], (unsigned char)mac[1], (unsigned char)mac[2],
            (unsigned char)mac[3], (unsigned char)mac[4], (unsigned char)mac[5]);
    return macStr;
}

int getInterfaceMac(const char *device, char *mac)
{
    int          s;
    struct ifreq buffer;

    if ((s = socket(PF_INET, SOCK_DGRAM, 0)) < 0)
    {
        syslog(LOG_ERR, "unable to create socket: '%s'", strerror(errno));
        return -1;
    }
    memset(&buffer, 0x00, sizeof(buffer));
    strncpy(buffer.ifr_name, device, sizeof(buffer.ifr_name) - 1);
    buffer.ifr_name[sizeof(buffer.ifr_name) - 1] = '\0';

    if (ioctl(s, SIOCGIFHWADDR, &buffer) < 0)
    {
        syslog(LOG_ERR, "unable to query %s MAC address: '%s'",
                device,
                strerror(errno));
        close(s);
        return -1;
    }

    close(s);
    memcpy(mac, buffer.ifr_hwaddr.sa_data, MACADDRLEN);
    return 0;
}

int getInterfaceIP(const char *device, unsigned int *ip)
{
    int          s;
    struct ifreq buffer;

    if ((s = socket(PF_INET, SOCK_DGRAM, 0)) < 0)
    {
        syslog(LOG_ERR, "unable to create socket: '%s'", strerror(errno));
        return -1;
    }
    memset(&buffer, 0x00, sizeof(buffer));
    buffer.ifr_addr.sa_family = AF_INET;
    strncpy(buffer.ifr_name, device, sizeof(buffer.ifr_name) - 1);
    buffer.ifr_name[sizeof(buffer.ifr_name) - 1] = '\0';

    if (ioctl(s, SIOCGIFADDR, &buffer) < 0)
    {
        syslog(LOG_ERR, "unable to query %s MAC address: '%s'", device, strerror(errno));
        close(s);
        return -1;
    }

    close(s);
    *ip = ((struct sockaddr_in *)&buffer.ifr_addr)->sin_addr.s_addr;
    return 0;
}

int nlmsg_ok(const struct nlmsghdr *nlh, ssize_t len)
{
    if (len < (int) sizeof (struct nlmsghdr)) return 0;
    if (nlh->nlmsg_len < sizeof(struct nlmsghdr)) return 0;
    if ((ssize_t) nlh->nlmsg_len > len) return 0;
    if (nlh->nlmsg_type == NLMSG_ERROR) return 0;
    return 1;
}

int getSenderInterface(unsigned int targetIP, char* device, char* mac)
{
    struct nlmsghdr* nlMsg;

    char               msgBuf[BUFSIZE];

    int sock;
    ssize_t len = 0;
    uint32_t msgSeq = 0;

    if ((sock = socket(PF_NETLINK, SOCK_DGRAM, NETLINK_ROUTE)) < 0)
    {
        syslog(LOG_ERR, "unable to create socket: '%s'", strerror(errno));
        return -1;
    }

    memset(msgBuf, 0, BUFSIZE);

    nlMsg = (struct nlmsghdr *)msgBuf;
    nlMsg->nlmsg_len   = NLMSG_LENGTH(sizeof(struct rtmsg));
    nlMsg->nlmsg_type  = RTM_GETROUTE;
    nlMsg->nlmsg_flags = NLM_F_DUMP | NLM_F_REQUEST;
    nlMsg->nlmsg_seq   = msgSeq++;
    nlMsg->nlmsg_pid   = getpid();

    if (send(sock, nlMsg, nlMsg->nlmsg_len, 0) < 0)
    {
        syslog(LOG_ERR, "unable to write to socket: '%s'", strerror(errno));
        close(sock);
        return -1;
    }

    if ((len = readNlSock(sock, msgBuf, msgSeq, getpid())) < 0)
    {
        syslog(LOG_ERR, "unable to read from socket: '%s'", strerror(errno));
        close(sock);
        return -1;
    }

    for (; nlmsg_ok(nlMsg, len); nlMsg = NLMSG_NEXT(nlMsg, len)) {
        struct rtmsg*  rtMsg = (struct rtmsg *)NLMSG_DATA(nlMsg);

        if (rtMsg->rtm_family == AF_INET || rtMsg->rtm_table == RT_TABLE_MAIN)
        {
            struct rtattr* rtAttr = (struct rtattr *)RTM_RTA(rtMsg);
            int            rtLen  = RTM_PAYLOAD(nlMsg);
            char           ifName[IF_NAMESIZE] = {0};
            unsigned int   dstAddr = 0, dstMask = 1;
            for (; RTA_OK(rtAttr, rtLen); rtAttr = RTA_NEXT(rtAttr, rtLen)) {
                switch (rtAttr->rta_type)
                {
                    case RTA_OIF:
                        if_indextoname(*(int *)RTA_DATA(rtAttr), ifName);
                        break;
                    case RTA_DST:
                        dstAddr = *(u_int *)RTA_DATA(rtAttr);
                        dstMask = rtLen;
                        break;
                }
            }
            if (dstMask <= 32)
            {
                dstMask = htonl(ntohl(inet_addr("255.255.255.255")) << (32 - dstMask));
                if ((dstAddr & dstMask) == (targetIP & dstMask))
                {
                    if (getInterfaceMac(ifName, mac) == 0)
                    {
                        close(sock);
                        strcpy(device, ifName);
                        syslog(LOG_INFO, "sending from device '%s' with MAC address '%s'",
                                device,
                                printMACStr(mac));
                        return 0;
                    }
                }
            }
        }
    }
    close(sock);
    return 1;
}

int readNlSock(int sockFd, char *bufPtr, uint32_t seqNum, uint32_t pId)
{
    struct nlmsghdr* nlHdr;
    int              msgLen = 0;

    do {
    ssize_t readLen = 0;

        /* Recieve response from the kernel */
        if ((readLen = recv(sockFd, bufPtr, BUFSIZE - msgLen, 0)) < 0)
        {
            syslog(LOG_ERR, "unable to read from socket: %s", strerror(errno));
            return -1;
        }

        nlHdr = (struct nlmsghdr *)bufPtr;

        /* Check if the header is valid */
        if (!nlmsg_ok(nlHdr, readLen)) {
            syslog(LOG_ERR, "error in recieved packet");
            return -1;
        }
        /* Check if the its the last message */
        if (nlHdr->nlmsg_type == NLMSG_DONE)
        {
            break;
        }
        else
        {
            /* Else move the pointer to buffer appropriately */
            bufPtr += readLen;
            msgLen += readLen;
        }
        /* Check if its a multi part message */
        if ((nlHdr->nlmsg_flags & NLM_F_MULTI) == 0)
        {
            /* return if its not */
            break;
        }
    } while ((nlHdr->nlmsg_seq != seqNum) || (nlHdr->nlmsg_pid != pId));

    return msgLen;
}

