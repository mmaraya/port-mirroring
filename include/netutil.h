/*
 * Copyright (c) 2015 Mike Maraya <mike[dot]maraya[at]gmail[dot]com>
 * All rights reserved.
 *
 * This file is subject to the terms and conditions defined in
 * https://github.com/mmaraya/port-mirroring/blob/master/LICENSE,
 * which is part of this software package.
 *
 */

#ifndef PORT_MIRRORING_NETWORK_UTIL_H_
#define PORT_MIRRORING_NETWORK_UTIL_H_

#include <arpa/inet.h>
#include <errno.h>
#include <linux/rtnetlink.h>
#include <linux/netlink.h>
#include <net/if.h>
#include <netinet/in.h>
#include <stdio.h>
#include <string.h>
#include <syslog.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>

#define BUFSIZE         8192
#define MACADDRLEN      6
#define ETH_P_ARP       0x0806              /* Address Resolution packet    */
#define ARPOP_REQUEST   1                   /* ARP request                  */
#define ARPOP_REPLY     2                   /* ARP reply                    */
#define ARP_WAIT_TIME   500                 /* ARP response wait time (ms)  */
#define ARP_ETH_PADDING 18                  /* ARP ethernet padding         */

int getInterfaceMac(const char *device, char *mac);
int getInterfaceIP(const char *device, unsigned int *ip);
int nlmsg_ok(const struct nlmsghdr *nlh, ssize_t len);
int getSenderInterface(unsigned int targetIP, char *device, char *mac);
int getRemoteARP(unsigned int targetIP, const char *device, char *mac);
int readNlSock(int sockFd, char *bufPtr, uint32_t seqNum, uint32_t pId);

#endif  // PORT_MIRRORING_NETWORK_UTIL_H_
