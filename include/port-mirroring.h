/*
 * Copyright (c) 2015 Mike Maraya <mike[dot]maraya[at]gmail[dot]com>
 * All rights reserved.
 *
 * This file is subject to the terms and conditions defined in
 * https://github.com/mmaraya/port-mirroring/blob/master/LICENSE,
 * which is part of this software package.
 *
 */

#ifndef PORT_MIRRORING_H_
#define PORT_MIRRORING_H_

#include <stdint.h>
#include <syslog.h>
#include "util.h"

#define LOG_IDENT       "port-mirroring"    /* program name for syslog      */
#define ETH_ALEN        6                   /* Octets in one ethernet addr  */
#define ETH_P_ARP       0x0806              /* Address Resolution packet    */
#define ETH_P_802_3     0x0001              /* Dummy type for 802.3 frames  */
#define ETH_P_IP        0x0800              /* Internet Protocol packet     */
#define ARPOP_REQUEST   1                   /* ARP request                  */
#define ARPOP_REPLY     2                   /* ARP reply                    */
#define ARP_WAIT_TIME   500                 /* ARP response wait time (ms)  */
#define ARP_ETH_PADDING 18                  /* ARP ethernet padding         */
#define MAX_SOURCE_IF   4                   /* maxium number of interfaces  */
#define LINEBUF_MAX     1024
#define TZSP_PORT       37008
#define ERRTIMEOUT      20
#define MACADDRLEN      6
#define BUFSIZE         8192
#define SNAP_LEN        65535               /* pcap snapshot length */

int loadCfg(const char* fpath);

void init();

int reopenSendHandle(const char* device);

int nlmsg_ok(const struct nlmsghdr *nlh, ssize_t len);

int readNlSock(int sockFd, char* bufPtr, uint32_t seqNum, uint32_t pId);

int getInterfaceMac(const char* device, char* mac);

int getInterfaceIP(const char* device, unsigned int* ip);

int getSenderInterface(unsigned int targetIP, char* device, char* mac);

int getRemoteARP(unsigned int targetIP, const char* device, char* mac);

int initSendHandle();

void packet_handler_ex(const struct pcap_pkthdr* header, const u_char* pkt_data);

void * start_mirroring(void* dev);

void write_pid();

int fork_daemon();

void sig_handler(int signum);

#endif 	// PORT_MIRRORING_H_
