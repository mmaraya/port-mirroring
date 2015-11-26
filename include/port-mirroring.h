/*
 * Copyright (c) 2012 Bruce Geng <gengw2000[at]163[dot]com>.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 * notice, this list of conditions and the following disclaimer in the
 * documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

#ifndef PORT_MIRRORING_H_
#define PORT_MIRRORING_H_

#include <stdbool.h>
#include <stdint.h>
#include "util.h"

#define ETH_ALEN        6       /* Octets in one ethernet addr      */
#define ETH_P_ARP       0x0806  /* Address Resolution packet        */
#define ETH_P_802_3     0x0001  /* Dummy type for 802.3 frames      */
#define ETH_P_IP        0x0800  /* Internet Protocol packet         */
#define ARPOP_REQUEST   1       /* ARP request                      */
#define ARPOP_REPLY     2       /* ARP reply                        */
#define ARP_WAIT_TIME   500     /* Arp Response waiting time (ms)   */
#define ARP_ETH_PADDING 18      /* 18 bytes ethernet padding        */
#define MAX_SOURCE_IF   4       /* maxium four source interfaces    */
#define LINEBUF_MAX     1024
#define OPTION_MAX      255
#define TZSP_PORT       37008
#define ERRTIMEOUT      20
#define MACADDRLEN      6
#define BUFSIZE         8192
#define TIMEBUF         32      /* max timestamp length in RFC 3339 */

typedef enum
{
    MYLOG_INFO = 0, //info
    MYLOG_ERROR     //error
} MYLOG_LEVEL;

void writeLog(MYLOG_LEVEL ll, const char* message, ...);

void addMonitoringSource(const char* s);

char * getUCIItem(char* buf, char* item);

int getUCIConf(char* buf, char* option, char* value);

int loadCfg(const char* fpath);

void init();

int reopenSendHandle(const char* device);

char * printMACStr(const char* mac);

bool nlmsg_ok(const struct nlmsghdr *nlh, ssize_t len);

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

int main(int argc, char** argv);

#endif 	// PORT_MIRRORING_H_
