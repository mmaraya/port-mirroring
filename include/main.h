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

#include <syslog.h>
#include "config.h"
#include "net.h"

#define LOG_IDENT   "port-mirroring"    /* program name for syslog      */
#define ETH_ALEN    6                   /* Octets in one ethernet addr  */
#define ETH_P_802_3 0x0001              /* Dummy type for 802.3 frames  */
#define ETH_P_IP    0x0800              /* Internet Protocol packet     */
#define SRC_IF_MAX  4                   /* maxium number of interfaces  */
#define LINEBUF_MAX 1024                /* max length of a line buffer  */
#define TZSP_PORT   37008               /* UDP port used by TZSP        */
#define ERRTIMEOUT  20                  /* seconds before timing out    */
#define SNAP_LEN    65535               /* pcap snapshot length         */

#define PM_DAEMON   (2^0)   /* run as background process                    */
#define PM_DEBUG    (2^1)   /* display debugging messages to console        */
#define PM_TEE      (2^2)   /* send packets using TEE iptables format       */
#define PM_TZSP     (2^3)   /* send packets using TaZmen Sniffer Protocol   */
#define PM_IFACE    (2^4)   /* destination is a network interface           */
#define PM_IPADDR   (2^5)   /* destination is an internet protocol address  */
#define PM_PROMISC  (2^6)   /* place source interface in promiscuous mode   */
#define PM_SYSLOG   (2^7)   /* log messages to syslog facility              */

int loadCfg(const char *fpath);
void init();
int reopenSendHandle(const char *device);
int initSendHandle();
void packet_handler_ex(const struct pcap_pkthdr *header, const u_char *pkt_data);
void * start_mirroring(void *dev);
void write_pid();
int fork_daemon();
void sig_handler(int signum);

#endif 	// PORT_MIRRORING_H_
