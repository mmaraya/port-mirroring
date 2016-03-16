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
#define SRC_IF_MAX  4                   /* maxium number of interfaces  */
#define LINEBUF_MAX 1024                /* max length of a line buffer  */
#define TZSP_PORT   37008               /* UDP port used by TZSP        */
#define ERRTIMEOUT  20                  /* seconds before timing out    */

int loadCfg(const char *fpath);
int init();
int reopenSendHandle(const char *device, pcap_t *handle);
int initSendHandle();
void packet_handler_ex(const struct pcap_pkthdr *header, const u_char *pkt_data,
                         pcap_t *handle, int *sock);
void * start_mirroring(void *dev, int *sock);
void write_pid();
int fork_daemon();
void sig_handler(int signum);

#endif 	// PORT_MIRRORING_H_
