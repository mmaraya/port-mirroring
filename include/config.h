/* * Copyright (c) 2015 Mike Maraya <mike[dot]maraya[at]gmail[dot]com>
 * All rights reserved.
 *
 * This file is subject to the terms and conditions defined in
 * https://github.com/mmaraya/port-mirroring/blob/master/LICENSE,
 * which is part of this software package.
 *
 */

#ifndef PORT_MIRRORING_UTIL_H_
#define PORT_MIRRORING_UTIL_H_

#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "net.h"

#define OPTION_MAX  255
#define TIMEBUF     32  /* max timestamp length RFC3339 */
#define SRC_IF_MAX  4   /* maxium number of interfaces  */

// if no configuration file is specified, look through these in order
#define CFG_PATH_1  "/etc/config/port-mirroring"
#define CFG_PATH_2  "/etc/port-mirroring"
#define CFG_PATH_3  "port-mirroring.conf"

struct pm_cfg
{
    char        *cfg_file;          /* path to configuration file       */
    uint8_t     flags;              /* boolean setting bitmask          */
    char        *src[SRC_IF_MAX];   /* source network interfaces        */
    char        *dst_if;            /* destination network interface    */
    in_addr_t   dst_ip;             /* destination IP address           */
    char        *pf;                /* tcpdump packet filter expression */
    char        *pid_file;          /* path to process id file          */
};

void find_cfg(struct pm_cfg *cfg);
char * printMACStr(const char *mac);
char * getUCIItem(char *buf, char *item);
int getUCIConf(char *buf, char *option, char *value);

#endif  // PORT_MIRRORING_UTIL_H_
