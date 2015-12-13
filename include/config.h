/*
 * Copyright (c) 2015 Mike Maraya <mike[dot]maraya[at]gmail[dot]com>
 * All rights reserved.
 *
 * This file is subject to the terms and conditions defined in
 * https://github.com/mmaraya/port-mirroring/blob/master/LICENSE,
 * which is part of this software package.
 *
 */

#ifndef PORT_MIRRORING_UTIL_H_
#define PORT_MIRRORING_UTIL_H_

#include <stdio.h>
#include <string.h>

#define OPTION_MAX  255
#define TIMEBUF     32  /* max timestamp length RFC3339 */

char * printMACStr(const char *mac);
char * getUCIItem(char *buf, char *item);
int getUCIConf(char *buf, char *option, char *value);

#endif  // PORT_MIRRORING_UTIL_H_
