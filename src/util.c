/*
 * Copyright (c) 2015 Mike Maraya <mike[dot]maraya[at]gmail[dot]com>
 * All rights reserved.
 *
 * This file is subject to the terms and conditions defined in
 * https://github.com/mmaraya/port-mirroring/blob/master/LICENSE,
 * which is part of this software package.
 *
 */

#include "util.h"

char * printMACStr(const char* mac)
{
    static char macStr[20]={0};
    sprintf(macStr, "%02x%02x%02x%02x%02x%02x",
            (unsigned char)mac[0], (unsigned char)mac[1], (unsigned char)mac[2],
            (unsigned char)mac[3], (unsigned char)mac[4], (unsigned char)mac[5]);
    return macStr;
}

char * getUCIItem(char *buf, char *item)
{
    char* p1 = buf;
    char* p2;
    while (*p1 == '\t' || *p1 == ' ') {
        p1++;
    }
    if (*p1 == '\'' || *p1 == '"')
    {
        char delim = *p1++;
        p2    = strchr(p1, delim);
    }
    else
    {
        p2 = strchr(p1, ' ');
        if (p2 == NULL)
        {
            p2 = strchr(p1, '\t');
        }
    }
    if (p2 != NULL)
    {
        *p2 = '\0';
        strncpy(item, p1, OPTION_MAX);
        return p2 + 1;
    }
    else
    {
        return NULL;
    }
}

int getUCIConf(char *buf, char *option, char *value)
{
    char* p = strstr(buf, "option");

    if (p != NULL)
    {
        p += 6;
        if ((p = getUCIItem(p, option)) != NULL)
        {
            if (getUCIItem(p, value) != NULL)
            {
                return 0;
            }
        }
    }
    return -1;
}

