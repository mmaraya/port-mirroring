/*
 * Copyright (c) 2015 Mike Maraya <mike[dot]maraya[at]gmail[dot]com>
 * All rights reserved.
 *
 * This file is subject to the terms and conditions defined in
 * https://github.com/mmaraya/port-mirroring/blob/master/LICENSE,
 * which is part of this software package.
 *
 */

#include <time.h>

void now(char* buf, const size_t size)
{
    time_t t   = time(NULL);
    size_t len = strftime(buf, size, "%Y-%m-%dT%H:%M:%S%z", localtime(&t));
    if (len == 0)
    {
        buf[size - 1] = '\0';
    }
}

