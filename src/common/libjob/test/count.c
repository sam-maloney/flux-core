/************************************************************\
 * Copyright 2018 Lawrence Livermore National Security, LLC
 * (c.f. AUTHORS, NOTICE.LLNS, COPYING)
 *
 * This file is part of the Flux resource manager framework.
 * For details, see https://github.com/flux-framework.
 *
 * SPDX-License-Identifier: LGPL-3.0
\************************************************************/

#if HAVE_CONFIG_H
#include "config.h"
#endif
#include <errno.h>


#include "src/common/libtap/tap.h"
#include "src/common/libjob/count.h"
#include "ccan/str/str.h"

struct inout {
    const char *in;
    int flags;
    const char *out;
};

struct inout test_codec_inputs[] = {
    { "2",              0,          "2" },
    { "7-9",            0,          "7,8,9" },
    { "1,7-9",          0,          "1,7,8,9" },
    { "1,7-9,16",       0,          "1,7,8,9,16" },
    { "1,7-9,14,16",    0,          "1,7,8,9,14,16" },
    { "1-3,7-9,14,16",  0,          "1,2,3,7,8,9,14,16" },
    { "2,3,4,5",        0,          "2,3,4,5" },
    { "1048576",        0,          "1048576"},
    { "3-5:1:+",        0,          "3-5:1:+"},
    { "2+",             0,          "2+:1:+" },
    { "3-3",            0,          "3" },

    { "[2]",            0,          "2" },
    { "[7-9]",          0,          "7,8,9" },
    { "[2,3,4,5]",      0,          "2,3,4,5" },

    { "2",              COUNT_FLAG_SHORT,  "2" },
    { "7-9",            COUNT_FLAG_SHORT,  "7-9" },
    { "1,7-9",          COUNT_FLAG_SHORT,  "1,7-9" },
    { "1,7-9,16",       COUNT_FLAG_SHORT,  "1,7-9,16" },
    { "1,7-9,14,16",    COUNT_FLAG_SHORT,  "1,7-9,14,16" },
    { "1-3,7-9,14,16",  COUNT_FLAG_SHORT,  "1-3,7-9,14,16" },
    { "2,3,4,5",        COUNT_FLAG_SHORT,  "2-5" },

    { "2",             COUNT_FLAG_SHORT|COUNT_FLAG_BRACKETS, "2" },
    { "7-9",           COUNT_FLAG_SHORT|COUNT_FLAG_BRACKETS, "[7-9]" },
    { "1,7-9",         COUNT_FLAG_SHORT|COUNT_FLAG_BRACKETS, "[1,7-9]" },
    { "1,7-9,16",      COUNT_FLAG_SHORT|COUNT_FLAG_BRACKETS, "[1,7-9,16]" },
    { "1,7-9,14,16",   COUNT_FLAG_SHORT|COUNT_FLAG_BRACKETS, "[1,7-9,14,16]" },
    { "1-3,7-9,14,16", COUNT_FLAG_SHORT|COUNT_FLAG_BRACKETS, "[1-3,7-9,14,16]"},
    { "2,3,4,5",       COUNT_FLAG_SHORT|COUNT_FLAG_BRACKETS, "[2-5]" },
    { "2-5:1:+",       COUNT_FLAG_SHORT|COUNT_FLAG_BRACKETS, "[2-5]" },
    { "2-8:2:*",       COUNT_FLAG_SHORT|COUNT_FLAG_BRACKETS, "[2-8:2:*]" },

    /* expected failures */
    { "2-8:1:+",        0xffff,     NULL },
    { "",               0,          NULL },
    { "[]",             0,          NULL },
    { "[0]",            0,          NULL },
    { "3-2:1:+",        0,          NULL },
    { "2-8:01",         0,          NULL },
    { "2-8:1;+",        0,          NULL },
    { "2-8:1:*",        0,          NULL },
    { "2-8:1:^",        0,          NULL },
    { "2-8:1:/",        0,          NULL },
    { "2-8:1:++",       0,          NULL },
    { "4.2",            0,          NULL },
    { "x",              0,          NULL },
    { "1-2x",           0,          NULL },
    { "01,2",           0,          NULL },
    { "00",             0,          NULL },
    { "3,2",            0,          NULL },
    { "3-0",            0,          NULL },
    { "2,2,2,2",        0,          NULL },
    { "[0",             0,          NULL },
    { "0]",             0,          NULL },
    { "[[0]]",          0,          NULL },
    { "[[0,2]",         0,          NULL },
    { "[0,2]]",         0,          NULL },
    { "0,[2",           0,          NULL },
    { "0]2",            0,          NULL },
    { "0-",             0,          NULL },
    { "[0-]",           0,          NULL },
    { "-5",             0,          NULL },
    { "[-5]",           0,          NULL },

    { NULL, 0, NULL },
};

void test_codec (void)
{
    struct inout *ip;

    for (ip = &test_codec_inputs[0]; ip->in != NULL; ip++) {
        struct count *count;

        errno = 0;
        count = count_decode (ip->in);
        if (ip->out == NULL) { // expected fail
            if (count != NULL) {
                char *s = count_encode (count, ip->flags);
                ok (s == NULL && errno == EINVAL,
                    "count_encode flags=0x%x '%s' fails with EINVAL",
                    ip->flags, ip->in);
                free (s);
            } else {
                ok (count == NULL && errno == EINVAL,
                    "count_decode '%s' fails with EINVAL",
                    ip->in);
            }
        }
        else {
            ok (count != NULL,
                "count_decode '%s' works", ip->in);
            if (count != NULL) {
                char *s = count_encode (count, ip->flags);
                bool match = (s && streq (s, ip->out));
                ok (match == true,
                    "count_encode flags=0x%x '%s'->'%s' works",
                    ip->flags, ip->in, ip->out);
                if (!match)
                    diag ("%s", s ? s : "NULL");
                free (s);
            }
        }
        count_destroy (count);
    }
}

struct inout test_iteration_inputs[] = {
    { "1", 0, "1" },
    { "[13]", 0, "13" },
    { "{\"min\": 4, \"max\": 6, \"operand\": 1, \"operator\": \"+\"}", 0, "4,5,6" },
    { "{\"min\": 1, \"max\": 3, \"operand\": 2, \"operator\": \"+\"}", 0, "1,3" },

    { NULL, 0, NULL },
};

void test_iteration (void)
{
    struct inout *ip;
    char s[256];

    for (ip = &test_iteration_inputs[0]; ip->in != NULL; ip++) {
        struct count *count;

        errno = 0;
        count = count_decode (ip->in);
        if (ip->out == NULL) { // expected fail
//            if (count != NULL) {
//                char *s = count_encode (count, ip->flags);
//                ok (s == NULL && errno == EINVAL,
//                    "count_encode flags=0x%x '%s' fails with EINVAL",
//                    ip->flags, ip->in);
//                free (s);
//            } else {
//                ok (count == NULL && errno == EINVAL,
//                    "count_decode '%s' fails with EINVAL",
//                    ip->flags, ip->in);
//            }
        }
        else {
            ok (count != NULL,
                "count_decode JSON '%s' works", ip->in);
            if (count != NULL) {
                int i = 0;
                int value = count_first (count);
                while (value != COUNT_INVALID_VALUE) {
                    i += sprintf (s+i, "%u, ", value);
                    value = count_next (count, value);
                }
                s[i-2] = '\0';
                bool match = streq (s, ip->out);
                ok (match == true,
                    "count iteration '%s'->'%s' works",
                    ip->in, ip->out);
                if (!match)
                    diag ("%s", s);
            }
        }
        count_destroy (count);
    }
}

int main (int argc, char *argv[])
{
    plan (NO_PLAN);

    test_codec ();
    test_iteration ();

    done_testing ();
}

/*
 * vi:tabstop=4 shiftwidth=4 expandtab
 */
