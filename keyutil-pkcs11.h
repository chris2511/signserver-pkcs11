/* vi: set sw=4 ts=4 expandtab: */
/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright (C) 2025 Christian Hohnstaedt.
 * All rights reserved.
 */

#ifndef _KEYUTIL_PKCS11_H
#define _KEYUTIL_PKCS11_H 1

#define CRYPTOKI_GNU
#include "opensc-pkcs11.h"
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <sys/param.h>

#include <keyutils.h>

#define MAX_SLOTS 128
#define MAX_SESSIONS 8
#define MAX_KEYS 32
#define MAX_ATTRIBUTES 32

#define COL_CYAN  "\x1b[36m"
#define COL_BLUE  "\x1b[94m"
#define COL_GREEN "\x1b[92m"
#define COL_RED   "\x1b[31m"
#define COL_MAGENTA "\x1b[35m"
#define COL_BOLD  "\x1b[1m"
#define COL_RESET "\x1b[0m"

extern int dbg;
#define DBG(...) \
    while (dbg) { \
        fprintf(stderr, COL_MAGENTA "%s" COL_GREEN COL_BOLD ":%d " \
                     COL_BLUE "%s() " COL_RESET , __FILE__, __LINE__, __func__); \
        fprintf(stderr, __VA_ARGS__); \
        fputs("\n", stderr); \
        break; \
    }

static inline char *dup_keyname(const char *name)
{
    if (name)
        name = strrchr(name, ';');
    return name ? strdup(name +1) : NULL;
}
static inline void copy_spaced_name(const char *name,
            unsigned char *ck_desc, size_t ck_len)
{
    size_t slen = strlen(name);
    memset(ck_desc, ' ', ck_len);
    memcpy(ck_desc, name, MIN(slen, ck_len));
}
#endif
