/* vi: set sw=4 ts=4 expandtab: */
/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright (C) 2025 Christian Hohnstaedt.
 * All rights reserved.
 */

#ifndef _SIGNSERVER_PKCS11_H
#define _SIGNSERVER_PKCS11_H 1

#define CRYPTOKI_GNU
#include "pkcs11.h"

#include <openssl/err.h>

#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <sys/param.h>

#define MAX_SECTION_NAME 64
#define MAX_SLOTS 128
#define MAX_SESSIONS 8
#define MAX_ATTRIBUTES 32

extern const char *colors[];
#define COL_CYAN  colors[0]
#define COL_BLUE  colors[1]
#define COL_GREEN colors[2]
#define COL_RED   colors[3]
#define COL_MAGENTA colors[4]
#define COL_BOLD   colors[5]
#define COL_RESET  colors[6]

extern int debug_level;

static inline const char* get_debug_color(int lvl)
{
    switch (lvl) {
    case 1: return COL_RED;
    case 2: return COL_GREEN;
    case 3: return COL_CYAN;
    case 4: return COL_BLUE;
    }
    return "";
}

static inline const char* get_debug_level(int lvl)
{
    switch (lvl) {
    case 1: return "ERR " ;
    case 2: return "INFO" ;
    case 3: return "DBG " ;
    case 4: return "DBG2" ;
    }
    return "";
}

#define _DBG(lvl, ...) \
    while (debug_level >= (lvl)) { \
        fprintf(stderr, "%s%s %s%s%s%s:%d %s%s() %s", \
            get_debug_color(lvl), get_debug_level(lvl), \
            COL_MAGENTA, __FILE__, COL_GREEN, COL_BOLD, \
             __LINE__, COL_BLUE, __func__, COL_RESET); \
        fprintf(stderr, __VA_ARGS__); \
        fputs("\n", stderr); \
        break; \
    }
#define ERR(...) _DBG(1, __VA_ARGS__)
#define INFO(...) _DBG(2, __VA_ARGS__)
#define DBG(...) _DBG(3, __VA_ARGS__)
#define DBG2(...) _DBG(4, __VA_ARGS__)

#define OSSL_ERR(msg) \
    do { \
        char errbuf[256]; \
        ERR_error_string_n(ERR_get_error(), errbuf, sizeof errbuf);\
        ERR("%s: %s", msg, errbuf); \
    } while (0)

#endif
