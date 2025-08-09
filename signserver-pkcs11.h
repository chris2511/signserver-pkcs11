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
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <sys/param.h>

#include "openssl/err.h"

#define MAX_SECTION_NAME 64
#define MAX_SLOTS 128
#define MAX_SESSIONS 8
#define MAX_ATTRIBUTES 32

#define COL_CYAN  "\x1b[36m"
#define COL_BLUE  "\x1b[94m"
#define COL_GREEN "\x1b[92m"
#define COL_RED   "\x1b[31m"
#define COL_MAGENTA "\x1b[35m"
#define COL_BOLD  "\x1b[1m"
#define COL_RESET "\x1b[0m"

extern int debug_level;

static inline char* get_debug_level(int lvl)
{
    switch (lvl) {
    case 1: return COL_RED "ERR " ;
    case 2: return COL_GREEN "INFO" ;
    case 3: return COL_CYAN "DBG " ;
    case 4: return COL_BLUE "DBG2" ;
    }
    return "";
}

#define _DBG(lvl, fmt, ...) \
    while (debug_level >= (lvl)) { \
        fprintf(stderr, "%s " COL_MAGENTA "%s" COL_GREEN COL_BOLD ":%d " \
            COL_BLUE "%s() " COL_RESET ,\
            get_debug_level(lvl), __FILE__, __LINE__, __func__); \
        fprintf(stderr, fmt, ##__VA_ARGS__); \
        fputs("\n", stderr); \
        break; \
    }
#define ERR(fmt, ...) _DBG(1, fmt, ##__VA_ARGS__)
#define INFO(fmt, ...) _DBG(2, fmt, ##__VA_ARGS__)
#define DBG(fmt, ...) _DBG(3, fmt, ##__VA_ARGS__)
#define DBG2(fmt, ...) _DBG(4, fmt, ##__VA_ARGS__)

#define OSSL_ERR(msg) \
    do { \
        char errbuf[256]; \
        ERR_error_string_n(ERR_get_error(), errbuf, sizeof errbuf);\
        ERR("%s: %s", msg, errbuf); \
    } while (0)

#endif
