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

#include <keyutils.h>

#define MAX_SLOTS 128
#define MAX_SESSIONS 8
#define MAX_KEYS 32
#define MAX_ATTRIBUTES 32

extern int dbg;
#define DBG(...) \
    while (dbg) { \
        fprintf(stderr, "%s(%d): ", __func__, __LINE__); \
        fprintf(stderr, __VA_ARGS__); \
        fputs("\n", stderr); \
        break; \
    }

#endif
