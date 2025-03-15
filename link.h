/* vi: set sw=4 ts=4 expandtab: */
/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright (C) 2025 Christian Hohnstaedt.
 * All rights reserved.
 */

#ifndef _LINK_H
#define _LINK_H 1

#include "keyutil-pkcs11.h"

/* Objects with the same public key (privs, pubs, x509)
 * link here */
struct link {
    struct link *next;
    unsigned long pkcs11_id;
    char *name;
    //EVP_PKEY *pkey;
};

struct link *link_new(const char *name);
void link_free(struct link *link);

#endif
