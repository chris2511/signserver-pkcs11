/* vi: set sw=4 ts=4 expandtab: */
/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright (C) 2025 Christian Hohnstaedt.
 * All rights reserved.
 */

#ifndef _X509_H
#define _X509_H 1

#include "keyutil-pkcs11.h"
#include <stddef.h>

#include <openssl/x509.h>

struct object;

struct x509 {
    X509 *certificate;
    unsigned char *certificate_der;
    unsigned long certificate_len;
};

struct object *x509_init(struct object *obj);
void x509_free(struct object *obj);

#endif
