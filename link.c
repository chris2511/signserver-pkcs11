/* vi: set sw=4 ts=4 expandtab: */
/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright (C) 2025 Christian Hohnstaedt.
 * All rights reserved.
 */

#include "link.h"
#include <stdlib.h>
#include <string.h>

static unsigned long pkcs11_id = 1000;

struct link *link_new(const char *name)
{
    struct link *link = calloc(1, sizeof *link);
    if (link) {
        link->pkcs11_id = pkcs11_id++;
        link->name = strdup(name);
        DBG("New Link P11_ID:%lu Name:%s", link->pkcs11_id, link->name);
        if (!link->name) {
            free(link);
            link = NULL;}
    }
    return link;
}

void link_free(struct link *link)
{
    DBG("Free Link P11_ID:%lu Name:%s", link->pkcs11_id, link->name);
    free(link->name);
    free(link);
}
