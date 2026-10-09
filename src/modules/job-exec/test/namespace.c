/************************************************************\
 * Copyright 2025 Lawrence Livermore National Security, LLC
 * (c.f. AUTHORS, NOTICE.LLNS, COPYING)
 *
 * This file is part of the Flux resource manager framework.
 * For details, see https://github.com/flux-framework.
 *
 * SPDX-License-Identifier: LGPL-3.0-only
\************************************************************/

#if HAVE_CONFIG_H
#include "config.h"
#endif
#include <errno.h>
#include <string.h>

#include "src/common/libtap/tap.h"
#include "src/common/libkvs/treeobj.h"
#include "ccan/str/str.h"

#include "namespace.h"

static const char *blobref = "sha1-2747efbcf83b485c0d9c62dd3616e724241a609e";

/* namespace_rootref() recovers the blobref from a dirref treeobj - the
 * representation namespace_graft() writes at job.<id>.guest.
 */
static void test_dirref (void)
{
    json_t *o;
    char *s;
    char *rootref;

    if (!(o = treeobj_create_dirref (blobref)))
        BAIL_OUT ("treeobj_create_dirref failed");
    if (!(s = treeobj_encode (o)))
        BAIL_OUT ("treeobj_encode failed");

    rootref = namespace_rootref (s);
    ok (rootref != NULL,
        "namespace_rootref returns rootref for a dirref");
    ok (rootref != NULL && streq (rootref, blobref),
        "namespace_rootref returns the expected blobref");

    free (rootref);
    free (s);
    json_decref (o);
}

/* A symlink is what remains at job.<id>.guest after an unclean shutdown
 * (the graft did not run).  namespace_rootref() must reject it so the caller
 * creates a fresh namespace rather than reattaching to lost content.
 */
static void test_symlink (void)
{
    json_t *o;
    char *s;
    char *rootref;

    if (!(o = treeobj_create_symlink ("job-123", ".")))
        BAIL_OUT ("treeobj_create_symlink failed");
    if (!(s = treeobj_encode (o)))
        BAIL_OUT ("treeobj_encode failed");

    errno = 0;
    rootref = namespace_rootref (s);
    ok (rootref == NULL && errno == ENOENT,
        "namespace_rootref returns NULL/ENOENT for a symlink");

    free (rootref);
    free (s);
    json_decref (o);
}

/* A val treeobj (not a directory reference) is also rejected. */
static void test_val (void)
{
    json_t *o;
    char *s;
    char *rootref;

    if (!(o = treeobj_create_val ("xyz", 3)))
        BAIL_OUT ("treeobj_create_val failed");
    if (!(s = treeobj_encode (o)))
        BAIL_OUT ("treeobj_encode failed");

    errno = 0;
    rootref = namespace_rootref (s);
    ok (rootref == NULL && errno == ENOENT,
        "namespace_rootref returns NULL/ENOENT for a val");

    free (rootref);
    free (s);
    json_decref (o);
}

static void test_invalid (void)
{
    char *rootref;

    errno = 0;
    rootref = namespace_rootref (NULL);
    ok (rootref == NULL && errno == EINVAL,
        "namespace_rootref (NULL) returns NULL/EINVAL");

    rootref = namespace_rootref ("not valid json");
    ok (rootref == NULL,
        "namespace_rootref returns NULL for non-treeobj input");
}

int main (int argc, char *argv[])
{
    plan (NO_PLAN);

    test_dirref ();
    test_symlink ();
    test_val ();
    test_invalid ();

    done_testing ();
    return 0;
}

/*
 * vi: ts=4 sw=4 expandtab
 */
