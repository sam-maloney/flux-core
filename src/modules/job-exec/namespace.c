/************************************************************\
 * Copyright 2026 Lawrence Livermore National Security, LLC
 * (c.f. AUTHORS, NOTICE.LLNS, COPYING)
 *
 * This file is part of the Flux resource manager framework.
 * For details, see https://github.com/flux-framework.
 *
 * SPDX-License-Identifier: LGPL-3.0-only
\************************************************************/

/* namespace.c - KVS guest namespace operations for job-exec */

#if HAVE_CONFIG_H
#include "config.h"
#endif
#include <errno.h>
#include <string.h>
#include <flux/core.h>

#include "src/common/libkvs/treeobj.h"

#include "namespace.h"

flux_future_t *namespace_create (flux_t *h,
                                 const char *ns,
                                 uint32_t userid,
                                 const char *rootref)
{
    if (!h || !ns) {
        errno = EINVAL;
        return NULL;
    }
    if (rootref)
        return flux_kvs_namespace_create_with (h, ns, rootref, userid, 0);
    return flux_kvs_namespace_create (h, ns, userid, 0);
}

flux_future_t *namespace_symlink (flux_t *h, flux_jobid_t id, const char *ns)
{
    int saved_errno;
    flux_kvs_txn_t *txn = NULL;
    flux_future_t *f = NULL;
    char key[64];

    if (!h || !ns) {
        errno = EINVAL;
        return NULL;
    }
    if (flux_job_kvs_key (key, sizeof (key), id, "guest") < 0)
        return NULL;
    if (!(txn = flux_kvs_txn_create ()))
        return NULL;
    if (flux_kvs_txn_symlink (txn, 0, key, ns, ".") < 0)
        goto out;
    f = flux_kvs_commit (h, NULL, 0, txn);
out:
    saved_errno = errno;
    flux_kvs_txn_destroy (txn);
    errno = saved_errno;
    return f;
}

flux_future_t *namespace_graft (flux_t *h, flux_jobid_t id, const char *ns)
{
    char key[64];

    if (!h || !ns) {
        errno = EINVAL;
        return NULL;
    }
    if (flux_job_kvs_key (key, sizeof (key), id, "guest") < 0)
        return NULL;
    return flux_kvs_copy (h, ns, ".", NULL, key, 0);
}

flux_future_t *namespace_remove (flux_t *h, const char *ns)
{
    if (!h || !ns) {
        errno = EINVAL;
        return NULL;
    }
    return flux_kvs_namespace_remove (h, ns);
}

flux_future_t *namespace_lookup (flux_t *h, flux_jobid_t id)
{
    char key[64];

    if (!h) {
        errno = EINVAL;
        return NULL;
    }
    if (flux_job_kvs_key (key, sizeof (key), id, "guest") < 0)
        return NULL;
    return flux_kvs_lookup (h, NULL, FLUX_KVS_TREEOBJ, key);
}

char *namespace_rootref (const char *treeobj_str)
{
    json_t *treeobj = NULL;
    const char *blobref;
    char *rootref = NULL;

    if (!treeobj_str) {
        errno = EINVAL;
        return NULL;
    }
    if (!(treeobj = treeobj_decode (treeobj_str)))
        return NULL;
    if (treeobj_is_dirref (treeobj)
        && (blobref = treeobj_get_blobref (treeobj, 0))) {
        if (!(rootref = strdup (blobref)))
            goto done;
    }
    else
        errno = ENOENT;
done:
    json_decref (treeobj);
    return rootref;
}

/*
 * vi: tabstop=4 shiftwidth=4 expandtab
 */
