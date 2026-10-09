/************************************************************\
 * Copyright 2026 Lawrence Livermore National Security, LLC
 * (c.f. AUTHORS, NOTICE.LLNS, COPYING)
 *
 * This file is part of the Flux resource manager framework.
 * For details, see https://github.com/flux-framework.
 *
 * SPDX-License-Identifier: LGPL-3.0-only
\************************************************************/

#ifndef HAVE_JOB_EXEC_NAMESPACE_H
#define HAVE_JOB_EXEC_NAMESPACE_H 1

#include <flux/core.h>

/* Create the guest namespace 'ns' owned by 'userid'.  If 'rootref' is
 * non-NULL, create it with that root reference (used to restore a namespace
 * on reattach); otherwise create an empty namespace.
 */
flux_future_t *namespace_create (flux_t *h,
                                 const char *ns,
                                 uint32_t userid,
                                 const char *rootref);

/* Link job.<id>.guest in the primary namespace as a symlink to 'ns'. */
flux_future_t *namespace_symlink (flux_t *h, flux_jobid_t id, const char *ns);

/* Graft the guest namespace 'ns' into the primary namespace by copying its
 * root to job.<id>.guest, which creates a dirref snapshot reachable from the
 * primary root (replacing the running-job symlink).  The content persists
 * after the namespace is removed because the backing store is shared.
 */
flux_future_t *namespace_graft (flux_t *h, flux_jobid_t id, const char *ns);

/* Remove the guest namespace 'ns'. */
flux_future_t *namespace_remove (flux_t *h, const char *ns);

/* Look up the job.<id>.guest treeobj in the primary namespace (RFC 11
 * treeobj form).  Combine with namespace_rootref() to recover a grafted
 * namespace's root reference on reattach.
 */
flux_future_t *namespace_lookup (flux_t *h, flux_jobid_t id);

/* Given the treeobj string returned by namespace_lookup(), return a newly
 * allocated root reference (caller frees) if it is a dirref (the grafted
 * form written by namespace_graft()), or NULL with errno set if it is
 * anything else, e.g. a symlink left by an unclean shutdown (ENOENT) or
 * invalid input (EINVAL).
 */
char *namespace_rootref (const char *treeobj_str);

#endif /* !HAVE_JOB_EXEC_NAMESPACE_H */

/* vi: ts=4 sw=4 expandtab
 */
