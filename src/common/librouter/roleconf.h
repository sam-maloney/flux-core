/************************************************************\
 * Copyright 2026 Lawrence Livermore National Security, LLC
 * (c.f. AUTHORS, NOTICE.LLNS, COPYING)
 *
 * This file is part of the Flux resource manager framework.
 * For details, see https://github.com/flux-framework.
 *
 * SPDX-License-Identifier: LGPL-3.0-only
\************************************************************/

#ifndef _ROUTER_ROLECONF_H
#define _ROUTER_ROLECONF_H

#include <sys/types.h>
#include <stdint.h>
#include <jansson.h>
#include <flux/core.h>

#include "src/common/libutil/errprintf.h"
#include "src/common/libutil/llog.h"

/* roleconf: assign supplemental message roles to guest connections based
 * on the connecting user's uid, as configured in the [access.roles] table.
 *
 * Only the "admin" role (FLUX_ROLE_ADMIN) is currently supported, e.g.
 *
 *   [access.roles.admin]
 *   users = ["alice", "bob"]
 *   groups = ["flux"]
 *
 * The configured user and group names are retained and resolved against the
 * connecting uid inline by roleconf_match(), via the name service.  There is
 * no caching: membership changes take effect on the next connection.
 *
 * N.B. group matching tests only the group's member list (struct group
 * gr_mem), i.e. the members listed for the group in the group database.
 * A user matches a group if listed in that group's member list, which for
 * a user's primary group is commonly the case.
 *
 * This module is deliberately kept free of message, connection, and reactor
 * details so that it may be unit tested in isolation.
 */

struct roleconf;

/* Create a roleconf from the value of the [access.roles] table, which may
 * be NULL when unconfigured (matches nothing). 'roles' is only accessed
 * during this call; the caller retains ownership. The configured names are
 * copied but not resolved until roleconf_match() is called.
 *
 * 'llog' (optional, may be NULL) and 'llog_data' receive warning messages
 * about unresolvable users/groups (emitted from roleconf_match()). Pass
 * flux_llog / a flux_t handle to route these to the broker log.
 *
 * Returns a new object on success, or NULL with errno set and 'errp'
 * filled in on error (e.g. malformed config).
 */
struct roleconf *roleconf_create (json_t *roles,
                                  llog_writer_f llog,
                                  void *llog_data,
                                  flux_error_t *errp);

void roleconf_destroy (struct roleconf *roleconf);

/* Return the supplemental rolemask (e.g. FLUX_ROLE_ADMIN) to be added to
 * the credential of a guest connecting with the given 'uid', or
 * FLUX_ROLE_NONE (0) if the uid matches no configured role.
 *
 * This resolves the configured users and groups against 'uid' via the name
 * service (getpwnam_r/getpwuid_r/getgrnam_r), costing O(configured users +
 * groups) lookups.  'roleconf' may be NULL, in which case FLUX_ROLE_NONE is
 * returned.
 */
uint32_t roleconf_match (struct roleconf *roleconf, uid_t uid);

#endif /* !_ROUTER_ROLECONF_H */

/*
 * vi:tabstop=4 shiftwidth=4 expandtab
 */
