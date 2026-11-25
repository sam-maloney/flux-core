/************************************************************\
 * Copyright 2018 Lawrence Livermore National Security, LLC
 * (c.f. AUTHORS, NOTICE.LLNS, COPYING)
 *
 * This file is part of the Flux resource manager framework.
 * For details, see https://github.com/flux-framework.
 *
 * SPDX-License-Identifier: LGPL-3.0-only
\************************************************************/

#ifndef _SUBPROCESS_REMOTE_H
#define _SUBPROCESS_REMOTE_H

#include "subprocess.h"

int subprocess_remote_setup (flux_subprocess_t *p, const char *service_name);

/* Set only the service name, deferring I/O channel setup.  Used by attach,
 * which sets up channels from the command received in the attach response.
 */
int subprocess_setup_service_name (flux_subprocess_t *p,
                                   const char *service_name);

int remote_exec (flux_subprocess_t *p);

int remote_attach (flux_subprocess_t *p, pid_t pid, const char *label);

flux_future_t *remote_kill (flux_subprocess_t *p, int signum);

#endif /* !_SUBPROCESS_REMOTE_H */

// vi: ts=4 sw=4 expandtab
