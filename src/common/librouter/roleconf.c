/************************************************************\
 * Copyright 2026 Lawrence Livermore National Security, LLC
 * (c.f. AUTHORS, NOTICE.LLNS, COPYING)
 *
 * This file is part of the Flux resource manager framework.
 * For details, see https://github.com/flux-framework.
 *
 * SPDX-License-Identifier: LGPL-3.0-only
\************************************************************/

/* roleconf.c - assign supplemental message roles from [access.roles] config
 *
 * See roleconf.h for the configuration format and rationale.
 *
 * roleconf_create() parses [access.roles] and retains the configured user
 * and group names.  roleconf_match() resolves them against the connecting
 * uid inline, via the name service:
 * - 'users': resolve each configured name with getpwnam_r(3) and compare.
 * - 'groups': resolve the connecting uid's name with getpwuid_r(3), then
 *   check each configured group's member list (gr_mem) with getgrnam_r(3).
 *
 * Cost is O(number of configured users + groups) name service lookups per
 * call, independent of group size and of the total passwd/group database.
 *
 * Defensive rules:
 * - "admin" is the only accepted role name; any other is a hard config error.
 * - Unresolvable user/group names are logged and skipped, not fatal, so a
 *   name service hiccup cannot wedge (re)configuration or deny in a way that
 *   surprises.  A lookup failure always errs toward fewer privileges.
 */

#if HAVE_CONFIG_H
#include "config.h"
#endif
#include <sys/types.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <pwd.h>
#include <grp.h>

#define LLOG_SUBSYSTEM "roleconf"
#include "roleconf.h"

/* Name service scratch buffer sizing.  A stack buffer of NSS_BUFSIZE_INIT
 * bytes serves the common case with no allocation; a passwd or group entry
 * too large for it (e.g. a group with very many members) is retried with a
 * heap buffer grown on ERANGE, up to NSS_BUFSIZE_MAX.
 */
#define NSS_BUFSIZE_INIT 4096
#define NSS_BUFSIZE_MAX  (1024 * 1024)

/* A configured role: the rolemask it confers and the configured user and
 * group names (retained and resolved inline by roleconf_match()).
 */
struct role {
    uint32_t mask;
    json_t *users;              /* array of configured user name strings */
    json_t *groups;             /* array of configured group name strings */
};

struct roleconf {
    struct role *roles;
    size_t roles_len;

    llog_writer_f llog;
    void *llog_data;
};

/* Map a [access.roles.<name>] key to the rolemask it confers.
 * Returns FLUX_ROLE_NONE for an unknown name.
 */
static uint32_t role_name2mask (const char *name)
{
    if (name && strcmp (name, "admin") == 0)
        return FLUX_ROLE_ADMIN;
    return FLUX_ROLE_NONE;
}

/* Validate that 'o' is an array of strings.
 * Returns 0 or -1 (EINVAL).
 */
static int check_string_array (json_t *o)
{
    size_t index;
    json_t *val;

    if (!json_is_array (o)) {
        errno = EINVAL;
        return -1;
    }
    json_array_foreach (o, index, val) {
        if (!json_is_string (val)) {
            errno = EINVAL;
            return -1;
        }
    }
    return 0;
}

/* Grow the heap scratch buffer for an NSS retry: double *szp and reallocate
 * *heapp to match, returning the new buffer, or NULL on allocation failure
 * (*heapp is left intact for the caller to free).  Consolidates the realloc
 * so the buffer-grow logic lives in exactly one place.
 */
static char *nss_buf_grow (char **bufp, size_t *szp)
{
    size_t newsz = *szp * 2;
    char *tmp = realloc (*bufp, newsz);
    if (!tmp)
        return NULL;
    *bufp = tmp;
    *szp = newsz;
    return tmp;
}

/* Look up 'name' in the user database and store its uid in '*uidp'.
 *
 * Uses the reentrant getpwnam_r(3) since broker modules run as threads
 * sharing the process name service state.  Returns:
 *    1  success ('*uidp' set)
 *    0  no such user (or a name service error, which callers treat as such
 *       so a lookup failure denies rather than grants privilege)
 *   -1  local allocation failure (errno set)
 *
 * A stack buffer serves the common case; only an ERANGE result (entry too
 * large) falls back to a grown heap buffer.
 *
 * N.B. POSIX specifies "not found" as return 0 with result==NULL, but real
 * NSS backends may instead return e.g. ENOENT/ESRCH.  We therefore key off
 * result==NULL for "not found" (and any error other than ERANGE), which
 * yields a deny.
 */
static int lookup_uid_by_name (const char *name, uid_t *uidp)
{
    char stackbuf[NSS_BUFSIZE_INIT];
    char *buf = stackbuf;
    char *heapbuf = NULL;
    size_t bufsize = sizeof (stackbuf);
    struct passwd pwd;
    struct passwd *result = NULL;
    int rc = -1;

    for (;;) {
        int e = getpwnam_r (name, &pwd, buf, bufsize, &result);

        if (e != ERANGE || bufsize >= NSS_BUFSIZE_MAX)
            break;
        if (!(buf = nss_buf_grow (&heapbuf, &bufsize)))
            goto done;          /* allocation failure: rc stays -1 */
    }
    if (result) {
        *uidp = result->pw_uid;
        rc = 1;
    }
    else {
        /* result==NULL means name not found or name service error
         * return rc = 0
         */
        rc = 0;
    }
done:
    free (heapbuf);
    return rc;
}

/* Look up 'uid' in the user database and return a malloc'd copy of its login
 * name, or NULL if not found or on error (the caller treats NULL as "matches
 * no group").  Caller frees.  Uses the reentrant getpwuid_r(3).
 *
 * A stack buffer serves the common case; only an ERANGE result falls back to
 * a grown heap buffer.
 */
static char *lookup_name_by_uid (uid_t uid)
{
    char stackbuf[NSS_BUFSIZE_INIT];
    char *buf = stackbuf;
    char *heapbuf = NULL;
    size_t bufsize = sizeof (stackbuf);
    struct passwd pwd;
    struct passwd *result = NULL;
    char *name = NULL;

    for (;;) {
        int e = getpwuid_r (uid, &pwd, buf, bufsize, &result);

        if (e != ERANGE || bufsize >= NSS_BUFSIZE_MAX)
            break;
        if (!(buf = nss_buf_grow (&heapbuf, &bufsize)))
            goto done;
    }
    if (result)
        name = strdup (result->pw_name);
done:
    free (heapbuf);
    return name;
}

/* Return true if 'username' is listed in the member list of 'group'.
 * Unresolvable groups are logged and skipped (return false).
 * Uses the reentrant getgrnam_r(3).
 *
 * Matching is by the group's member list (gr_mem); see roleconf.h.
 */
static bool user_in_group (struct roleconf *roleconf,
                           const char *username,
                           const char *group)
{
    char stackbuf[NSS_BUFSIZE_INIT];
    char *buf = stackbuf;
    char *heapbuf = NULL;
    size_t bufsize = sizeof (stackbuf);
    struct group grp;
    struct group *result = NULL;
    bool found = false;

    for (;;) {
        int e = getgrnam_r (group, &grp, buf, bufsize, &result);

        if (e != ERANGE || bufsize >= NSS_BUFSIZE_MAX)
            break;
        if (!(buf = nss_buf_grow (&heapbuf, &bufsize)))
            goto done;          /* allocation failure: deny */
    }
    if (!result) {              /* not found or name service error: skip */
        llog_warning (roleconf,
                      "[access.roles] ignoring unknown group '%s'",
                      group ? group : "(null)");
        goto done;
    }
    for (char **mem = result->gr_mem; mem && *mem; mem++) {
        if (strcmp (*mem, username) == 0) {
            found = true;
            break;
        }
    }
done:
    free (heapbuf);
    return found;
}

/* Return true if the configured 'users' list names 'uid'.
 * Unresolvable user names are logged and skipped.
 */
static bool match_users (struct roleconf *roleconf,
                         struct role *role,
                         uid_t uid)
{
    size_t index;
    json_t *val;

    json_array_foreach (role->users, index, val) {
        const char *name = json_string_value (val);
        uid_t u;
        int n = lookup_uid_by_name (name, &u);

        if (n < 0)
            return false;       /* allocation failure: deny */
        if (n == 0) {
            llog_warning (roleconf,
                          "[access.roles] ignoring unknown user '%s'",
                          name ? name : "(null)");
            continue;
        }
        if (u == uid)
            return true;
    }
    return false;
}

/* Return true if a configured group of 'role' lists 'username' as a member.
 */
static bool match_groups (struct roleconf *roleconf,
                          struct role *role,
                          const char *username)
{
    size_t index;
    json_t *val;

    json_array_foreach (role->groups, index, val) {
        if (user_in_group (roleconf, username, json_string_value (val)))
            return true;
    }
    return false;
}

/* Parse one [access.roles.<name>] entry, retaining its configured names.
 */
static int parse_role (struct role *role,
                       const char *name,
                       json_t *entry,
                       flux_error_t *errp)
{
    json_t *users = NULL;
    json_t *groups = NULL;
    json_error_t jerror;

    if ((role->mask = role_name2mask (name)) == FLUX_ROLE_NONE) {
        errprintf (errp, "unknown role '%s' in [access.roles]", name);
        errno = EINVAL;
        return -1;
    }
    if (json_unpack_ex (entry,
                        &jerror,
                        0,
                        "{s?o s?o !}",
                        "users", &users,
                        "groups", &groups) < 0) {
        errprintf (errp,
                   "[access.roles.%s]: %s",
                   name,
                   jerror.text);
        errno = EINVAL;
        return -1;
    }
    if (users) {
        if (check_string_array (users) < 0) {
            errprintf (errp,
                       "[access.roles.%s] users must be a string array",
                       name);
            errno = EINVAL;
            return -1;
        }
        role->users = json_incref (users);
    }
    if (groups) {
        if (check_string_array (groups) < 0) {
            errprintf (errp,
                       "[access.roles.%s] groups must be a string array",
                       name);
            errno = EINVAL;
            return -1;
        }
        role->groups = json_incref (groups);
    }
    return 0;
}

static void role_fini (struct role *role)
{
    if (role) {
        json_decref (role->users);
        json_decref (role->groups);
    }
}

struct roleconf *roleconf_create (json_t *roles,
                                  llog_writer_f llog,
                                  void *llog_data,
                                  flux_error_t *errp)
{
    struct roleconf *roleconf;
    const char *name;
    json_t *entry;
    size_t count;

    if (!(roleconf = calloc (1, sizeof (*roleconf)))) {
        errprintf (errp, "out of memory");
        return NULL;
    }
    roleconf->llog = llog;
    roleconf->llog_data = llog_data;

    if (!roles || json_is_null (roles))
        return roleconf;

    if (!json_is_object (roles)) {
        errprintf (errp, "[access.roles] must be a table");
        errno = EINVAL;
        goto error;
    }
    if ((count = json_object_size (roles)) == 0)
        return roleconf;
    if (!(roleconf->roles = calloc (count, sizeof (roleconf->roles[0])))) {
        errprintf (errp, "out of memory");
        goto error;
    }
    json_object_foreach (roles, name, entry) {
        /* Count the slot before parsing so that a parse failure after a
         * partial json_incref() is still cleaned up by roleconf_destroy().
         */
        struct role *role = &roleconf->roles[roleconf->roles_len++];
        if (parse_role (role, name, entry, errp) < 0)
            goto error;
    }
    return roleconf;
error:
    roleconf_destroy (roleconf);
    return NULL;
}

void roleconf_destroy (struct roleconf *roleconf)
{
    if (roleconf) {
        int saved_errno = errno;
        for (size_t i = 0; i < roleconf->roles_len; i++)
            role_fini (&roleconf->roles[i]);
        free (roleconf->roles);
        free (roleconf);
        errno = saved_errno;
    }
}

uint32_t roleconf_match (struct roleconf *roleconf, uid_t uid)
{
    uint32_t mask = FLUX_ROLE_NONE;
    char *username = NULL;
    bool username_resolved = false;

    if (!roleconf)
        return FLUX_ROLE_NONE;

    for (size_t i = 0; i < roleconf->roles_len; i++) {
        struct role *role = &roleconf->roles[i];

        if ((mask & role->mask))        /* already granted */
            continue;
        if (match_users (roleconf, role, uid)) {
            mask |= role->mask;
            continue;
        }
        if (role->groups) {
            /* Resolve the connecting uid's name once, lazily. */
            if (!username_resolved) {
                username = lookup_name_by_uid (uid);
                username_resolved = true;
            }
            if (username && match_groups (roleconf, role, username))
                mask |= role->mask;
        }
    }
    free (username);
    return mask;
}

/*
 * vi:tabstop=4 shiftwidth=4 expandtab
 */
