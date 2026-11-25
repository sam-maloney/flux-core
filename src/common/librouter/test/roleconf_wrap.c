/************************************************************\
 * Copyright 2026 Lawrence Livermore National Security, LLC
 * (c.f. AUTHORS, NOTICE.LLNS, COPYING)
 *
 * This file is part of the Flux resource manager framework.
 * For details, see https://github.com/flux-framework.
 *
 * SPDX-License-Identifier: LGPL-3.0-only
\************************************************************/

/* roleconf_wrap.c - roleconf tests against a faked passwd/group database
 *
 * The real getpwnam_r(3)/getpwuid_r(3)/getgrnam_r(3) are interposed at link
 * time via ld --wrap (see Makefile.am), so these tests run against a fully
 * controlled in-memory database rather than the host's.  This makes
 * group-based role resolution deterministic and, in particular, lets us
 * verify that adding or removing a user from the admin group immediately
 * changes FLUX_ROLE_ADMIN on the next roleconf_match().
 *
 * N.B. ld --wrap is not portable (e.g. the macos linker lacks it), so this
 * test is only built where configure detects support.
 */

#if HAVE_CONFIG_H
#include "config.h"
#endif
#include <sys/types.h>
#include <string.h>
#include <errno.h>
#include <pwd.h>
#include <grp.h>
#include <jansson.h>
#include <flux/core.h>

#include "src/common/libtap/tap.h"
#include "src/common/librouter/roleconf.h"

/* Fake user database: name -> uid.  NULL-name sentinel terminates. */
struct fake_user {
    const char *name;
    uid_t uid;
};

static struct fake_user fake_users[] = {
    { "alice", 1001 },
    { "bob",   1002 },
    { "carol", 1003 },
    { NULL,    0 },
};

/* Fake admin group membership: a NULL-terminated, mutable member list.
 * Tests rewrite this vector to simulate membership changes, which take
 * effect on the next roleconf_match() (no refresh step).
 */
static char *admin_members[8] = { "alice", "bob", NULL };

#define ADMIN_GID 5000

/* When nonzero, the wrapped lookups below return ERANGE unless 'buflen' is at
 * least this many bytes, forcing roleconf's ERANGE buffer-grow path.  Set by
 * test_erange_grow() and reset to 0 afterward.
 */
static size_t erange_min_buflen = 0;

/* --- interposed libc functions (see ld --wrap in Makefile.am) --- */

extern int __real_getpwnam_r (const char *name,
                              struct passwd *pwd,
                              char *buf,
                              size_t buflen,
                              struct passwd **result);

int __wrap_getpwnam_r (const char *name,
                       struct passwd *pwd,
                       char *buf,
                       size_t buflen,
                       struct passwd **result)
{
    if (buflen < erange_min_buflen) {
        *result = NULL;
        return ERANGE;
    }
    for (struct fake_user *u = fake_users; u->name; u++) {
        if (strcmp (u->name, name) == 0) {
            pwd->pw_name = (char *)u->name;
            pwd->pw_uid = u->uid;
            pwd->pw_gid = u->uid;
            *result = pwd;
            return 0;
        }
    }
    *result = NULL;             /* not found */
    return 0;
}

extern int __real_getpwuid_r (uid_t uid,
                              struct passwd *pwd,
                              char *buf,
                              size_t buflen,
                              struct passwd **result);

int __wrap_getpwuid_r (uid_t uid,
                       struct passwd *pwd,
                       char *buf,
                       size_t buflen,
                       struct passwd **result)
{
    if (buflen < erange_min_buflen) {
        *result = NULL;
        return ERANGE;
    }
    for (struct fake_user *u = fake_users; u->name; u++) {
        if (u->uid == uid) {
            pwd->pw_name = (char *)u->name;
            pwd->pw_uid = u->uid;
            pwd->pw_gid = u->uid;
            *result = pwd;
            return 0;
        }
    }
    *result = NULL;             /* not found */
    return 0;
}

extern int __real_getgrnam_r (const char *name,
                              struct group *grp,
                              char *buf,
                              size_t buflen,
                              struct group **result);

int __wrap_getgrnam_r (const char *name,
                       struct group *grp,
                       char *buf,
                       size_t buflen,
                       struct group **result)
{
    if (buflen < erange_min_buflen) {
        *result = NULL;
        return ERANGE;
    }
    if (strcmp (name, "admins") == 0) {
        grp->gr_name = "admins";
        grp->gr_gid = ADMIN_GID;
        grp->gr_mem = admin_members;
        *result = grp;
        return 0;
    }
    *result = NULL;             /* not found */
    return 0;
}

/* --- helpers --- */

static json_t *admin_group_config (void)
{
    json_error_t error;
    json_t *o = json_pack_ex (&error, 0,
                              "{s:{s:[s]}}", "admin", "groups", "admins");
    if (!o)
        BAIL_OUT ("json_pack: %s", error.text);
    return o;
}

static void test_group_membership (void)
{
    struct roleconf *rc;
    flux_error_t error;
    json_t *o = admin_group_config ();

    rc = roleconf_create (o, NULL, NULL, &error);
    ok (rc != NULL,
        "roleconf_create with faked admin group works");
    ok (rc && roleconf_match (rc, 1001) == FLUX_ROLE_ADMIN,
        "alice (member) gets FLUX_ROLE_ADMIN");
    ok (rc && roleconf_match (rc, 1002) == FLUX_ROLE_ADMIN,
        "bob (member) gets FLUX_ROLE_ADMIN");
    ok (rc && roleconf_match (rc, 1003) == FLUX_ROLE_NONE,
        "carol (non-member) gets FLUX_ROLE_NONE");

    roleconf_destroy (rc);
    json_decref (o);
}

/* Adding a member to the group grants admin on the next match, with no
 * refresh step (roleconf resolves membership inline).
 */
static void test_membership_add (void)
{
    struct roleconf *rc;
    flux_error_t error;
    json_t *o = admin_group_config ();

    admin_members[0] = "alice";
    admin_members[1] = NULL;    /* group = { alice } */

    rc = roleconf_create (o, NULL, NULL, &error);
    ok (rc && roleconf_match (rc, 1002) == FLUX_ROLE_NONE,
        "bob is not admin before being added to the group");

    admin_members[1] = "bob";
    admin_members[2] = NULL;
    ok (rc && roleconf_match (rc, 1002) == FLUX_ROLE_ADMIN,
        "bob becomes admin immediately after being added");

    roleconf_destroy (rc);
    json_decref (o);
}

/* Removing a member revokes admin on the next match. */
static void test_membership_remove (void)
{
    struct roleconf *rc;
    flux_error_t error;
    json_t *o = admin_group_config ();

    admin_members[0] = "alice";
    admin_members[1] = "bob";
    admin_members[2] = NULL;    /* group = { alice, bob } */

    rc = roleconf_create (o, NULL, NULL, &error);
    ok (rc && roleconf_match (rc, 1002) == FLUX_ROLE_ADMIN,
        "bob is admin before removal");

    admin_members[1] = NULL;    /* group = { alice } */
    ok (rc && roleconf_match (rc, 1002) == FLUX_ROLE_NONE,
        "bob loses admin immediately after removal");
    ok (rc && roleconf_match (rc, 1001) == FLUX_ROLE_ADMIN,
        "alice retains admin after bob's removal");

    roleconf_destroy (rc);
    json_decref (o);
}

/* A gr_mem entry that does not match the connecting user's name is simply
 * not a match; it must not disturb the other members' matches.
 */
static void test_extra_group_member (void)
{
    struct roleconf *rc;
    flux_error_t error;
    json_t *o = admin_group_config ();

    admin_members[0] = "alice";
    admin_members[1] = "carol";   /* a member who never connects here */
    admin_members[2] = "bob";
    admin_members[3] = NULL;

    rc = roleconf_create (o, NULL, NULL, &error);
    ok (rc && roleconf_match (rc, 1001) == FLUX_ROLE_ADMIN,
        "alice matches despite an unrelated member in the list");
    ok (rc && roleconf_match (rc, 1002) == FLUX_ROLE_ADMIN,
        "bob (listed after the unrelated member) still matches");

    roleconf_destroy (rc);
    json_decref (o);
}

/* A connecting uid with no passwd entry cannot be resolved to a name, so it
 * matches no group and is denied (fail closed).
 */
static void test_unknown_connecting_uid (void)
{
    struct roleconf *rc;
    flux_error_t error;
    json_t *o = admin_group_config ();

    admin_members[0] = "alice";
    admin_members[1] = NULL;

    rc = roleconf_create (o, NULL, NULL, &error);
    ok (rc && roleconf_match (rc, 9999) == FLUX_ROLE_NONE,
        "uid with no passwd entry is denied the group role");

    roleconf_destroy (rc);
    json_decref (o);
}

/* A uid present in both users= and the admin group matches. */
static void test_user_and_group_dedup (void)
{
    struct roleconf *rc;
    flux_error_t error;
    json_error_t jerror;
    json_t *o;

    admin_members[0] = "alice";
    admin_members[1] = "bob";
    admin_members[2] = NULL;

    /* alice appears both explicitly and via the group. */
    o = json_pack_ex (&jerror, 0,
                      "{s:{s:[s] s:[s]}}",
                      "admin",
                      "users", "alice",
                      "groups", "admins");
    if (!o)
        BAIL_OUT ("json_pack: %s", jerror.text);

    rc = roleconf_create (o, NULL, NULL, &error);
    ok (rc && roleconf_match (rc, 1001) == FLUX_ROLE_ADMIN,
        "uid listed in both users and group still matches");
    ok (rc && roleconf_match (rc, 1002) == FLUX_ROLE_ADMIN,
        "group-only member matches alongside the duplicated user");

    roleconf_destroy (rc);
    json_decref (o);
}

/* Force the ERANGE buffer-grow path: the wrapped lookups return ERANGE until
 * the buffer exceeds the initial (stack) size, so roleconf must grow onto the
 * heap and retry.  The result must be identical to the non-grow case.
 * 20000 bytes forces two doublings (4096 -> 8192 -> 16384), so the retry
 * realloc()s an already-heap-allocated buffer; run under valgrind this
 * confirms the grow path neither leaks nor corrupts.
 */
static void test_erange_grow (void)
{
    struct roleconf *rc;
    flux_error_t error;
    json_t *o;

    admin_members[0] = "alice";
    admin_members[1] = NULL;

    erange_min_buflen = 20000;

    /* users= path exercises getpwnam_r grow */
    o = json_pack_ex (NULL, 0, "{s:{s:[s]}}", "admin", "users", "alice");
    if (!o)
        BAIL_OUT ("json_pack failed");
    rc = roleconf_create (o, NULL, NULL, &error);
    ok (rc && roleconf_match (rc, 1001) == FLUX_ROLE_ADMIN,
        "users match works when getpwnam_r requires a grown buffer");
    ok (rc && roleconf_match (rc, 1003) == FLUX_ROLE_NONE,
        "users non-match works when getpwnam_r requires a grown buffer");
    roleconf_destroy (rc);
    json_decref (o);

    /* groups= path exercises getpwuid_r + getgrnam_r grow */
    o = admin_group_config ();
    rc = roleconf_create (o, NULL, NULL, &error);
    ok (rc && roleconf_match (rc, 1001) == FLUX_ROLE_ADMIN,
        "group match works when getpwuid_r/getgrnam_r require a grown buffer");
    roleconf_destroy (rc);
    json_decref (o);

    erange_min_buflen = 0;
}

int main (int argc, char *argv[])
{
    plan (NO_PLAN);

    test_group_membership ();
    test_membership_add ();
    test_membership_remove ();
    test_extra_group_member ();
    test_unknown_connecting_uid ();
    test_user_and_group_dedup ();
    test_erange_grow ();

    done_testing ();

    return 0;
}

/*
 * vi: ts=4 sw=4 expandtab
 */
