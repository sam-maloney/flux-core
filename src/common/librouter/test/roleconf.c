/************************************************************\
 * Copyright 2026 Lawrence Livermore National Security, LLC
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
#include <sys/types.h>
#include <unistd.h>
#include <pwd.h>
#include <grp.h>
#include <string.h>
#include <errno.h>
#include <jansson.h>
#include <flux/core.h>

#include "src/common/libtap/tap.h"
#include "src/common/librouter/roleconf.h"

/* Test fixtures resolved from the running user, so the test is portable:
 * these names are guaranteed to resolve.
 */
static uid_t my_uid;
static const char *my_user;

/* A group whose member list (gr_mem) contains my_user, or NULL if none could
 * be found.  roleconf matches on gr_mem, so the positive group tests are
 * skipped when this is NULL (e.g. in a minimal container).
 */
static const char *my_memb_group;

/* Return true if group 'gr' lists 'user' in its member list. */
static bool group_has_member (struct group *gr, const char *user)
{
    for (char **mem = gr->gr_mem; mem && *mem; mem++) {
        if (strcmp (*mem, user) == 0)
            return true;
    }
    return false;
}

/* Find a group that lists my_user in its member list by scanning the
 * group database.  Sets my_memb_group (strdup'd) or leaves it NULL.  Uses
 * getgrent(3) rather than getgrouplist(3), whose signature differs between
 * glibc (gid_t *) and BSD/macos (int *).
 */
static void find_membership_group (void)
{
    struct group *gr;

    setgrent ();
    while ((gr = getgrent ())) {
        if (group_has_member (gr, my_user)) {
            my_memb_group = strdup (gr->gr_name);
            break;
        }
    }
    endgrent ();
}

static void get_ids (void)
{
    struct passwd *pw;

    my_uid = getuid ();
    if (!(pw = getpwuid (my_uid)))
        BAIL_OUT ("getpwuid(%ju) failed", (uintmax_t)my_uid);
    if (!(my_user = strdup (pw->pw_name)))
        BAIL_OUT ("out of memory");
    find_membership_group ();
    diag ("running as user=%s(%ju) membership-group=%s",
          my_user, (uintmax_t)my_uid, my_memb_group ? my_memb_group : "(none)");
}

/* Build a [access.roles] table object from a JSON pattern. */
static json_t *roles (const char *fmt, ...)
{
    json_error_t error;
    json_t *o;
    va_list ap;

    va_start (ap, fmt);
    o = json_vpack_ex (&error, 0, fmt, ap);
    va_end (ap);
    if (!o)
        BAIL_OUT ("json_pack: %s", error.text);
    return o;
}

static void test_null_and_empty (void)
{
    struct roleconf *rc;
    flux_error_t error;
    json_t *o;

    ok (roleconf_match (NULL, my_uid) == FLUX_ROLE_NONE,
        "roleconf_match rc=NULL returns FLUX_ROLE_NONE");

    rc = roleconf_create (NULL, NULL, NULL, &error);
    ok (rc != NULL,
        "roleconf_create roles=NULL works");
    ok (roleconf_match (rc, my_uid) == FLUX_ROLE_NONE,
        "roleconf_match on empty config returns FLUX_ROLE_NONE");
    roleconf_destroy (rc);

    o = json_object ();
    rc = roleconf_create (o, NULL, NULL, &error);
    ok (rc != NULL && roleconf_match (rc, my_uid) == FLUX_ROLE_NONE,
        "roleconf_create with empty table matches nothing");
    roleconf_destroy (rc);
    json_decref (o);
}

static void test_admin_by_user (void)
{
    struct roleconf *rc;
    flux_error_t error;
    json_t *o;

    o = roles ("{s:{s:[s]}}", "admin", "users", my_user);
    rc = roleconf_create (o, NULL, NULL, &error);
    ok (rc != NULL,
        "roleconf_create admin users=[me] works");
    ok (rc && roleconf_match (rc, my_uid) == FLUX_ROLE_ADMIN,
        "roleconf_match returns FLUX_ROLE_ADMIN for configured user");
    ok (rc && roleconf_match (rc, my_uid + 1) == FLUX_ROLE_NONE,
        "roleconf_match returns FLUX_ROLE_NONE for other user");
    roleconf_destroy (rc);
    json_decref (o);
}

/* The same user listed more than once must still match. */
static void test_duplicate_user (void)
{
    struct roleconf *rc;
    flux_error_t error;
    json_t *o;

    o = roles ("{s:{s:[s,s,s]}}",
               "admin",
               "users", my_user, my_user, my_user);
    rc = roleconf_create (o, NULL, NULL, &error);
    ok (rc && roleconf_match (rc, my_uid) == FLUX_ROLE_ADMIN,
        "duplicate user entries still match");
    roleconf_destroy (rc);
    json_decref (o);
}

static void test_admin_by_group (void)
{
    struct roleconf *rc;
    flux_error_t error;
    json_t *o;

    skip (my_memb_group == NULL,
          2,
          "no group lists this user as a member");
    o = roles ("{s:{s:[s]}}", "admin", "groups", my_memb_group);
    rc = roleconf_create (o, NULL, NULL, &error);
    ok (rc != NULL,
        "roleconf_create admin groups=[mygroup] works");
    ok (rc && roleconf_match (rc, my_uid) == FLUX_ROLE_ADMIN,
        "roleconf_match returns FLUX_ROLE_ADMIN via group membership");
    roleconf_destroy (rc);
    json_decref (o);
    end_skip;
}

static void test_users_and_groups (void)
{
    struct roleconf *rc;
    flux_error_t error;
    json_t *o;

    skip (my_memb_group == NULL,
          1,
          "no group lists this user as a member");
    /* Both users and groups configured; either avenue grants the role. */
    o = roles ("{s:{s:[s] s:[s]}}",
               "admin",
               "users", my_user,
               "groups", my_memb_group);
    rc = roleconf_create (o, NULL, NULL, &error);
    ok (rc && roleconf_match (rc, my_uid) == FLUX_ROLE_ADMIN,
        "admin with both users and groups grants admin");
    roleconf_destroy (rc);
    json_decref (o);
    end_skip;
}

static void test_unknown_names_skipped (void)
{
    struct roleconf *rc;
    flux_error_t error;
    json_t *o;

    /* A bogus user alongside a valid one: bogus is skipped, valid matches. */
    o = roles ("{s:{s:[s,s]}}",
               "admin",
               "users", "nonexistent-user-xyzzy", my_user);
    rc = roleconf_create (o, NULL, NULL, &error);
    ok (rc != NULL,
        "roleconf_create succeeds despite unknown user name");
    ok (rc && roleconf_match (rc, my_uid) == FLUX_ROLE_ADMIN,
        "valid user still matches when listed with an unknown one");
    roleconf_destroy (rc);
    json_decref (o);

    /* Only a bogus group: config loads, matches nothing. */
    o = roles ("{s:{s:[s]}}",
               "admin",
               "groups", "nonexistent-group-xyzzy");
    rc = roleconf_create (o, NULL, NULL, &error);
    ok (rc != NULL,
        "roleconf_create succeeds despite unknown group name");
    ok (rc && roleconf_match (rc, my_uid) == FLUX_ROLE_NONE,
        "unknown group grants nothing");
    roleconf_destroy (rc);
    json_decref (o);
}

static void test_bad_config (void)
{
    struct roleconf *rc;
    flux_error_t error;
    json_t *o;

    /* Unknown role name is a hard error. */
    o = roles ("{s:{s:[s]}}", "operator", "users", my_user);
    errno = 0;
    error.text[0] = '\0';
    rc = roleconf_create (o, NULL, NULL, &error);
    ok (rc == NULL && errno == EINVAL,
        "roleconf_create fails with EINVAL on unknown role name");
    diag ("%s", error.text);
    json_decref (o);

    /* Unknown key within a role is a hard error. */
    o = roles ("{s:{s:[s]}}", "admin", "userz", my_user);
    errno = 0;
    rc = roleconf_create (o, NULL, NULL, &error);
    ok (rc == NULL && errno == EINVAL,
        "roleconf_create fails with EINVAL on unknown role key");
    diag ("%s", error.text);
    json_decref (o);

    /* users must be an array of strings. */
    o = roles ("{s:{s:i}}", "admin", "users", 42);
    errno = 0;
    rc = roleconf_create (o, NULL, NULL, &error);
    ok (rc == NULL && errno == EINVAL,
        "roleconf_create fails with EINVAL when users is not an array");
    diag ("%s", error.text);
    json_decref (o);

    o = roles ("{s:{s:[i]}}", "admin", "users", 42);
    errno = 0;
    rc = roleconf_create (o, NULL, NULL, &error);
    ok (rc == NULL && errno == EINVAL,
        "roleconf_create fails with EINVAL on non-string user entry");
    diag ("%s", error.text);
    json_decref (o);

    /* groups must be an array of strings (distinct code path from users). */
    o = roles ("{s:{s:i}}", "admin", "groups", 42);
    errno = 0;
    rc = roleconf_create (o, NULL, NULL, &error);
    ok (rc == NULL && errno == EINVAL,
        "roleconf_create fails with EINVAL when groups is not an array");
    diag ("%s", error.text);
    json_decref (o);

    o = roles ("{s:{s:[i]}}", "admin", "groups", 42);
    errno = 0;
    rc = roleconf_create (o, NULL, NULL, &error);
    ok (rc == NULL && errno == EINVAL,
        "roleconf_create fails with EINVAL on non-string group entry");
    diag ("%s", error.text);
    json_decref (o);

    /* roles table that is not an object. */
    o = json_string ("nope");
    errno = 0;
    rc = roleconf_create (o, NULL, NULL, &error);
    ok (rc == NULL && errno == EINVAL,
        "roleconf_create fails with EINVAL when roles is not a table");
    diag ("%s", error.text);
    json_decref (o);
}

int main (int argc, char *argv[])
{
    plan (NO_PLAN);

    get_ids ();

    test_null_and_empty ();
    test_admin_by_user ();
    test_duplicate_user ();
    test_admin_by_group ();
    test_users_and_groups ();
    test_unknown_names_skipped ();
    test_bad_config ();

    free ((char *)my_user);
    free ((char *)my_memb_group);

    done_testing ();

    return 0;
}

/*
 * vi: ts=4 sw=4 expandtab
 */
