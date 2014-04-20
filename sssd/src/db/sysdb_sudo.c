/*
    Authors:
        Jakub Hrozek <jhrozek@redhat.com>

    Copyright (C) 2011 Red Hat

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#define _XOPEN_SOURCE

#include <talloc.h>
#include <time.h>

#include "db/sysdb.h"
#include "db/sysdb_private.h"
#include "db/sysdb_sudo.h"

#define NULL_CHECK(val, rval, label) do { \
    if (!val) {                           \
        rval = ENOMEM;                    \
        goto label;                       \
    }                                     \
} while(0)

/* ====================  Utility functions ==================== */

static errno_t sysdb_sudo_convert_time(const char *str, time_t *unix_time)
{
    struct tm tm;
    char *tret = NULL;

    /* SUDO requires times to be in generalized time format:
     * YYYYMMDDHHMMSS[.|,fraction][(+|-HHMM)|Z]
     *
     * We need to use more format strings to parse this with strptime().
     */
    const char **format = NULL;
    const char *formats[] = {"%Y%m%d%H%M%SZ",    /* 201212121300Z */
                             "%Y%m%d%H%M%S%z",   /* 201212121300+-0200 */
                             "%Y%m%d%H%M%S.0Z",
                             "%Y%m%d%H%M%S.0%z",
                             "%Y%m%d%H%M%S,0Z",
                             "%Y%m%d%H%M%S,0%z",
                             NULL};

    for (format = formats; *format != NULL; format++) {
        tret = strptime(str, *format, &tm);
        if (tret != NULL && *tret == '\0') {
            *unix_time = mktime(&tm);
            return EOK;
        }
    }

    return EINVAL;
}

static errno_t sysdb_sudo_check_time(struct sysdb_attrs *rule,
                                     time_t now,
                                     bool *result)
{
    TALLOC_CTX *tmp_ctx = NULL;
    const char **values = NULL;
    const char *name = NULL;
    time_t notBefore = 0;
    time_t notAfter = 0;
    time_t converted;
    errno_t ret;
    int i;

    if (!result) return EINVAL;
    *result = false;

    tmp_ctx = talloc_new(NULL);
    NULL_CHECK(tmp_ctx, ret, done);

    ret = sysdb_attrs_get_string(rule, SYSDB_SUDO_CACHE_AT_CN, &name);
    if (ret == ENOENT) {
        name = "<missing>";
    } else if(ret != EOK) {
        goto done;
    }

    /*
     * From man sudoers.ldap:
     *
     * If multiple sudoNotBefore entries are present, the *earliest* is used.
     * If multiple sudoNotAfter entries are present, the *last one* is used.
     *
     * From sudo sources, ldap.c:
     * If either the sudoNotAfter or sudoNotBefore attributes are missing,
     * no time restriction shall be imposed.
     */

    /* check for sudoNotBefore */
    ret = sysdb_attrs_get_string_array(rule, SYSDB_SUDO_CACHE_AT_NOTBEFORE,
                                       tmp_ctx, &values);
    if (ret == EOK) {
        for (i=0; values[i] ; i++) {
            ret = sysdb_sudo_convert_time(values[i], &converted);
            if (ret != EOK) {
                DEBUG(SSSDBG_MINOR_FAILURE, ("Invalid time format in rule [%s]!\n",
                      name));
                goto done;
            }

            /* Grab the earliest */
            if (!notBefore) {
                notBefore = converted;
            } else if (notBefore > converted) {
                notBefore = converted;
            }
        }
    } else if (ret != ENOENT) {
        goto done;
    }

    /* check for sudoNotAfter */
    ret = sysdb_attrs_get_string_array(rule, SYSDB_SUDO_CACHE_AT_NOTAFTER,
                                       tmp_ctx, &values);
    if (ret == EOK) {
        for (i=0; values[i] ; i++) {
            ret = sysdb_sudo_convert_time(values[i], &converted);
            if (ret != EOK) {
                DEBUG(SSSDBG_MINOR_FAILURE, ("Invalid time format in rule [%s]!\n",
                      name));
                goto done;
            }

            /* Grab the latest */
            if (!notAfter) {
                notAfter = converted;
            } else if (notAfter < converted) {
                notAfter = converted;
            }
        }
    } else if (ret != ENOENT) {
        goto done;
    }

    if ((notBefore == 0 || now >= notBefore)
        && (notAfter == 0 || now <= notAfter)) {
        *result = true;
    }

    if (*result) {
        DEBUG(SSSDBG_TRACE_ALL, ("Rule [%s] matches time restrictions\n",
                                 name));
    } else {
        DEBUG(SSSDBG_TRACE_ALL, ("Rule [%s] does not match time "
                                 "restrictions\n", name));
    }

    ret = EOK;
done:
    talloc_free(tmp_ctx);
    return ret;
}

errno_t sysdb_sudo_filter_rules_by_time(TALLOC_CTX *mem_ctx,
                                        uint32_t in_num_rules,
                                        struct sysdb_attrs **in_rules,
                                        time_t now,
                                        uint32_t *_num_rules,
                                        struct sysdb_attrs ***_rules)
{
    uint32_t num_rules = 0;
    struct sysdb_attrs **rules = NULL;
    TALLOC_CTX *tmp_ctx = NULL;
    bool allowed = false;
    errno_t ret;
    int i;

    tmp_ctx = talloc_new(NULL);
    NULL_CHECK(tmp_ctx, ret, done);

    if (now == 0) {
        now = time(NULL);
    }

    for (i = 0; i < in_num_rules; i++) {
        ret = sysdb_sudo_check_time(in_rules[i], now, &allowed);
        if (ret == EOK && allowed) {
            num_rules++;
            rules = talloc_realloc(tmp_ctx, rules, struct sysdb_attrs *,
                                   num_rules);
            NULL_CHECK(rules, ret, done);

            rules[num_rules - 1] = in_rules[i];
        }
    }

    *_num_rules = num_rules;
    *_rules = talloc_steal(mem_ctx, rules);

    ret = EOK;

done:
    talloc_free(tmp_ctx);
    return ret;
}

errno_t
sysdb_get_sudo_filter(TALLOC_CTX *mem_ctx, const char *username,
                      uid_t uid, char **groupnames, unsigned int flags,
                      char **_filter)
{
    TALLOC_CTX *tmp_ctx = NULL;
    char *filter = NULL;
    char *specific_filter = NULL;
    time_t now;
    errno_t ret;
    int i;

    tmp_ctx = talloc_new(NULL);
    NULL_CHECK(tmp_ctx, ret, done);

    /* build specific filter */

    specific_filter = talloc_zero(tmp_ctx, char); /* assign to tmp_ctx */
    NULL_CHECK(specific_filter, ret, done);

    if (flags & SYSDB_SUDO_FILTER_INCLUDE_ALL) {
        specific_filter = talloc_asprintf_append(specific_filter, "(%s=ALL)",
                                                 SYSDB_SUDO_CACHE_AT_USER);
        NULL_CHECK(specific_filter, ret, done);
    }

    if (flags & SYSDB_SUDO_FILTER_INCLUDE_DFL) {
        specific_filter = talloc_asprintf_append(specific_filter, "(%s=defaults)",
                                                 SYSDB_NAME);
        NULL_CHECK(specific_filter, ret, done);
    }

    if ((flags & SYSDB_SUDO_FILTER_USERNAME) && (username != NULL)) {
        specific_filter = talloc_asprintf_append(specific_filter, "(%s=%s)",
                                                 SYSDB_SUDO_CACHE_AT_USER,
                                                 username);
        NULL_CHECK(specific_filter, ret, done);
    }

    if ((flags & SYSDB_SUDO_FILTER_UID) && (uid != 0)) {
        specific_filter = talloc_asprintf_append(specific_filter, "(%s=#%llu)",
                                                 SYSDB_SUDO_CACHE_AT_USER,
                                                 (unsigned long long) uid);
        NULL_CHECK(specific_filter, ret, done);
    }

    if ((flags & SYSDB_SUDO_FILTER_GROUPS) && (groupnames != NULL)) {
        for (i=0; groupnames[i] != NULL; i++) {
            specific_filter = talloc_asprintf_append(specific_filter, "(%s=%%%s)",
                                                     SYSDB_SUDO_CACHE_AT_USER,
                                                     groupnames[i]);
            NULL_CHECK(specific_filter, ret, done);
        }
    }

    if (flags & SYSDB_SUDO_FILTER_NGRS) {
        specific_filter = talloc_asprintf_append(specific_filter, "(%s=+*)",
                                                 SYSDB_SUDO_CACHE_AT_USER);
        NULL_CHECK(specific_filter, ret, done);
    }

    /* build global filter */

    filter = talloc_asprintf(tmp_ctx, "(&(%s=%s)",
                             SYSDB_OBJECTCLASS, SYSDB_SUDO_CACHE_OC);
    NULL_CHECK(filter, ret, done);

    if (specific_filter[0] != '\0') {
        filter = talloc_asprintf_append(filter, "(|%s)", specific_filter);
        NULL_CHECK(filter, ret, done);
    }

    if (flags & SYSDB_SUDO_FILTER_ONLY_EXPIRED) {
        now = time(NULL);
        filter = talloc_asprintf_append(filter, "(&(%s<=%lld))",
                                        SYSDB_CACHE_EXPIRE, (long long)now);
        NULL_CHECK(filter, ret, done);
    }

    filter = talloc_strdup_append(filter, ")");
    NULL_CHECK(filter, ret, done);

    ret = EOK;
    *_filter = talloc_steal(mem_ctx, filter);

done:
    talloc_free(tmp_ctx);
    return ret;
}

errno_t
sysdb_get_sudo_user_info(TALLOC_CTX *mem_ctx,
                         struct sss_domain_info *domain,
                         const char *username, uid_t *_uid,
                         char ***groupnames)
{
    TALLOC_CTX *tmp_ctx;
    errno_t ret;
    struct ldb_message *msg;
    struct ldb_message *group_msg = NULL;
    char **sysdb_groupnames = NULL;
    const char *primary_group = NULL;
    struct ldb_message_element *groups;
    uid_t uid = 0;
    gid_t gid = 0;
    size_t num_groups = 0;
    int i;
    const char *attrs[] = { SYSDB_MEMBEROF,
                            SYSDB_GIDNUM,
                            SYSDB_UIDNUM,
                            NULL };
    const char *group_attrs[] = { SYSDB_NAME,
                                  NULL };

    tmp_ctx = talloc_new(NULL);
    NULL_CHECK(tmp_ctx, ret, done);

    ret = sysdb_search_user_by_name(tmp_ctx, domain, username, attrs, &msg);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, ("Error looking up user %s\n", username));
        goto done;
    }

    if (_uid != NULL) {
        uid = ldb_msg_find_attr_as_uint64(msg, SYSDB_UIDNUM, 0);
        if (!uid) {
            DEBUG(SSSDBG_CRIT_FAILURE, ("A user with no UID?\n"));
            ret = EIO;
            goto done;
        }
    }

    /* resolve secondary groups */
    if (groupnames != NULL) {
        groups = ldb_msg_find_element(msg, SYSDB_MEMBEROF);
        if (!groups || groups->num_values == 0) {
            /* No groups for this user in sysdb currently */
            sysdb_groupnames = NULL;
            num_groups = 0;
        } else {
            num_groups = groups->num_values;
            sysdb_groupnames = talloc_array(tmp_ctx, char *, num_groups + 1);
            NULL_CHECK(sysdb_groupnames, ret, done);

            /* Get a list of the groups by groupname only */
            for (i = 0; i < groups->num_values; i++) {
                ret = sysdb_group_dn_name(domain->sysdb,
                                          sysdb_groupnames,
                                          (const char *)groups->values[i].data,
                                          &sysdb_groupnames[i]);
                if (ret != EOK) {
                    ret = ENOMEM;
                    goto done;
                }
            }
            sysdb_groupnames[groups->num_values] = NULL;
        }
    }

    /* resolve primary group */
    gid = ldb_msg_find_attr_as_uint64(msg, SYSDB_GIDNUM, 0);
    if (gid != 0) {
        ret = sysdb_search_group_by_gid(tmp_ctx, domain, gid, group_attrs,
                                        &group_msg);
        if (ret == EOK) {
            primary_group = ldb_msg_find_attr_as_string(group_msg, SYSDB_NAME,
                                                        NULL);
            if (primary_group == NULL) {
                ret = ENOMEM;
                goto done;
            }

            num_groups++;
            sysdb_groupnames = talloc_realloc(tmp_ctx, sysdb_groupnames,
                                              char *, num_groups + 1);
            NULL_CHECK(sysdb_groupnames, ret, done);

            sysdb_groupnames[num_groups - 1] = talloc_strdup(sysdb_groupnames,
                                                             primary_group);
            NULL_CHECK(sysdb_groupnames[num_groups - 1], ret, done);

            sysdb_groupnames[num_groups] = NULL;
        } else if (ret != ENOENT) {
            DEBUG(SSSDBG_CRIT_FAILURE, ("Error looking up group [%d]: %s\n",
                                        ret, strerror(ret)));
            goto done;
        }
    }

    ret = EOK;

    if (_uid != NULL) {
        *_uid = uid;
    }

    if (groupnames != NULL) {
        *groupnames = talloc_steal(mem_ctx, sysdb_groupnames);
    }
done:
    talloc_free(tmp_ctx);
    return ret;
}

errno_t
sysdb_save_sudorule(struct sss_domain_info *domain,
                    const char *rule_name,
                    struct sysdb_attrs *attrs)
{
    errno_t ret;

    DEBUG(SSSDBG_TRACE_FUNC, ("Adding sudo rule %s\n", rule_name));

    ret = sysdb_attrs_add_string(attrs, SYSDB_OBJECTCLASS,
                                 SYSDB_SUDO_CACHE_OC);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, ("Could not set rule object class [%d]: %s\n",
              ret, strerror(ret)));
        return ret;
    }

    ret = sysdb_attrs_add_string(attrs, SYSDB_NAME, rule_name);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, ("Could not set name attribute [%d]: %s\n",
              ret, strerror(ret)));
        return ret;
    }

    ret = sysdb_store_custom(domain, rule_name,
                             SUDORULE_SUBDIR, attrs);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, ("sysdb_store_custom failed [%d]: %s\n",
              ret, strerror(ret)));
        return ret;
    }

    return EOK;
}

static errno_t sysdb_sudo_set_refresh_time(struct sss_domain_info *domain,
                                           const char *attr_name,
                                           time_t value)
{
    TALLOC_CTX *tmp_ctx;
    struct ldb_dn *dn;
    struct ldb_message *msg = NULL;
    struct ldb_result *res = NULL;
    errno_t ret;
    int lret;

    tmp_ctx = talloc_new(NULL);
    if (!tmp_ctx) {
        ret = ENOMEM;
        goto done;
    }

    dn = ldb_dn_new_fmt(tmp_ctx, domain->sysdb->ldb,
                        SYSDB_TMPL_CUSTOM_SUBTREE,
                        SUDORULE_SUBDIR, domain->name);
    if (!dn) {
        ret = ENOMEM;
        goto done;
    }

    lret = ldb_search(domain->sysdb->ldb, tmp_ctx, &res, dn, LDB_SCOPE_BASE,
                      NULL, NULL);
    if (lret != LDB_SUCCESS) {
        ret = sysdb_error_to_errno(lret);
        goto done;
    }

    msg = ldb_msg_new(tmp_ctx);
    if (msg == NULL) {
        ret = ENOMEM;
        goto done;
    }
    msg->dn = dn;

    if (res->count == 0) {
        lret = ldb_msg_add_string(msg, "cn", SUDORULE_SUBDIR);
        if (lret != LDB_SUCCESS) {
            ret = sysdb_error_to_errno(lret);
            goto done;
        }
    } else if (res->count != 1) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              ("Got more than one reply for base search!\n"));
        ret = EIO;
        goto done;
    } else {
        lret = ldb_msg_add_empty(msg, attr_name, LDB_FLAG_MOD_REPLACE, NULL);
        if (lret != LDB_SUCCESS) {
            ret = sysdb_error_to_errno(lret);
            goto done;
        }
    }

    lret = ldb_msg_add_fmt(msg, attr_name, "%lld", (long long)value);
    if (lret != LDB_SUCCESS) {
        ret = sysdb_error_to_errno(lret);
        goto done;
    }

    if (res->count) {
        lret = ldb_modify(domain->sysdb->ldb, msg);
    } else {
        lret = ldb_add(domain->sysdb->ldb, msg);
    }

    ret = sysdb_error_to_errno(lret);

done:
    talloc_free(tmp_ctx);
    return ret;
}

static errno_t sysdb_sudo_get_refresh_time(struct sss_domain_info *domain,
                                           const char *attr_name,
                                           time_t *value)
{
    TALLOC_CTX *tmp_ctx;
    struct ldb_dn *dn;
    struct ldb_result *res;
    errno_t ret;
    int lret;
    const char *attrs[2] = {attr_name, NULL};

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        return ENOMEM;
    }

    dn = ldb_dn_new_fmt(tmp_ctx, domain->sysdb->ldb, SYSDB_TMPL_CUSTOM_SUBTREE,
                        SUDORULE_SUBDIR, domain->name);
    if (!dn) {
        ret = ENOMEM;
        goto done;
    }

    lret = ldb_search(domain->sysdb->ldb, tmp_ctx, &res, dn, LDB_SCOPE_BASE,
                      attrs, NULL);
    if (lret != LDB_SUCCESS) {
        ret = sysdb_error_to_errno(lret);
        goto done;
    }

    if (res->count == 0) {
        /* This entry has not been populated in LDB
         * This is a common case, as unlike LDAP,
         * LDB does not need to have all of its parent
         * objects actually exist.
         */
        *value = 0;
        ret = EOK;
        goto done;
    } else if (res->count != 1) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              ("Got more than one reply for base search!\n"));
        ret = EIO;
        goto done;
    }

    *value = ldb_msg_find_attr_as_int(res->msgs[0], attr_name, 0);

    ret = EOK;

done:
    talloc_free(tmp_ctx);
    return ret;
}

errno_t sysdb_sudo_set_last_full_refresh(struct sss_domain_info *domain,
                                         time_t value)
{
    return sysdb_sudo_set_refresh_time(domain,
                                       SYSDB_SUDO_AT_LAST_FULL_REFRESH, value);
}

errno_t sysdb_sudo_get_last_full_refresh(struct sss_domain_info *domain,
                                         time_t *value)
{
    return sysdb_sudo_get_refresh_time(domain,
                                       SYSDB_SUDO_AT_LAST_FULL_REFRESH, value);
}

/* ====================  Purge functions ==================== */

static errno_t sysdb_sudo_purge_all(struct sss_domain_info *domain)
{
    struct ldb_dn *base_dn = NULL;
    TALLOC_CTX *tmp_ctx = NULL;
    errno_t ret;

    tmp_ctx = talloc_new(NULL);
    NULL_CHECK(tmp_ctx, ret, done);

    base_dn = sysdb_custom_subtree_dn(tmp_ctx, domain, SUDORULE_SUBDIR);
    NULL_CHECK(base_dn, ret, done);

    ret = sysdb_delete_recursive(domain->sysdb, base_dn, true);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, ("sysdb_delete_recursive failed.\n"));
        goto done;
    }

    ret = EOK;
done:
    talloc_free(tmp_ctx);
    return ret;
}

errno_t sysdb_sudo_purge_byname(struct sss_domain_info *domain,
                                const char *name)
{
    DEBUG(SSSDBG_TRACE_INTERNAL, ("Deleting sudo rule %s\n", name));
    return sysdb_delete_custom(domain, name, SUDORULE_SUBDIR);
}

errno_t sysdb_sudo_purge_byfilter(struct sss_domain_info *domain,
                                  const char *filter)
{
    TALLOC_CTX *tmp_ctx;
    size_t count;
    struct ldb_message **msgs;
    const char *name;
    int i;
    errno_t ret;
    errno_t sret;
    bool in_transaction = false;
    const char *attrs[] = { SYSDB_OBJECTCLASS,
                            SYSDB_NAME,
                            SYSDB_SUDO_CACHE_AT_CN,
                            NULL };

    /* just purge all if there's no filter */
    if (!filter) {
        return sysdb_sudo_purge_all(domain);
    }

    tmp_ctx = talloc_new(NULL);
    NULL_CHECK(tmp_ctx, ret, done);

    /* match entries based on the filter and remove them one by one */
    ret = sysdb_search_custom(tmp_ctx, domain, filter,
                              SUDORULE_SUBDIR, attrs,
                              &count, &msgs);
    if (ret == ENOENT) {
        DEBUG(SSSDBG_TRACE_FUNC, ("No rules matched\n"));
        ret = EOK;
        goto done;
    } else if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, ("Error looking up SUDO rules"));
        goto done;
    }

    ret = sysdb_transaction_start(domain->sysdb);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, ("Failed to start transaction\n"));
        goto done;
    }
    in_transaction = true;

    for (i = 0; i < count; i++) {
        name = ldb_msg_find_attr_as_string(msgs[i], SYSDB_NAME, NULL);
        if (name == NULL) {
            DEBUG(SSSDBG_OP_FAILURE, ("A rule without a name?\n"));
            /* skip this one but still delete other entries */
            continue;
        }

        ret = sysdb_sudo_purge_byname(domain, name);
        if (ret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE, ("Could not delete rule %s\n", name));
            goto done;
        }
    }

    ret = sysdb_transaction_commit(domain->sysdb);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, ("Failed to commit transaction\n"));
        goto done;
    }
    in_transaction = false;

done:
    if (in_transaction) {
        sret = sysdb_transaction_cancel(domain->sysdb);
        if (sret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE, ("Could not cancel transaction\n"));
        }
    }

    talloc_free(tmp_ctx);
    return ret;
}
