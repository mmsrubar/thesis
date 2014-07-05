/*
    SSSD

    Authors:
        Michal Šrubař <mmsrubar@gmail.com>

    Copyright (C) 2014 Michal Šrubař

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

#include <stdio.h>
#include <ldb.h>
#include <string.h>
#include <talloc.h>

#include "providers/ipa/ipa_common.h"
#include "providers/ipa/ipa_sudo_cmd.h"
#include "providers/ipa/ipa_sudo.h"
#include "providers/ipa/ipa_sudo_export.h"
#include "db/sysdb_sudo.h"
#include "util/util.h"

enum attr_type {
    USER = 0,
    USER_GROUP,
    HOST,
    HOST_GROUP,
    COMMAND,
    CMDS_GROUP,
    UPPER_CASE,
    COPY,
};

struct ipa_sudo_export {
    enum attr_type type;
    
    const char *orig_name;
    const char *orig_value;
};


/* tmp func ... */
void print_rules(const char *title, struct sysdb_attrs **rules, int count)
{
    int i, j, k;

    printf("===========================================================================\n");
    printf("%s\n", title);
    printf("===========================================================================\n");
    /* for each rule */
    for (i = 0; i < count; i++) {

        printf("Entry %d\n", i+1);
        printf("---------------------------------------------------------------------------\n");

        /* for each attribute */
        for (j = 0; j < rules[i]->num; j++) {

            /* for each value of the attribute */
            for (k = 0; k < rules[i]->a[j].num_values; k++) {

                printf("%s(%d):\t%s\n", rules[i]->a[j].name, rules[i]->a[j].num_values, rules[i]->a[j].values[k].data);
            }
        }

        printf("===========================================================================\n\n");
    }
}

/*
 * e.g.
 * ipaUniqueID=6f74dc10b,cn=sudocmds,cn=sudo,$DC    =>  6f74dc10b
 * uid=admin,cn=users,cn=accounts,dc=example,dc=cz  => admin
 */
errno_t get_third_rdn_value(TALLOC_CTX *mem_ctx, 
                            struct sysdb_ctx *sysdb,
                            const char *dn_str,
                            const char *first_attr,
                            const char *second_attr,
                            const char *second_val,
                            const char *third_attr,
                            const char *third_val,
                            char **value)
{
    errno_t ret = EOK;

    struct ldb_dn *dn = NULL;
    const struct ldb_val *val;
    const char *rdn;
    char *str = NULL;

    TALLOC_CTX *tmp = talloc_init(NULL);

    dn = ldb_dn_new(tmp, sysdb_ctx_get_ldb(sysdb), dn_str);
    if (dn == NULL) {
        goto done;
    }

    /* first rdn, second rdn, third rdn and least one domain component */
    if (ldb_dn_get_comp_num(dn) < 4) {
        ret = ENOENT;
        goto done;
    }

    /* rdn must be name of the first component */
    rdn = ldb_dn_get_rdn_name(dn);
    if (rdn == NULL) {
        ret = EINVAL;
        goto done;
    }

    if (strcasecmp(first_attr, rdn) != 0) {
        ret = ENOENT;
        goto done;
    }

    /* second component must be 'second->attr=second->val' */
    rdn = ldb_dn_get_component_name(dn, 1);
    if (strcasecmp(second_attr, rdn) != 0) {
        ret = ENOENT;
        goto done;
    }
    
    val = ldb_dn_get_component_val(dn, 1);
    if (strncasecmp(second_val, (const char *) val->data,
                    val->length) != 0) {
        ret = ENOENT;
        goto done;
    }

    /* third component must be 'third->attr=third->val' */
    rdn = ldb_dn_get_component_name(dn, 2);
    if (strcasecmp(third_attr, rdn) != 0) {
        ret = ENOENT;
        goto done;
    }

    val = ldb_dn_get_component_val(dn, 2);
    if (strncasecmp(third_val, (const char *) val->data,
                    val->length) != 0) {
        ret = ENOENT;
        goto done;
    }

    val = ldb_dn_get_rdn_val(dn);
    str = talloc_strndup(tmp, (const char *)val->data, val->length);
    if (str == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, ("talloc_strdup() failed\n"));
        ret = ENOMEM;
        goto done;
    }

    *value = talloc_steal(mem_ctx, str);

done:
    talloc_free(tmp);
    return ret;
}

static errno_t get_upper_letter_value(TALLOC_CTX *mem_ctx, 
                                      const char *val,
                                      char **new_value)
{
    errno_t ret = EOK;

    /* value should always be 'all' */
    if (strcmp(val, "all") != 0) {
        DEBUG(SSSDBG_CRIT_FAILURE, ("Trying to export other than *category attribute\n"));
        return ENOENT;
    }

    *new_value = talloc_strdup(mem_ctx, "ALL");
    if (*new_value == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, ("talloc_strdup() failed\n"));
        ret = ENOMEM;
    }

    return ret;
}

/*
 * These attr name could be handled automatically by ipa_sudorule_map:
 *      externalUser, externalHost, ipaSudoOpt,
 *      ipaSudoRunAsExtUser, ipaSudoRunAsExtGroup 
 */
static errno_t export_attr_name(TALLOC_CTX *mem,
                                const char *ipa_name,
                                const char **sysdb_name)
{
    errno_t ret = EOK;

    /* FIXME: 
     * use map or think through something smarter? Or let it be this way
     * because it's more readable?
     */

    /* attrs which names need to be exported */
    if (strcasecmp(ipa_name, "memberUser") == 0 ) {
        *sysdb_name = talloc_strdup(mem, "sudoUser");
    }
    else if (strcasecmp(ipa_name, "externalUser") == 0 ) {
        *sysdb_name = talloc_strdup(mem, "sudoUser");
    }
    else if (strcasecmp(ipa_name, "memberHost") == 0 ) {
        *sysdb_name = talloc_strdup(mem, "sudoHost");
    }
    else if (strcasecmp(ipa_name, "externalHost") == 0 ) {
        *sysdb_name = talloc_strdup(mem, "sudoHost");
    }
    else if (strcasecmp(ipa_name, "memberAllowCmd") == 0 ||
             strcasecmp(ipa_name, "memberDenyCmd") == 0) {
        *sysdb_name = talloc_strdup(mem, "sudoCommand");
    } 
    else if (strcasecmp(ipa_name, "ipaSudoRunAs") == 0) {
        *sysdb_name = talloc_strdup(mem, "sudoRunAsUser");
    }
    else if (strcasecmp(ipa_name, "ipaSudoRunAsExtUser") == 0) {
        *sysdb_name = talloc_strdup(mem, "sudoRunAsUser");
    }
    else if (strcasecmp(ipa_name, "ipaSudoRunAsGroup") == 0) {
        *sysdb_name = talloc_strdup(mem, "sudoRunAsGroup");
    }
    else if (strcasecmp(ipa_name, "ipaSudoRunAsExtGroup") == 0) {
        *sysdb_name = talloc_strdup(mem, "sudoRunAsGroup");
    }
    else if (strcasecmp(ipa_name, "userCategory") == 0) {
        *sysdb_name = talloc_strdup(mem, "sudoUser");
    }
    else if (strcasecmp(ipa_name, "hostCategory") == 0) {
        *sysdb_name = talloc_strdup(mem, "sudoHost");
    }
    else if (strcasecmp(ipa_name, "cmdCategory") == 0) {
        *sysdb_name = talloc_strdup(mem, "sudoCommand");
    }
    else if (strcasecmp(ipa_name, "ipaSudoRunAsUserCategory") == 0) {
        *sysdb_name = talloc_strdup(mem, "sudoRunAsUser");
    }
    else if (strcasecmp(ipa_name, "ipaSudoRunAsGroupCategory") == 0) {
        *sysdb_name = talloc_strdup(mem, "sudoRunAsGroup");
    }
    else if (strcasecmp(ipa_name, "ipaSudoOpt") == 0) {
        *sysdb_name = talloc_strdup(mem, "sudoOption");
    } /* these attrs are still legal */
    else if (strcasecmp(ipa_name, "originalDN") == 0 ||
             strcasecmp(ipa_name, "cn") == 0 ||
             strcasecmp(ipa_name, "sudoUser") == 0 ||
             strcasecmp(ipa_name, "sudoHost") == 0 ||
             strcasecmp(ipa_name, "sudoCommand") == 0 ||
             strcasecmp(ipa_name, "sudoOption") == 0 ||
             strcasecmp(ipa_name, "sudoRunAsUser") == 0 ||
             strcasecmp(ipa_name, "sudoRunAsGroup") == 0 ||
             strcasecmp(ipa_name, "entryUSN") == 0) {
        
        *sysdb_name = talloc_strdup(mem, ipa_name);
    } else {    /* ipa should NOT sent attr with other name */
        DEBUG(SSSDBG_CRIT_FAILURE, ("Unknown attr name: %s\n", ipa_name));
        return ENOENT;
    }
    
    if (sysdb_name == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, ("talloc_strdup() failed\n"));
        return ENOMEM;
    }

    return ret;
}

static errno_t export_attr_value(TALLOC_CTX *mem,
                                 struct ipa_sudo_export *properties,
                                 struct sysdb_ctx *sysdb,
                                 char **new_value)
{
    errno_t ret = EOK;
    char *value;

    switch (properties->type) {
        case USER:
            ret = get_third_rdn_value(mem, sysdb, properties->orig_value,
                            "uid", "cn", "users", "cn", "accounts", new_value);
            break;
        case USER_GROUP:
            ret = get_third_rdn_value(mem, sysdb, properties->orig_value,
                            "cn", "cn", "groups", "cn", "accounts", &value);
            *new_value = talloc_asprintf_append(*new_value, "%c%s", 
                                                USER_GROUP_PREFIX, value);
            break;
        case HOST:
            ret = get_third_rdn_value(mem, sysdb, properties->orig_value,
                            "fqdn", "cn", "computers", "cn", "accounts", new_value);
            break;
        case HOST_GROUP:
            ret = get_third_rdn_value(mem, sysdb, properties->orig_value,
                            "cn", "cn", "hostgroups", "cn", "accounts", &value);
            *new_value = talloc_asprintf_append(*new_value, "%c%s", 
                                                HOST_GROUP_PREFIX, value);
            break;
        case COMMAND:
            ret = get_third_rdn_value(mem, sysdb, properties->orig_value,
                            "ipaUniqueID", "cn", "sudocmds", "cn", "sudo", new_value);
            break;
        case UPPER_CASE:
            ret = get_upper_letter_value(mem, properties->orig_value, new_value);
            break;
        case CMDS_GROUP:
            *new_value = talloc_strdup(mem, properties->orig_value);
            break;
        case COPY:
            *new_value = talloc_strdup(mem, properties->orig_value);
            break;
    }

    if (new_value == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, ("talloc() failed\n"));
        return ENOMEM;
    }

    return ret;
}
 

/* FIXME: 
 * Use ipa_sudorule_map and macros for these constants? It's much more 
 * readable and clear this way in my opinion.
 */
static errno_t export_set_properties(TALLOC_CTX *mem,
                                     const char *attr_name, 
                                     const char *attr_val,
                                     struct ipa_sudo_export **properties)
{
    struct ipa_sudo_export *prop;
    errno_t ret = EOK;

    prop = talloc_zero(mem, struct ipa_sudo_export);
    if (prop == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, ("talloc_zero() failed\n"));
        ret = ENOMEM;
        goto fail;
    }

    /* ipa users and user groups attributes */
    if (strcasecmp(attr_name, "memberUser") == 0 ||
        strcasecmp(attr_name, "ipaSudoRunAs") == 0 ||
        strcasecmp(attr_name, "ipaSudoRunAsGroup") == 0) {

        if (strstr(attr_val, "cn=users,cn=accounts") != NULL) {
            prop->type = USER;
        } else if (strstr(attr_val, "cn=groups,cn=accounts") != NULL) {
            prop->type = USER_GROUP;
        }
    } /* ipa command attributes */
    else if (strcasecmp(attr_name, "memberAllowCmd") == 0 ||
             strcasecmp(attr_name, "memberDenyCmd") == 0) {

        if (strstr(attr_val, "cn=sudocmds,cn=sudo") != NULL) {
            prop->type = COMMAND;
        } else if (strstr(attr_val, "cn=sudocmdgroups,cn=sudo") != NULL) {
            prop->type = CMDS_GROUP;
        }
    } /* ipa hosts and host groups attributes */
    else if (strcasecmp(attr_name, "memberHost") == 0 ) {

        if (strstr(attr_val, "cn=computers,cn=accounts") != NULL) {
            prop->type = HOST;
        } else if (strstr(attr_val, "cn=hostgroups,cn=accounts") != NULL) {
            prop->type = HOST_GROUP;
        }
    } /* sudo is case sensitive so we need to export all to ALL */
    else if (strcasecmp(attr_name, "userCategory") == 0 ||
               strcasecmp(attr_name, "hostCategory") == 0 ||
               strcasecmp(attr_name, "cmdCategory") == 0 ||
               strcasecmp(attr_name, "ipaSudoRunAsUserCategory") == 0 ||
               strcasecmp(attr_name, "ipaSudoRunAsGroupCategory") == 0) {
        prop->type = UPPER_CASE;
    } /* attrs which values will be copied */
    else if (strcasecmp(attr_name, "originalDN") == 0 ||
             strcasecmp(attr_name, "cn") == 0 ||
             strcasecmp(attr_name, "sudoUser") == 0 ||
             strcasecmp(attr_name, "externalUser") == 0 ||
             strcasecmp(attr_name, "sudoHost") == 0 ||
             strcasecmp(attr_name, "externalHost") == 0 ||
             strcasecmp(attr_name, "sudoCommand") == 0 ||
             strcasecmp(attr_name, "ipaSudoOpt") == 0 ||
             strcasecmp(attr_name, "sudoOption") == 0 ||
             strcasecmp(attr_name, "sudoRunAsUser") == 0 ||
             strcasecmp(attr_name, "ipaSudoRunAsExtUser") == 0 ||
             strcasecmp(attr_name, "sudoRunAsGroup") == 0 ||
             strcasecmp(attr_name, "ipaSudoRunAsExtGroup") == 0 ||
             strcasecmp(attr_name, "entryUSN") == 0) {
        prop->type = COPY;
    }
    else {
        DEBUG(SSSDBG_CRIT_FAILURE, ("Don't know how to export this attr: %s\n", 
                                     attr_name));
        ret = ENOENT;
        goto fail;
    }

    /* make a copy of original name and value of the attribute */
    prop->orig_name = talloc_strdup(prop, attr_name);
    if (prop->orig_name == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, ("talloc_strdup() failed\n"));
        ret = ENOMEM;
        goto fail;
    }
    prop->orig_value = talloc_strdup(prop, attr_val);
    if (prop->orig_value == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, ("talloc_strdup() failed\n"));
        ret = ENOMEM;
        goto fail;
    }

    *properties = prop;

fail:
    return ret;
}

static errno_t export_attr_values(TALLOC_CTX *mem_sudoer,
                                  TALLOC_CTX *mem_cmd,
                                  struct sysdb_ctx *sysdb,
                                  struct ldb_message_element *e,
                                  struct ipa_sudoer_cmds **cmd_index,
                                  struct sysdb_attrs **sudoers,
                                  const char *new_name,
                                  struct tevent_req *req)
{
    struct ldb_message_element *new_el = NULL;
    struct ipa_sudo_export *prop = NULL;
    char *new_value = NULL;
    errno_t ret = EOK;
    int k;

    /* EXPORT all values of the attribute */
    for (k = 0; k < e->num_values; k++) {

        ret = export_set_properties(mem_sudoer, e->name, 
                                    (const char *)e->values[k].data, &prop);
        if (ret != EOK) {
            goto fail;
        }

        ret = export_attr_value(mem_sudoer, prop, sysdb, &new_value);
        if (ret != EOK) {
            goto fail;
        }

        /* For commands we build cmd_index but do not copy it's values into
         * final sudoers yet. Because we need to export the value first but we
         * don't have downloaded the IPA SUDO commands yet.
         */
        if (strcasecmp(e->name, IPA_SUDO_ATTR_ALLOW_CMD) == 0 ||
            strcasecmp(e->name, IPA_SUDO_ATTR_DENY_CMD) == 0) {

            ret = ipa_sudo_index_commands(mem_cmd, *cmd_index, e->name, new_value);
            if (ret != EOK) {
                goto fail;
            }

            continue;
        }

        /* create new attribute or get the existing one based on the
         * new name of the attribute */
        ret = sysdb_attrs_get_el_ext(*sudoers, new_name, true, &new_el);
        if (ret != EOK) {
            DEBUG(SSSDBG_CRIT_FAILURE, ("talloc_realloc() failed\n"));
            goto fail;
        }

        /* copy exported value to the values of the new attribute */
        ret = sysdb_attrs_add_string(*sudoers, new_name, new_value);
        if (ret != EOK) {
            DEBUG(SSSDBG_CRIT_FAILURE, ("talloc_realloc() failed\n"));
            goto fail;
        }

        talloc_zfree(prop);
        talloc_zfree(new_value);
    }

fail:
    return ret;
}

/* 
 * Export IPA specific attributes, copy attributes that doesn't need to be
 * exported and create command index (remeber commands for each rule so when we
 * get the commands we don't have to iterate through all rules attrs again).
 *
 * Skip the commands attributes for now because we don't have the commands
 * donwloaded yet.
 */
errno_t export_sudoers(TALLOC_CTX *mem, 
                       struct sysdb_ctx *sysdb,
                       struct sysdb_attrs **ipa_rules, 
                       size_t ipa_rules_count, 
                       struct sysdb_attrs ***exported_rules,
                       size_t *sudoers_count,
                       struct ipa_sudoer_cmds ***index,
                       struct tevent_req *req)
{
    struct ldb_message_element *e = NULL;
    struct sysdb_attrs **sudoers;
    struct ipa_sudoer_cmds **cmds_index;
    const char *new_name = NULL;
    errno_t ret = EOK;
    int i, j;

    /* no rules to export */
    if (ipa_rules == NULL || ipa_rules_count == 0) {
        DEBUG(SSSDBG_CRIT_FAILURE, ("no IPA sudo rules to export\n"));
        return EINVAL;
    }

    /* an array of exported sudoers (without commands) */
    *sudoers_count = 0;
    sudoers = talloc_zero_array(mem, struct sysdb_attrs *, ipa_rules_count);
    if (sudoers == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, ("talloc_zero_array() failed\n"));
        ret = ENOMEM;
        goto fail;
    }

    cmds_index = talloc_zero_array(mem, struct ipa_sudoer_cmds *, ipa_rules_count);
    if (cmds_index == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, ("talloc_zero_array() failed\n"));
        ret = ENOMEM;
        goto fail;
    }

    /* for each rule aplicable to this host */
    for (i = 0; i < ipa_rules_count; i++) {

        DEBUG(SSSDBG_TRACE_FUNC, ("Exporting IPA SUDO rule %s\n",
                                  (char *)ipa_rules[i]->a[1].values[0].data));

        /* new sudo rule */
        sudoers[i] = sysdb_new_attrs(sudoers);
        /* new index of allowed and denied commands for this specific rule*/
        cmds_index[i] = talloc_zero(cmds_index, struct ipa_sudoer_cmds);

        /* for each attribute of the rule */
        for (j = 0; j < ipa_rules[i]->num; j++) {

            /* get element -> one attribute of the rule */
            e = &(ipa_rules[i]->a[j]);

            /* EXPORT the name of the attribute */
            ret = export_attr_name(sudoers[i], e->name, &new_name);
            if (ret != EOK) {
                goto fail;
            }

            /* EXPORT all values of the attribute */
            ret = export_attr_values(sudoers[i], cmds_index[i], sysdb, e, 
                                     &(cmds_index[i]), &(sudoers[i]), 
                                     new_name, req);
                                              
            if (ret != EOK) {
                goto fail;
            }

            talloc_zfree(new_name);

        } /* for each attribute of the rule */

        (*sudoers_count)++;

    } /* for each rule aplicable to this host */

    if (ipa_rules_count != *sudoers_count || ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, ("Unsuccessful export of IPA SUDO rules\n"));
        ret = EIO;
        goto fail;
    }

    *exported_rules = talloc_steal(mem, sudoers);
    *index = cmds_index;

fail:
    return ret;
}

/* If attr_name is ipaUniqueID then it'l return value of sudoCmd attribute on a
 * first call and NULL on second call.
 *
 * If attr_name is DN of a commands group then it'll return sudoCmd on each call
 * and NULL if there are no more commands.
 */
static const char *get_sudoCmd_value(TALLOC_CTX *mem,
                                     struct sysdb_attrs **ipa_cmds,
                                     int ipa_cmds_count, 
                                     const char *attr_name,
                                     const char *attr_value,
                                     bool cmd_group,
                                     int *error)
{
    const char **values = NULL;
    const char **val;
    const char *sudo_cmd = NULL;
    const char *tmp = NULL;

    static int i;
    int ret;

    /* for each ipa cmd (continue where we stopped the last time) */
    for ( ; i < ipa_cmds_count; i++) {

        sysdb_attrs_get_string_array(ipa_cmds[i], attr_name, mem, &values);

        for (val = values; val != NULL && *val != NULL; val++) {
            
            if (strcasecmp(*val, attr_value) == 0) {
                /* searched ipa command found, returning value of sudoCmd */
                ret = sysdb_attrs_get_string(ipa_cmds[i], IPA_SUDO_ATTR_CMD, &tmp);
                if (ret != EOK) {
                    DEBUG(SSSDBG_CRIT_FAILURE, ("sysdb_attrs_get_string() failed\n"));
                    *error = ret;
                    return NULL;
                }

                /* don't start in the same entry next time */
                i++;

                sudo_cmd = talloc_strdup(mem, tmp);
                if (sudo_cmd == NULL) {
                    DEBUG(SSSDBG_CRIT_FAILURE, ("talloc_strdup() failed\n"));
                    *error = ENOMEM;
                    return NULL;
                }

                return sudo_cmd;
            }
        }

        talloc_zfree(values);
    }

    /* no more sudoCmd(s) for this group of ipa commands */
    i = 0;
    return NULL;
}

static int ipa_sudo_assign_command(struct sysdb_attrs *sudoers, 
                                   struct sysdb_attrs **ipa_cmds, 
                                   int ipa_cmds_count,
                                   const char **cmds, 
                                   int count, bool prefix)
{
    TALLOC_CTX *tmp = talloc_init(NULL);

    struct ldb_message_element *el;
    const char *attr_name = NULL;
    const char *sudo_cmd = NULL;
    char *p_sudo_cmd = NULL;
    bool cmd_group = false;
    errno_t ret = EOK;
    int j;

    if (cmds == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, ("No IPA command index\n"));
        ret = ENOENT;
        goto fail;
    }

    /* create sudoCommand attribute if there isn't yet */
    ret = sysdb_attrs_get_el_ext(sudoers, SYSDB_SUDO_CACHE_AT_COMMAND, true, &el);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, ("talloc_realloc() failed\n"));
        goto fail;

    }

    /* for each allowed or denied command */
    for (j = 0; j < count; j++) {

        /* look up a single command or a group? */
        if (strstr(cmds[j], IPA_SUDO_CONTAINER_CMD_GRPS) == NULL) {
            attr_name = talloc_strdup(tmp, IPA_SUDO_ATTR_ID);
            cmd_group = false;
        } else {
            attr_name = talloc_strdup(tmp, IPA_SUDO_ATTR_MEMBEROF);
            cmd_group = true;
        }

        if (attr_name == NULL) {
            DEBUG(SSSDBG_CRIT_FAILURE, ("talloc_strdup() failed\n"));
            ret = ENOMEM;
            goto fail;
        }

        while ((sudo_cmd = get_sudoCmd_value(tmp, ipa_cmds, ipa_cmds_count, 
                                        attr_name, cmds[j], cmd_group, &ret)) != NULL)
        {

            if (prefix) {   /* denied cmds has to have ! prefix */
                p_sudo_cmd = talloc_asprintf_append(p_sudo_cmd, "%c%s", 
                                                DENIED_CMD_PREFIX, sudo_cmd);
                if (p_sudo_cmd == NULL) {
                    DEBUG(SSSDBG_CRIT_FAILURE, ("talloc_strdup() failed\n"));
                    ret = ENOMEM;
                    goto fail;
                }

                sysdb_attrs_add_string(sudoers, SYSDB_SUDO_CACHE_AT_COMMAND, p_sudo_cmd);
            } else {
                sysdb_attrs_add_string(sudoers, SYSDB_SUDO_CACHE_AT_COMMAND, sudo_cmd);
            }

            talloc_zfree(p_sudo_cmd);
            talloc_zfree(sudo_cmd);
        }
    }

fail:
    talloc_free(tmp);
    return ret;
}

int export_sudoers_cmds(TALLOC_CTX *mem,
                        struct sysdb_attrs **sudoers,
                        int sudoers_count,
                        struct ipa_sudoer_cmds **index, 
                        struct sysdb_attrs **ipa_cmds,
                        int ipa_cmds_count)
{
    errno_t ret = EOK;
    int i;

    DEBUG(SSSDBG_TRACE_FUNC, ("Exporting IPA sudo commands\n"));

    /* for each sudoer */
    for (i = 0; i < sudoers_count; i++) {

        /* are there any allowed commands for this sudoer? */
        if (index[i]->allowed_num != 0) {
            ret = ipa_sudo_assign_command(sudoers[i], ipa_cmds, ipa_cmds_count, 
                                          index[i]->allowed, 
                                          index[i]->allowed_num, false);
            if (ret != EOK) {
                goto fail;
            }
        }

        /* same for denied commands */
        if (index[i]->denied_num != 0) {
            ret = ipa_sudo_assign_command(sudoers[i], ipa_cmds, ipa_cmds_count, 
                                          index[i]->denied, 
                                          index[i]->denied_num, true);
            if (ret != EOK) {
                goto fail;
            }
        }
    }
fail:
    return ret;
}
