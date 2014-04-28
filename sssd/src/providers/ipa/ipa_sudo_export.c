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
//#include "providers/ipa/ipa_opts.h"   // ipa sudo rule map
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
void print_rules(struct sysdb_attrs **rules, int count)
{
    int i, j, k;

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

/* FIXME: This could be useful for other devs too so better parametrization 
 * might be good.
 *
 * e.g.
 * ipaUniqueID=6f...74dc10b,cn=sudocmds,cn=sudo,$DC =>  6f...74dc10b
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

errno_t get_upper_letter_value(TALLOC_CTX *mem_ctx, 
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
 * These attr name should be handled automatically by ipa_sudorule_map:
 *  externalUser, externalHost, ipaSudoOpt, 
 *  ipaSudoRunAsExtUser, ipaSudoRunAsExtGroup
 */
static errno_t ipa_sudo_export_attr_name(TALLOC_CTX *mem,
                                         const char *ipa_name,
                                         const char **sysdb_name)
{
    errno_t ret = EOK;

    // FIXME: use map or think through something smarter? Or let it be this way
    // because it's more readable?

    /* attrs which names need to be exported */
    if (strcasecmp(ipa_name, "memberUser") == 0 ) {
        *sysdb_name = talloc_strdup(mem, "sudoUser");
    }
    else if (strcasecmp(ipa_name, "memberHost") == 0 ) {
        *sysdb_name = talloc_strdup(mem, "sudoHost");
    }
    else if (strcasecmp(ipa_name, "memberAllowCmd") == 0 ||
             strcasecmp(ipa_name, "memberDenyCmd") == 0) {
        *sysdb_name = talloc_strdup(mem, "sudoCommand");
    } 
    else if (strcasecmp(ipa_name, "ipaSudoRunAs") == 0) {
        *sysdb_name = talloc_strdup(mem, "sudoRunAsUser");
    }
    else if (strcasecmp(ipa_name, "ipaSudoRunAsGroup") == 0) {
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
        ret = ENOENT;
    }
    
    if (sysdb_name == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, ("talloc_strdup() failed\n"));
        ret = ENOMEM;
    }

    return ret;
}

errno_t ipa_sudo_export_attr_value(TALLOC_CTX *mem,
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

    if (ret != EOK || new_value == NULL) {
        goto fail;
    }

fail:
    return ret;
}
 

// FIXME: use ipa_sudorule_map and macros for these constants?
errno_t ipa_sudo_export_set_properties(TALLOC_CTX *mem,
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
             strcasecmp(attr_name, "sudoHost") == 0 ||
             strcasecmp(attr_name, "sudoCommand") == 0 ||
             strcasecmp(attr_name, "sudoOption") == 0 ||
             strcasecmp(attr_name, "sudoRunAsUser") == 0 ||
             strcasecmp(attr_name, "sudoRunAsGroup") == 0 ||
             strcasecmp(attr_name, "entryUSN") == 0) {
        prop->type = COPY;
    }
    else {
        DEBUG(SSSDBG_CRIT_FAILURE, 
             ("Don't know how to export this attr: %s\n", attr_name));
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

errno_t ipa_sudo_export_attr_values(TALLOC_CTX *mem, 
                                    struct sysdb_ctx *sysdb, 
                                    struct ldb_message_element *e,
                                    struct ipa_sudoer_cmds **cmd_index,
                                    struct sysdb_attrs **sudoer,
                                    const char *new_name)
{
    struct ldb_message_element *new_el = NULL;
    struct ipa_sudo_export *prop = NULL;
    char *new_value = NULL;
    errno_t ret = EOK;
    int k;

    /* EXPORT all values of the attribute */
    for (k = 0; k < e->num_values; k++) {

        ret = ipa_sudo_export_set_properties(mem, e->name, 
                                        (const char *)e->values[k].data, &prop);
        if (ret != EOK) {
            goto fail;
        }

        ret = ipa_sudo_export_attr_value(mem, prop, sysdb, &new_value);
        if (ret != EOK) {
            goto fail;
        }

        /* For commands we build cmd_index but do not copy it's values into
         * final sudoers yet.
         */
        if (strcasecmp(e->name, IPA_SUDO_ATTR_ALLOW_CMD) == 0 ||
            strcasecmp(e->name, IPA_SUDO_ATTR_DENY_CMD) == 0) {

            ret = ipa_sudo_index_commands(mem, *cmd_index, e->name, new_value);
            if (ret != EOK) {
                goto fail;
            }

            continue;
        }

        /* create new attribute or get the existing one based on the
         * new name of the attribute */
        ret = sysdb_attrs_get_el_ext(*sudoer, new_name, true, &new_el);
        if (ret != EOK) {
            // FIXME: can't get new attribute
            goto fail;
        }

        /* add exported value to the values of the attribute */
        ret = sysdb_attrs_add_string(*sudoer, new_name, new_value);
        if (ret != EOK) {
            // FIXME: can't get new attribute
            goto fail;
        }

        talloc_zfree(prop);
        talloc_zfree(new_value);
    }

fail:
    return ret;
}

/* 
 * Export ipa specific attributes, copy attributes that doesn't need to be
 * exported and create command index (remeber commands for each rule so when we
 * got the commands we don't have to iterate through all rules again).
 */
errno_t ipa_sudo_export_sudoers(TALLOC_CTX *mem, 
                                struct sysdb_ctx *sysdb,
                                struct sysdb_attrs **ipa_rules, 
                                int rules_count, 
                                struct sysdb_attrs ***exported_rules,
                                int *sudoers_count,
                                struct ipa_sudoer_cmds ***index)
{
    struct ldb_message_element *e = NULL;
    struct sysdb_attrs **sudoers;
    struct ipa_sudoer_cmds **cmds_index;
    const char *new_name = NULL;
    errno_t ret = EOK;
    int i, j;

    /* an array of exported sudoers (without commands) */
    *sudoers_count = 0;
    sudoers = talloc_zero_array(mem, struct sysdb_attrs *, rules_count);
    if (sudoers == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, ("talloc_strdup() failed\n"));
        goto fail;
    }

    cmds_index = talloc_zero_array(mem, struct ipa_sudoer_cmds *, rules_count);
    if (cmds_index == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, ("talloc_strdup() failed\n"));
        goto fail;
    }

    /* for each rule aplicable to this host */
    for (i = 0; i < rules_count; i++) {

        DEBUG(SSSDBG_TRACE_FUNC, ("Exporting IPA SUDO rule cn=%s "
                                  "into native LDAP SUDO scheme.\n", 
                                  (char *)ipa_rules[i]->a[1].values[0].data));

        /* new sudo rule */
        sudoers[i] = sysdb_new_attrs(mem);
        /* new index of allowed and denied commands for this rules */
        cmds_index[i] = talloc_zero(mem, struct ipa_sudoer_cmds);

        /* for each attribute of the rule */
        for (j = 0; j < ipa_rules[i]->num; j++) {

            /* get element -> one attribute of the rule */
            e = &(ipa_rules[i]->a[j]);

            /* EXPORT the name of the attribute */
            // FIXME: new atttrs has to be stored under sudoers attrs!
            ret = ipa_sudo_export_attr_name(mem, e->name, &new_name);
            if (ret != EOK) {
                goto fail;
            }

            /* EXPORT all values of the attribute */
            // FIXME: new atttrs has to be stored under sudoers context attrs!
            ret = ipa_sudo_export_attr_values(mem, sysdb, e, &(cmds_index[i]), 
                                              &(sudoers[i]), new_name);
            if (ret != EOK) {
                goto fail;
            }

            talloc_zfree(new_name);
        }

        (*sudoers_count)++;
    }

    if (rules_count != *sudoers_count || ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, ("Unsuccessful export of IPA SUDO rules\n"));
        goto fail;
    }

    *exported_rules = talloc_steal(mem, sudoers);
    *index = cmds_index;

fail:
    return ret;
}
