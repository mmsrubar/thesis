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
    
    const char *orig_value;
    const char *orig_name;
};



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
errno_t get_third_rdn_value( TALLOC_CTX *mem_ctx, 
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
        ret = ENOMEM;
        goto done;
    }

    *value = talloc_steal(mem_ctx, str);

done:
    talloc_free(tmp);
    return ret;
}

errno_t get_upper_letter_value(TALLOC_CTX *mem_ctx, 
                               char *val,
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

    // FIXME: use map or think through something smarter

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

    return ret;
}


// FIXME: it's not necesary to export new name every time you export value of an
// attribute ... so move it to main 1st cycle
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
            *new_value = talloc_asprintf_append(*new_value, "%%%s", value);
            break;
        case HOST:
            ret = get_third_rdn_value(mem, sysdb, properties->orig_value,
                            "fqdn", "cn", "computers", "cn", "accounts", new_value);
            break;
        case HOST_GROUP:
            ret = get_third_rdn_value(mem, sysdb, properties->orig_value,
                            "cn", "cn", "hostgroups", "cn", "accounts", &value);
            *new_value = talloc_asprintf_append(*new_value, "+%s", value);
            break;
        case COMMAND:
            ret = get_third_rdn_value(mem, sysdb, properties->orig_value,
                            "ipaUniqueID", "cn", "sudocmds", "cn", "sudo", new_value);
            break;
        case UPPER_CASE:
            ret = get_upper_letter_value(mem, properties->orig_value, new_value);
            break;
        case CMDS_GROUP:
            *new_value = properties->orig_value;
            break;
        case COPY:
            *new_value = (char *)properties->orig_value;
            break;
    }

    if (ret != EOK || new_value == NULL) {
        goto fail;
    }

fail:
    return ret;
}
 

// FIXME: use ipa_sudorule_map and macros for these constants
errno_t ipa_sudo_export_set_properties(TALLOC_CTX *mem,
                                       const char *attr_name, 
                                       const char *attr_val,
                                       struct ipa_sudo_export **properties)
{
    struct ipa_sudo_export *prop;
    errno_t ret = EOK;

    prop = talloc_zero(mem, struct ipa_sudo_export);
    if (prop == NULL) {
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
             ("Don't know how to export value of this attr: %s\n", attr_name));
        ret = ENOENT;
        goto fail;
    }

    /* make a copy of original name and value of the attribute */
    prop->orig_name = talloc_strdup(mem, attr_name);
    if (prop->orig_name == NULL) {
        ret = ENOMEM;
        goto fail;
    }
    prop->orig_value = talloc_strdup(mem, attr_val);
    if (prop->orig_value == NULL) {
        ret = ENOMEM;
        goto fail;
    }

    *properties = prop;

fail:
    return ret;
}


/* 1st Cycle 
 * =========
 * Export ipa specific attributes, copy attributes that doesn't need to be
 * exported and create command index (remeber commands for each rule so when we
 * got the commands we don't have to iterate through all rules again).
 *
 * FIXME: break it into little more pieces ...
 */
errno_t ipa_sudo_export_sudoers(TALLOC_CTX *mem, 
                            struct sysdb_ctx *sysdb,
                                struct sysdb_attrs **ipa_rules, 
                                int rules_count, 
                                struct sysdb_attrs ***exported_rules,
                                int *sudoers_count,
                                struct ipa_sudoer_cmds ***index)
{
    //TALLOC_CTX *tmp;

    struct ldb_message_element *e = NULL;
    struct ldb_message_element *new_el = NULL;
    struct ipa_sudo_export *prop;
    struct sysdb_attrs **sudoers;
    struct ipa_sudoer_cmds **cmds_index;
    const char *new_name;
    char *new_value;
    int i, j, k;
    errno_t ret = EOK;

    /* an array of exported sudoers (without commands) */
    sudoers = talloc_zero_array(mem, struct sysdb_attrs *, rules_count);
    *sudoers_count = 0;

    cmds_index = talloc_zero_array(mem, struct ipa_sudoer_cmds *, rules_count);

    /* for each rule aplicable to this host */
    for (i = 0; i < rules_count; i++) {

        DEBUG(SSSDBG_TRACE_FUNC, ("Exporting IPA SUDO rule cn=%s "
                                  "into native LDAP SUDO scheme.\n", 
                                  ipa_rules[i]->a[1].values[0]));

        /* new sudo rule */
        sudoers[i] = sysdb_new_attrs(mem);
        /* new index of allowed and denied commands for this rules */
        cmds_index[i] = talloc_zero(mem, struct ipa_sudoer_cmds);

        /* for each attribute of the rule */
        for (j = 0; j < ipa_rules[i]->num; j++) {

            new_name = NULL;

            /* get element -> one attribute of the rule */
            e = &(ipa_rules[i]->a[j]);

            /* EXPORT the name of the attribute */
            ret = ipa_sudo_export_attr_name(mem, e->name, &new_name);
            if (ret != EOK) {
                goto fail;
            }

            /* EXPORT all values of the attribute */
            for (k = 0; k < e->num_values; k++) {

                new_value = NULL;

                ipa_sudo_export_set_properties(mem, e->name, 
                                    (const char *)e->values[k].data, &prop);
                ipa_sudo_export_attr_value(mem, prop, sysdb, &new_value);

                /* For commands we build cmd_index but do not copy it's values into
                 * final sudoers yet.
                 */
                if (strcasecmp(e->name, IPA_SUDO_ATTR_ALLOW_CMD) == 0 ||
                    strcasecmp(e->name, IPA_SUDO_ATTR_DENY_CMD) == 0) {

                    ipa_sudo_index_commands(mem, cmds_index[i], e->name, new_value);
                    continue;
                }

                /* create new attribute or get the existing one based on the
                 * new name of the attribute */
                ret = sysdb_attrs_get_el_ext(sudoers[i], new_name, true, &new_el);
                if (ret != EOK) {
                    // FIXME: can't get new attribute
                    goto fail;
                }

                /* add exported value to the values of the attribute */
                ret = sysdb_attrs_add_string(sudoers[i], new_name, new_value);
                if (ret != EOK) {
                    // FIXME: can't get new attribute
                    goto fail;
                }

                talloc_free(prop);
            }
        }

        (*sudoers_count)++;
    }

    if (rules_count != *sudoers_count) {
        printf("Error: nezkopiroval jsem vsechny pravidla!\n");
        goto fail;
    }

 //   printf("sudoers \n===========\n");
//    print_rules(sudoers, *sudoers_count);

    *exported_rules = talloc_steal(mem, sudoers);
    *index = cmds_index;

fail:
    return ret;
}
