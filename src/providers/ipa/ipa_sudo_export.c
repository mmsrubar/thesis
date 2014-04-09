#include <stdio.h>
#include <ldb.h>
#include <string.h>
#include "providers/ipa/ipa_common.h"
#include "providers/ipa/ipa_sudo_cmd.h"
#include "util/util.h"

#define SUDO_USER_GROUP_SING '%'
#define SUDO_HOSTGROUP_SING '+'
#define SUDO_DENY_CMD_SING '!'


enum attr_type {
    USER = 0,
    USER_GROUP,
    HOST,
    HOST_GROUP,
    COMMAND,
    CMDS_GROUP,
    COPY,
};


struct ipa_sudo_export {
    enum attr_type type;
    
    const char *orig_value;
    const char *orig_name;

    /* "!" for denied command, ... */
    char prefix;     
};

void print_rules(struct sysdb_attrs **rules, int count)
{
    int i, j, k;

    /* for each rule */
    for (i = 0; i < count; i++) {

        printf("Entry %d\n", i+1);

        /* for each attribute */
        for (j = 0; j < rules[i]->num; j++) {

            /* for each value of the attribute */
            for (k = 0; k < rules[i]->a[j].num_values; k++) {

                printf("%s(%d):\t%s\n", rules[i]->a[j].name, rules[i]->a[j].num_values, rules[i]->a[j].values[k].data);
            }
        }
    }
}

/* FIXME: This could be useful for other devs too so better parametrization 
 * might be good.
 */
static errno_t get_third_rdn_value( TALLOC_CTX *mem_ctx, 
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

static errno_t ipa_sudo_export_attr_name(TALLOC_CTX *mem,
                                         const char *ipa_name,
                                         const char **sysdb_name)
{
    errno_t ret = EOK;

    // FIXME: use map or think through something smarter
    // FIXME: cover ilegal attribute case

    if (strncmp(ipa_name, "memberUser", strlen("memberUser")) == 0) {
        *sysdb_name = talloc_strdup(mem, "sudoUser");
    } 
    else if (strncmp(ipa_name, "ipaSudoRunAs", strlen("ipaSudoRunAs")) == 0) {
        *sysdb_name = talloc_strdup(mem, "sudoRunAsUser");
    }
    else if (strcasecmp(ipa_name, "memberHost") == 0 ) {
        *sysdb_name = talloc_strdup(mem, "sudoHost");
    }
    else if (strcasecmp(ipa_name, "memberAllowCmd") == 0 ||
        strcasecmp(ipa_name, "memberDenyCmd") == 0) {
        *sysdb_name = talloc_strdup(mem, "sudoCommand");
    } 
    else {
        *sysdb_name = ipa_name;
    }

    return ret;
}

errno_t ipa_sudo_add_cmd(TALLOC_CTX *mem, 
                struct ipa_sudoer_cmds *cmds, 
                struct ipa_sudo_export *prop, 
                const char *name, 
                const char *new_value)
{
    errno_t ret = EOK;

    if (strcasecmp(name, "memberAllowCmd") == 0) {
        cmds->allowed = talloc_realloc(mem, cmds->allowed, const char *, 1);
        if (cmds->allowed == NULL) {
            ret = ENOMEM;
            goto fail;
        }

        /* add new cmd or DN to group of commands */
        cmds->allowed[cmds->allowed_num] = talloc_strdup(mem, new_value);
        if (cmds->allowed[cmds->allowed_num] == NULL) {
            ret = ENOMEM;
            goto fail;
        }

        cmds->allowed_num++;
    }
    else if (strcasecmp(name, "memberDenyCmd") == 0) {
        cmds->denied = talloc_realloc(mem, cmds->denied, const char *, 1);
        if (cmds->denied == NULL) {
            ret = ENOMEM;
            goto fail;
        }

        /* add new cmd or DN to group of commands */
        cmds->denied[cmds->denied_num] = talloc_strdup(mem, new_value);
        if (cmds->denied[cmds->denied_num] == NULL) {
            ret = ENOMEM;
            goto fail;
        }

        cmds->denied_num++;
    }
    else {
        printf("unknown command attribute!\n");
        ret = ENOENT;
        goto fail;
    }


fail:
    return ret;
}

// FIXME: it's not necesary to export new name every time you export value of an
// attribute ... so move to main 1st cycle
// FIXME: you do the same thing many times ...
errno_t ipa_sudo_export_attr_value(TALLOC_CTX *mem,
                        struct ipa_sudo_export *properties,
                            struct sysdb_ctx *sysdb,
                        char **new_value)
                        
{
    errno_t ret = EOK;

    switch (properties->type) {
        case USER:
            /* get new value */
            ret = get_third_rdn_value(mem, sysdb, properties->orig_value,
                                    "uid",
                                    "cn", "users",
                                    "cn", "accounts",
                                    new_value);
            if (ret != EOK) {
                goto fail;
            }

           break;
        case USER_GROUP:
            /* get new value */
            ret = get_third_rdn_value(mem, sysdb, properties->orig_value,
                                    "cn",
                                    "cn", "groups",
                                    "cn", "accounts",
                                    new_value);
            if (ret != EOK) {
                goto fail;
            }
            break;

        case HOST:
            /* get new value */
            ret = get_third_rdn_value(mem, sysdb, properties->orig_value,
                                    "fqdn",
                                    "cn", "computers",
                                    "cn", "accounts",
                                    new_value);
            if (ret != EOK) {
                goto fail;
            }

            break;

        case HOST_GROUP:
            /* get new value */
            ret = get_third_rdn_value(mem, sysdb, properties->orig_value,
                                    "cn",
                                    "cn", "hostgroups",
                                    "cn", "accounts",
                                    new_value);
            if (ret != EOK) {
                goto fail;
            }

            break;

        case COMMAND:
            ret = get_third_rdn_value(mem, sysdb, properties->orig_value,
                                    "ipaUniqueID",
                                    "cn", "sudocmds",
                                    "cn", "sudo",
                                    new_value);
            if (ret != EOK) {
                goto fail;
            }
            
            break;

        case CMDS_GROUP:
            *new_value = (char *)properties->orig_value;
            break;
        case COPY:
            *new_value = (char *)properties->orig_value;
            break;
    }
fail:
    return ret;
}
 

errno_t ipa_sudo_export_set_properties(TALLOC_CTX *mem,
                                    const char *attr_name, 
                                    const char *attr_val,
                                    struct ipa_sudo_export **properties)
{
    errno_t ret = EOK;

    struct ipa_sudo_export *prop = talloc_zero(mem, struct ipa_sudo_export);
    if (prop == NULL) {
        ret = ENOMEM;
        goto fail;
    }

    /* ipa command attributes */
    if (strcasecmp(attr_name, "memberAllowCmd") == 0 ||
        strcasecmp(attr_name, "memberDenyCmd") == 0) {

        if (strstr(attr_val, "cn=sudocmds,cn=sudo") != NULL) {
            prop->type = COMMAND;
        } else if (strstr(attr_val, "cn=sudocmdgroups,cn=sudo") != NULL) {
            prop->type = CMDS_GROUP;
        }
    }
    else if (strcasecmp(attr_name, "memberUser") == 0 ||
        strcasecmp(attr_name, "ipaSudoRunAs") == 0) {
        /* ipa users and user groups attributes */

        if (strstr(attr_val, "cn=users,cn=accounts") != NULL) {
            prop->type = USER;
        } else if (strstr(attr_val, "cn=groups,cn=accounts") != NULL) {
            prop->type = USER_GROUP;
            prop->prefix = SUDO_USER_GROUP_SING;
        }
    }
    else if (strcasecmp(attr_name, "memberHost") == 0 ) {
        /* ipa hosts and host groups attributes */

        if (strstr(attr_val, "cn=computers,cn=accounts") != NULL) {
            prop->type = HOST;
        } else if (strstr(attr_val, "cn=hostgroups,cn=accounts") != NULL) {
            prop->type = HOST_GROUP;
            prop->prefix = SUDO_HOSTGROUP_SING;
        }
    } else {
        // FIXME: add attributes that doesn't need to be copied to catch ilegat
        // attributes cases?
        prop->type = COPY;
    }

    /* copy orig name and value of the attribute */
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
    struct ldb_message_element *new_el = NULL;
    int i, j, k;
    errno_t ret = EOK;

    /* an array of exported sudoers (without commands) */
    struct sysdb_attrs **sudoers;
    sudoers = talloc_zero_array(mem, struct sysdb_attrs *, rules_count);
    sudoers[0] = sysdb_new_attrs(mem);
    *sudoers_count = 0;

    struct ipa_sudoer_cmds **cmds_index;
    cmds_index = talloc_zero_array(mem, struct ipa_sudoer_cmds *, rules_count);


    /* exported name and value of the attribute */
    const char *new_name;
    char *new_value;

    /* attributes properties for export */
    struct ipa_sudo_export *prop;


    /* for each rule aplicable to this host */
    for (i = 0; i < rules_count; i++) {

        /* new array for copied attributes 
        struct sysdb_attrs *attrs;
        attrs = talloc_zero(mem, struct sysdb_attrs);
        sudoers[i] = attrs;
        //attrs->a = talloc_zero_array(mem, struct ldb_message_element, ipa_rules[i]->num);
        */

        /* index of allowed and denied commands for this rules */
        cmds_index[i] = talloc_zero(mem, struct ipa_sudoer_cmds);

        /* for each attribute of the rule */
        for (j = 0; j < ipa_rules[i]->num; j++) {

            new_el = NULL;
            new_name = NULL;
            new_value = NULL;

            /* get element -> one attribute of the rule */
            e = &(ipa_rules[i]->a[j]);

            /* get new name for the attribute */
            ret = ipa_sudo_export_attr_name(mem, e->name, &new_name);
            if (ret != EOK) {
                goto fail;
            }

            /* export all value of the attribute */
            for (k = 0; k < e->num_values; k++) {
                ipa_sudo_export_set_properties(mem, e->name, (const char *)e->values[k].data, &prop);
                ipa_sudo_export_attr_value(mem, prop, sysdb, &new_value);

                /* For commands we build cmd_index but do not copy it's values into
                 * final sudoers.
                 */
                if (strcasecmp(e->name, "memberAllowCmd") == 0 ||
                    strcasecmp(e->name, "memberDenyCmd") == 0) {

                    ipa_sudo_add_cmd(mem, cmds_index[i], prop, e->name, new_value);
                    continue;
                }

                /* create new attribute or get the existing one based on the
                 * name of the attribute */
                ret = sysdb_attrs_get_el_ext(sudoers[i], new_name, true, &new_el);
                if (ret != EOK) {
                    // FIXME: can't get new attribute
                    goto fail;
                }

                /* add prefix to the value */
                //ret = ipa_sudo_export_add_value_prefix(sudoers, prop, &new_value);

                /* add exported value to the attribute */
                ret = sysdb_attrs_add_string(sudoers[i], new_name, new_value);
                if (ret != EOK) {
                    // FIXME: can't get new attribute
                    goto fail;
                }
            }
        }

        (*sudoers_count)++;
    }

    if (rules_count != *sudoers_count) {
        printf("Error: nezkopiroval jsem vsechny pravidla!\n");
        goto fail;
    }

    printf("sudoers \n===========\n");
    print_rules(sudoers, *sudoers_count);

    *exported_rules = talloc_steal(mem, sudoers);
    *index = cmds_index;

fail:
    return ret;
}


