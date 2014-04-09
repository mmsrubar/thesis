#include "providers/ipa/ipa_common.h"
#include "providers/ipa/ipa_sudo_cmd.h"
#include "providers/ipa/ipa_sudo_export.h"  // FIXME: just because of print_rules


/* ipa sudo rule attributes */
#define IPA_SUDO_RULE_OC            "ipaSudoRule"
#define IPA_SUDO_RULE_ALLOWCMD            "memberAllowCmd"
#define IPA_SUDO_RULE_DENYCMD            "memberDenyCmd"


/*
 * Return ipaUniqueID value out of DN which is in following form:
 * ipaUniqueID=6f545188-...-0800274dc10b,cn=sudocmds,cn=sudo,$DC
 */
static errno_t ipa_sudo_cmd_get_ipauniqueid(TALLOC_CTX *mem_ctx, 
                                            struct sysdb_ctx *sysdb, 
                                            const char *dn_str,
                                            char **ipa_unique_id)
{
    errno_t ret = EOK;

    struct ldb_dn *dn = NULL;
    const struct ldb_val *val;
    const char *rdn;
    char *id;

    TALLOC_CTX *tmp = talloc_new(NULL);

    dn = ldb_dn_new(tmp, sysdb_ctx_get_ldb(sysdb), dn_str);
    if (dn == NULL) {
        goto fail;
    }

    /* ipaUniqueID, sudocmds, sudo and least one domain component */
    if (ldb_dn_get_comp_num(dn) < 4) {
        ret = ENOENT;
        goto fail;
    }

    /* rdn must be 'ipaUniqueID' */
    rdn = ldb_dn_get_rdn_name(dn);
    if (rdn == NULL) {
        ret = EINVAL;
        goto fail;
    }

    if (strcasecmp("ipaUniqueID", rdn) != 0) {
        ret = ENOENT;
        goto fail;
    }

    /* second component must be 'cn=sudocmds' */
    rdn = ldb_dn_get_component_name(dn, 1);
    if (strcasecmp("cn", rdn) != 0) {
        ret = ENOENT;
        goto fail;
    }
    
    val = ldb_dn_get_component_val(dn, 1);
    if (strncasecmp("sudocmds", (const char *) val->data,
                    val->length) != 0) {
        ret = ENOENT;
        goto fail;
    }

    /* third component must be 'cn=sudo' */
    rdn = ldb_dn_get_component_name(dn, 2);
    if (strcasecmp("cn", rdn) != 0) {
        ret = ENOENT;
        goto fail;
    }

    val = ldb_dn_get_component_val(dn, 2);
    if (strncasecmp("sudo", (const char *) val->data,
                    val->length) != 0) {
        ret = ENOENT;
        goto fail;
    }

    val = ldb_dn_get_rdn_val(dn);
    id = talloc_strndup(tmp, (const char *)val->data, val->length);
    if (id == NULL) {
        ret = ENOMEM;
        goto fail;
    }

    *ipa_unique_id = talloc_steal(mem_ctx, id);

fail:
    talloc_free(tmp);
    return ret;
}

// FIXME: skip the command if it can't be parsed?
static errno_t ipa_cmd_get_filter(TALLOC_CTX *mem, 
                                  struct sysdb_ctx *sysdb,
                                  const char **values, 
                                  char **filter)
{
    TALLOC_CTX *tmp = NULL;
    char *ipa_unique_id = NULL;
    char *cmds_filter = *filter;
    int ret = EOK;

    /* for all commands (ipaUniquedID or DN of cmds group) 
     * FIXME: check if the cmd isn't already in filter because filter
     * length is limited
     */
    for (; *values != NULL; values = values+1) {

        /* DN of a command */
        if (strstr(*values, "ipaUniqueID") != NULL) {

            /* get value of the ipaUniqueID out of the dn of a command */
            // FIXME: replace this func name with get_third_....
            ret = ipa_sudo_cmd_get_ipauniqueid(tmp, sysdb, *values, &ipa_unique_id);
            if (ret != EOK) {
                DEBUG(SSSDBG_MINOR_FAILURE, 
                      ("Couldn't parse out ipaUniqueID based on DN\n"));
                return ret;
            }

            cmds_filter = talloc_asprintf_append_buffer(
                    cmds_filter, "(ipaUniqueID=%s)", ipa_unique_id);

            if (cmds_filter == NULL) {
                DEBUG(SSSDBG_MINOR_FAILURE, 
                      ("Couldn't add value of the ipaUniqueID to the commnads filter\n"));
                ret = ENOMEM;
                goto fail;
            }
        } 
        /* DN of commands group */
        else if (strstr(*values, cmds_filter) == NULL) { 
            cmds_filter = talloc_asprintf_append_buffer(cmds_filter, 
                                                        "(memberOf=%s)", *values);
            if (cmds_filter == NULL) {
                DEBUG(SSSDBG_MINOR_FAILURE, 
                      ("Couldn't add value of the ipaUniqueID to the commnads filter\n"));
                ret = ENOMEM;
                goto fail;
            }
        }
    }

    *filter = talloc_steal(mem, cmds_filter);

fail:
    talloc_free(tmp);
    return ret;
}




/* Build commands filter for all ipa rules aplicable to this host */
errno_t ipa_sudo_build_cmds_filter(TALLOC_CTX *mem,
                                   struct sysdb_ctx *sysdb,
                                   struct sysdb_attrs **rules, 
                                   int count, 
                                   const char **cmd_filter)
{
    TALLOC_CTX *tmp = NULL;
    const char *filter;
    const char **attr_vals;
    char *cmds_filter = NULL;

    int i;
    errno_t ret;

    filter = talloc_asprintf(tmp, "(&(objectClass=%s)(|", "ipasudocmd");
     //FIXME: ipa_sudocmds_map[SDAP_OC_SUDO_CMD].def_name);
    if (filter == NULL) {
        ret = ENOMEM;
        goto fail;
    }


    /* for all ipa rules aplicable to this host */
    for (i = 0; i < count; i++) {

        /* get values of the memberAllowCmd attr if any
         */
        if (sysdb_attrs_get_string_array(rules[i], 
                    IPA_SUDO_RULE_ALLOWCMD, tmp, &attr_vals) == EOK) {
            ret = ipa_cmd_get_filter(tmp, sysdb, attr_vals, &cmds_filter);
            if (ret != EOK) {
                goto fail;
            }
        }

        if (sysdb_attrs_get_string_array(rules[i], 
                    IPA_SUDO_RULE_DENYCMD, tmp, &attr_vals) == EOK) {
            ret = ipa_cmd_get_filter(tmp, sysdb, attr_vals, &cmds_filter);
            if (ret != EOK) {
                goto fail;
            }
        }
    }

    /* add commands and close the filter */
    filter = talloc_asprintf_append_buffer(filter, "%s))", cmds_filter);

    if (filter == NULL) {
        goto fail;
    }

    *cmd_filter = talloc_steal(mem, filter);

fail:
    talloc_free(tmp);
    return ret;
}

/* Pri kazdem zavolani vrati hodnotu attributu sudoCmd u kazdeho zaznamu kde se
 * nachazi attr_name=attr_value
 *
 * If attr_name is ipaUniqueID then it'l return value of sudoCmd attribute on a
 * first call and NULL on second call.
 *
 * If attr_name is DN of a commands group then it'l return sudoCmd on each call
 * and NULL if there are no more commands.
 */
const char *get_sudoCmd_value(TALLOC_CTX *mem,
                    struct sysdb_attrs **ipa_cmds,
                    int ipa_cmds_count, 
                    const char *attr_name,
                    const char *attr_value,
                    bool cmd_group)
{
    struct ldb_message_element *e = NULL;
    const char **values = NULL;
    const char **val;
    const char *sudo_cmd = NULL;

    static int i;  // optimatization static

    /* for each ipa cmd (continue where we stopped the last time) */
    for ( ; i < ipa_cmds_count; i++) {

        sysdb_attrs_get_string_array(ipa_cmds[i], attr_name, mem, &values);

        //FIXME:
        for (val = values; val != NULL && *val != NULL; val++) {
            
            if (strcasecmp(*val, attr_value) == 0) {
                /* searched ipa command found, returning value of sudoCmd */
                sysdb_attrs_get_string(ipa_cmds[i], "sudoCmd", &sudo_cmd);

                i++;    /* don't start in the same entry next time */
                return sudo_cmd;
            }
        }

        talloc_free(values);
    }

    /* no more sudoCmds for this group of ipa commands */
    i = 0;
    return NULL;
}

ipa_sudo_export_cmds(TALLOC_CTX *mem,
                     struct sysdb_attrs **sudoers,
                     int sudoers_count,
                     struct ipa_sudoer_cmds **index, 
                     struct sysdb_attrs **ipa_cmds,
                     int ipa_cmds_count)
{
    TALLOC_CTX *tmp = talloc_init(NULL);

    struct ldb_message_element *el;
    char *sudo_cmd = NULL;
    const char *attr_name;
    int i, j;
    errno_t ret = EOK;
    bool cmd_group = false;

    /* for each sudoer */
    for (i = 0; i < sudoers_count; i++) {

        /* are there any allowed commands for this sudoer? */
        if (index[i]->allowed_num != 0) {
            sysdb_attrs_get_el_ext(sudoers[i], "sudoCommand", true, &el);

            // FIXME: do the same for denied but add '!' prefix 
            /* for each allowed command */
            for (j = 0; j < index[i]->allowed_num; j++) {

                /* looking for a single command or a group? */
                if (strstr(index[i]->allowed[j], "cn=sudocmdgroups,cn=sudo") == NULL) {
                    attr_name = talloc_strdup(tmp, "ipaUniqueID");
                } else {
                    attr_name = talloc_strdup(tmp, "memberOf");
                    cmd_group = true;
                }
                if (attr_name == NULL) {
                    ret = ENOMEM;
                    goto fail;
                }


                while ((sudo_cmd = get_sudoCmd_value(tmp,
                    ipa_cmds,
                    ipa_cmds_count, 
                    attr_name,
                    index[i]->allowed[j], cmd_group)) != NULL) {

                    sysdb_attrs_add_string(sudoers[i], "sudoCommand", sudo_cmd);
                }
            }
        }
    }

fail:
    talloc_free(tmp);
    return ret;
}
