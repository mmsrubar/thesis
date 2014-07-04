/*
    SSSD

    Helper routines for exporting IPA SUDO commands.

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


#include "providers/ipa/ipa_common.h"
#include "providers/ipa/ipa_sudo_export.h"
#include "providers/ipa/ipa_sudo_cmd.h"
#include "providers/ipa/ipa_sudo.h"
#include "db/sysdb_sudo.h"


/* Takes values of a member{Allow,Deny}Cmd attribute and returns this values in
 * filter
 */
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

    /* for all values (ipaUniquedID or DN of cmds group) 
     * FIXME: check if the cmd isn't already in filter because filter
     * length is limited
     */
    for (; *values != NULL; values = values+1) {

        /* DN of a command => we need to get value of ipaUniqueID */
        if (strstr(*values, IPA_SUDO_CONTAINER_CMDS) != NULL) {

            ret = get_third_rdn_value(tmp, sysdb, *values, IPA_SUDO_ATTR_ID, 
                            "cn", "sudocmds", "cn", "sudo", &ipa_unique_id);
            if (ret != EOK) {
                DEBUG(SSSDBG_MINOR_FAILURE, 
                      ("Couldn't parse out the ipaUniqueID out of the DN\n"));
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
        else if (strstr(*values, IPA_SUDO_CONTAINER_CMD_GRPS) != NULL) { 
            cmds_filter = talloc_asprintf_append_buffer(cmds_filter, 
                                   "(%s=%s)", IPA_SUDO_ATTR_MEMBEROF, *values);
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

/* 
 * Build commands filter which will download necessary ipa sudo commands for
 * rules aplicable to this host. 
 *
 * When it fails, we can't get ipa sudo commands => we don't have complete
 * sudoers so we can't store rules into sysdb!
 *
 * FIXME: 
 * optimalization: this could be done in first iteration through the sudo rules
 */
errno_t ipa_sudo_build_cmds_filter(TALLOC_CTX *mem,
                                   struct sysdb_ctx *sysdb,
                                   struct sysdb_attrs **rules, 
                                   int count, 
                                   const char **cmd_filter)
{
    TALLOC_CTX *tmp = NULL;
    const char **attr_vals;
    char *cmds_filter = NULL;
    char *filter;
    errno_t ret = EOK;
    int i;

    /* no ipa sudo rules -> nothing to build new filter from */
    if (rules == NULL || count == 0) {
        return ENOENT;
        DEBUG(SSSDBG_TRACE_FUNC, ("No IPA sudo rules necessary for building "
                                  "LDAP filter for commands\n"));
    }

    DEBUG(SSSDBG_TRACE_FUNC,
          ("Building filter out of IPA SUDO rules to get IPA SUDO commands "
           "for those rules.\n"));

    filter = talloc_asprintf(tmp, IPA_SUDO_CMD_FILTER, "ipasudocmd");
    if (filter == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, ("talloc_asprint() failed\n"));
        ret = ENOMEM;
        goto fail;
    }

    /* for all ipa rules aplicable to this host */
    for (i = 0; i < count; i++) {

        /* get values of a memberAllowCmd attr if any  */
        if (sysdb_attrs_get_string_array(rules[i], 
                    IPA_SUDO_ATTR_ALLOW_CMD, tmp, &attr_vals) == EOK) {

            ret = ipa_cmd_get_filter(tmp, sysdb, attr_vals, &cmds_filter);
            if (ret != EOK) {
                goto fail;
            }
        }

        /* get values of a memberDenyCmd attr if any  */
        if (sysdb_attrs_get_string_array(rules[i], 
                    IPA_SUDO_ATTR_DENY_CMD, tmp, &attr_vals) == EOK) {
            ret = ipa_cmd_get_filter(tmp, sysdb, attr_vals, &cmds_filter);
            if (ret != EOK) {
                goto fail;
            }
        }
    }
 
    /* join object class with ipa sudo cmds to get final filter */
    filter = talloc_asprintf_append_buffer(filter, "%s))", cmds_filter);
    if (filter == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, ("talloc_asprintf_append_buffer() failed\n"));
        ret = ENOMEM;
        goto fail;
    }

    *cmd_filter = talloc_steal(mem, filter);

    /* no ipa commands needed by these ipa sudo rules */
    if (cmds_filter == NULL) {
        DEBUG(SSSDBG_TRACE_FUNC,
          ("No IPA sudo commands needed for downloaded IPA sudo rules\n"));
        ret = ENOENT;
    }

fail:
    talloc_free(tmp);
    return ret;
}

/* If attr_name is ipaUniqueID then it'l return value of sudoCmd attribute on a
 * first call and NULL on second call.
 *
 * If attr_name is DN of a commands group then it'l return sudoCmd on each call
 * and NULL if there are no more commands.
 */
static const char *get_sudoCmd_value(TALLOC_CTX *mem,
                                     struct sysdb_attrs **ipa_cmds,
                                     int ipa_cmds_count, 
                                     const char *attr_name,
                                     const char *attr_value,
                                     bool cmd_group)
{
    const char **values = NULL;
    const char **val;
    const char *sudo_cmd = NULL;
    const char *tmp = NULL;

    static int i;

    /* for each ipa cmd (continue where we stopped the last time) */
    for ( ; i < ipa_cmds_count; i++) {

        sysdb_attrs_get_string_array(ipa_cmds[i], attr_name, mem, &values);

        //FIXME:
        for (val = values; val != NULL && *val != NULL; val++) {
            
            if (strcasecmp(*val, attr_value) == 0) {
                /* searched ipa command found, returning value of sudoCmd */
                sysdb_attrs_get_string(ipa_cmds[i], IPA_SUDO_ATTR_CMD, &tmp);

                i++;    /* don't start in the same entry next time */
                sudo_cmd = talloc_strdup(mem, tmp);     // FIXME: check return val
                return sudo_cmd;
            }
        }

        //talloc_zfree(values);
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

    //print_rules(ipa_cmds, ipa_cmds_count);
    
    if (cmds == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, ("No ipa command index\n"));
    }

    /* create sudoCommand attribute if there isn't yet */
    sysdb_attrs_get_el_ext(sudoers, SYSDB_SUDO_CACHE_AT_COMMAND, true, &el);

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
            attr_name, cmds[j], cmd_group)) != NULL)
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

    //print_rules(ipa_cmds, ipa_cmds_count);
fail:
    talloc_free(tmp);
    return ret;
}

/* Add a denied or allowed command of a rule into command index. */
errno_t ipa_sudo_index_commands(TALLOC_CTX *mem, 
                                struct ipa_sudoer_cmds *cmds, 
                                const char *name, 
                                const char *command)
{
    errno_t ret = EOK;

    DEBUG(SSSDBG_TRACE_FUNC,
          ("Building commands index for: %s\n", command));

    if (strcasecmp(name, IPA_SUDO_ATTR_ALLOW_CMD) == 0) {

        /* make a space for one more command */
        cmds->allowed = talloc_realloc(mem, cmds->allowed, const char *, cmds->allowed_num+1);
        if (cmds->allowed == NULL) {
            DEBUG(SSSDBG_CRIT_FAILURE, ("talloc_realloc() failed\n"));
            ret = ENOMEM;
            goto fail;
        }

        /* add new cmd or DN of a group of commands */
        cmds->allowed[cmds->allowed_num] = talloc_strdup(mem, command);
        if (cmds->allowed[cmds->allowed_num] == NULL) {
            DEBUG(SSSDBG_CRIT_FAILURE, ("talloc_strdup() failed\n"));
            ret = ENOMEM;
            goto fail;
        }

        cmds->allowed_num++;
    }
    else if (strcasecmp(name, IPA_SUDO_ATTR_DENY_CMD) == 0) {

        /* make a space for one more command */
        cmds->denied = talloc_realloc(mem, cmds->denied, const char *, cmds->denied_num+1);
        if (cmds->denied == NULL) {
            DEBUG(SSSDBG_CRIT_FAILURE, ("talloc_realloc() failed\n"));
            ret = ENOMEM;
            goto fail;
        }

        /* add new cmd or DN to group of commands */
        cmds->denied[cmds->denied_num] = talloc_strdup(mem, command);
        if (cmds->denied[cmds->denied_num] == NULL) {
            DEBUG(SSSDBG_CRIT_FAILURE, ("talloc_strdup() failed\n"));
            ret = ENOMEM;
            goto fail;
        }

        cmds->denied_num++;
    }
    else {
        DEBUG(SSSDBG_CRIT_FAILURE, ("Unknown IPA SUDO command attribute\n"));
        ret = ENOENT;
        goto fail;
    }

fail:
    return ret;
}

int ipa_sudo_export_cmds(TALLOC_CTX *mem,
                         struct sysdb_attrs **sudoers,
                         int sudoers_count,
                         struct ipa_sudoer_cmds **index, 
                         struct sysdb_attrs **ipa_cmds,
                         int ipa_cmds_count)
{
    errno_t ret = EOK;
    int i;

    DEBUG(SSSDBG_TRACE_FUNC, ("Exporting IPA SUDO commands\n"));

    /* for each sudoer */
    for (i = 0; i < sudoers_count; i++) {

        /* are there any allowed commands for this sudoer? */
        if (index[i]->allowed_num != 0) {
            ret = ipa_sudo_assign_command(sudoers[i], ipa_cmds, ipa_cmds_count, 
                                    index[i]->allowed, index[i]->allowed_num, false);
            if (ret != EOK) {
                goto fail;
            }
        }

        /* same for denied commands */
        if (index[i]->denied_num != 0) {
            ret = ipa_sudo_assign_command(sudoers[i], ipa_cmds, ipa_cmds_count, 
                                    index[i]->denied, index[i]->denied_num, true);
            if (ret != EOK) {
                goto fail;
            }
        }
    }
fail:
    return ret;
}
