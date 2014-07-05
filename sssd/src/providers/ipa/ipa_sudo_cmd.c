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


/* Take values of a memberAllowCmd or memberDenyCmd attribute and return 
 * these values as LDAP filter.
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

    /* for all values (ipaUniquedID or DN of a cmds group) 
     * FIXME: check if the cmd isn't already in a filter because the length of 
     * the filter is limited
     */
    for (; *values != NULL; values = values+1) {

        /* DN of a command => we need to get value of ipaUniqueID */
        if (strstr(*values, IPA_SUDO_CONTAINER_CMDS) != NULL) {

            ret = get_third_rdn_value(tmp, sysdb, *values, IPA_SUDO_ATTR_ID, 
                            "cn", "sudocmds", "cn", "sudo", &ipa_unique_id);
            if (ret != EOK) {
                DEBUG(SSSDBG_MINOR_FAILURE, 
                      ("Couldn't parse out the ipaUniqueID out of the DN\n"));
                ret = ENOMEM;
                goto fail;
            }

            cmds_filter = talloc_asprintf_append_buffer(
                    cmds_filter, "(ipaUniqueID=%s)", ipa_unique_id);
            if (cmds_filter == NULL) {
                DEBUG(SSSDBG_MINOR_FAILURE, 
                      ("Couldn't add value of an ipaUniqueID to the commnads filter\n"));
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
                      ("Couldn't add DN of a cmds group to the commnads filter\n"));
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
 * Build LDAP filter that will match all only neceary sudo command for
 * downloaded ipa sudo rules in IPA SUDO schema.
 *
 * If it fails, we can't get ipa sudo commands => we don't have complete
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

    /* no ipa sudo rules -> nothing to build the new filter from */
    if (rules == NULL && count == 0) {
        DEBUG(SSSDBG_FATAL_FAILURE, ("ipa_sudo_build_cmds_filter() "
                                     "no ipa sudo rules\n"));
        return ENOENT;
    }

    DEBUG(SSSDBG_TRACE_FUNC,
          ("Building filter out of IPA sudo rules to get sudo commands "
           "for those rules\n"));

    filter = talloc_asprintf(tmp, IPA_SUDO_CMD_FILTER, "ipasudocmd");
    if (filter == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, ("talloc_asprint() failed\n"));
        ret = ENOMEM;
        goto fail;
    }

    /* for all downloaded ipa sudo rules */
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
          ("No sudo commands needed by downloaded IPA sudo rules\n"));
        ret = ENOENT;
    }

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

    DEBUG(SSSDBG_TRACE_FUNC, ("Building commands index for: %s\n", command));

    if (strcasecmp(name, IPA_SUDO_ATTR_ALLOW_CMD) == 0) {

        /* make a space for one more command */
        cmds->allowed = talloc_realloc(mem, cmds->allowed, const char *, 
                                       cmds->allowed_num+1);
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


