/*
    SSSD
    
    This module prepares parameters for refresh of IPA sudo rules. Parameters
    as LDAP or SYSDB filters are set based on a kind of refresh. There are 
    currently three kinds of refreshes:
      1) FULL Refersh
      2) SMART Refersh
      3) RULES Refersh

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
#include "providers/ldap/sdap_sudo.h"
#include "providers/ldap/sdap.h"
#include "providers/ldap/ldap_common.h"
#include "providers/ipa/ipa_sudo.h"
#include "providers/ipa/ipa_async_sudo.h"
#include "providers/ipa/ipa_async_sudo_hostgroups.h"
#include "providers/dp_backend.h"
#include "db/sysdb_sudo.h"

struct ipa_sudo_full_refresh_state {
    struct sdap_sudo_ctx *sudo_ctx;
    struct sdap_id_ctx *id_ctx;
    struct sysdb_ctx *sysdb;
    struct sss_domain_info *domain;
    int dp_error;
    int error;
};

struct ipa_sudo_smart_refresh_state {
    struct tevent_req *subreq;
    struct sdap_id_ctx *id_ctx;
    struct sysdb_ctx *sysdb;
};

struct ipa_sudo_rules_refresh_state {
    struct sdap_id_ctx *id_ctx;
    size_t num_rules;
    int dp_error;
    int error;
};

static void ipa_sudo_get_hostinfo_finish(struct tevent_req *subreq);
static void ipa_sudo_full_refresh_step(struct tevent_req *subreq);
static void ipa_sudo_full_refresh_done(struct tevent_req *subreq);
static void ipa_sudo_smart_refresh_done(struct tevent_req *subreq);
static void ipa_sudo_rules_refresh_done(struct tevent_req *subreq);

/* returns IPA LDAP host filter in the following format:
 * (hostCategory=ALL)(externalHost=...)(...)
 */
static char *ipa_sudo_build_host_filter(TALLOC_CTX *mem_ctx,
                                        struct sdap_attr_map *map,
                                        char *basedn,
                                        char *hostnames,
                                        char **ip_addr,
                                        char **hostgroups)
{
    TALLOC_CTX *tmp_ctx = NULL;
    char *filter = NULL;
    int i = 0;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "talloc_new() failed\n");
        return NULL;
    }

    /* ALL */
    filter = talloc_asprintf_append_buffer(filter, "(%s=ALL)",
                                           map[SDAP_AT_IPA_SUDO_HOST_CAT].name);
    if (filter == NULL) {
        goto done;
    }

    /* we specify the IPA host by FQDN */
    filter = talloc_asprintf_append_buffer(filter, IPA_HOST_FILTER,
                                           hostnames, basedn);
    if (filter == NULL) {
        goto done;
    }

    /* external host */
    filter = talloc_asprintf_append_buffer(filter, "(%s=%s)",
                                           map[SDAP_AT_IPA_SUDO_EXT_HOST].name,
                                           hostnames);
    if (filter == NULL) {
        goto done;
    }

    /* host groups */
    if (hostgroups != NULL) {
        for (i = 0; hostgroups[i] != NULL; i++) {

            filter = talloc_asprintf_append_buffer(filter, IPA_HOST_GROUP_FILTER,
                                                   hostgroups[i], basedn);
            if (filter == NULL) {
                goto done;
            }
        }
    }

    /* ip addresses and networks */
    if (ip_addr != NULL) {
        for (i = 0; ip_addr[i] != NULL; i++) {

            /* only external host can be specified by IP */
            filter = talloc_asprintf_append_buffer(filter, "(%s=%s)",
                                                   map[SDAP_AT_IPA_SUDO_EXT_HOST].name,
                                                   ip_addr[i]);
            if (filter == NULL) {
                goto done;
            }
        }
    }

    talloc_steal(mem_ctx, filter);

done:
    talloc_free(tmp_ctx);
    return filter;
}

static char *ipa_sudo_get_filter(TALLOC_CTX *mem_ctx,
                                 struct sdap_attr_map *map,
                                 struct sdap_sudo_ctx *sudo_ctx,
                                 const char *rule_filter)
{
    TALLOC_CTX *tmp_ctx = NULL;
    char *host_filter = NULL;
    char *filter = NULL;

    if (!sudo_ctx->use_host_filter) {
        return talloc_strdup(mem_ctx, rule_filter);
    }

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "talloc_new() failed\n");
        return NULL;
    }

    host_filter = ipa_sudo_build_host_filter(tmp_ctx, map,
                                             sudo_ctx->id_ctx->opts->sdom->basedn,
                                             sudo_ctx->ipa_hostname,
                                             sudo_ctx->ip_addr,
                                             sudo_ctx->ipa_hostgroups);
    if (host_filter == NULL) {
        goto done;
    }

    filter = talloc_asprintf(tmp_ctx, "(%s%s)",
                                 rule_filter, host_filter);
 
    //FIXME: 
    /*
    filter = sdap_get_id_specific_filter(tmp_ctx, rule_filter, host_filter);
    if (filter == NULL) {
        goto done;
    }
    */

    talloc_steal(mem_ctx, filter);

done:
    talloc_free(tmp_ctx);
    return filter;
}

/* issue a full refresh of sudo rules */
struct tevent_req *ipa_sudo_full_refresh_send(TALLOC_CTX *mem_ctx,
                                              struct tevent_context *ev,
                                              struct be_ctx *be_ctx,
                                              struct be_ptask *be_ptask,
                                              void *pvt)
{
    struct ipa_sudo_full_refresh_state *state = NULL;
    struct sdap_sudo_ctx *sudo_ctx = NULL;
    struct sdap_id_ctx *id_ctx = NULL;
    struct tevent_req *subreq = NULL;
    struct tevent_req *req = NULL;

    sudo_ctx = talloc_get_type(pvt, struct sdap_sudo_ctx);
    id_ctx = sudo_ctx->id_ctx;

    req = tevent_req_create(mem_ctx, &state, struct ipa_sudo_full_refresh_state);
    if (req == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "tevent_req_create() failed\n");
        return NULL;
    }

    sudo_ctx->full_refresh_in_progress = true;

    state->sudo_ctx = sudo_ctx;
    state->id_ctx = id_ctx;
    state->sysdb = id_ctx->be->domain->sysdb;
    state->domain = id_ctx->be->domain;

    /* get the hostgroups first */
    if (sudo_ctx->ipa_hostname == NULL) {
        /* if the hostname of the client isn't FQDN then we can't get sudo 
         * rules aplicable to a hostgroup but we can still use the other rules
         */
        DEBUG(SSSDBG_MINOR_FAILURE, "Hostname isn't FQDN - unable to get "
                                    "hostgroups - (sudo won't work correctly\n");
        ipa_sudo_full_refresh_step(req);
        return req;
    }

    subreq = ipa_sudo_get_hostgroups_send(sudo_ctx, sudo_ctx);
    if (subreq == NULL) {
        DEBUG(SSSDBG_MINOR_FAILURE, "Unable to get hostgroups - (sudo won't "
                                    "work correctly)\n");
        ipa_sudo_full_refresh_step(req);
        return req;
    }
 
    tevent_req_set_callback(subreq, ipa_sudo_get_hostinfo_finish, req);
    return req;
}

static void ipa_sudo_get_hostinfo_finish(struct tevent_req *subreq)
{
    struct ipa_sudo_full_refresh_state *state;
    struct sdap_sudo_ctx *sudo_ctx;
    struct sysdb_attrs **hostgroups;
    struct tevent_req *req;
    const char *group_name;
    size_t hostgroup_count;
    errno_t ret;
    int dp_error;
    int error;
    int i;

    req = tevent_req_callback_data(subreq, struct tevent_req);
    state = tevent_req_data(req, struct ipa_sudo_full_refresh_state);

    sudo_ctx = state->sudo_ctx;

    ret = ipa_sudo_get_hostgroups_recv(subreq, sudo_ctx, &dp_error, &error,
                                       &hostgroups, &hostgroup_count);
    talloc_zfree(subreq);
    if (ret != EOK || state->dp_error != DP_ERR_OK || state->error != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to retrieve hostgroups information - "
                                    "(sudo won't work correctly)\n");
        ipa_sudo_full_refresh_step(req);
    }

    sudo_ctx->ipa_hostgroups = talloc_zero_array(sudo_ctx, char *, hostgroup_count+1);
    if (sudo_ctx->ipa_hostgroups == NULL) {
        DEBUG(SSSDBG_FATAL_FAILURE, "talloc_zero_array() failed\n");
        return;
    }

    for (i = 0; i < hostgroup_count; i++) {

        ret = sysdb_attrs_get_string(hostgroups[i], "name", &group_name);
        if (ret != EOK) {
            DEBUG(SSSDBG_CRIT_FAILURE, "Unable to get common name of a "
                        "hostgroup. Trying another hostgroup record.\n");
            continue;
        }

        sudo_ctx->ipa_hostgroups[i] = talloc_strdup(sudo_ctx->ipa_hostgroups, 
                                                group_name);
    }

    sudo_ctx->ipa_hostgroups[hostgroup_count] = NULL;
    ipa_sudo_full_refresh_step(req);
}

static void ipa_sudo_full_refresh_step(struct tevent_req *req)
{
    struct ipa_sudo_full_refresh_state *state;
    struct tevent_req *subreq;
    struct sdap_sudo_ctx *sudo_ctx;
    struct sdap_id_ctx *id_ctx = NULL;
    char *ldap_full_filter = NULL;
    char *sysdb_filter = NULL;
    char *ldap_filter = NULL;
    int ret = EOK;
 
    state = tevent_req_data(req, struct ipa_sudo_full_refresh_state);
    sudo_ctx = state->sudo_ctx;
    id_ctx = state->id_ctx;

     /* filter will match all enabled and aplicable sudo rules to this host at IPA */
    ldap_filter = talloc_asprintf(state, IPA_SUDO_FULL_FILTER,
                    sudo_ctx->id_ctx->opts->ipa_sudorule_map[SDAP_OC_SUDORULE].name);
    if (ldap_filter == NULL) {
        ret = ENOMEM;
        goto immediately;
    }

    ldap_full_filter = ipa_sudo_get_filter(state, id_ctx->opts->ipa_sudorule_map,
                                           sudo_ctx, ldap_filter);
    if (ldap_full_filter == NULL) {
        ret = ENOMEM;
        goto immediately;
    }

    /* close the filter */
    ldap_full_filter = talloc_strdup_append_buffer(ldap_full_filter, ")");
    if (ldap_full_filter == NULL) {
        ret = ENOMEM;
        goto immediately;
    }

    /* Remove all rules from cache */
    sysdb_filter = talloc_asprintf(state, "(%s=%s)",
                                   SYSDB_OBJECTCLASS, SYSDB_SUDO_CACHE_OC);
    if (sysdb_filter == NULL) {
        ret = ENOMEM;
        goto immediately;
    }

    DEBUG(SSSDBG_TRACE_FUNC, "Issuing a full refresh of IPA sudo rules\n");

    subreq = ipa_sudo_refresh_send(state, id_ctx->be, id_ctx->opts,
                                   id_ctx->conn->conn_cache,
                                   ldap_full_filter, sysdb_filter);
    if (subreq == NULL) {
        ret = ENOMEM;
        goto immediately;
    }

    tevent_req_set_callback(subreq, ipa_sudo_full_refresh_done, req);

    /* free filters */
    talloc_free(ldap_filter);
    talloc_free(ldap_full_filter);
    talloc_free(sysdb_filter);

    return;

immediately:
    if (ret == EOK) {
        tevent_req_done(req);
    } else {
        tevent_req_error(req, ret);
    }
    tevent_req_post(req, id_ctx->be->ev);
}

static void ipa_sudo_full_refresh_done(struct tevent_req *subreq)
{
    struct tevent_req *req = NULL;
    struct ipa_sudo_full_refresh_state *state = NULL;
    char *highest_usn = NULL;
    int ret;

    req = tevent_req_callback_data(subreq, struct tevent_req);
    state = tevent_req_data(req, struct ipa_sudo_full_refresh_state);

    ret = ipa_sudo_refresh_recv(state, subreq, &state->dp_error,
                                &state->error, &highest_usn, NULL, NULL);
    talloc_zfree(subreq);
    if (ret != EOK || state->dp_error != DP_ERR_OK || state->error != EOK) {
        goto done;
    }

    state->sudo_ctx->full_refresh_done = true;

    /* save the time in the sysdb */
    ret = sysdb_sudo_set_last_full_refresh(state->domain, time(NULL));
    if (ret != EOK) {
        DEBUG(SSSDBG_MINOR_FAILURE, "Unable to save time of "
                                    "a successful full refresh\n");
        /* this is only a minor error that does not affect the functionality,
         * therefore there is no need to report it with tevent_req_error()
         * which would cause problems in the consumers */
    }

    DEBUG(SSSDBG_TRACE_FUNC, "Successful full refresh of IPA sudo rules\n");

    /* set highest usn */
    if (highest_usn != NULL) {
        sdap_sudo_set_usn(state->id_ctx->srv_opts, highest_usn);
    }

done:
    state->sudo_ctx->full_refresh_in_progress = false;

    if (ret != EOK) {
        tevent_req_error(req, ret);
        return;
    }

    tevent_req_done(req);
}

/* Full refresh can be perform by ptask or as request from SUDO responder. 
 * Prototype of a ptask recv func is different than recv func in sudo reply 
 * so full refresh request has to have two recv functions */
int ipa_sudo_full_refresh_recv(struct tevent_req *req,
                               int *dp_error,
                               int *error)
{
    struct ipa_sudo_full_refresh_state *state = NULL;
    state = tevent_req_data(req, struct ipa_sudo_full_refresh_state);

    TEVENT_REQ_RETURN_ON_ERROR(req);

    *dp_error = state->dp_error;
    *error = state->error;

    return EOK;
}

int ipa_sudo_full_refresh_ptask_recv(struct tevent_req *req)
{
    TEVENT_REQ_RETURN_ON_ERROR(req);
    return EOK;
}

/* issue a smart refresh of IPA SUDO rules */
struct tevent_req *ipa_sudo_smart_refresh_send(TALLOC_CTX *mem_ctx,
                                   struct tevent_context *ev,
                                   struct be_ctx *be_ctx,
                                   struct be_ptask *be_ptask,
                                   void *pvt)
{
    struct tevent_req *req = NULL;
    struct tevent_req *subreq = NULL;
    struct sdap_id_ctx *id_ctx = NULL;
    struct sdap_sudo_ctx *sudo_ctx = NULL;
    struct sdap_attr_map *map = NULL;
    struct sdap_server_opts *srv_opts = NULL;
    struct ipa_sudo_smart_refresh_state *state = NULL;
    char *ldap_filter = NULL;
    char *ldap_smart_filter = NULL;
    const char *usn;
    int ret = EOK;

    sudo_ctx = talloc_get_type(pvt, struct sdap_sudo_ctx);
    id_ctx = sudo_ctx->id_ctx;
    map = id_ctx->opts->ipa_sudorule_map;
    srv_opts = id_ctx->srv_opts;
 
    req = tevent_req_create(mem_ctx, &state, struct ipa_sudo_smart_refresh_state);
    if (req == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, ("tevent_req_create() failed\n"));
        return NULL;
    }

    if (!sudo_ctx->full_refresh_done
            && (srv_opts == NULL || srv_opts->max_sudo_value == 0)) {
        /* Perform full refresh first */
        DEBUG(SSSDBG_TRACE_FUNC, "USN value is unknown, "
                                 "waiting for a full refresh!\n");
        ret = EINVAL;
        goto immediately;
    }

    state->id_ctx = id_ctx;
    state->sysdb = id_ctx->be->domain->sysdb;

    /* Download all rules from LDAP that are newer than usn */
    usn = srv_opts->max_sudo_value;
    if (usn != NULL) {
        ldap_filter = talloc_asprintf(state, IPA_SUDO_SMART_FILTER,
                                      map[SDAP_OC_IPA_SUDORULE].name,
                                      map[SDAP_AT_IPA_SUDO_USN].name, usn,
                                      map[SDAP_AT_IPA_SUDO_USN].name, usn);
    } else {
        /* no valid USN value known, match any sudo rule */
        ldap_filter = talloc_asprintf(state, IPA_SUDO_FULL_FILTER,
                                      map[SDAP_OC_SUDORULE].name);
    }
    if (ldap_filter == NULL) {
        ret = ENOMEM;
        goto immediately;
    }

    ldap_smart_filter = ipa_sudo_get_filter(state, map, sudo_ctx, ldap_filter);
    if (ldap_smart_filter == NULL) {
        ret = ENOMEM;
        goto immediately;
    }

    /* close the filter */
    ldap_smart_filter = talloc_asprintf_append_buffer(ldap_smart_filter, ")");
    if (ldap_smart_filter == NULL) {
        goto immediately;
    }

    /* Do not remove any rules that are already in the sysdb
     * sysdb_filter = NULL;
     */

    DEBUG(SSSDBG_TRACE_FUNC, "Issuing a smart refresh of IPA sudo rules "
                             "(USN > %s)\n", (usn == NULL ? "0" : usn));

    subreq = ipa_sudo_refresh_send(state, id_ctx->be, id_ctx->opts,
                                    id_ctx->conn->conn_cache,
                                    ldap_smart_filter, NULL);
    if (subreq == NULL) {
        ret = ENOMEM;
        goto immediately;
    }

    state->subreq = subreq;
    tevent_req_set_callback(subreq, ipa_sudo_smart_refresh_done, req);

    /* free filters */
    talloc_free(ldap_filter);
    talloc_free(ldap_smart_filter);

    return req;

immediately:
    if (ret == EOK) {
        tevent_req_done(req);
    } else {
        tevent_req_error(req, ret);
    }
    tevent_req_post(req, id_ctx->be->ev);

    return req;
}

static void ipa_sudo_smart_refresh_done(struct tevent_req *subreq)
{
    struct tevent_req *req = NULL;
    struct ipa_sudo_smart_refresh_state *state = NULL;
    char *highest_usn = NULL;
    int dp_error;
    int error;
    int ret;

    req = tevent_req_callback_data(subreq, struct tevent_req);
    state = tevent_req_data(req, struct ipa_sudo_smart_refresh_state);

    ret = ipa_sudo_refresh_recv(state, subreq, &dp_error, &error,
                                 &highest_usn, NULL, NULL);
    if (ret != EOK || dp_error != DP_ERR_OK || error != EOK) {
        goto done;
    }

    DEBUG(SSSDBG_TRACE_FUNC, "Successful smart refresh of IPA sudo rules\n");

    /* set highest usn */
    if (highest_usn != NULL) {
        sdap_sudo_set_usn(state->id_ctx->srv_opts, highest_usn);
    }

done:
    if (ret != EOK) {
        tevent_req_error(req, ret);
        return;
    }

    tevent_req_done(req);
}

int ipa_sudo_smart_refresh_recv(struct tevent_req *req)
{
    TEVENT_REQ_RETURN_ON_ERROR(req);
    return EOK;
}

/* issue a refresh of specific sudo rules */
struct tevent_req *ipa_sudo_rules_refresh_send(TALLOC_CTX *mem_ctx,
                                               struct sdap_sudo_ctx *sudo_ctx,
                                               struct be_ctx *be_ctx,
                                               struct sdap_options *opts,
                                               struct sdap_id_conn_cache *conn_cache,
                                               char **rules)
{
    struct tevent_req *req = NULL;
    struct tevent_req *subreq = NULL;
    struct ipa_sudo_rules_refresh_state *state = NULL;
    TALLOC_CTX *tmp_ctx = NULL;
    char *ldap_filter = NULL;
    char *ldap_rules_filter = NULL;
    char *sysdb_filter = NULL;
    char *safe_rule = NULL;
    int ret = EOK;
    int i;

    if (rules == NULL) {
        return NULL;
    }

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "talloc_new() failed\n");
        return NULL;
    }

    req = tevent_req_create(mem_ctx, &state, struct ipa_sudo_rules_refresh_state);
    if (req == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "tevent_req_create() failed\n");
        return NULL;
    }

    ldap_filter = talloc_zero(tmp_ctx, char);
    sysdb_filter = talloc_zero(tmp_ctx, char);

    /* Download only selected rules from IPA and remove all selected rules from
     * cache */
    for (i = 0; rules[i] != NULL; i++) {
        ret = sss_filter_sanitize(tmp_ctx, rules[i], &safe_rule);
        if (ret != EOK) {
            ret = ENOMEM;
            goto immediately;
        }

        ldap_filter = talloc_asprintf_append_buffer(ldap_filter, "(%s=%s)",
                                     opts->ipa_sudorule_map[SDAP_AT_SUDO_NAME].name,
                                     safe_rule);
        if (ldap_filter == NULL) {
            ret = ENOMEM;
            goto immediately;
        }

        sysdb_filter = talloc_asprintf_append_buffer(sysdb_filter, "(%s=%s)",
                                                     SYSDB_SUDO_CACHE_AT_CN,
                                                     safe_rule);
        if (sysdb_filter == NULL) {
            ret = ENOMEM;
            goto immediately;
        }
    }

    state->id_ctx = sudo_ctx->id_ctx;
    state->num_rules = i;

    ldap_filter = talloc_asprintf(tmp_ctx, IPA_SUDO_RULES_FILTER,
                                  opts->ipa_sudorule_map[SDAP_OC_IPA_SUDORULE].name,
                                  ldap_filter);
    if (ldap_filter == NULL) {
        ret = ENOMEM;
        goto immediately;
    }

    ldap_rules_filter = ipa_sudo_get_filter(tmp_ctx, opts->ipa_sudorule_map,
                                           sudo_ctx, ldap_filter);
    if (ldap_rules_filter == NULL) {
        ret = ENOMEM;
        goto immediately;
    }

    /* close the filter */
    ldap_rules_filter = talloc_asprintf_append_buffer(ldap_rules_filter, ")");
    if (ldap_rules_filter == NULL) {
        goto immediately;
    }


    sysdb_filter = talloc_asprintf(tmp_ctx, "(&(%s=%s)(|%s))",
                                   SYSDB_OBJECTCLASS, SYSDB_SUDO_CACHE_OC,
                                   sysdb_filter);
    if (sysdb_filter == NULL) {
        ret = ENOMEM;
        goto immediately;
    }

    subreq = ipa_sudo_refresh_send(req, be_ctx, opts, conn_cache,
                                    ldap_rules_filter, sysdb_filter);

    if (subreq == NULL) {
        ret = ENOMEM;
        goto immediately;
    }

    tevent_req_set_callback(subreq, ipa_sudo_rules_refresh_done, req);

immediately:
    talloc_free(tmp_ctx);

    if (ret != EOK) {
        tevent_req_error(req, ret);
        tevent_req_post(req, be_ctx->ev);
    }

    return req;
}

static void ipa_sudo_rules_refresh_done(struct tevent_req *subreq)
{
    struct tevent_req *req = NULL;
    struct ipa_sudo_rules_refresh_state *state = NULL;
    char *highest_usn = NULL;
    size_t downloaded_rules_num;
    int ret;

    req = tevent_req_callback_data(subreq, struct tevent_req);
    state = tevent_req_data(req, struct ipa_sudo_rules_refresh_state);

    ret = ipa_sudo_refresh_recv(state, subreq, &state->dp_error, &state->error,
                                 &highest_usn, &downloaded_rules_num, NULL);
    talloc_zfree(subreq);
    if (ret != EOK || state->dp_error != DP_ERR_OK || state->error != EOK) {
        goto done;
    }

    /* set highest usn */
    if (highest_usn != NULL) {
        sdap_sudo_set_usn(state->id_ctx->srv_opts, highest_usn);
    }

    if (downloaded_rules_num != state->num_rules) {
        state->error = ENOENT;
    }

done:
    if (ret != EOK) {
        tevent_req_error(req, ret);
        return;
    }

    tevent_req_done(req);
}

int ipa_sudo_rules_refresh_recv(struct tevent_req *req,
                                int *dp_error,
                                int *error)
{
    struct ipa_sudo_rules_refresh_state *state = NULL;
    state = tevent_req_data(req, struct ipa_sudo_rules_refresh_state);

    TEVENT_REQ_RETURN_ON_ERROR(req);

    *dp_error = state->dp_error;
    *error = state->error;

    return EOK;
}
