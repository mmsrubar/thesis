/*
    SSSD

    Async IPA module for getting sudo commands.

    - this module is used by ipa_async_sudo.c to get sudo commands for 
        donwloaded IPA SUDO rules
    - sudo commands are dowloaded after we got the rules because commands are 
        in separate container at IPA
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

#include "db/sysdb_sudo.h"
#include "providers/ldap/sdap_async.h"
#include "providers/ldap/sdap.h"
#include "providers/ipa/ipa_common.h"
#include "providers/ipa/ipa_sudo_export.h"
#include "providers/ipa/ipa_sudo.h"

static errno_t ipa_sudo_get_cmds_retry(struct tevent_req *req);
static void ipa_sudo_get_cmds_connect_done(struct tevent_req *subreq);
static void ipa_sudo_cmds_process(struct tevent_req *subreq);

struct ipa_sudo_get_cmds_state {

    struct be_ctx *be_ctx;
    struct sdap_id_op *sdap_op;
    struct sysdb_ctx *sysdb;
    struct tevent_context *ev;
    struct sdap_id_conn_cache *conn_cache;
    struct sdap_options *opts;

    const char *filter;     /* LDAP filter for IPA sudo commands */
    const char *basedn;
    const char **attrs;
    int scope;
    int timeout;

    int dp_error;
    int error;

    struct sudo_rules *rules;
};

struct tevent_req *ipa_sudo_get_cmds_send(TALLOC_CTX *mem,
                                          struct sysdb_attrs **ipa_rules,
                                          int ipa_rules_count,
                                          struct be_ctx *be_ctx,
                                          struct sdap_id_conn_cache *conn_cache,
                                          struct sdap_options *opts)
{
    struct ipa_sudo_get_cmds_state *state;
    struct tevent_req *req;
    errno_t ret = EOK;
    errno_t cmds_ret = EOK;

    req = tevent_req_create(mem, &state, struct ipa_sudo_get_cmds_state);
    if (!req) {
        DEBUG(SSSDBG_FATAL_FAILURE, "tevent_req_create() failed\n");
        return NULL;
    }

    state->be_ctx = be_ctx;
    state->sdap_op = NULL;
    state->opts = opts;
    state->sysdb = be_ctx->domain->sysdb;
    state->ev = be_ctx->ev;
    state->conn_cache = conn_cache;

    state->filter = NULL;
    state->basedn = talloc_strdup(state, IPA_SUDO_CMDS_BASEDN);
    state->attrs = NULL;
    state->scope = LDAP_SCOPE_SUBTREE;
    state->timeout = dp_opt_get_int(opts->basic, SDAP_SEARCH_TIMEOUT);

    state->dp_error = DP_ERR_OK;
    state->error = EOK;

    state->rules = talloc_zero(state, struct sudo_rules);
    if (state->rules == NULL) {
        DEBUG(SSSDBG_FATAL_FAILURE, "talloc_zero() failed\n");
        ret = ENOMEM;
        goto immediately;
    }

    state->rules->ipa_rules = talloc_steal(state->rules, ipa_rules);
    state->rules->ipa_rules_count = ipa_rules_count;

    if (state->basedn == NULL) {
        DEBUG(SSSDBG_FATAL_FAILURE, "talloc_strdup() failed\n");
        ret = ENOMEM;
        goto immediately;
    }
 
    DEBUG(SSSDBG_TRACE_FUNC, "Getting commands for downloaded IPA SUDO rules\n");

    cmds_ret = build_cmds_filter(state, state->sysdb, ipa_rules, 
                                 ipa_rules_count, &(state->filter));
    if (cmds_ret != ENOENT && cmds_ret != EOK) {
        /* an error has occured */
        ret = cmds_ret;
        goto immediately;
    }

    /* EXPORT sudo rules but skip commands */
    ret = export_sudoers(state, state->sysdb,
                         state->rules->ipa_rules, 
                         state->rules->ipa_rules_count, 
                         &(state->rules->sudoers),
                         &(state->rules->sudoers_count),
                         &(state->rules->cmds_index),
                         req);
    if (ret != EOK) {
        goto immediately;
    } else if (ret == EOK && cmds_ret == ENOENT) {
        /* ipa sudoers exported and if building cmds filter returned ENOENT 
         * then we don't need to download any ipa sudo commands */
        goto immediately;
    }

    ret = ipa_sudo_get_cmds_retry(req);
    if (ret == EAGAIN) {
        return req;
    }

immediately:
    if (ret == EOK) {
        tevent_req_done(req);
    } else {
        tevent_req_error(req, ret);
    }
    tevent_req_post(req, state->ev);

    return req;
}

int ipa_sudo_get_cmds_recv(struct tevent_req *req,
                           TALLOC_CTX *mem_ctx,
                           size_t *reply_count,
                           struct sysdb_attrs ***reply)
{
    struct ipa_sudo_get_cmds_state *ipa_state;

    ipa_state = tevent_req_data(req, struct ipa_sudo_get_cmds_state);

    TEVENT_REQ_RETURN_ON_ERROR(req);

    *reply_count = ipa_state->rules->sudoers_count;
    *reply = talloc_steal(mem_ctx, ipa_state->rules->sudoers);

    return EOK;
}

static errno_t ipa_sudo_get_cmds_retry(struct tevent_req *req)
{
    struct ipa_sudo_get_cmds_state *state;
    struct tevent_req *subreq;
    errno_t ret = EOK;

    state = tevent_req_data(req, struct ipa_sudo_get_cmds_state);

    if (be_is_offline(state->be_ctx)) {
        state->dp_error = DP_ERR_OFFLINE;
        state->error = EAGAIN;
        return EOK;
    }

    if (state->sdap_op == NULL) {

        state->sdap_op = sdap_id_op_create(state, state->conn_cache);
        if (state->sdap_op == NULL) {
            DEBUG(SSSDBG_CRIT_FAILURE, "sdap_id_op_create() failed\n");
            state->dp_error = DP_ERR_FATAL;
            state->error = EIO;
            return EIO;
        }
    }

    subreq = sdap_id_op_connect_send(state->sdap_op, state, &ret);
    if (subreq == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "sdap_id_op_connect_send() failed: %d(%s)\n",
                                   ret, strerror(ret));
        talloc_zfree(state->sdap_op);
        state->dp_error = DP_ERR_FATAL;
        state->error = ret;
        return ret;
    }

    tevent_req_set_callback(subreq, ipa_sudo_get_cmds_connect_done, req);

    return EAGAIN;
}

static void ipa_sudo_get_cmds_connect_done(struct tevent_req *subreq)
{
    struct ipa_sudo_get_cmds_state *state;
    struct tevent_req *req;
    int dp_error;
    int ret;

    /* req from ipa_sudo_get_cmds_send */
    req = tevent_req_callback_data(subreq, struct tevent_req);
    state = tevent_req_data(req, struct ipa_sudo_get_cmds_state);

    ret = sdap_id_op_connect_recv(subreq, &dp_error);
    talloc_zfree(subreq);

    if (dp_error == DP_ERR_OFFLINE) {
        talloc_zfree(state->sdap_op);
        state->dp_error = DP_ERR_OFFLINE;
        state->error = EAGAIN;
        tevent_req_done(req);
        return;
    } else if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "IPA SUDO cmds connection failed - %s\n", 
                                    strerror(ret));
        goto fail;
    }

    DEBUG(SSSDBG_TRACE_FUNC, "IPA SUDO cmds connection successful\n");

    struct sdap_attr_map *map = state->opts->ipa_sudocmds_map;

    /* create attrs from map */
    ret = build_attrs_from_map(state, map, SDAP_OPTS_SUDO_CMD, NULL, &state->attrs, NULL);
    if (ret != EOK) {
        goto fail;
    }

    DEBUG(SSSDBG_TRACE_FUNC, "Searching for IPA SUDO commands\n");

    subreq = sdap_get_generic_send(state,
                                   state->ev,
                                   state->opts,
                                   sdap_id_op_handle(state->sdap_op),
                                   state->basedn,
                                   state->scope,
                                   state->filter,
                                   state->attrs,
                                   map,
                                   SDAP_OPTS_SUDO_CMD,
                                   state->timeout,
                                   true);
    if (subreq == NULL) {
        goto fail;
    }

    tevent_req_set_callback(subreq, ipa_sudo_cmds_process, req);

fail:
    state->error = ret;

    if (ret != EOK) {
        tevent_req_error(req, ret);
    }
}

static void ipa_sudo_cmds_process(struct tevent_req *subreq)
{
    struct ipa_sudo_get_cmds_state *state;
    struct tevent_req *req;
    int ret;

    /* req from ipa_sudo_get_cmds_send */
    req = tevent_req_callback_data(subreq, struct tevent_req);
    state = tevent_req_data(req, struct ipa_sudo_get_cmds_state);
 
    DEBUG(SSSDBG_TRACE_FUNC, "Receiving commands for IPA SUDO rules with "
                             "base [%s]\n", state->basedn);

    /* get IPA sudo commands */
    ret = sdap_get_generic_recv(subreq, state, 
                                &state->rules->ipa_cmds_count, 
                                &state->rules->ipa_cmds);
    talloc_zfree(subreq);
    if (ret != EOK) {
        goto fail;
    }

    ret = export_sudoers_cmds(state, 
                              state->rules->sudoers, 
                              state->rules->sudoers_count,
                              state->rules->cmds_index, 
                              state->rules->ipa_cmds, 
                              state->rules->ipa_cmds_count);
    if (ret != EOK) {
        goto fail;
    }

    DEBUG(SSSDBG_TRACE_FUNC, "All IPA sudo rules successfully exported into "
                             "the native LDAP SUDO scheme.\n");

fail:
    if (ret == EOK) {
        /* ipa_sudo_get_cmds_send */
        tevent_req_done(req);
    } else {
        tevent_req_error(req, ret);
    }
}


