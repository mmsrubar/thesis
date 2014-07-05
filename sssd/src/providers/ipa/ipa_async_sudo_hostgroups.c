/*
    SSSD

    Get all hostgroups the IPA client is member of

    Authors:
        Michal Srubar <mmsrubar@gmail.com>

    Copyright (C) 2014 Michal Srubar

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
#include "providers/ipa/ipa_hosts.h"
#include "providers/ipa/ipa_access.h"
#include "providers/ipa/ipa_sudo_export.h"  // just for debugging
#include "providers/ldap/sdap_sudo.h"

struct ipa_sudo_get_hostgroups_state {

    struct be_ctx *be_ctx;
    struct sdap_id_op *sdap_op;
    struct sdap_id_conn_cache *conn_cache;
    struct sdap_options *opts;

    const char *hostname;
    struct sdap_attr_map *host_map;
    struct sdap_attr_map *hostgroup_map;
    struct sdap_search_base **host_search_bases;
 
    int dp_error;
    int error;

    /* Hosts */
    size_t host_count;
    struct sysdb_attrs **hosts;
    size_t hostgroup_count;
    struct sysdb_attrs **hostgroups;
};

static errno_t ipa_sudo_get_hostgroups_connect(struct tevent_req *req);
static void ipa_sudo_get_hostgroups_connect_done(struct tevent_req *subreq);
static void ipa_sudo_get_hostgroups_done(struct tevent_req *subreq);

struct tevent_req *ipa_sudo_get_hostgroups_send(TALLOC_CTX *mem, 
                                                struct sdap_sudo_ctx *sudo_ctx)
{
    struct ipa_sudo_get_hostgroups_state *state;
    struct ipa_access_ctx *access_ctx;
    struct tevent_req *req;
    int ret;

    req = tevent_req_create(mem, &state, struct ipa_sudo_get_hostgroups_state);
    if (req == NULL) {
        DEBUG(SSSDBG_FATAL_FAILURE, ("tevent_req_create() failed\n"));
        return NULL;
    }

    access_ctx = talloc_get_type(sudo_ctx->be_ctx->bet_info[BET_ACCESS].pvt_bet_data,
                                 struct ipa_access_ctx);
 
    state->be_ctx = access_ctx->sdap_ctx->be;
    state->conn_cache = access_ctx->sdap_ctx->conn->conn_cache;
    state->opts = access_ctx->sdap_ctx->opts;
    state->hostname = talloc_strdup(state, sudo_ctx->ipa_hostname);
    state->host_map = access_ctx->host_map;
    state->hostgroup_map = access_ctx->hostgroup_map;
    state->host_search_bases = access_ctx->host_search_bases;

    if (state->hostname == NULL) {
        return NULL;
        goto immediately;
    }

    ret = ipa_sudo_get_hostgroups_connect(req);
    if (ret == EAGAIN) {
        /* the backend went offline */
        return req;
    }

immediately:
    if (ret != EOK) {
        tevent_req_error(req, ret);
    }
    //tevent_req_post(req, state->be_ctx->ev);

    return req;
}

static errno_t ipa_sudo_get_hostgroups_connect(struct tevent_req *req)
{
    struct ipa_sudo_get_hostgroups_state *state;
    struct tevent_req *subreq;
    errno_t ret = EOK;

    state = tevent_req_data(req, struct ipa_sudo_get_hostgroups_state);

    if (be_is_offline(state->be_ctx)) {
        state->dp_error = DP_ERR_OFFLINE;
        state->error = EAGAIN;
        return EOK;
    }

    if (state->sdap_op == NULL) {
        state->sdap_op = sdap_id_op_create(state, 
                state->conn_cache);
        if (state->sdap_op == NULL) {
            DEBUG(SSSDBG_CRIT_FAILURE, ("sdap_id_op_create() failed\n"));
            state->dp_error = DP_ERR_FATAL;
            state->error = EIO;
            return EIO;
        }
    }

    subreq = sdap_id_op_connect_send(state->sdap_op, state, &ret);
    if (subreq == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              ("sdap_id_op_connect_send() failed: %d(%s)\n", ret, strerror(ret)));
        talloc_zfree(state->sdap_op);
        state->dp_error = DP_ERR_FATAL;
        state->error = ret;
        return ret;
    }

    tevent_req_set_callback(subreq, ipa_sudo_get_hostgroups_connect_done, req);

    return ret;
}

static void ipa_sudo_get_hostgroups_connect_done(struct tevent_req *subreq)
{
    struct ipa_sudo_get_hostgroups_state *state;
    struct tevent_req *req;
    int dp_error;
    int ret;

    /* req from ipa_sudo_get_hostgroups_send */
    req = tevent_req_callback_data(subreq, struct tevent_req);
    state = tevent_req_data(req, struct ipa_sudo_get_hostgroups_state);
 
    ret = sdap_id_op_connect_recv(subreq, &dp_error);
    talloc_zfree(subreq);
                
    if (dp_error == DP_ERR_OFFLINE) {
        talloc_zfree(state->sdap_op);
        state->dp_error = DP_ERR_OFFLINE;
        state->error = EAGAIN;
        tevent_req_done(req);
        return;
    } else if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              ("IPA SUDO connection failed - %s\n", strerror(ret)));
        state->error = ret;
        tevent_req_error(req, ret);
        return;
    }

    DEBUG(SSSDBG_TRACE_FUNC, ("IPA connection successful\n"));

    subreq = ipa_host_info_send(state, 
                                state->be_ctx->ev,
                                sdap_id_op_handle(state->sdap_op),
                                state->opts,
                                state->hostname,
                                state->host_map,
                                state->hostgroup_map,
                                state->host_search_bases);
    if (subreq == NULL) {
        DEBUG(1, ("Could not get host info\n"));
        tevent_req_error(req, ret);
    }

    tevent_req_set_callback(subreq, ipa_sudo_get_hostgroups_done, req);
}

static void ipa_sudo_get_hostgroups_done(struct tevent_req *subreq)
{
    struct ipa_sudo_get_hostgroups_state *state;
    struct tevent_req *req;
    errno_t ret;

    req = tevent_req_callback_data(subreq, struct tevent_req);
    state = tevent_req_data(req, struct ipa_sudo_get_hostgroups_state);
 
    ret = ipa_host_info_recv(subreq, state,
                             &state->host_count,
                             &state->hosts,
                             &state->hostgroup_count,
                             &state->hostgroups);
    talloc_zfree(subreq);
    if (ret) {
        tevent_req_error(req, ret);
        return;
    }

    /* getting hostgroups is done now */
    tevent_req_done(req);
}

int ipa_sudo_get_hostgroups_recv(struct tevent_req *req,
                                 TALLOC_CTX *mem_ctx,
                                 int *dp_error,
                                 int *error,
                                 struct sysdb_attrs ***hostgroups,
                                 size_t *hostgroup_count)
{
    struct ipa_sudo_get_hostgroups_state *state;

    state = tevent_req_data(req, struct ipa_sudo_get_hostgroups_state);

    TEVENT_REQ_RETURN_ON_ERROR(req);

    *dp_error = state->dp_error;
    *error = state->error;

    *hostgroup_count = state->hostgroup_count;
    *hostgroups = state->hostgroups;

    return EOK;
}
