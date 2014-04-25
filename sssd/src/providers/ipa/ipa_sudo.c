/*
    SSSD

    IPA Provider Initialization functions

    Authors:
        Lukas Slebodnik <lslebodn@redhat.com>

    Copyright (C) 2013 Red Hat

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
//#include "providers/ipa/ipa_opts.h"
#include "providers/ldap/sdap_sudo.h"
#include "db/sysdb_sudo.h"

static void ipa_sudo_shutdown(struct be_req *req);
void ipa_sudo_handler(struct be_req *be_req);

struct bet_ops ipa_sudo_ops = {
    .handler = ipa_sudo_handler,
    .finalize = ipa_sudo_shutdown
};

void ipa_sudo_handler_done(struct be_req *req, int dp_err,
                           int error, const char *errstr)
{
    return be_req_terminate(req, dp_err, error, errstr);
}

static void ipa_sudo_shutdown(struct be_req *req)
{
    ipa_sudo_handler_done(req, DP_ERR_OK, EOK, NULL);
}

static void ipa_sudo_reply(struct tevent_req *req)
{
    struct be_req *be_req = NULL;
    struct be_sudo_req *sudo_req = NULL;
    int dp_error = DP_ERR_OK;
    int error = EOK;
    int ret = EOK;

    be_req = tevent_req_callback_data(req, struct be_req);
    sudo_req = talloc_get_type(be_req_get_data(be_req), struct be_sudo_req);

    switch (sudo_req->type) {
    case BE_REQ_SUDO_FULL:
        //ret = sdap_sudo_full_refresh_recv(req, &dp_error, &error);
        break;
    case BE_REQ_SUDO_RULES:
        ret = sdap_sudo_rules_refresh_recv(req, &dp_error, &error);
        break;
    default:
        DEBUG(SSSDBG_CRIT_FAILURE, ("Invalid request type: %d\n",
                                    sudo_req->type));
        ret = EINVAL;
    }

    talloc_zfree(req);
    if (ret != EOK) {
        ipa_sudo_handler_done(be_req, DP_ERR_FATAL, ret, strerror(ret));
        return;
    }

    ipa_sudo_handler_done(be_req, dp_error, error, strerror(error));
}

void ipa_sudo_handler(struct be_req *be_req)
{
    struct be_ctx *be_ctx = be_req_get_be_ctx(be_req);
    struct tevent_req *req = NULL;
    struct be_sudo_req *sudo_req = NULL;
    struct sdap_sudo_ctx *sudo_ctx = NULL;
    struct sdap_id_ctx *id_ctx = NULL;
    int ret = EOK;

    sudo_ctx = talloc_get_type(be_ctx->bet_info[BET_SUDO].pvt_bet_data,
                               struct sdap_sudo_ctx);
    id_ctx = sudo_ctx->id_ctx;

    sudo_req = talloc_get_type(be_req_get_data(be_req), struct be_sudo_req);

    switch (sudo_req->type) {
    case BE_REQ_SUDO_FULL:
        DEBUG(SSSDBG_TRACE_FUNC, ("Issuing a full refresh of IPA SUDO rules\n"));
        req = ipa_sudo_full_refresh_send(be_req, sudo_ctx);
        break;
    case BE_REQ_SUDO_RULES:
        DEBUG(SSSDBG_TRACE_FUNC, ("Issuing a refresh of specific IPA SUDO rules\n"));
        req = ipa_sudo_rules_refresh_send(be_req, sudo_ctx, id_ctx->be,
                                               id_ctx->opts, id_ctx->conn->conn_cache,
                                               sudo_req->rules);
        break;
    default:
        DEBUG(SSSDBG_CRIT_FAILURE, ("Invalid request type: %d\n",
                                    sudo_req->type));
        ret = EINVAL;
        goto fail;
    }

    if (req == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, ("Unable to send request: %d\n",
                                    sudo_req->type));
        ret = ENOMEM;
        goto fail;
    }

    //tevent_req_set_callback(req, sdap_sudo_reply, be_req);
    tevent_req_set_callback(req, ipa_sudo_reply, be_req);

    return;

fail:
    sdap_handler_done(be_req, DP_ERR_FATAL, ret, NULL);
}



int ipa_sudo_init(struct be_ctx *be_ctx,
                  struct ipa_id_ctx *id_ctx,
                  struct bet_ops **ops,
                  void **pvt_data)
{
    int ret;
    struct ipa_options *ipa_options;
    struct sdap_options *ldap_options;

    DEBUG(SSSDBG_TRACE_INTERNAL, ("Initializing sudo IPA back end\n"));

    /*
     * SDAP_SUDO_SEARCH_BASE has already been initialized in
     * function ipa_get_id_options
     */
    ret = sdap_sudo_init(be_ctx, id_ctx->sdap_id_ctx, ops, pvt_data);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, ("Cannot initialize LDAP SUDO [%d]: %s\n",
                                  ret, strerror(ret)));
        return ret;
    }

    ipa_options = id_ctx->ipa_options;
    ldap_options = id_ctx->sdap_id_ctx->opts;

    /* corrent the handler */
    *ops = &ipa_sudo_ops;

    ipa_options->id->sudorule_map = ldap_options->sudorule_map;
    return EOK;
}
