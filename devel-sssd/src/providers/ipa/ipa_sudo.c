/*
    SSSD

    IPA Provider Initialization functions

    Authors:
        Lukas Slebodnik <lslebodn@redhat.com>
        MIchal Šrubař <mmsrubar@gmail.com>

    Copyright (C) 2013 Red Hat
    Copyright (C) 2014 MIchal Šrubař

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
#include "providers/ipa/ipa_sudo_refreshes.h"
#include "providers/dp_ptask.h"
#include "db/sysdb_sudo.h"

void ipa_sudo_handler(struct be_req *be_req);
static void ipa_sudo_reply(struct tevent_req *req);
static void ipa_sudo_shutdown(struct be_req *req);

static int ipa_sudo_setup_periodical_refreshes(struct sdap_sudo_ctx *sudo_ctx);

struct bet_ops ipa_sudo_ops = {
    .handler = ipa_sudo_handler,
    .finalize = ipa_sudo_shutdown
};

int ipa_sudo_init(struct be_ctx *be_ctx,
                  struct ipa_id_ctx *ipa_id_ctx,
                  struct bet_ops **ops,
                  void **pvt_data)
{
    struct sdap_id_ctx *id_ctx = ipa_id_ctx->sdap_id_ctx;
    struct sdap_sudo_ctx *sudo_ctx = NULL;
    const char *hostname = NULL;
    char *dot = NULL;
    int ret;

    DEBUG(SSSDBG_TRACE_INTERNAL, "Initializing IPA sudo back end\n");

    sudo_ctx = talloc_zero(be_ctx, struct sdap_sudo_ctx);
    if (sudo_ctx == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "talloc() failed\n");
        return ENOMEM;
    }

    sudo_ctx->id_ctx = id_ctx;
    sudo_ctx->be_ctx = be_ctx;
    sudo_ctx->ipa_hostname = NULL;
    sudo_ctx->ipa_hostgroups = NULL;
    /* no full refresh done yet so we don't have current usn values available */
    sudo_ctx->full_refresh_done = false;

    *ops = &ipa_sudo_ops;
    *pvt_data = sudo_ctx;

    ret = ldap_get_sudo_options(id_ctx, be_ctx->cdb,
                                be_ctx->conf_path, id_ctx->opts,
                                &sudo_ctx->use_host_filter,
                                &sudo_ctx->include_regexp,
                                &sudo_ctx->include_netgroups);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "Cannot get sudo options [%d]: %s\n",
                                  ret, strerror(ret));
        return ret;
    }

    /* if IPA hostname isn't set in sssd.conf (ipa_hostname option) then it'll
     * be get automatically by 'gethostname()' in ipa_get_options and set into 
     * ipa_options->basic as IPA_HOSTNAME 
     */
    hostname = dp_opt_get_string(ipa_id_ctx->ipa_options->basic, IPA_HOSTNAME);
    if (hostname != NULL) {

        dot = strchr(hostname, '.');
        if (dot != NULL) {
            
            DEBUG(SSSDBG_TRACE_INTERNAL, "Found IPA hostname: %s\n", hostname);

            sudo_ctx->ipa_hostname = talloc_strdup(sudo_ctx, hostname);
            if (sudo_ctx->ipa_hostname == NULL) {
                DEBUG(SSSDBG_CRIT_FAILURE, "talloc_strdup() failed\n");
                return ENOMEM;
            }
        }
    }

    if (hostname == NULL || dot == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Machine hostname ins't FQDN, sudo "
                                   "won't work correctly");
        sudo_ctx->use_host_filter = false;
    }

    return ipa_sudo_setup_periodical_refreshes(sudo_ctx);
}

static int ipa_sudo_setup_periodical_refreshes(struct sdap_sudo_ctx *sudo_ctx)
{
    struct sdap_id_ctx *id_ctx = sudo_ctx->id_ctx;
    time_t smart_default;
    time_t smart_interval;
    time_t full_interval;
    time_t last_full;
    time_t delay;
    int ret;

    DEBUG(SSSDBG_TRACE_INTERNAL, "Setting up periodical refreshes of sudo "
                                 "rules using ptask scheduler\n");

    /* get configured values */
    smart_interval = dp_opt_get_int(id_ctx->opts->basic,
                                    SDAP_SUDO_SMART_REFRESH_INTERVAL);
    full_interval = dp_opt_get_int(id_ctx->opts->basic,
                                   SDAP_SUDO_FULL_REFRESH_INTERVAL);

    if (smart_interval == 0 && full_interval == 0) {
        smart_default = id_ctx->opts->basic[SDAP_SUDO_SMART_REFRESH_INTERVAL].def_val.number;
        DEBUG(SSSDBG_MINOR_FAILURE, "At least one periodical update has to be "
              "enabled. Setting smart refresh interval to default value (%ld).\n",
              smart_default);

        ret = dp_opt_set_int(id_ctx->opts->basic,
                             SDAP_SUDO_SMART_REFRESH_INTERVAL,
                             smart_default);
        if (ret != EOK) {
            return ret;
        }
    }

    if (full_interval <= smart_interval) {
        DEBUG(SSSDBG_MINOR_FAILURE, "Full refresh interval has to be greater"
              "than smart refresh interval. Periodical full refresh will be "
              "disabled.\n");
        ret = dp_opt_set_int(id_ctx->opts->basic,
                             SDAP_SUDO_FULL_REFRESH_INTERVAL,
                             0);
        if (ret != EOK) {
            return ret;
        }
    }

    ret = sysdb_sudo_get_last_full_refresh(id_ctx->be->domain, &last_full);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to get the time of the "
                                   "last full refresh\n");
        return ret;
    }

    if (last_full == 0) {
        /* If this is the first startup, we need to kick off sh immediately, 
         * to close a window where clients requesting sudo information won't 
         * get an immediate reply with no entries.
         */
        delay = 0;
    } else {
        /* At least one update has previously run, so clients will get cached 
         * data. We will delay the refresh so we don't slow down the startup 
         * process if this is happening during system boot.
         */
        delay = 10;
    }

    /* Schedule full refresh
     * If the backend is offline then this kind of refresh is disabled and when
     * we got online again ptask will fire it immediately.
     */
    ret = be_ptask_create(sudo_ctx, sudo_ctx->be_ctx, full_interval, delay, 
                          1, 60, BE_PTASK_OFFLINE_DISABLE, /* FIXME: timeout? */
                          ipa_sudo_full_refresh_send, 
                          ipa_sudo_full_refresh_recv,
                          sudo_ctx, 
                          "full refresh of IPA sudo rules", NULL);
    if (ret != EOK) {
        DEBUG(SSSDBG_FATAL_FAILURE, "Unable to initialize periodic full "
                                    "refresh of IPA sudo rules\n");
    }

    /* Schedule smart refresh 
     * If backend is offline then this kind of refresh is just skipped.
     */
    ret = be_ptask_create(sudo_ctx, sudo_ctx->be_ctx, smart_interval, 
                          smart_interval, 
                          11, 60, BE_PTASK_OFFLINE_SKIP,
                          ipa_sudo_smart_refresh_send, 
                          ipa_sudo_smart_refresh_recv,
                          sudo_ctx, 
                          "smart refresh of IPA sudo rules", NULL);
    if (ret != EOK) {
        DEBUG(SSSDBG_FATAL_FAILURE, "Unable to initialize periodic smart "
                                    "refresh of IPA sudo rules\n");
    }

    return EOK;
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
        DEBUG(SSSDBG_TRACE_FUNC, "Issuing a full refresh of IPA sudo rules\n");
        req = ipa_sudo_full_refresh_send(sudo_ctx, id_ctx->be->ev, id_ctx->be,
                                         NULL, sudo_ctx);
        break;
    case BE_REQ_SUDO_RULES:
        DEBUG(SSSDBG_TRACE_FUNC, "Issuing a refresh of specific "
                                 "IPA sudo rules\n");
        req = ipa_sudo_rules_refresh_send(be_req, sudo_ctx, id_ctx->be,
                                          id_ctx->opts, 
                                          id_ctx->conn->conn_cache,
                                          sudo_req->rules);
        break;
    default:
        DEBUG(SSSDBG_CRIT_FAILURE, "Invalid request type: %d\n",sudo_req->type);
        ret = EINVAL;
        goto fail;
    }

    if (req == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to send request: %d\n",
                                    sudo_req->type);
        ret = ENOMEM;
        goto fail;
    }

    tevent_req_set_callback(req, ipa_sudo_reply, be_req);
    return;

fail:
    sdap_handler_done(be_req, DP_ERR_FATAL, ret, NULL);
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
        ret = ipa_sudo_full_refresh_recv(req, &dp_error, &error);
        break;
    case BE_REQ_SUDO_RULES:
        ret = ipa_sudo_rules_refresh_recv(req, &dp_error, &error);
        break;
    default:
        DEBUG(SSSDBG_CRIT_FAILURE, "Invalid request type: %d\n",
                                    sudo_req->type);
        ret = EINVAL;
    }

    talloc_zfree(req);
    if (ret != EOK) {
        sdap_handler_done(be_req, DP_ERR_FATAL, ret, strerror(ret));
        return;
    }

    sdap_handler_done(be_req, dp_error, error, strerror(error));
}

static void ipa_sudo_shutdown(struct be_req *req)
{
    sdap_handler_done(req, DP_ERR_OK, EOK, NULL);
}
