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
#include "providers/ipa/ipa_hosts.h"
#include "providers/ipa/ipa_access.h"
#include "providers/ipa/ipa_sudo_export.h"  // for debug prit_rules 
#include "providers/ipa/ipa_async_sudo.h"
#include "providers/ipa/ipa_async_sudo_hostgroups.h"
#include "providers/ldap/sdap_sudo.h"
#include "providers/ipa/ipa_sudo.h"
#include "db/sysdb_sudo.h"
//#include "providers/ipa/ipa_opts.h"

#define FQDN    0

void ipa_sudo_handler(struct be_req *be_req);
static void ipa_sudo_shutdown(struct be_req *req);
//static void sdap_sudo_get_hostinfo_next(struct tevent_req *req);
static void ipa_sudo_get_hostinfo_done(struct tevent_req *req);

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

    tevent_req_set_callback(req, ipa_sudo_reply, be_req);

    return;

fail:
    sdap_handler_done(be_req, DP_ERR_FATAL, ret, NULL);
}

int ipa_sudo_init(struct be_ctx *be_ctx,
                  struct ipa_id_ctx *ipa_id_ctx,
                  struct bet_ops **ops,
                  void **pvt_data)
{
    struct sdap_id_ctx *id_ctx = ipa_id_ctx->sdap_id_ctx;
    struct sdap_sudo_ctx *sudo_ctx = NULL;
    struct ipa_access_ctx *ipa_access_ctx;
    struct tevent_req *req = NULL;
    char hostname[HOST_NAME_MAX + 1];
    const char *ipa_hostname = NULL;
    char *dot = NULL;
    int ret;

    DEBUG(SSSDBG_TRACE_INTERNAL, ("Initializing sudo IPA back end\n"));

    sudo_ctx = talloc_zero(be_ctx, struct sdap_sudo_ctx);
    if (sudo_ctx == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, ("talloc() failed\n"));
        return ENOMEM;
    }

    sudo_ctx->id_ctx = id_ctx;
    sudo_ctx->ipa_provider = true;
    *ops = &ipa_sudo_ops;
    *pvt_data = sudo_ctx;

    /* we didn't do any full refresh now,
     * so we don't have current usn values available */
    sudo_ctx->full_refresh_done = false;

    ret = ldap_get_sudo_options(id_ctx, be_ctx->cdb,
                                be_ctx->conf_path, id_ctx->opts,
                                &sudo_ctx->use_host_filter,
                                &sudo_ctx->include_regexp,
                                &sudo_ctx->include_netgroups);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, ("Cannot get SUDO options [%d]: %s\n",
                                  ret, strerror(ret)));
        return ret;
    }

    // FIXME: put this getting fqdn into separea file?
    /* hostname of the IPA client should be FQDN, if it isn't then try to resolv
     * it with DNS? */
    ipa_hostname = dp_opt_get_string(ipa_id_ctx->ipa_options->basic, IPA_HOSTNAME);
    if (ipa_hostname == NULL) {

        DEBUG(SSSDBG_TRACE_INTERNAL, ("No clinet's hostname specified in sssd.conf, "
                                      "trying to get machine hostname\n"));

        ret = gethostname(hostname, HOST_NAME_MAX);
        if (ret != EOK) {
            ret = errno;
            DEBUG(SSSDBG_CRIT_FAILURE, ("Unable to retrieve machine hostname "
                                        "[%d]: %s\n", ret, strerror(ret)));
            //FIXME: what now? we can't receive any rules if we don't know the
            //       hostname
        }
        hostname[HOST_NAME_MAX] = '\0';

        dot = strchr(hostname, '.');
        if (dot != NULL) {
            DEBUG(SSSDBG_TRACE_INTERNAL, ("Found fqdn: %s\n", hostname));
        } else {
            DEBUG(SSSDBG_CRIT_FAILURE, ("Machine hostname ins't FQDN"));
            //FIXME: what now? we can't receive any rules if we don't know the
            //       hostname
        }
    } else {
        DEBUG(SSSDBG_TRACE_INTERNAL, ("Found fqdn: %s\n", ipa_hostname));
    }

    sudo_ctx->hostname = talloc_strdup(sudo_ctx, 
                                (ipa_hostname == NULL)? hostname:ipa_hostname);
    if (sudo_ctx->hostname == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, ("talloc_strdup() failed\n"));
        return ENOMEM;  // FIXME:
    }

    ipa_access_ctx = talloc_get_type(be_ctx->bet_info[BET_ACCESS].pvt_bet_data,
                                     struct ipa_access_ctx);
 
    /* we have FQDN of the client so we can perform hostgroups lookup */
    req = ipa_sudo_get_hostgroups_send(sudo_ctx, 
                                          sudo_ctx->hostname, 
                                          ipa_access_ctx);
    if (req == NULL) {
        return ENOENT;
    }
 
    tevent_req_set_callback(req, ipa_sudo_get_hostinfo_done, sudo_ctx);

    return EOK;
}


static void ipa_sudo_get_hostinfo_done(struct tevent_req *subreq)
{
    struct sdap_sudo_ctx *sudo_ctx;
    //struct tevent_req *req;
    size_t hostgroup_count;
    struct sysdb_attrs **hostgroups;
    const char *group_name;
    int dp_error;
    int error;
    errno_t ret;
    int i;

    sudo_ctx = tevent_req_callback_data(subreq, struct sdap_sudo_ctx);
 
    ret = ipa_sudo_get_hostgroups_recv(subreq, sudo_ctx,
                                       &dp_error, &error,
                                       &hostgroups,
                                       &hostgroup_count);
    talloc_zfree(subreq);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, ("Unable to retrieve hostgroups information - "
              "(host filter will be disabled) [%d]: %s\n", ret, strerror(ret)));
        sudo_ctx->use_host_filter = false;
    }

    sudo_ctx->hostgroups = talloc_zero_array(sudo_ctx, char *, hostgroup_count+1);
    if (sudo_ctx->hostgroups == NULL) {
        DEBUG(SSSDBG_FATAL_FAILURE, ("talloc_zero_array() failed\n"));
        return;
    }

    for (i = 0; i < hostgroup_count; i++) {

        ret = sysdb_attrs_get_string(hostgroups[i], "name", &group_name);
        if (ret != EOK) {
            DEBUG(SSSDBG_CRIT_FAILURE, ("Unable to get common name of a "
                        "hostgroup. Trying another hostgroup record.\n"));
            continue;
        }

        sudo_ctx->hostgroups[i] = talloc_strdup(sudo_ctx->hostgroups, 
                                                group_name);
        DEBUG(SSSDBG_TRACE_FUNC, ("IPA client is member of hostgroup: %s\n",
                                   sudo_ctx->hostgroups[i]));

        //FIXME: free(group_name);
    }

    sudo_ctx->hostgroups[hostgroup_count] = NULL;

    DEBUG(SSSDBG_TRACE_INTERNAL, ("Setting up periodical refresh of sudo "
                                  "rules using LDAP SUDO scheduler\n"));

    ret = sdap_sudo_setup_periodical_refresh(sudo_ctx);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
        ("Unable to setup periodical refresh"
        "of sudo rules [%d]: %s\n", ret, strerror(ret)));
        /* periodical updates will not work, but specific-rule update
         * is no affected by this, therefore we don't have to fail here */
    }
}
