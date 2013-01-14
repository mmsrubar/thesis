/*
    Authors:
        Jan Zeleny <jzeleny@redhat.com>

    Copyright (C) 2011 Red Hat

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

#include "util/util.h"
#include "responder/common/responder.h"
#include "providers/data_provider.h"
#include "db/sysdb.h"

/* ========== Get subdomains for a domain ================= */
static DBusMessage *sss_dp_get_domains_msg(void *pvt);

struct sss_dp_domains_info {
    struct sss_domain_info *dom;
    const char *hint;
    bool force;
};

static struct tevent_req *
get_subdomains_send(TALLOC_CTX *mem_ctx, struct resp_ctx *rctx,
                    struct sss_domain_info *dom,
                    const bool force,
                    const char *hint)
{
    errno_t ret;
    struct tevent_req *req;
    struct sss_dp_req_state *state;
    struct sss_dp_domains_info *info;
    char *key;

    req = tevent_req_create(mem_ctx, &state, struct sss_dp_req_state);
    if (req == NULL) {
        return NULL;
    }

    info = talloc_zero(state, struct sss_dp_domains_info);
    if (!info) {
        ret = ENOMEM;
        goto fail;
    }
    info->hint = hint;
    info->force = force;
    info->dom = dom;

    key = talloc_asprintf(state, "domains@%s", dom->name);
    if (key == NULL) {
        ret = ENOMEM;
        goto fail;
    }

    ret = sss_dp_issue_request(state, rctx, key, dom,
                               sss_dp_get_domains_msg, info, req);
    talloc_free(key);
    if (ret != EOK) {
        ret = EIO;
        goto fail;
    }

    return req;

fail:
    tevent_req_error(req, ret);
    tevent_req_post(req, rctx->ev);
    return req;
}

static DBusMessage *
sss_dp_get_domains_msg(void *pvt)
{
    struct sss_dp_domains_info *info;
    DBusMessage *msg = NULL;
    dbus_bool_t dbret;

    info = talloc_get_type(pvt, struct sss_dp_domains_info);

    msg = dbus_message_new_method_call(NULL,
                                       DP_PATH,
                                       DP_INTERFACE,
                                       DP_METHOD_GETDOMAINS);
    if (msg == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, ("Out of memory?!\n"));
        return NULL;
    }

    DEBUG(SSSDBG_TRACE_FUNC,
          ("Sending get domains request for [%s][%sforced][%s]\n",
           info->dom->name, info->force ? "" : "not ", info->hint));

    /* Send the hint argument to provider as well. This will
     * be useful for some cases of transitional trust where
     * the server might not know all trusted domains
     */
    dbret = dbus_message_append_args(msg,
                                     DBUS_TYPE_BOOLEAN, &info->force,
                                     DBUS_TYPE_STRING, &info->hint,
                                     DBUS_TYPE_INVALID);
    if (!dbret) {
        DEBUG(SSSDBG_OP_FAILURE ,("Failed to build message\n"));
        dbus_message_unref(msg);
        return NULL;
    }

    return msg;
}

static errno_t
get_next_domain_recv(TALLOC_CTX *mem_ctx,
                     struct tevent_req *req,
                     dbus_uint16_t *dp_err,
                     dbus_uint32_t *dp_ret,
                     char **err_msg)
{
    return sss_dp_req_recv(mem_ctx, req, dp_err, dp_ret, err_msg);
}

/* ====== Iterate over all domains, searching for their subdomains  ======= */
static errno_t process_subdomains(struct sss_domain_info *dom);
static void set_time_of_last_request(struct resp_ctx *rctx);
static errno_t check_last_request(struct resp_ctx *rctx, const char *hint);

struct sss_dp_get_domains_state {
    struct resp_ctx *rctx;
    struct sss_domain_info *dom;
    const char *hint;
    bool force;
};

static void
sss_dp_get_domains_process(struct tevent_req *subreq);

struct tevent_req *sss_dp_get_domains_send(TALLOC_CTX *mem_ctx,
                                           struct resp_ctx *rctx,
                                           bool force,
                                           const char *hint)
{
    errno_t ret;
    struct tevent_req *req;
    struct tevent_req *subreq;
    struct sss_dp_get_domains_state *state;

    req = tevent_req_create(mem_ctx, &state, struct sss_dp_get_domains_state);
    if (req == NULL) {
         return NULL;
    }

    if (rctx->domains == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, ("No domains configured.\n"));
        ret = EINVAL;
        goto immediately;
    }

    if (!force) {
        ret = check_last_request(rctx, hint);
        if (ret == EOK) {
            DEBUG(SSSDBG_TRACE_FUNC,
                  ("Last call was too recent, nothing to do!\n"));
            goto immediately;
        } else if (ret != EAGAIN) {
            DEBUG(SSSDBG_TRACE_FUNC, ("check_domain_request failed with [%d][%s]\n",
                                      ret, strerror(ret)));
            goto immediately;
        }
    }

    state->rctx = rctx;
    state->force = force;
    if (hint != NULL) {
        state->hint = hint;
    } else {
        state->hint = talloc_strdup(state, "");
        if (state->hint == NULL) {
            ret = ENOMEM;
            goto immediately;
        }
    }

    state->dom = rctx->domains;
    while(state->dom != NULL && !NEED_CHECK_PROVIDER(state->dom->provider)) {
        state->dom = state->dom->next;
    }

    if (state->dom == NULL) {
        /* All domains were local */
        ret = EOK;
        goto immediately;
    }

    subreq = get_subdomains_send(req, rctx, state->dom,
                                 state->force, state->hint);
    if (subreq == NULL) {
        ret = ENOMEM;
        goto immediately;
    }
    tevent_req_set_callback(subreq, sss_dp_get_domains_process, req);

    return req;

immediately:
    if (ret == EOK) {
        set_time_of_last_request(rctx);
        tevent_req_done(req);
    } else {
        tevent_req_error(req, ret);
    }
    tevent_req_post(req, rctx->ev);

    return req;
}

static void
sss_dp_get_domains_process(struct tevent_req *subreq)
{
    errno_t ret;
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);
    struct sss_dp_get_domains_state *state = tevent_req_data(req,
                                                struct sss_dp_get_domains_state);
    dbus_uint16_t dp_err;
    dbus_uint32_t dp_ret;
    char *err_msg;

    ret = get_next_domain_recv(req, subreq, &dp_err, &dp_ret, &err_msg);
    talloc_zfree(subreq);
    if (ret != EOK) {
        goto fail;
    }

    ret = process_subdomains(state->dom);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, ("process_subdomains failed, "
                                  "trying next domain.\n"));
        goto fail;
    }

    /* Advance to the next domain */
    state->dom = state->dom->next;

    /* Skip local domains */
    while(state->dom != NULL && !NEED_CHECK_PROVIDER(state->dom->provider)) {
        state->dom = state->dom->next;
    }

    if (state->dom == NULL) {
        /* All domains were local */
        set_time_of_last_request(state->rctx);
        tevent_req_done(req);
        return;
    }

    subreq = get_subdomains_send(req, state->rctx, state->dom, state->force, state->hint);
    if (subreq == NULL) {
        ret = ENOMEM;
        goto fail;
    }
    tevent_req_set_callback(subreq, sss_dp_get_domains_process, req);
    return;

fail:
    tevent_req_error(req, ret);
    return;
}

static errno_t
process_subdomains(struct sss_domain_info *domain)
{
    int ret;
    size_t c;
    size_t subdomain_count;
    struct sss_domain_info **subdomains;
    struct sysdb_subdom *master_info;

    /* Retrieve all subdomains of this domain from sysdb
     * and create their struct sss_domain_info representations
     */
    ret = sysdb_get_subdomains(domain, domain,
                               &subdomain_count, &subdomains);
    if (ret != EOK) {
        DEBUG(SSSDBG_FUNC_DATA, ("sysdb_get_subdomains failed.\n"));
        goto done;
    }

    if (subdomain_count == 0) {
        talloc_zfree(domain->subdomains);
        domain->subdomain_count = 0;
        goto done;
    }

    /* Link all subdomains into single-linked list
     * (the list is used when processing all domains)
     */
    for (c = 0; c < subdomain_count - 1; c++) {
        subdomains[c]->next = subdomains[c + 1];
    }

    if (domain->flat_name == NULL || domain->domain_id == NULL) {
        ret = sysdb_master_domain_get_info(domain, domain->sysdb,
                                           domain, &master_info);
        if (ret != EOK) {
                DEBUG(SSSDBG_FUNC_DATA, ("sysdb_master_domain_get_info " \
                                         "failed.\n"));
                goto done;
        }

        if (domain->flat_name == NULL) {
            domain->flat_name = talloc_strdup(domain, master_info->flat_name);
            if (domain->flat_name == NULL) {
                DEBUG(SSSDBG_MINOR_FAILURE, ("talloc_strdup failed, ignoring"));
            }
        }

        if (domain->domain_id == NULL) {
            domain->domain_id = talloc_strdup(domain, master_info->id);
            if (domain->domain_id == NULL) {
                DEBUG(SSSDBG_MINOR_FAILURE, ("talloc_strdup failed, ignoring"));
            }
        }
        talloc_free(master_info);
        DEBUG(SSSDBG_TRACE_LIBS, ("Adding flat name [%s] to domain [%s].\n",
                                  domain->flat_name, domain->name));
    }

    errno = 0;
    ret = gettimeofday(&domain->subdomains_last_checked, NULL);
    if (ret == -1) {
        ret = errno;
        goto done;
    }

    talloc_zfree(domain->subdomains);
    domain->subdomain_count = subdomain_count;
    domain->subdomains = subdomains;

    ret = EOK;

done:
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, ("Failed to update sub-domains "
                                  "of domain [%s].\n", domain->name));
        talloc_free(subdomains);
    }

    return ret;
}

errno_t sss_dp_get_domains_recv(struct tevent_req *req)
{
    TEVENT_REQ_RETURN_ON_ERROR(req);

    return EOK;
}

static void set_time_of_last_request(struct resp_ctx *rctx)
{
    int ret;

    errno = 0;
    ret = gettimeofday(&rctx->get_domains_last_call, NULL);
    if (ret == -1) {
        ret = errno;
        DEBUG(SSSDBG_TRACE_FUNC, ("gettimeofday failed [%d][%s].\n",
                                  ret, strerror(ret)));
    }
}

static errno_t check_last_request(struct resp_ctx *rctx, const char *hint)
{
    struct sss_domain_info *dom;
    time_t now = time(NULL);
    time_t diff;
    int i;

    diff = now-rctx->get_domains_last_call.tv_sec;
    if (diff >= rctx->domains_timeout) {
        /* Timeout, expired, fetch domains again */
        return EAGAIN;
    }

    if (hint != NULL) {
        dom = rctx->domains;
        while (dom) {
            for (i = 0; i< dom->subdomain_count; i++) {
                if (strcasecmp(dom->subdomains[i]->name, hint) == 0) {
                    diff = now-dom->subdomains_last_checked.tv_sec;
                    if (diff >= rctx->domains_timeout) {
                        /* Timeout, expired, fetch domains again */
                        return EAGAIN;
                    }
                    /* Skip the rest of this domain, but check other domains
                     * perhaps this subdomain will be also a part of another
                     * domain where it will need refreshing
                     */
                    break;
                }
            }
            dom = dom->next;
        }
    }

    return EOK;
}
