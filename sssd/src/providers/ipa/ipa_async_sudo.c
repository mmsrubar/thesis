#include "db/sysdb_sudo.h"
#include "providers/ldap/sdap_async.h"
#include "providers/ldap/sdap_async_sudo.h"
#include "providers/ldap/sdap.h"
#include "providers/ipa/ipa_async_sudo.h"
#include "providers/ipa/ipa_common.h"
#include "providers/ipa/ipa_sudo_export.h"
#include "providers/ipa/ipa_sudo_cmd.h"
#include "providers/ipa/ipa_sudo.h"

struct ipa_sudo_get_cmds_state {

    struct sdap_sudo_load_sudoers_state *sudo_state;

    struct sdap_id_op *sdap_op;
    struct sysdb_ctx *sysdb;
    struct tevent_req *req;     /* req from sdap_sudo_load_sudoers_send */

    const char *sysdb_filter;   /* sysdb delete filter */
    const char *filter;
    const char *basedn;
    const char **attrs;
    int scope;

    int timeout;
    int dp_error;
    int error;

    struct sudo_rules *rules;
    struct sysdb_attrs **tmp;
};

static int ipa_sudo_get_cmds_retry(struct tevent_req *req);
static void ipa_sudo_get_cmds_connect_done(struct tevent_req *subreq);
static void ipa_sudo_get_cmds_done(struct tevent_req *subreq);

int ipa_sudo_export_rules_recv(struct tevent_req *req,
                           TALLOC_CTX *mem_ctx,
                           size_t *reply_count,
                           struct sysdb_attrs ***reply,
                           struct sdap_sudo_load_sudoers_state **state,
                           struct tevent_req **req_sdap)
{
    struct ipa_sudo_get_cmds_state *ipa_state;

    ipa_state = tevent_req_data(req, struct ipa_sudo_get_cmds_state);

    *reply_count = ipa_state->rules->sudoers_count;
    *reply = talloc_steal(mem_ctx, ipa_state->rules->sudoers);

    /* req from sdap_sudo_load_sudoers_send */
    *req_sdap = ipa_state->req;

    *state = tevent_req_data(ipa_state->req, struct sdap_sudo_load_sudoers_state);
    /*
    *state->refresh_state->dp_error = ipa_state->dp_error;
    *state->refresh_state->error = ipa_state->error;
    */

    return EOK;
}

struct tevent_req *
ipa_sudo_export_rules_send(struct sysdb_attrs **ipa_rules, 
                           int ipa_rules_count, 
                           struct sdap_sudo_load_sudoers_state *sudo_state,
                           struct tevent_req *req_sdap)
{

    TALLOC_CTX *tmp = talloc_init(NULL);

    struct ipa_sudo_get_cmds_state *state;
    struct sudo_rules *rules;
    struct tevent_req *req;
    errno_t ret = EOK;
    errno_t cmds_ret = EOK;

    req = tevent_req_create(tmp, &state, struct ipa_sudo_get_cmds_state);
    if (!req) {
        return NULL;
    }

    state->sudo_state = sudo_state;
    state->sysdb = sudo_state->refresh_state->sysdb;
    state->sdap_op = NULL;
    state->basedn = talloc_strdup(state, IPA_SUDO_CMDS_BASEDN);
    state->scope = LDAP_SCOPE_SUBTREE;
    state->req = req_sdap;  /* req from sdap_sudo_load_sudoers_send */

    rules = talloc_zero(state, struct sudo_rules);
    state->rules = rules;

    /* check this after the state is initialized because we need it to be for
     * #_recv() func
     */
    if (ipa_rules == NULL && ipa_rules_count <= 0) {
        /* no ipa sudo rules -> nothing to build new filter from */
        goto imediaty;
    }


    cmds_ret = ipa_sudo_build_cmds_filter(state, state->sysdb, ipa_rules, 
                                     ipa_rules_count, &(state->filter));
    if (cmds_ret != EOK && cmds_ret != ENOENT) {
        goto imediaty;
    }

    ret = ipa_sudo_export_sudoers(state, state->sysdb,
                                  ipa_rules, 
                                  ipa_rules_count, 
                                  &(state->rules->sudoers),
                                  &(state->rules->sudoers_count),
                                  &(state->rules->cmds_index));
    //print_rules(state->rules->sudoers, state->rules->sudoers_count);
    if (ret != EOK || cmds_ret == ENOENT) {
        /* if building cmds filter returned ENOENT then we don't need to
         * download any ipa sudo commands */
        goto imediaty;
    }

    ret = ipa_sudo_get_cmds_retry(req);
    if (ret == EOK) {
        /* connection req sent successfully, we can return without finishing
         * this request */
        return req;
    }

imediaty:
    if (ret == EOK) {
        tevent_req_done(req);
    } else {
        tevent_req_error(req, ret);
    }
    tevent_req_post(req, sudo_state->ev);

    return req;
}

static errno_t ipa_sudo_get_cmds_retry(struct tevent_req *req)
{
    struct ipa_sudo_get_cmds_state *state;
    struct tevent_req *subreq;
    errno_t ret = EOK;

    state = tevent_req_data(req, struct ipa_sudo_get_cmds_state);

    if (be_is_offline(state->sudo_state->refresh_state->be_ctx)) {
        state->dp_error = DP_ERR_OFFLINE;
        state->error = EAGAIN;
        return EOK;
    }

    if (state->sdap_op == NULL) {
        state->sdap_op = sdap_id_op_create(state, 
                state->sudo_state->refresh_state->sdap_conn_cache);
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

    tevent_req_set_callback(subreq, ipa_sudo_get_cmds_connect_done, req);

    return ret;
}

static void ipa_sudo_get_cmds_connect_done(struct tevent_req *subreq)
{
    struct ipa_sudo_get_cmds_state *state;
    struct tevent_req *req;
    int dp_error;
    int ret;

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
        DEBUG(SSSDBG_CRIT_FAILURE,
              ("IPA SUDO LDAP connection failed - %s\n", strerror(ret)));
        goto fail;
    }

    DEBUG(SSSDBG_TRACE_FUNC, ("IPA SUDO LDAP connection successful\n"));

    struct sdap_attr_map *map = state->sudo_state->opts->ipa_sudocmds_map;

    /* create attrs from map */
    ret = build_attrs_from_map(state, map, SDAP_OPTS_SUDO_CMD, NULL, &state->attrs, NULL);
    if (ret != EOK) {
        goto fail;
    }

    DEBUG(SSSDBG_TRACE_FUNC, ("Searching for IPA SUDO commands\n"));

    subreq = sdap_get_generic_send(state,
                                   state->sudo_state->ev,
                                   state->sudo_state->opts,
                                   sdap_id_op_handle(state->sdap_op),
                                   state->basedn,
                                   state->scope,
                                   state->filter,
                                   state->attrs,
                                   map,
                                   SDAP_OPTS_SUDO_CMD,
                                   state->sudo_state->timeout,
                                   true);
    if (subreq == NULL) {
        goto fail;
    }

    tevent_req_set_callback(subreq, ipa_sudo_get_cmds_done, req);

fail:
    state->error = ret;
    tevent_req_error(req, ret);
}

static void ipa_sudo_get_cmds_done(struct tevent_req *subreq)
{
    struct ipa_sudo_get_cmds_state *state;
    struct sysdb_attrs **attrs;
    struct tevent_req *req;
    size_t count;
    int ret;

    req = tevent_req_callback_data(subreq, struct tevent_req);
    state = tevent_req_data(req, struct ipa_sudo_get_cmds_state);
 
    DEBUG(SSSDBG_TRACE_FUNC,
          ("Receiving commands for IPA SUDO rules with base [%s]\n",
           state->basedn));

    ret = sdap_get_generic_recv(subreq, state, &count, &attrs);
    talloc_zfree(subreq);
    if (ret) {
        return;
    }

    /* if we don't have any rules but downloaded some commands then something
     * went wrong! */
    if (state->rules->sudoers_count == 0 || state->rules->sudoers == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE,
            ("We got some ipa sudo commands but we have no sudo rules\n"));
        goto fail;
    }

    //print_rules(attrs, count);
    ipa_sudo_export_cmds(state, 
                         state->rules->sudoers, 
                         state->rules->sudoers_count,
                         state->rules->cmds_index, 
                         attrs, count);

    DEBUG(SSSDBG_TRACE_FUNC, ("All IPA SUDO rules successfully exported into "
                              "native LDAP SUDO scheme. Giving control back to "
                              "the LDAP SUDO Provider.\n"));
    //print_rules(state->rules->sudoers, state->rules->sudoers_count);

fail:
    /* ipa_sudo_export_rules_send */
    tevent_req_done(req);
}
