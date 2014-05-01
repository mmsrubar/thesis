/*
 * FIXME:
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include <errno.h>
#include <talloc.h>
#include <tevent.h>

#include "providers/dp_backend.h"
#include "providers/ldap/ldap_common.h"
#include "providers/ldap/sdap.h"
#include "providers/ldap/sdap_async.h"
#include "providers/ldap/sdap_async_sudo.h"
#include "providers/ldap/sdap_sudo.h"
#include "providers/ldap/sdap_sudo_cache.h"
#include "providers/ipa/ipa_async_sudo_cmds.h"   // for ipa specific functionality
#include "providers/ipa/ipa_sudo_export.h"   // for print_rules
#include "db/sysdb_sudo.h"

static int ipa_sudo_refresh_retry(struct tevent_req *req);

static void ipa_sudo_refresh_connect_done(struct tevent_req *subreq);

static struct tevent_req * ipa_sudo_load_sudoers_send(TALLOC_CTX *mem_ctx,
                                                       struct tevent_context *ev,
                                                       struct sdap_options *opts,
                                                       struct sdap_handle *sh,
                                                       const char *ldap_filter,
                                                       int attrs_count);

static errno_t ipa_sudo_load_sudoers_next_base(struct tevent_req *req);

static void ipa_sudo_load_sudoers_process(struct tevent_req *subreq);
static void ipa_sudo_load_ipa_sudoers_process(struct tevent_req *subreq);
static void ipa_sudo_process_ipa_rules(struct tevent_req *subreq);
static void ipa_sudo_get_cmds_done(struct tevent_req *subreq);

static int ipa_sudo_load_sudoers_recv(struct tevent_req *req,
                                       TALLOC_CTX *mem_ctx,
                                       size_t *rules_count,
                                       struct sysdb_attrs ***rules);

struct tevent_req *ipa_sudo_refresh_send(TALLOC_CTX *mem_ctx,
                                          struct be_ctx *be_ctx,
                                          struct sdap_options *opts,
                                          struct sdap_id_conn_cache *conn_cache,
                                          const char *ldap_filter,
                                          const char *sysdb_filter)
{
    struct tevent_req *req;
    struct sdap_sudo_refresh_state *state;
    int ret;

    req = tevent_req_create(mem_ctx, &state, struct sdap_sudo_refresh_state);
    if (!req) {
        return NULL;
    }

    /* if we don't have a search filter, this request is meaningless */
    if (ldap_filter == NULL) {
        ret = EINVAL;
        goto immediately;
    }

    printf("sysdb_filter: %s\n", sysdb_filter);
    state->be_ctx = be_ctx;
    state->opts = opts;
    state->sdap_op = NULL;
    state->sdap_conn_cache = conn_cache;
    state->sysdb = be_ctx->domain->sysdb;
    state->domain = be_ctx->domain;
    state->ldap_filter = talloc_strdup(state, ldap_filter);
    state->sysdb_filter = talloc_strdup(state, sysdb_filter);
    state->dp_error = DP_ERR_OK;
    state->error = EOK;
    state->highest_usn = NULL;

    if (state->ldap_filter == NULL) {
        ret = ENOMEM;
        goto immediately;
    }

    if (sysdb_filter != NULL && state->sysdb_filter == NULL) {
        ret = ENOMEM;
        goto immediately;
    }

    ret = ipa_sudo_refresh_retry(req);
    if (ret == EAGAIN) {
        /* asynchronous processing */
        return req;
    }

immediately:
    if (ret == EOK) {
        tevent_req_done(req);
    } else {
        tevent_req_error(req, ret);
    }
    tevent_req_post(req, be_ctx->ev);

    return req;
}

int ipa_sudo_refresh_recv(TALLOC_CTX *mem_ctx,
                           struct tevent_req *req,
                           int *dp_error,
                           int *error,
                           char **usn,
                           size_t *num_rules)
{
    struct sdap_sudo_refresh_state *state;

    state = tevent_req_data(req, struct sdap_sudo_refresh_state);

    TEVENT_REQ_RETURN_ON_ERROR(req);

    *dp_error = state->dp_error;
    *error = state->error;

    if (usn != NULL && state->highest_usn != NULL) {
        *usn = talloc_steal(mem_ctx, state->highest_usn);
    }

    if (num_rules != NULL) {
        *num_rules = state->num_rules;
    }

    return EOK;
}

static int ipa_sudo_refresh_retry(struct tevent_req *req)
{
    struct sdap_sudo_refresh_state *state;
    struct tevent_req *subreq;
    int ret;

    state = tevent_req_data(req, struct sdap_sudo_refresh_state);

    if (be_is_offline(state->be_ctx)) {
        state->dp_error = DP_ERR_OFFLINE;
        state->error = EAGAIN;
        return EOK;
    }

    if (state->sdap_op == NULL) {
        state->sdap_op = sdap_id_op_create(state, state->sdap_conn_cache);
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

    tevent_req_set_callback(subreq, ipa_sudo_refresh_connect_done, req);

    return EAGAIN;
}

static void ipa_sudo_refresh_connect_done(struct tevent_req *subreq)
{
    struct tevent_req *req; /* req from ipa_sudo_refresh_send() */
    struct sdap_sudo_refresh_state *state;
    int attrs_count;
    int dp_error;
    int ret;

    req = tevent_req_callback_data(subreq, struct tevent_req);
    state = tevent_req_data(req, struct sdap_sudo_refresh_state);

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
              ("SUDO LDAP connection failed - %s\n", strerror(ret)));
        goto fail;
    }

    DEBUG(SSSDBG_TRACE_FUNC, ("IPA SUDO LDAP connection successful\n"));

    subreq = ipa_sudo_load_sudoers_send(state, state->be_ctx->ev,
                                        state->opts,
                                        sdap_id_op_handle(state->sdap_op),
                                        state->ldap_filter,
                                        SDAP_OPTS_IPA_SUDO);
    if (subreq == NULL) {
        ret = EFAULT;
        goto fail;
    }

    tevent_req_set_callback(subreq, sdap_sudo_refresh_load_done, req);

    return;

fail:
    state->dp_error = DP_ERR_FATAL;
    state->error = ret;
    tevent_req_error(req, ret);
}

static struct tevent_req *ipa_sudo_load_sudoers_send(TALLOC_CTX *mem_ctx,
                                                       struct tevent_context *ev,
                                                       struct sdap_options *opts,
                                                       struct sdap_handle *sh,
                                                       const char *ldap_filter,
                                                       int attrs_count)
{
    struct tevent_req *req;
    struct sdap_sudo_load_sudoers_state *state;
    int ret;

    req = tevent_req_create(mem_ctx, &state, struct sdap_sudo_load_sudoers_state);
    if (!req) {
        return NULL;
    }

    state->ev = ev;
    state->opts = opts;
    state->sh = sh;
    state->base_iter = 0;
    state->search_bases = opts->sdom->sudo_search_bases;
    state->filter = ldap_filter;
    state->timeout = dp_opt_get_int(opts->basic, SDAP_SEARCH_TIMEOUT);
    state->refresh_state = mem_ctx;
    state->ldap_rules = NULL;
    state->ldap_rules_count = 0;

    if (!state->search_bases) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              ("SUDOERS lookup request without a search base\n"));
        ret = EINVAL;
        goto done;
    }

    /* create attrs from map */
    ret = build_attrs_from_map(state, opts->ipa_sudorule_map, attrs_count,
                               NULL, &state->attrs, NULL);
    if (ret != EOK) {
        goto fail;
    }

    /* begin search */
    ret = ipa_sudo_load_sudoers_next_base(req);

done:
    if (ret != EOK) {
        tevent_req_error(req, ret);
        tevent_req_post(req, ev);
    }

    return req;

fail:
    talloc_zfree(req);
    return NULL;
}

static errno_t ipa_sudo_load_sudoers_next_base(struct tevent_req *req)
{
    struct sdap_sudo_load_sudoers_state *state;
    struct sdap_search_base *search_base;
    struct tevent_req *subreq;
    char *filter;

    state = tevent_req_data(req, struct sdap_sudo_load_sudoers_state);
    search_base = state->search_bases[state->base_iter];
    if (search_base == NULL) {
        /* should not happen */
        DEBUG(SSSDBG_CRIT_FAILURE, ("search_base is null\n"));
        return EFAULT;
    }

    /* create filter 
    filter = sdap_get_id_specific_filter(state, state->filter,
                                         search_base->filter);
    if (filter == NULL) {
        return ENOMEM;
    }*/

    /* send request */
    DEBUG(SSSDBG_TRACE_FUNC,
          ("Searching for IPA sudo rules with base [%s]\n",
           search_base->basedn));

    subreq = sdap_get_generic_send(state,
                                   state->ev,
                                   state->opts,
                                   state->sh,
                                   search_base->basedn,
                                   search_base->scope,
                                   state->filter,
                                   state->attrs,
                                   state->opts->ipa_sudorule_map,
                                   SDAP_OPTS_IPA_SUDO,  
                                   state->timeout,
                                   true);
    if (subreq == NULL) {
        return ENOMEM;
    }

    /* we'll receive SUDO rules in IPA scheme. We need to export these rules 
     * into native LDAP SUDO scheme before we can store them into sysdb.
     */
    tevent_req_set_callback(subreq, ipa_sudo_load_ipa_sudoers_process, req);

    return EOK;
}

static void ipa_sudo_load_ipa_sudoers_process(struct tevent_req *subreq)
{
    struct tevent_req *req;
    struct tevent_req *subsubreq;
    struct sdap_sudo_load_sudoers_state *state;
    struct sdap_search_base *search_base;
    struct sysdb_attrs **ipa_rules = NULL;
    size_t ipa_rules_count;
    const char *filter;
    int ret;

    req = tevent_req_callback_data(subreq, struct tevent_req);
    state = tevent_req_data(req, struct sdap_sudo_load_sudoers_state);
    search_base = state->search_bases[state->base_iter];

    DEBUG(SSSDBG_TRACE_FUNC, ("Receiving IPA SUDO rules with base [%s] and "
                              "giving control to IPA SUDO Provider\n", 
                               search_base->basedn));

    ret = sdap_get_generic_recv(subreq, state, &ipa_rules_count, &ipa_rules);
    talloc_zfree(subreq);
    if (ret) {
        tevent_req_error(req, ret);
        return;
    }

    //subsubreq = ipa_sudo_export_rules_send(state, attrs, count, state, req);
    subsubreq = ipa_sudo_get_cmds_send(ipa_rules,ipa_rules_count, state, req);
    if (subsubreq == NULL) {
        tevent_req_error(req, ENOMEM);
        return;
    }

    tevent_req_set_callback(subsubreq, ipa_sudo_get_cmds_done, req);
}

static void ipa_sudo_get_cmds_done(struct tevent_req *subreq)
{

    struct tevent_req *req;
    struct sdap_sudo_load_sudoers_state *state;
    struct sdap_search_base *search_base;
    struct sysdb_attrs **attrs = NULL;
    size_t count;
    int ret;
    int i;

    /* req from ipa_sudo_load_sudoers_send() */
    req = tevent_req_callback_data(subreq, struct tevent_req);
    state = tevent_req_data(req, struct sdap_sudo_load_sudoers_state);

    /* get EXPORTED sudoers */
    ret = ipa_sudo_get_cmds_recv(subreq, state, &count, &attrs);
    if (ret) {
        tevent_req_error(req, ret);
        return;
    }

    print_rules("Exported ipa sudoers:", attrs, count);

    search_base = state->search_bases[state->base_iter];

    /* add exported rules to result */
    if (count > 0) {
        state->ldap_rules = talloc_realloc(state, state->ldap_rules,
                                           struct sysdb_attrs *,
                                           state->ldap_rules_count + count);
        if (state->ldap_rules == NULL) {
            tevent_req_error(req, ENOMEM);
            return;
        }

        for (i = 0; i < count; i++) {
            state->ldap_rules[state->ldap_rules_count + i] = talloc_steal(
                                                   state->ldap_rules, attrs[i]);
        }

        state->ldap_rules_count += count;
    }

    /* free data of IPA SUDO Provider */
    //talloc_zfree(subreq);

    /* go to next base */
    state->base_iter++;
    if (state->search_bases[state->base_iter]) {
        ret = ipa_sudo_load_sudoers_next_base(req);
        if (ret != EOK) {
            tevent_req_error(req, ret);
        }

        return;
    }

    /* we are done - ipa_sudo_load_sudoers_send */
    tevent_req_done(req);
}

#ifdef fuckoff
static int ipa_sudo_load_sudoers_recv(struct tevent_req *req,
                                       TALLOC_CTX *mem_ctx,
                                       size_t *rules_count,
                                       struct sysdb_attrs ***rules)
{
    struct sdap_sudo_load_sudoers_state *state;

    state = tevent_req_data(req, struct sdap_sudo_load_sudoers_state);

    TEVENT_REQ_RETURN_ON_ERROR(req);

    *rules_count = state->ldap_rules_count;
    *rules = talloc_steal(mem_ctx, state->ldap_rules);

    return EOK;
}

static void ipa_sudo_refresh_load_done(struct tevent_req *subreq)
{
    struct tevent_req *req; /* req from sdap_sudo_refresh_send() */
    struct sdap_sudo_refresh_state *state;
    struct sysdb_attrs **rules = NULL;
    size_t rules_count = 0;
    int ret;
    errno_t sret;
    bool in_transaction = false;
    time_t now;

    req = tevent_req_callback_data(subreq, struct tevent_req);
    state = tevent_req_data(req, struct sdap_sudo_refresh_state);

    ret = ipa_sudo_load_sudoers_recv(subreq, state, &rules_count, &rules);
    talloc_zfree(subreq);
    if (ret != EOK) {
        goto done;
    }

    DEBUG(SSSDBG_TRACE_FUNC, ("Received %zu rules\n", rules_count));

    //print_rules(rules, rules_count);

    /* start transaction */
    ret = sysdb_transaction_start(state->sysdb);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, ("Failed to start transaction\n"));
        goto done;
    }
    in_transaction = true;

    /* purge cache */
    ret = sdap_sudo_purge_sudoers(state->domain, state->sysdb_filter,
                                  state->opts->sudorule_map, rules_count, rules);
    if (ret != EOK) {
        goto done;
    }

    /* store rules */
    now = time(NULL);
    ret = sdap_sudo_store_sudoers(state, state->domain,
                                  state->opts, rules_count, rules,
                                  state->domain->sudo_timeout, now,
                                  &state->highest_usn);
    if (ret != EOK) {
        goto done;
    }

    /* commit transaction */
    ret = sysdb_transaction_commit(state->sysdb);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, ("Failed to commit transaction\n"));
        goto done;
    }
    in_transaction = false;

    DEBUG(SSSDBG_TRACE_FUNC, ("Sudoers is successfully stored in cache\n"));

    ret = EOK;
    state->num_rules = rules_count;

done:
    if (in_transaction) {
        sret = sysdb_transaction_cancel(state->sysdb);
        if (sret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE, ("Could not cancel transaction\n"));
        }
    }

    state->error = ret;
    if (ret == EOK) {
        state->dp_error = DP_ERR_OK;
        tevent_req_done(req);
    } else {
        state->dp_error = DP_ERR_FATAL;
        tevent_req_error(req, ret);
    }
}

static int ipa_sudo_purge_sudoers(struct sss_domain_info *dom,
                            const char *filter,
                            struct sdap_attr_map *map,
                            size_t rules_count,
                            struct sysdb_attrs **rules)
{
    const char *name;
    int i;
    errno_t ret;

    if (filter == NULL) {
        /* removes downloaded rules from the cache */
        if (rules_count == 0 || rules == NULL) {
            return EOK;
        }

        for (i = 0; i < rules_count; i++) {
            ret = sysdb_attrs_get_string(rules[i],
                                         map[SDAP_AT_SUDO_NAME].sys_name,
                                         &name);
            if (ret != EOK) {
                DEBUG(SSSDBG_MINOR_FAILURE,
                      ("Failed to retrieve rule name: [%s]\n", strerror(ret)));
                continue;
            }

            ret = sysdb_sudo_purge_byname(dom, name);
            if (ret != EOK) {
                DEBUG(SSSDBG_MINOR_FAILURE,
                      ("Failed to delete rule %s: [%s]\n",
                       name, strerror(ret)));
                continue;
            }
        }

        ret = EOK;
    } else {
        /* purge cache by provided filter */
        ret = sysdb_sudo_purge_byfilter(dom, filter);
        if (ret != EOK) {
            goto done;
        }
    }

done:
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, ("failed to purge sudo rules [%d]: %s\n",
                                  ret, strerror(ret)));
    }

    return ret;
}

static int ipa_sudo_store_sudoers(TALLOC_CTX *mem_ctx,
                                   struct sss_domain_info *domain,
                                   struct sdap_options *opts,
                                   size_t rules_count,
                                   struct sysdb_attrs **rules,
                                   int cache_timeout,
                                   time_t now,
                                   char **_usn)
{
    errno_t ret;

    /* Empty sudoers? Done. */
    if (rules_count == 0 || rules == NULL) {
        return EOK;
    }

    ret = sdap_save_native_sudorule_list(mem_ctx, domain,
                                         opts->sudorule_map, rules,
                                         rules_count, cache_timeout, now,
                                         _usn);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, ("failed to save sudo rules [%d]: %s\n",
              ret, strerror(ret)));
        return ret;
    }

    return EOK;
}
#endif
