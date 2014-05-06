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

/*
static void ipa_sudo_process_ipa_rules(struct tevent_req *subreq);
static int ipa_sudo_refresh_retry(struct tevent_req *req);
static void ipa_sudo_refresh_connect_done(struct tevent_req *subreq);
static void ipa_sudo_load_sudoers_process(struct tevent_req *subreq);
static struct tevent_req * ipa_sudo_load_sudoers_send(TALLOC_CTX *mem_ctx,
                                                       struct tevent_context *ev,
                                                       struct sdap_options *opts,
                                                       struct sdap_handle *sh,
                                                       const char *ldap_filter,
                                                       int attrs_count);
static int ipa_sudo_load_sudoers_recv(struct tevent_req *req,
                                       TALLOC_CTX *mem_ctx,
                                       size_t *rules_count,
                                       struct sysdb_attrs ***rules);

                                                       */

static void ipa_sudo_load_sudoers_finish(struct tevent_req *req, 
                                         struct sdap_sudo_refresh_state *state,
                                         struct sysdb_attrs **rules,
                                         size_t count);
static errno_t ipa_sudo_load_sudoers_next_base(struct tevent_req *req);
static void ipa_sudo_load_ipa_sudoers_process(struct tevent_req *subreq);
static void ipa_sudo_get_cmds_done(struct tevent_req *subreq);


struct tevent_req *ipa_sudo_refresh_send(TALLOC_CTX *mem_ctx,
                                          struct be_ctx *be_ctx,
                                          struct sdap_options *opts,
                                          struct sdap_id_conn_cache *conn_cache,
                                          const char *ldap_filter,
                                          const char *sysdb_filter)
{
    struct tevent_req *req;
    struct sdap_sudo_refresh_state *state;
    //136Gint ret;

    req = tevent_req_create(mem_ctx, &state, struct sdap_sudo_refresh_state);
    if (!req) {
        return NULL;
    }

    state->be_ctx = be_ctx;
    state->opts = opts;
    state->sdap_op = NULL;
    state->sdap_conn_cache = conn_cache;
    state->sysdb = be_ctx->domain->sysdb;
    state->domain = be_ctx->domain;
    state->req = NULL;
    state->load_req = NULL;
    state->ldap_filter = talloc_strdup(state, ldap_filter);
    state->sysdb_filter = talloc_strdup(state, sysdb_filter);
    state->dp_error = DP_ERR_OK;
    state->error = EOK;
    state->highest_usn = NULL;

    state->ldap_rules = NULL;
    state->ldap_rules_count = 0;

    // FIXME: check filters for null

    ipa_sudo_load_sudoers_next_base(req);

#ifdef old
    req = tevent_req_create(mem_ctx, &state, struct sdap_sudo_refresh_state);
    if (!req) {
        return NULL;
    }

    /* if we don't have a search filter, this request is meaningless */
    if (ldap_filter == NULL) {
        ret = EINVAL;
        goto immediately;
    }
#endif

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

static errno_t ipa_sudo_load_sudoers_next_base(struct tevent_req *req)
{
    struct sdap_sudo_refresh_state *state;
    struct tevent_req *subreq;
    //188Gstruct sdap_search_base *search_base;
    //char *filter;

    state = tevent_req_data(req, struct sdap_sudo_refresh_state);
    /*
    search_base = state->search_bases[state->base_iter];
    if (search_base == NULL) {
       * should not happen *
        DEBUG(SSSDBG_CRIT_FAILURE, ("search_base is null\n"));
        return EFAULT;
    }

     create filter 
    filter = sdap_get_id_specific_filter(state, state->filter,
                                         search_base->filter);
    if (filter == NULL) {
        return ENOMEM;
    }

    DEBUG(SSSDBG_TRACE_FUNC,
          ("Searching for IPA sudo rules with base [%s]\n",
           search_base->basedn));
    */

    DEBUG(SSSDBG_TRACE_FUNC, ("Giving control to LDAP SUDO provider to download IPA sudo rules\n"));

    /* we will use ldap sudo plugin to get the rules */
    subreq = sdap_sudo_refresh_send(state,
                                    state->be_ctx,
                                    state->opts,
                                    state->sdap_conn_cache,
                                    state->ldap_filter,
                                    "");
    if (subreq == NULL) {
        return ENOMEM;
    }

    /* we'll receive SUDO rules in IPA scheme. We need to export these rules 
     * into native LDAP SUDO scheme before we can store them into sysdb.
     */
    tevent_req_set_callback(subreq, ipa_sudo_load_ipa_sudoers_process, req);

    return EOK;
}

/* subreq -> req from sdap_sudo_refresh_send */
static void ipa_sudo_load_ipa_sudoers_process(struct tevent_req *subreq)
{
    struct tevent_req *req;
    struct tevent_req *subsubreq;
    struct sdap_sudo_refresh_state *state;
    struct sysdb_attrs **ipa_rules = NULL;
    size_t ipa_rules_count;
    //const char *filter;
    int ret = EOK;

    /* req from ipa_sudo_refresh_send */
    req = tevent_req_callback_data(subreq, struct tevent_req);
    state = tevent_req_data(req, struct sdap_sudo_refresh_state);


    // FIXME: where to free ipa rules? or put under in sdap_sudo_refresh_state?
    sdap_sudo_refresh_recv(state, subreq, &state->dp_error, &state->error, 
                           &state->highest_usn, 
                           &ipa_rules_count, &ipa_rules, NULL);

    /* you have to steal it rule by rule before you free the struct !*/
    talloc_zfree(subreq);
    if (ret != EOK || state->dp_error != DP_ERR_OK || state->error != EOK) {
        return;
        //goto done;
    }

    print_rules("IPA sudoers:", ipa_rules, ipa_rules_count);

    subsubreq = ipa_sudo_get_cmds_send(state,
                                       ipa_rules, 
                                       ipa_rules_count, 
                                       state->be_ctx, 
                                       state->sdap_conn_cache,
                                       state->opts);
    if (subsubreq == NULL) {
        tevent_req_error(req, ENOMEM);
        return;
    }

    tevent_req_set_callback(subsubreq, ipa_sudo_get_cmds_done, req);
}

static void ipa_sudo_get_cmds_done(struct tevent_req *subreq)
{

    struct tevent_req *req;
    struct sdap_sudo_refresh_state *state;
    struct sysdb_attrs **attrs = NULL;
    size_t count;
    int ret;
    int i;

    /* req from ipa_sudo_refresh_send */
    req = tevent_req_callback_data(subreq, struct tevent_req);
    state = tevent_req_data(req, struct sdap_sudo_refresh_state);

    /* steal EXPORTED sudoers and free IPA sudo commands req */
    ret = ipa_sudo_get_cmds_recv(subreq, state, &count, &attrs);
    talloc_zfree(subreq);
    if (ret) {
        //tevent_req_error(req, ret);
        return;
    }

    print_rules("Exported ipa sudoers:", attrs, count);

    // FIXME: multiple search bases not supported yet
    /* add exported rules to result (because of multiple search bases) */
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

    /* FIXME: skip next bases for now */

    /* now I need to purge sysdb and store sudoers */
    ipa_sudo_load_sudoers_finish(req, state, 
                                 state->ldap_rules, 
                                 state->ldap_rules_count);
}

/* req from ipa_sudo_refresh_send() */
static void ipa_sudo_load_sudoers_finish(struct tevent_req *req, 
                                         struct sdap_sudo_refresh_state *state,
                                         struct sysdb_attrs **rules,
                                         size_t count)
{
    bool in_transaction = false;
    errno_t sret;
    time_t now;
    int ret;

    /* start transaction */
    ret = sysdb_transaction_start(state->sysdb);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, ("Failed to start transaction\n"));
        goto done;
    }
    in_transaction = true;

    /* purge cache */
    ret = sdap_sudo_purge_sudoers(state->domain, state->sysdb_filter,
                                  state->opts->ipa_sudorule_map, count, rules);
    if (ret != EOK) {
        goto done;
    }

    /* store rules */
    now = time(NULL);
    ret = sdap_sudo_store_sudoers(state, state->domain,
                                  state->opts, count, rules,
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
    state->num_rules = count;

done:
    if (in_transaction) {
        sret = sysdb_transaction_cancel(state->sysdb);
        if (sret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE, ("Could not cancel transaction\n"));
        }
    }

    /* finish req from ipa_sudo_refresh_send */
    state->error = ret;
    if (ret == EOK) {
        state->dp_error = DP_ERR_OK;
        tevent_req_done(req);
    } else {
        state->dp_error = DP_ERR_FATAL;
        tevent_req_error(req, ret);
    }
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
#endif
