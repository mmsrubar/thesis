#include "db/sysdb_sudo.h"
#include "providers/ldap/sdap_async.h"
#include "providers/ldap/sdap_async_sudo.h"
#include "providers/ldap/sdap.h"
#include "providers/ipa/ipa_async_sudo.h"
#include "providers/ipa/ipa_common.h"
#include "providers/ipa/ipa_sudo_export.h"
#include "providers/ipa/ipa_sudo_cmd.h"

struct ipa_sudo_get_cmds_state {
    struct be_ctx *be_ctx;
    struct sdap_id_op *sdap_op;
    struct sdap_id_conn_cache *sdap_conn_cache;
    struct sdap_options *opts;
    struct tevent_context *ev;
    struct sysdb_ctx *sysdb;
    struct sss_domain_info *domain;

    const char *sysdb_filter;   /* delete */
    const char *filter;
    const char *basedn;
    const char **attrs;
    int scope;

    int timeout;
    int dp_error;
    int error;

    struct sudo_rules *rules;
};


static int ipa_sudo_get_cmds_retry(struct tevent_req *req);
static errno_t ipa_sudo_get_cmds_connect_done(struct tevent_req *subreq);
static void ipa_sudo_get_cmds_done(struct tevent_req *subreq);

struct sdap_attr_map ipa_sudocmds_map[] = {
    { "ipa_sudocmd_object_class", "ipasudocmd", "ipasudocmd", NULL },
    { "ipa_sudocmd_ipauniqueid", "ipaUniqueID", "ipaUniqueID", NULL },
    { "ipa_sudocmd_command", "sudoCmd", "sudoCmd", NULL },
    { "ipa_sudocmd_memberof", "memberOf", "memberOf", NULL },
    SDAP_ATTR_MAP_TERMINATOR
};


enum sdap_sudocmds_attrs {
    SDAP_OC_SUDO_CMD = 0,
    SDAP_OC_SUDO_CMD_CMD,
    SDAP_OC_SUDO_CMD_MEMBEROF,
    SDAP_OC_SUDO_CMD_IPAUNIQUEID,

    SDAP_OPTS_SUDO_CMD  /* attrs counter */
};


/*
#define SYSDB_SUDO_CACHE_AT_CN         "cn"
#define SYSDB_SUDO_CACHE_AT_USER       "sudoUser"
#define SYSDB_SUDO_CACHE_AT_HOST       "sudoHost"
#define SYSDB_SUDO_CACHE_AT_COMMAND    "sudoCommand"
#define SYSDB_SUDO_CACHE_AT_OPTION     "sudoOption"
#define SYSDB_SUDO_CACHE_AT_RUNASUSER  "sudoRunAsUser"
#define SYSDB_SUDO_CACHE_AT_RUNASGROUP "sudoRunAsGroup"
#define SYSDB_SUDO_CACHE_AT_NOTBEFORE  "sudoNotBefore"
#define SYSDB_SUDO_CACHE_AT_NOTAFTER   "sudoNotAfter"
#define SYSDB_SUDO_CACHE_AT_ORDER      "sudoOrder"
*/


#ifdef A
errno_t get_new_attr_value( TALLOC_CTX *mem, 
                            struct sysdb_ctx *sysdb, 
                            const char *attr, 
                            const char *value, 
                            char **third_value)
{
    TALLOC_CTX *tmp = talloc_init(NULL);

    struct rdn *first   = talloc_zero(tmp, struct rdn);
    struct rdn *second  = talloc_zero(tmp, struct rdn);
    struct rdn *third   = talloc_zero(tmp, struct rdn);

    errno_t ret = EOK;
    char *tmp_value = NULL;
    char sing = '\0';
   
    if (strncmp(attr, "memberHost", strlen("memberHost")) == 0) {

        /* first two RDNs are different but third is the same */
        if (strcasestr(value, "cn=computers") != NULL) {
            first->attr = talloc_strdup(tmp, "fqdn");
            first->val = NULL;

            second->attr = talloc_strdup(tmp, "cn");
            second->val = talloc_strdup(tmp, "computers");
        } 
        else if (strcasestr(value, "cn=hostgroups") != NULL) {
            first->attr = talloc_strdup(tmp, "cn");
            first->val = NULL;

            second->attr = talloc_strdup(tmp, "cn");
            second->val = talloc_strdup(tmp, "hostgroups");
            sing = SUDO_HOSTGROUP_SING;
        }
        else {
            ret = ENOENT;
            goto fail;
        }
        
        third->attr = talloc_strdup(tmp, "cn");
        third->val = talloc_strdup(tmp, "accounts");
    }
    else if (strncmp(attr, "memberUser", strlen("memberUser")) == 0) {

        /* first two RDNs are different but third is the same */
        if (strcasestr(value, "cn=users") != NULL) {
            first->attr = talloc_strdup(tmp, "uid");
            first->val = NULL;      

            second->attr = talloc_strdup(tmp, "cn");
            second->val = talloc_strdup(tmp, "users");
        } 
        else if (strcasestr(value, "cn=groups") != NULL) {
            first->attr = talloc_strdup(tmp, "cn");
            first->val = NULL;

            second->attr = talloc_strdup(tmp, "cn");
            second->val = talloc_strdup(tmp, "groups");
            sing = SUDO_USER_GROUP_SING;
        }
        else {
            ret = ENOENT;
            goto fail;
        }
        
        third->attr = talloc_strdup(tmp, "cn");
        third->val = talloc_strdup(tmp, "accounts");
    }

    get_third_rdn_value(tmp, sysdb, value, first, second, third, &tmp_value);

    /* add sign */

    if (sing != '\0') {
        tmp_value = talloc_asprintf_append_buffer(tmp, "%c%s", sing, tmp_value);
    }
    
    *third_value = talloc_steal(mem, tmp_value);

fail:
    talloc_free(tmp);
    return ret;

}
#endif




#ifdef A
errno_t index_ipa_cmds(TALLOC_CTX *mem,
                       struct ldb_message_element *e,
                       const char ***cmds)
{
    TALLOC_CTX *tmp = talloc_init(NULL);
    const char **values;
    errno_t ret = EOK;

    /* create array for command strings plus NULL sentinel */
    values = talloc_zero_array(tmp, const char *, e->num_values+1);
    if (values == NULL) {
        goto fail;
        ret = ENOMEM;
    }

    for (int i = 0; i < e->num_values; i++) {
        /* copy cmd => ipaUniqueID or DN of commands group */
        values[i] = talloc_strndup(tmp, e->values[i].data, e->values[i].length);

        if (values[i] == NULL) {
            goto fail;
            ret = ENOMEM;
        }
    }

    *cmds = talloc_steal(mem, values);

fail:
    talloc_free(tmp);
    return ret;
}
#endif

void ipa_sudo_export_rules_send( struct sysdb_attrs **attrs, int count, 
                            struct sdap_sudo_load_sudoers_state *sudo_state)
{

    TALLOC_CTX *tmp = talloc_init(NULL);

    struct tevent_req *req;
    struct ipa_sudo_get_cmds_state *state;

    req = tevent_req_create(tmp, &state, struct ipa_sudo_get_cmds_state);
    if (!req) {
        return;
    }

    state->ev = sudo_state->refresh_state->be_ctx->ev;
    state->be_ctx = sudo_state->refresh_state->be_ctx;
    state->sdap_conn_cache = sudo_state->refresh_state->sdap_conn_cache;
    state->opts = sudo_state->opts;
    state->sysdb = sudo_state->refresh_state->sysdb;
    state->domain = sudo_state->refresh_state->domain;
    state->sysdb_filter = talloc_steal(state, sudo_state->refresh_state->sysdb_filter);
    state->sdap_op = NULL;
    state->basedn = talloc_strdup(state, "cn=sudocmds,cn=sudo,dc=example,dc=cz");
    state->scope = LDAP_SCOPE_SUBTREE;
    state->timeout = dp_opt_get_int(sudo_state->opts->basic, SDAP_SEARCH_TIMEOUT);


    struct sudo_rules *rules;
    rules = talloc_zero(state, struct sudo_rules);
    rules->ipa_rules = talloc_steal(state, attrs);
    rules->ipa_rules_count = count;
    state->rules = rules;

    /* get filter so we can download commands necessay for downloaded ipa sudo 
     * rules 
     */
    ipa_sudo_build_cmds_filter(state,
                               state->sysdb, 
                               state->rules->ipa_rules, 
                               state->rules->ipa_rules_count, 
                               &(state->filter));

    print_rules(state->rules->ipa_rules, state->rules->ipa_rules_count);

    ipa_sudo_export_sudoers(state, state->sysdb,
                             state->rules->ipa_rules, 
                             state->rules->ipa_rules_count, 
                             &(state->rules->sudoers),
                             &(state->rules->sudoers_count),
                             &(state->rules->cmds_index));

    ipa_sudo_get_cmds_retry(req);
}

static int ipa_sudo_get_cmds_retry(struct tevent_req *req)
{
    int ret;
    struct tevent_req *subreq;
    struct ipa_sudo_get_cmds_state *state;

    state = tevent_req_data(req, struct ipa_sudo_get_cmds_state);
    print_rules(state->rules->ipa_rules, state->rules->ipa_rules_count);

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

    tevent_req_set_callback(subreq, ipa_sudo_get_cmds_connect_done, req);

    return EAGAIN;
}

static errno_t ipa_sudo_get_cmds_connect_done(struct tevent_req *subreq)
{
    int ret;
    int dp_error;

    struct tevent_req *req;
    req = tevent_req_callback_data(subreq, struct tevent_req);
    struct ipa_sudo_get_cmds_state *state;
    state = tevent_req_data(req, struct ipa_sudo_get_cmds_state);
 
    /*
    struct ipa_sudo_get_cmds_state *state;
    state = tevent_req_callback_data(subreq, struct ipa_sudo_get_cmds_state);
    */

    ret = sdap_id_op_connect_recv(subreq, &dp_error);
    talloc_zfree(subreq);

    if (dp_error == DP_ERR_OFFLINE) {
        talloc_zfree(state->sdap_op);
        state->dp_error = DP_ERR_OFFLINE;
        state->error = EAGAIN;
        //tevent_req_done(req);
        return;
    }

    DEBUG(SSSDBG_TRACE_FUNC, ("IPA SUDO LDAP connection successful\n"));

    struct sdap_attr_map *ipa_sudorules_cmds_map = NULL;

    /* create IPA SUDO attribute map 
     * FIXME: should be done in initialization of IPA SUDO provider
     */
    ret = sdap_get_map(state->opts, state->be_ctx->cdb, state->be_ctx->conf_path,
                       ipa_sudocmds_map,
                       SDAP_OPTS_SUDO_CMD,
                       &ipa_sudorules_cmds_map);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, ("Could not get IPA SUDO attribute map\n"));
        return ret;
    }

    // create attrs from map 
    ret = build_attrs_from_map(state, ipa_sudorules_cmds_map, SDAP_OPTS_SUDO_CMD,
                               NULL, &state->attrs, NULL);
    if (ret != EOK) {
        return;
    }

    // send request 
    DEBUG(SSSDBG_TRACE_FUNC, ("Searching for ipa sudo rule commands\n"));

    subreq = sdap_get_generic_send(state,
                                   state->ev,
                                   state->opts,
                                   sdap_id_op_handle(state->sdap_op),
                                   state->basedn,
                                   state->scope,
                                   state->filter,
                                   state->attrs,
                                   ipa_sudorules_cmds_map,
                                   SDAP_OPTS_SUDO_CMD,
                                   state->timeout,
                                   true);
    if (subreq == NULL) {
        return ENOMEM;
    }

    tevent_req_set_callback(subreq, ipa_sudo_get_cmds_done, req);

    return EOK;
}


static void ipa_sudo_get_cmds_done(struct tevent_req *subreq)
{
    struct tevent_req *req;
    struct ipa_sudo_get_cmds_state *state;
    struct sysdb_attrs **attrs= NULL;
    size_t count;
    int ret;

    req = tevent_req_callback_data(subreq, struct tevent_req);
    state = tevent_req_data(req, struct ipa_sudo_get_cmds_state);
 
    DEBUG(SSSDBG_TRACE_FUNC,
          ("Receiving cmds for ipa sudo rules with base [%s]\n",
           state->basedn));

    ret = sdap_get_generic_recv(subreq, state, &count, &attrs);
    talloc_zfree(subreq);
    if (ret) {
        return;
    }

    printf("ipa commands:\n");
    print_rules(attrs, count);

    printf("sudoers without commands:\n");
    print_rules(state->rules->sudoers, state->rules->sudoers_count);

    ipa_sudo_export_cmds(state, state->rules->sudoers, state->rules->sudoers_count,
                         state->rules->cmds_index, attrs, count);

    printf("sudoers ready to be stored into sysdb:\n");
    print_rules(state->rules->sudoers, state->rules->sudoers_count);

    /* start transaction 
    ret = sysdb_transaction_start(state->sysdb);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, ("Failed to start transaction\n"));
        goto done;
    }
    in_transaction = true;
    */

    /* purge cache */
    ret = sdap_sudo_purge_sudoers(state->domain, state->sysdb_filter,
                                  state->opts->sudorule_map, state->rules->sudoers_count, state->rules->sudoers);
    if (ret != EOK) {
        goto done;
    }

    /* store rules */
    time_t now = time(NULL);
    char *highest_usn = "141245";   //FIXME

    ret = sdap_sudo_store_sudoers(state, state->domain,
                                  state->opts, state->rules->sudoers_count, state->rules->sudoers,
                                  state->domain->sudo_timeout, now,
                                  &highest_usn);
    if (ret != EOK) {
        goto done;
    }

    /* commit transaction 
    ret = sysdb_transaction_commit(state->sysdb);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, ("Failed to commit transaction\n"));
        goto done;
    }
    in_transaction = false;
    */

    DEBUG(SSSDBG_TRACE_FUNC, ("Sudoers is successfuly stored in cache\n"));

done:
    return ret;
}
