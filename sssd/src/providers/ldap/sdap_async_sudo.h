#ifndef _SDAP_ASYNC_SUDO_H_
#define _SDAP_ASYNC_SUDO_H_

//void sdap_sudo_refresh_load_done(struct tevent_req *subreq);
static void sdap_sudo_refresh_load_done_ex(struct tevent_req *subreq);

int sdap_sudo_load_sudoers_recv(struct tevent_req *req,
                                       TALLOC_CTX *mem_ctx,
                                       size_t *rules_count,
                                       struct sysdb_attrs ***rules);


int sdap_sudo_purge_sudoers(struct sss_domain_info *dom,
                            const char *filter,
                            struct sdap_attr_map *map,
                            size_t rules_count,
                            struct sysdb_attrs **rules);
int sdap_sudo_store_sudoers(TALLOC_CTX *mem_ctx,
                            struct sss_domain_info *domain,
                            struct sdap_options *opts,
                            size_t rules_count,
                            struct sysdb_attrs **rules,
                            int cache_timeout,
                            time_t now,
                            char **_usn);


struct sdap_sudo_refresh_state {
    struct be_ctx *be_ctx;
    struct sdap_options *opts;
    struct sdap_id_op *sdap_op;
    struct sdap_id_conn_cache *sdap_conn_cache;
    struct sysdb_ctx *sysdb;
    struct sss_domain_info *domain;
    struct tevent_req *req;     /* req from sdap_sudo_refresh_send */
    struct tevent_req *load_req;     /* req from sdap_sudo_load_sudoers_send */

    const char *ldap_filter;    /* search */
    const char *sysdb_filter;   /* delete */

    struct sysdb_attrs **ldap_rules; /* search result will be stored here */
    size_t ldap_rules_count;         /* search result will be stored here */

    int dp_error;
    int error;
    char *highest_usn;
    size_t num_rules;
    bool ipa_provider;
};

struct sdap_sudo_load_sudoers_state {
    struct sdap_sudo_refresh_state *refresh_state;
    struct tevent_req *req;     /* req from sdap_sudo_refresh_send */

    struct tevent_context *ev;
    struct sdap_options *opts;
    struct sdap_handle *sh;
    struct sysdb_attrs **ldap_rules; /* search result will be stored here */
    size_t ldap_rules_count;         /* search result will be stored here */

    const char **attrs;
    const char *filter;
    size_t base_iter;
    struct sdap_search_base **search_bases;
    int timeout;
};

#endif	// _SDAP_ASYNC_SUDO_H_
