#ifndef _SDAP_ASYNC_SUDO_H_
#define _SDAP_ASYNC_SUDO_H_

struct sdap_sudo_refresh_state {
    struct be_ctx *be_ctx;
    struct sdap_options *opts;
    struct sdap_id_op *sdap_op;
    struct sdap_id_conn_cache *sdap_conn_cache;
    struct sysdb_ctx *sysdb;
    struct sss_domain_info *domain;

    const char *ldap_filter;    /* search */
    const char *sysdb_filter;   /* delete */

    int dp_error;
    int error;
    char *highest_usn;
    size_t num_rules;
};

struct sdap_sudo_load_sudoers_state {
    struct sdap_sudo_refresh_state *refresh_state;
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
