#ifndef _IPA_ASYNC_SUDO_H_
#define _IPA_ASYNC_SUDO_H_

struct tevent_req *ipa_sudo_refresh_send(TALLOC_CTX *mem_ctx,
                                          struct be_ctx *be_ctx,
                                          struct sdap_options *opts,
                                          struct sdap_id_conn_cache *conn_cache,
                                          const char *ldap_filter,
                                          const char *sysdb_filter);


#endif	// _IPA_ASYNC_SUDO_H_

