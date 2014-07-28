#ifndef _IPA_ASYNC_SUDO_H_
#define _IPA_ASYNC_SUDO_H_

struct tevent_req *ipa_sudo_refresh_send(TALLOC_CTX *mem_ctx,
                                          struct be_ctx *be_ctx,
                                          struct sdap_options *opts,
                                          struct sdap_id_conn_cache *conn_cache,
                                          const char *ldap_filter,
                                          const char *sysdb_filter);
int ipa_sudo_refresh_recv(TALLOC_CTX *mem_ctx,
                           struct tevent_req *req,
                           int *dp_error,
                           int *error,
                           char **usn,
                           size_t *num_rules,
                           struct sysdb_attrs ***rules);

#endif	// _IPA_ASYNC_SUDO_H_
