#ifndef _IPA_ASYNC_SUDO_CMDS_H_
#define _IPA_ASYNC_SUDO_CMDS_H_

struct tevent_req *
ipa_sudo_get_cmds_send(TALLOC_CTX *mem,
                       struct sysdb_attrs **ipa_rules,
                       int ipa_rules_count,
                       struct be_ctx *be_ctx,
                       struct sdap_id_conn_cache *conn_cache,
                       struct sdap_options *opts);

int ipa_sudo_get_cmds_recv(struct tevent_req *req,
                               TALLOC_CTX *mem_ctx,
                               size_t *reply_count,
                               struct sysdb_attrs ***reply);

#endif	// _IPA_ASYNC_SUDO_CMDS_H_
