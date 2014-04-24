#ifndef _IPA_ASYNC_SUDO_H_
#define _IPA_ASYNC_SUDO_H_

struct tevent_req *
ipa_sudo_export_rules_send(TALLOC_CTX *mem,
                           struct sysdb_attrs **ipa_rules,
                           int ipa_rules_count,
                           struct sdap_sudo_load_sudoers_state *sudo_state,
                           struct tevent_req *req_sdap);

int ipa_sudo_export_rules_recv(struct tevent_req *req,
                               TALLOC_CTX *mem_ctx,
                               size_t *reply_count,
                               struct sysdb_attrs ***reply,
                               struct sdap_sudo_load_sudoers_state **state,
                               struct tevent_req **req_sdap);

#endif	// _IPA_ASYNC_SUDO_H_
