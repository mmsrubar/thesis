#ifndef _IPA_SUDO_REFRESHES_H_
#define _IPA_SUDO_REFRESHES_H_

struct tevent_req *ipa_sudo_full_refresh_send(TALLOC_CTX *mem_ctx,
                                              struct tevent_context *ev,
                                              struct be_ctx *be_ctx,
                                              struct be_ptask *be_ptask,
                                              void *pvt);
int ipa_sudo_full_refresh_recv(struct tevent_req *req);

struct tevent_req *ipa_sudo_rules_refresh_send(TALLOC_CTX *mem_ctx,
                                               struct sdap_sudo_ctx *sudo_ctx,
                                               struct be_ctx *be_ctx,
                                               struct sdap_options *opts,
                                               struct sdap_id_conn_cache *conn_cache,
                                               char **rules);
struct tevent_req *ipa_sudo_smart_refresh_send(TALLOC_CTX *mem_ctx,
                                   struct tevent_context *ev,
                                   struct be_ctx *be_ctx,
                                   struct be_ptask *be_ptask,
                                   void *pvt);
int ipa_sudo_smart_refresh_recv(struct tevent_req *req);

#endif	// _IPA_SUDO_REFRESHES_H_
