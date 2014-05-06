#ifndef _IPA_ASYNC_SUDO_HOSTGROUPS_
#define _IPA_ASYNC_SUDO_HOSTGROUPS_


struct tevent_req *
ipa_sudo_get_hostgroups_send(TALLOC_CTX *mem, 
                             const char *fqdn,
                             struct ipa_access_ctx *access_ctx);

int ipa_sudo_get_hostgroups_recv(struct tevent_req *req,
                                 TALLOC_CTX *mem_ctx,
                                 int *dp_error,
                                 int *error,
                                 struct sysdb_attrs ***hostgroup,
                                 size_t *hostgrups_count);

#endif	// _IPA_ASYNC_SUDO_HOSTGROUPS_
