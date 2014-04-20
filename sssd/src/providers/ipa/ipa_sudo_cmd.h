#ifndef _IPA_SUDO_CMD_H_
#define _IPA_SUDO_CMD_H_


struct ipa_sudoer_cmds {
    /* if there are no cmds for the rule then allowed and denied points to NULL
     * and allowd_num and denied_num is zero
     */
    const char **allowed;
    int allowed_num;
    const char **denied;
    int denied_num;
};

ipa_sudo_export_cmds(TALLOC_CTX *mem,
                     struct sysdb_attrs **sudoers,
                     int sudoers_count,
                     struct ipa_sudoer_cmds **index, 
                     struct sysdb_attrs **ipa_cmds,
                     int ipa_cmds_count);

errno_t ipa_sudo_build_cmds_filter(TALLOC_CTX *mem,
                                   struct sysdb_ctx *sysdb,
                                   struct sysdb_attrs **rules, 
                                   int count, 
                                   const char **cmd_filter);

#endif	// _IPA_SUDO_CMD_H_
