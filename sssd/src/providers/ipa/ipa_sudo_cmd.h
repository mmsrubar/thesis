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

errno_t build_cmds_filter(TALLOC_CTX *mem,
                          struct sysdb_ctx *sysdb,
                          struct sysdb_attrs **rules, 
                          int count, 
                          const char **cmd_filter);

/* Add a denied or allowed command of a rule into command index. */
errno_t ipa_sudo_index_commands(TALLOC_CTX *mem, 
                                struct ipa_sudoer_cmds *cmds, 
                                const char *name, 
                                const char *value);

#endif	// _IPA_SUDO_CMD_H_
