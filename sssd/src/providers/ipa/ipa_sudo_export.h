#ifndef _IPA_SUDO_EXPORT_H_
#define _IPA_SUDO_EXPORT_H_

struct ipa_sudoer_cmds {
    /* if there are no cmds for the rule then allowed and denied points to NULL
     * and allowd_num and denied_num is zero
     */
    const char **allowed;
    int allowed_num;
    const char **denied;
    int denied_num;
};

struct sudo_rules {
    /* sudo rules in native LDAP format ready to be saved into sysdb */
    struct sysdb_attrs **sudoers;
    size_t sudoers_count;

    /* sudo rules in IPA format */
    struct sysdb_attrs **ipa_rules;
    size_t ipa_rules_count;

    /* IPA SUDO commands for thoso rules */
    struct sysdb_attrs **ipa_cmds;
    size_t ipa_cmds_count;

    /* commands index is an array created from ipa sudo rules which the length 
     * is the same as number of ipa_rules 
     *
     * +----------------------------------------+-------------------------+
     * |cn=users_op,cn=sudocmdgroups,cn=sudo,$DC|fdfcaf84-...-080027eec4b0|
     * +----------------------------------------+-------------------------+
     *                                 /|\
     *     rule[0]       rule[1]        |
     * +-------------+---------------+  |
     * | allowed     | allowed ------|---
     * | allowed_num | allowed_num=2 | ...
     * | denied      | denied        |
     * | denied_num  | denied_num    |
     * +-------------+---------------+
     */
    struct ipa_sudoer_cmds **cmds_index;
};

// FIXME:
void print_rules(const char *title, struct sysdb_attrs **rules, int count);

errno_t export_sudoers(TALLOC_CTX *mem, 
                       struct sysdb_ctx *sysdb,
                       struct sysdb_attrs **ipa_rules, 
                       size_t rules_count, 
                       struct sysdb_attrs ***exported_rules,
                       size_t *sudoers_count,
                       struct ipa_sudoer_cmds ***index,
                       struct tevent_req *req);
int export_sudoers_cmds(TALLOC_CTX *mem,
                        struct sysdb_attrs **sudoers,
                        int sudoers_count,
                        struct ipa_sudoer_cmds **index, 
                        struct sysdb_attrs **ipa_cmds,
                        int ipa_cmds_count);

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


#define DENIED_CMD_PREFIX       '!'
#define USER_GROUP_PREFIX       '%'
#define HOST_GROUP_PREFIX       '+'

#endif	// _IPA_SUDO_EXPORT_H_
