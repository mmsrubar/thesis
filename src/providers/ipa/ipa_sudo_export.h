#ifndef _IPA_SUDO_EXPORT_H_
#define _IPA_SUDO_EXPORT_H_

struct sudo_rules {
    /* sudo rules in native LDAP format */
    struct sysdb_attrs **sudoers;
    int sudoers_count;

    /* sudo rules in IPA format */
    struct sysdb_attrs **ipa_rules;
    int ipa_rules_count;

    /* ipa sudo commands for these rules */
    struct sysdb_attrs **ipa_cmds;
    int ipa_cmds_count;

    /* commands index created from ipa sudo rules, the length is same as len of
     * ipa_rules 
     *
     *     rule[0]       rule[1]
     * +-------------+-------------+
     * | allowed     | allowed     |
     * | allowed_num | allowed_num | ...
     * | denied      | denied      |
     * | denied_num  | denied_num  |
     * +-------------+-------------+
     */
    struct ipa_sudoer_cmds **cmds_index;
};


void print_rules(struct sysdb_attrs **rules, int count);

errno_t ipa_sudo_export_sudoers(TALLOC_CTX *mem, 
                            struct sysdb_ctx *sysdb,
                                struct sysdb_attrs **ipa_rules, 
                                int rules_count, 
                                struct sysdb_attrs ***exported_rules,
                                int *sudoers_count,
                                struct ipa_sudoer_cmds ***index);

errno_t get_third_rdn_value( TALLOC_CTX *mem_ctx, 
                                    struct sysdb_ctx *sysdb,
                                    const char *dn_str,
                                    const char *first_attr,
                                    const char *second_attr,
                                    const char *second_val,
                                    const char *third_attr,
                                    const char *third_val,
                                    char **value);

#endif	// _IPA_SUDO_EXPORT_H_
