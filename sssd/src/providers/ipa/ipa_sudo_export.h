#ifndef _IPA_SUDO_EXPORT_H_
#define _IPA_SUDO_EXPORT_H_

struct sudo_rules {
    /* sudoers in native SUDO LDAP format */
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

  #endif	// _IPA_SUDO_EXPORT_H_
