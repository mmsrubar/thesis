#ifndef _IPA_ASYNC_SUDO_H_
#define _IPA_ASYNC_SUDO_H_

void ipa_print_rules(struct sysdb_attrs **attrs, int count);
void ipa_sudo_export_rules(struct sysdb_attrs **rules, int count, struct sdap_sudo_load_sudoers_state *state);

#endif	// _IPA_ASYNC_SUDO_H_
