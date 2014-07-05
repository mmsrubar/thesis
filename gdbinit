file /sbin/sssd
set args -i -d 0xbff0 --debug-timestamps=0
show args
set breakpoint pending on
set follow-fork-mode child
set print elements 0

# break in backend init and follow the backed
break be_process_init
commands
set follow-fork-mode parent
continue
end

# SUDO INIT
# =========
b ipa_sudo_init
b ipa_sudo_get_hostinfo_finish
b ipa_sudo_full_refresh_send
#b ipa_sudo_smart_refresh_send
#b ldap_get_sudo_options
#b sdap_parse_search_base
#b ipa_sudo_full_refresh_send
#b ipa_sudo_rules_refresh_send
#b sdap_sudo_rules_refresh_send
#b sdap_sudo_refresh_send

# SUDO HOSTGROUPS
# ===============
#b sdap_sudo_get_hostinfo_send
#b sdap_sudo_get_hostinfo_next
#b ipa_sudo_get_hostgroups_send
#b ipa_sudo_get_hostgroups_connect_done
#b ipa_sudo_get_hostgroups_done
#b ipa_sudo_get_hostinfo_finish
#b ipa_sudo_full_refresh_send
b ipa_sudo_full_refresh_done
b ipa_sudo_smart_refresh_send
b ipa_sudo_refresh_send
b ipa_sudo_load_ipa_sudoers_process
b ipa_sudo_periodical_full_refresh_recv

# CORE SUDO REFRESH
# =================
#b sdap_sudo_refresh_connect_done
#b sdap_sudo_load_sudoers_send
#b sdap_sudo_load_sudoers_next_base
#b sdap_sudo_process_ipa_rules
#b sdap_sudo_load_sudoers_process
#b sdap_id_op_connect_done
#b be_run_unconditional_online_cb
#b sdap_sudo_load_ipa_sudoers_process
#b sdap_sudo_refresh_load_done
#b ipa_sudo_assign_command
#b sdap_parse_entry
#graph display (struct sysdb_attrs[8]) *ipa_cmds

# EXPORT IPA RULES
# ================
#b ipa_sudo_refresh_send
#b ipa_sudo_load_sudoers_next_base
#b sdap_sudo_load_sudoers_process
#b ipa_sudo_load_ipa_cmds_process
#b ipa_sudo_load_ipa_sudoers_process 
#b ipa_sudo_smart_refresh_send
#b sdap_sudo_periodical_first_refresh_done
#b ipa_sudo_get_cmds_connect_done

#b ipa_sudo_export_sudoers
#b ipa_sudo_export_set_properties
#b ipa_sudo_export_attr_values
#b ipa_sudo_get_cmds_send
#b ipa_sudo_get_cmds_done
#b ipa_sudo_load_sudoers_finish
#b ipa_sudo_export_sudoers
#b ipa_sudo_index_commands
#b ipa_sudo_export_cmds

b sdap_sudo_handler
b ipa_sudo_handler
b ipa_sudo_reply

run
