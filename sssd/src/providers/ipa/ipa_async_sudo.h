#ifndef _IPA_ASYNC_SUDO_H_
#define _IPA_ASYNC_SUDO_H_

struct tevent_req *
ipa_sudo_export_rules_send(struct sysdb_attrs **attrs, 
                           int count, 
                           struct sdap_sudo_load_sudoers_state *sudo_state,
                           struct tevent_req *req_sdap);

int ipa_sudo_export_rules_recv(struct tevent_req *req,
                           TALLOC_CTX *mem_ctx,
                           size_t *reply_count,
                           struct sysdb_attrs ***reply,
                           struct sdap_sudo_load_sudoers_state **state,
                           struct tevent_req **req_sdap);

/*
 * IPA SUDO PROVIDER
 * =========================================================================
 */
// hostnoty nekterych attributu muzu ulozit do sysdb primo pod spravnym
// attributem napr( 
//      userCategory=ALL => sudoUser=ALL)
// ale hodnoty jinych musim jeste upravit 
//      memberHost =fqdn=client1.example.cz,cd=..... => sudoHost=client1.example.cz
// originalni ipa jmeno attributu mne bude indikovat, ze hodnota musi byt jeste
// nejak transformovana, nez se ulozi do sysdb ...
//   FIXME: ipasudocmd come first for full refresh this will fail for SMART AND
//     RULES...
/*
struct sdap_attr_map ipa_sudorules_map[] = {
   { "ipa_sudorule_object_class", "ipasudorule", "ipasudorule", NULL },
    { "ipa_sudorule_object_class", "ipasudorule", "ipasudorule", NULL },
    { "ipa_sudorule_name", "cn", SYSDB_SUDO_CACHE_AT_CN, NULL },
    { "ipa_sudorule_usercategory", "userCategory", "userCategory", NULL },
    { "ipa_sudorule_memberuser", "memberUser", "memberUser", NULL },
    { "ipa_sudorule_externaluser", "externalUser", "externalUser", NULL },
    { "ipa_sudorule_hostcategory", "hostCategory", "hostCategory", NULL },
    { "ipa_sudorule_memberhost", "memberHost", "memberHost", NULL },
    { "ipa_sudorule_externalhost", "externalHost", "externalHost", NULL },
    { "ipa_sudorule_cmdcategory", "cmdCategory", "cmdCategory", NULL },
    { "ipa_sudorule_memberallowcmd", "memberAllowCmd", "memberAllowCmd", NULL },
    { "ipa_sudorule_memberdenycmd", "memberDenyCmd", "memberDenyCmd", NULL },
    { "ipa_sudorule_ipasudoopt", "ipaSudoOpt", "ipaSudoOpt", NULL },
    { "ipa_sudorule_ipasudorunasusercategory", "ipaSudoRunAsUserCategory", "ipaSudoRunAsUserCategory", NULL },
    { "ipa_sudorule_ipasudorunas", "ipaSudoRunAs", "ipaSudoRunAs", NULL },
    { "ipa_sudorule_ipasudorunasextuser", "ipaSudoRunAsExtUser", "ipaSudoRunAsExtUser", NULL },
    { "ipa_sudorule_ipasudorunasgroupcategory", "ipaSudoRunAsGroupCategory", "ipaSudoRunAsGroupCategory", NULL },
    { "ipa_sudorule_ipasudorunasgroup", "ipaSudoRunAsGroup", "ipaSudoRunAsGroup", NULL },
    { "ipa_sudorule_ipasudorunasextgroup", "ipaSudoRunAsExtGroup", "ipaSudoRunAsExtGroup", NULL },
    { "ipa_sudorule_entry_usn", NULL, SYSDB_USN, NULL },
    { "ipa_sudorule_cmd", "sudoCmd", "sudoCmd", NULL },
    { "ipa_sudorule_", "memberOf", "memberOf", NULL },
    { "ipa_sudorule_", "ipaUniqueID", "ipaUniqueID", NULL },
    SDAP_ATTR_MAP_TERMINATOR
};
*/

/* mapa ktera vyuziva to ze hodnoty nekterych attr nemusi byt exportovany */

#endif	// _IPA_ASYNC_SUDO_H_
