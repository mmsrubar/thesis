#!/usr/bin/bash

sudo /usr/bin/install -cv .libs/libsss_ldap_common.so /usr/lib/sssd/libsss_ldap_common.so 
sudo /usr/bin/install -cv .libs/libsss_ldap_common.lai /usr/lib/sssd/libsss_ldap_common.la
sudo /usr/bin/install -cv .libs/sssd_be /usr/libexec/sssd/sssd_be 
sudo /usr/bin/install -cv .libs/ldap_child /usr/libexec/sssd/ldap_child
sudo /usr/bin/install -cv .libs/sssd_sudo /usr/libexec/sssd/sssd_sudo
sudo /usr/bin/install -cv .libs/libsss_ldap.soT /usr/lib/sssd/libsss_ldap.so
sudo /usr/bin/install -cv .libs/libsss_ldap.lai /usr/lib/sssd/libsss_ldap.la
sudo /usr/bin/install -cv .libs/libsss_ipa.soT /usr/lib/sssd/libsss_ipa.so
sudo /usr/bin/install -cv .libs/libsss_ipa.lai /usr/lib/sssd/libsss_ipa.la
sudo /usr/bin/install -cv .libs/libsss_sudo.so /usr/lib/libsss_sudo.so
sudo /usr/bin/install -cv .libs/libsss_sudo.lai /usr/lib/libsss_sudo.la
