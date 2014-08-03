/*
    SSSD

    Authors:
        Michal Šrubař <mmsrubar@gmail.com>

    Copyright (C) 2014 Michal Šrubař

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/


#ifndef _IPA_SUDO_H_
#define _IPA_SUDO_H_

#define IPA_SUDO_CMDS_BASEDN            "cn=sudocmds,cn=sudo,dc=example,dc=cz"
#define IPA_SUDO_CONTAINER_CMDS         "cn=sudocmds,cn=sudo"
#define IPA_SUDO_CONTAINER_CMD_GRPS     "cn=sudocmdgroups,cn=sudo"

#define IPA_SUDO_ATTR_ID                "ipaUniqueID"
#define IPA_SUDO_ATTR_MEMBEROF          "memberOf"
#define IPA_SUDO_ATTR_CMD               "sudoCmd"
#define IPA_SUDO_ATTR_ALLOW_CMD         "memberAllowCmd"
#define IPA_SUDO_ATTR_DENY_CMD          "memberDenyCmd"
#define IPA_SUDO_ATTR_CMD_ALL           "cmdCategory"

#define IPA_SUDO_MEMBER_USER            "memberUser"
#define IPA_SUDO_MEMBER_HOST            "memberHost"
#define IPA_SUDO_RUN_AS                 "ipaSudoRunAs"
#define IPA_SUDO_RUN_AS_GROUP           "ipaSudoRunAsGroup"
 
#define IPA_HOST_FILTER         "(memberHost=fqdn=%s,cn=computers,cn=accounts,%s)"
#define IPA_HOST_GROUP_FILTER   "(memberHost=cn=%s,cn=hostgroups,cn=accounts,%s)"

#define IPA_SUDO_RULE_FILTER    "(objectClass=%s)(ipaEnabledFlag=TRUE)"
#define IPA_SUDO_SMART_FILTER   "&(&(objectclass=%s)(ipaEnabledFlag=TRUE)(%s>=%s)(!(%s=%s)))(|"
#define IPA_SUDO_RULES_FILTER   "&(&(objectClass=%s)(ipaEnabledFlag=TRUE)(|%s))(|"
#define IPA_SUDO_FULL_FILTER    "&(objectClass=%s)(ipaEnabledFlag=TRUE)(|(cn=defaults)"
#define IPA_SUDO_CMD_FILTER     "(&(objectClass=%s)(|"

#endif	// _IPA_SUDO_H_
