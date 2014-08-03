/*
    SSSD

    Authors:
        MIchal Šrubař <mmsrubar@gmail.com>

    Copyright (C) 2014 MIchal Šrubař

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


#ifndef _IPA_ASYNC_SUDO_HOSTGROUPS_
#define _IPA_ASYNC_SUDO_HOSTGROUPS_

struct tevent_req *ipa_sudo_get_hostgroups_send(TALLOC_CTX *mem, 
                                                struct sdap_sudo_ctx *sudo_ctx);
int ipa_sudo_get_hostgroups_recv(struct tevent_req *req,
                                 TALLOC_CTX *mem_ctx,
                                 int *dp_error,
                                 int *error,
                                 struct sysdb_attrs ***hostgroup,
                                 size_t *hostgrups_count);

#endif	// _IPA_ASYNC_SUDO_HOSTGROUPS_
