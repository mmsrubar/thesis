/*
    SSSD

    Authors:
        Michal Šrubař <xsruba03@stud.fit.vutbr.cz>

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


#ifndef _IPA_ASYNC_SUDO_CMDS_H_
#define _IPA_ASYNC_SUDO_CMDS_H_

struct tevent_req *
ipa_sudo_get_cmds_send(TALLOC_CTX *mem,
                       struct sysdb_attrs **ipa_rules,
                       int ipa_rules_count,
                       struct be_ctx *be_ctx,
                       struct sdap_id_conn_cache *conn_cache,
                       struct sdap_options *opts);
int ipa_sudo_get_cmds_recv(struct tevent_req *req,
                               TALLOC_CTX *mem_ctx,
                               size_t *reply_count,
                               struct sysdb_attrs ***reply);

#endif	// _IPA_ASYNC_SUDO_CMDS_H_
