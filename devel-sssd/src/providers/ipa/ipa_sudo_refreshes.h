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


#ifndef _IPA_SUDO_REFRESHES_H_
#define _IPA_SUDO_REFRESHES_H_

struct tevent_req *ipa_sudo_full_refresh_send(TALLOC_CTX *mem_ctx,
                                              struct tevent_context *ev,
                                              struct be_ctx *be_ctx,
                                              struct be_ptask *be_ptask,
                                              void *pvt);
int ipa_sudo_full_refresh_ptask_recv(struct tevent_req *req);
int ipa_sudo_full_refresh_recv(struct tevent_req *req,
                               int *dp_error,
                               int *error);

struct tevent_req *ipa_sudo_rules_refresh_send(TALLOC_CTX *mem_ctx,
                                               struct sdap_sudo_ctx *sudo_ctx,
                                               struct be_ctx *be_ctx,
                                               struct sdap_options *opts,
                                               struct sdap_id_conn_cache *conn_cache,
                                               char **rules);
int ipa_sudo_rules_refresh_recv(struct tevent_req *req,
                                int *dp_error,
                                int *error);

struct tevent_req *ipa_sudo_smart_refresh_send(TALLOC_CTX *mem_ctx,
                                   struct tevent_context *ev,
                                   struct be_ctx *be_ctx,
                                   struct be_ptask *be_ptask,
                                   void *pvt);
int ipa_sudo_smart_refresh_recv(struct tevent_req *req);

#endif	// _IPA_SUDO_REFRESHES_H_
