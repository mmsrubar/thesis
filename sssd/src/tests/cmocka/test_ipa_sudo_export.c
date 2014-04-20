/*
    Authors:
        Michal Srubar <mmsrubar@gmail.com>

    Copyright (C) 2014 Red Hat

    SSSD tests: Dynamic tests of exporting IPA SUDO rules from IPA SUDO scheme 
    into native LDAP SUDO scheme.

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

#include <talloc.h>
#include <tevent.h>
#include <errno.h>
#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>

#include "providers/ldap/sdap.h"
#include "providers/ldap/sdap_async_sudo.h"
#include "db/sysdb.h"

#include "providers/ipa/ipa_sudo_export.c"
#include "providers/ipa/ipa_sudo_cmd.c"
#include "providers/ipa/ipa_async_sudo.c"
//#include "src/providers/ipa/ipa_async_sudo.h"

void __wrap_be_is_offline(void)
{
}

void __wrap_sdap_id_op_create(void)
{
}

void __wrap_sdap_id_op_connect_send(void)
{
}
void __wrap_sdap_id_op_connect_recv(void)
{
}
void __wrap_sdap_id_op_handle(void)
{
}
void __wrap_sdap_get_generic_send(void)
{
}
void __wrap_sdap_get_generic_recv(void)
{
}

struct sudo_rule {
    const char *attr;
    const char *val;
};

struct sudo_rule ipa_rule1[] = {
    {"ipaUniqueID", "027d986e-c579-11e3-9220-0800274dc10b"},
    {"description", "Rule allowing 'admin' to run 'blkid' at ALL hosts."},
    {"ipaEnabledFlag", "TRUE"},
    {"cn", "test1"},
    {"memberUser", "uid=admin,cn=users,cn=accounts,dc=example,dc=cz"},
    {"hostCategory", "all"},
    {"memberAllowCmd", "ipaUniqueID=fdfcaf84-5a87-11e3-b71d-080027eec4b0,cn=sudocmds,cn=sudo,dc=example,dc=cz"},
    {"entryUSN", "8740"},
    {NULL, NULL}
};

struct sudo_rule ldap_rule1[] = {
    {"originalDN", "ipaUniqueID=...,cn=sudorules,cn=sudo,$DC"},
    {"cn", "test1"},
    {"sudoUser", "admin"},
    {"sudoHost", "ALL"},
    {"entryUSN", "8740"},
    {"sudoCommand", "/sbin/blkid"},
    {NULL, NULL}
};

struct sysdb_attrs *create_rule(struct sudo_rule rule[])
{
    TALLOC_CTX *mem = talloc_init(NULL);

    struct ldb_message_element *new_el = NULL;
    const char *attr;
    const char *val;
    int i;

    struct sysdb_attrs *sudoer = sysdb_new_attrs(mem);
    if (rule == NULL) {
        return NULL;
    }

    for (i = 0; rule[i].attr != NULL && rule[i].val != NULL; i++) {

        /* create attribute */
        if (sysdb_attrs_get_el_ext(sudoer, rule[i].attr, true, &new_el) != EOK) {
            return NULL;
        }

        /* add value */
        if (sysdb_attrs_add_string(sudoer, rule[i].attr, rule[i].val) != EOK) {
            return NULL;
        }
    }

    return sudoer;
}

static void test_export_no_rules_done(struct tevent_req *subreq);

void test_export_no_rules_send(void **state)
{
    struct tevent_req *req;
    struct tevent_context *ctx;
    TALLOC_CTX *tmp = talloc_init(NULL);
	ctx = tevent_context_init(tmp);
    int count = 1;
    int i;

    struct sysdb_attrs **sudoers;
    sudoers = talloc_zero_array(tmp, struct sysdb_attrs *, count);

    for (i = 0; i < count; i++) {
        sudoers[i] = create_rule(ipa_rule1);
    }

    struct sdap_sudo_load_sudoers_state *state;
    struct sdap_sudo_refresh_state *refresh_state
    refresh_state = talloc_zero(tmp, struct sdap_sudo_refresh_state);
    refresh_state->sysdb = NULL
    state->sysdb = sudo_state->refresh_state->sysdb;
    state->req = req_sdap;  /* req from sdap_sudo_load_sudoers_send */

    rules = talloc_zero(state, struct sudo_rules);
    state->rules = rules;

    cmds_ret = ipa_sudo_build_cmds_filter(state, state->sysdb, ipa_rules, 
     

    req = ipa_sudo_export_rules_send(sudoers, 0, NULL, NULL);
    assert_non_null(req);

    tevent_req_set_callback(req, test_export_no_rules_done, req);
    tevent_loop_once(ctx);
}

static void test_export_no_rules_done(struct tevent_req *req)
{
    assert_non_null(req);

    printf("fdsaf");
    struct ipa_sudo_get_cmds_state *ipa_state;  /* state of the IPA provider */
    int ret;
    struct sdap_sudo_load_sudoers_state *state;
    struct sysdb_attrs **attrs = NULL;
    size_t count;
    int i;


    ipa_state = tevent_req_data(req, struct ipa_sudo_get_cmds_state);

    ret = ipa_sudo_export_rules_recv(req, ipa_state, &count, &attrs, &state, &req);
    assert_int_equal(ret, EOK);
}


int main(int argc, const char *argv[])
{
    const UnitTest tests[] = {
        unit_test(test_export_no_rules_send),
    };

    run_tests(tests);
    return 0;
}
