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

#include "db/sysdb.h"
#include "db/sysdb_private.h"
#include "confdb/confdb_setup.h"

#include "providers/ldap/sdap.h"
#include "providers/ldap/sdap_async_sudo.h"
#include "providers/ipa/ipa_async_sudo.h"
#include "providers/ipa/ipa_sudo_export.h"
#include "providers/ipa/ipa_sudo_cmd.h"
/*
#include "providers/ipa/ipa_sudo_export.c"
*/

#define TESTS_PATH "tests_ipa_sudo_export"
#define TEST_CONF_FILE "tests_conf.ldb"

/* WHAT TO TEST ? */
/* =================
 * - situation where there are no command needed for downloaded sudo rules
 * - projit vsechny mista, kde by se to mohlo posrat a zkusit je nasimulovat
 *   ... mozna v jinych testech?
 *
 */

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

/*
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

        // create attribute //
        if (sysdb_attrs_get_el_ext(sudoer, rule[i].attr, true, &new_el) != EOK) {
            return NULL;
        }

        if (sysdb_attrs_add_string(sudoer, rule[i].attr, rule[i].val) != EOK) {
            return NULL;
        }
    }

    return sudoer;
}

static void test_export_no_rules_done(struct tevent_req *subreq);

*/
struct sysdb_test_ctx {
    struct sysdb_ctx *sysdb;
    struct confdb_ctx *confdb;
    struct tevent_context *ev;
    struct sss_domain_info *domain;
};

static int _setup_sysdb_tests(struct sysdb_test_ctx **ctx, bool enumerate)
{
    struct sysdb_test_ctx *test_ctx;
    struct ldb_context *ldb;
    char *conf_db;
    int ret;

    const char *val[2];
    val[1] = NULL;

    /* Create tests directory if it doesn't exist */
    /* (relative to current dir) */
    ret = mkdir(TESTS_PATH, 0775);
    if (ret == -1 && errno != EEXIST) {
        //fail("Could not create %s directory", TESTS_PATH);
        return EFAULT;
    }

    test_ctx = talloc_zero(NULL, struct sysdb_test_ctx);
    if (test_ctx == NULL) {
        //fail("Could not allocate memory for test context");
        return ENOMEM;
    }

    test_ctx->sysdb = talloc_zero(NULL, struct sysdb_ctx);
    if (test_ctx->sysdb == NULL) {
        //fail("Could not allocate memory for test context");
        return ENOMEM;
    }

    conf_db = talloc_asprintf(test_ctx, "%s/%s", TESTS_PATH, TEST_CONF_FILE);
    if (conf_db == NULL) {
        //fail("Out of memory, aborting!");
        talloc_free(test_ctx);
        return ENOMEM;
    }
    DEBUG(3, ("CONFDB: %s\n", conf_db));


    test_ctx->sysdb->ldb = ldb_init(NULL, NULL);
    if (test_ctx->sysdb->ldb == NULL) {
        return EIO;
    }

    /* flag 0 to create ldb if it doesn't exists yet? */
    ret = ldb_connect(test_ctx->sysdb->ldb, conf_db, 0, NULL);
    if (ret != LDB_SUCCESS) {
        DEBUG(0, ("Unable to open config database [%s]\n", conf_db));
        return EIO;
    }

    test_ctx->sysdb->ldb_file = talloc_strdup(test_ctx, "/home/base/thesis/sssd/i686/tests_ipa_sudo_export/tests_conf.ldb");

    ipa_sudo_export_rules_send(NULL, 0, NULL, NULL);
#ifdef A

    /* Create an event context
     * It will not be used except in confdb_init and sysdb_init
     */
    test_ctx->ev = tevent_context_init(test_ctx);
    if (test_ctx->ev == NULL) {
        //fail("Could not create event context");
        talloc_free(test_ctx);
        return EIO;
    }

    /* Connect to the conf db */
    ret = confdb_init(test_ctx, &test_ctx->confdb, conf_db);
    if (ret != EOK) {
        //fail("Could not initialize connection to the confdb");
        talloc_free(test_ctx);
        return ret;
    }

    val[0] = "LOCAL";
    ret = confdb_add_param(test_ctx->confdb, true,
                           "config/sssd", "domains", val);
    if (ret != EOK) {
        //fail("Could not initialize domains placeholder");
        talloc_free(test_ctx);
        return ret;
    }

    val[0] = "local";
    ret = confdb_add_param(test_ctx->confdb, true,
                           "config/domain/LOCAL", "id_provider", val);
    if (ret != EOK) {
        //fail("Could not initialize provider");
        talloc_free(test_ctx);
        return ret;
    }

    val[0] = enumerate ? "TRUE" : "FALSE";
    ret = confdb_add_param(test_ctx->confdb, true,
                           "config/domain/LOCAL", "enumerate", val);
    if (ret != EOK) {
        //fail("Could not initialize LOCAL domain");
        talloc_free(test_ctx);
        return ret;
    }

    val[0] = "TRUE";
    ret = confdb_add_param(test_ctx->confdb, true,
                           "config/domain/LOCAL", "cache_credentials", val);
    if (ret != EOK) {
        //("Could not initialize LOCAL domain");
        talloc_free(test_ctx);
        return ret;
    }

    ret = sssd_domain_init(test_ctx, test_ctx->confdb, "local",
                           TESTS_PATH, &test_ctx->domain);
    if (ret != EOK) {
        //("Could not initialize connection to the sysdb (%d)", ret);
        talloc_free(test_ctx);
        return ret;
    }
    test_ctx->sysdb = test_ctx->domain->sysdb;

    *ctx = test_ctx;
#endif
    return EOK;
}

#ifdef A
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

#endif

int main(int argc, const char *argv[])
{
    struct sysdb_test_ctx *test_ctx;
    int ret;

    ret = _setup_sysdb_tests(&test_ctx, false);
    if (ret != EOK) {
        //fail("Could not set up the test");
        return;
    }


    const UnitTest tests[] = {
//        unit_test(test_export_no_rules_send),
    };

    run_tests(tests);
    return 0;
}
