/*
    Authors:
        Michal Šrubař <mmsrubar@gmail.com>

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
#include "providers/data_provider.h"
#include "providers/dp_backend.h"
#include "util/util.h"

/*
#include "providers/ldap/sdap_async_sudo.h"
#include "providers/ldap/sdap_id_op.h"
*/
#include "providers/ldap/ldap_common.h"
#include "providers/ldap/sdap_async_sudo.h"
#include "providers/ldap/sdap_sudo_cache.h"
#include "providers/ldap/ldap_opts.h"
#include "providers/ipa/ipa_async_sudo.h"
#include "providers/ipa/ipa_async_sudo_cmds.h"
#include "providers/ipa/ipa_sudo_export.h"
#include "providers/ipa/ipa_sudo_cmd.h"

#include "tests/common.h"

#define TESTS_PATH "tests_ipa_sudo_export"
#define TEST_CONF_FILE "tests_conf.ldb"

static void test_export_done(struct tevent_req *subreq);
void test_build_commands_filter_fail_done(struct tevent_req *subreq);

struct sudo_rule {
    const char *attr;
    const char *val;
};


// FIXME: put real entries into scheme file and rules from file?

struct sudo_rule ipa_cmd1[] = {
    {"sudoCmd", "/sbin/blkid"},
    {"ipaUniqueID", "fdfcaf84-5a87-11e3-b71d-080027eec4b0"},
    {"memberOf", "cn=network,cn=sudocmdgroups,cn=sudo,dc=example,dc=cz"},
    {NULL, NULL}
};

struct sudo_rule ipa_cmd2[] = {
    {"sudoCmd", "/bin/cat /etc/shadow"},
    {"ipaUniqueID", "6f545188-6630-11e3-92be-0800274dc10b"},
    {NULL, NULL}
};

struct sudo_rule ipa_cmd3[] = {
    {"sudoCmd", "/sbin/fdisk"},
    {"ipaUniqueID", "c484ca28-c019-11e3-84b4-0800274dc10b"},
    {"memberOf", "cn=dics,cn=sudocmdgroups,cn=sudo,dc=example,dc=cz"},
    {NULL, NULL}
};

struct sudo_rule ipa_cmd4[] = {
    {"sudoCmd", "/sbin/usermod"},
    {"ipaUniqueID", "20a53dc2-c79c-11e3-be99-0800274dc10b"},
    {"memberOf", "cn=user,cn=sudocmdgroups,cn=sudo,dc=example,dc=cz"},
    {NULL, NULL}
};

struct sudo_rule ipa_cmd5[] = {
    {"sudoCmd", "/sbin/userdel"},
    {"ipaUniqueID", "35d89eaa-c79c-11e3-ab17-0800274dc10b"},
    {"memberOf", "cn=user,cn=sudocmdgroups,cn=sudo,dc=example,dc=cz"},
    {NULL, NULL}
};

struct sudo_rule ipa_cmd6[] = {
    {"sudoCmd", "/sbin/useradd"},
    {"ipaUniqueID", "41e9a39c-c79c-11e3-8011-0800274dc10b"},
    {"memberOf", "cn=user,cn=sudocmdgroups,cn=sudo,dc=example,dc=cz"},
    {NULL, NULL}
};

struct sudo_rule ipa_cmd7[] = {
    {"sudoCmd", "/sbin/unix_update"},
    {"ipaUniqueID", "87a54b3e-c79c-11e3-9f89-0800274dc10b"},
    {"memberOf", "cn=user,cn=sudocmdgroups,cn=sudo,dc=example,dc=cz"},
    {NULL, NULL}
};

struct sudo_rule ipa_cmd8[] = {
    {"sudoCmd", "/sbin/groupadd"},
    {"ipaUniqueID", "d9c991ea-c79c-11e3-ac02-0800274dc10b"},
    {"memberOf", "cn=group,cn=sudocmdgroups,cn=sudo,dc=example,dc=cz"},
    {NULL, NULL}
};

struct sudo_rule ipa_cmd9[] = {
    {"sudoCmd", "/sbin/groupdel"},
    {"ipaUniqueID", "fcbf4276-c79c-11e3-b1f1-0800274dc10b"},
    {"memberOf", "cn=group,cn=sudocmdgroups,cn=sudo,dc=example,dc=cz"},
    {NULL, NULL}
};

struct sudo_rule ipa_cmd10[] = {
    {"sudoCmd", "/sbin/groupmems"},
    {"ipaUniqueID", "1708d444-c79d-11e3-ac02-0800274dc10b"},
    {"memberOf", "cn=group,cn=sudocmdgroups,cn=sudo,dc=example,dc=cz"},
    {NULL, NULL}
};

struct sudo_rule ipa_cmd11[] = {
    {"sudoCmd", "/sbin/groupmod"},
    {"ipaUniqueID", "26b070b4-c79d-11e3-b620-0800274dc10b"},
    {"memberOf", "cn=group,cn=sudocmdgroups,cn=sudo,dc=example,dc=cz"},
    {NULL, NULL}
};

struct sudo_rule ipa_cmd12[] = {
    {"sudoCmd", "/sbin/dumpcap"},
    {"ipaUniqueID", "48268de6-c79d-11e3-bdc6-0800274dc10b"},
    {"memberOf", "cn=network,cn=sudocmdgroups,cn=sudo,dc=example,dc=cz"},
    {NULL, NULL}
};


/* 1st IPA sudo rule -------------------------------------------------------- */
struct sudo_rule ipa_rule1[] = {
    {"cn", "test1"},
    {"memberUser", "uid=admin,cn=users,cn=accounts,dc=example,dc=cz"},
    {"hostCategory", "all"},
    {"memberAllowCmd", "ipaUniqueID=fdfcaf84-5a87-11e3-b71d-080027eec4b0,cn=sudocmds,cn=sudo,dc=example,dc=cz"},
    {"entryUSN", "8740"},
    {NULL, NULL}
};

struct sudo_rule ldap_rule1[] = {
    {"cn", "test1"},
    {"sudoUser", "admin"},
    {"sudoHost", "ALL"},
    {"entryUSN", "8740"},
    {"sudoCommand", "/sbin/blkid"},
    {NULL, NULL}
};
/* -------------------------------------------------------------------------- */

/* 2nd IPA sudo rule -------------------------------------------------------- */
struct sudo_rule ipa_rule2[] = {
    {"cn", "test2"},
    {"userCategory", "all"},
    {"hostCategory", "all"},
    {"cmdCategory", "all"},
    {"entryUSN", "8040"},
    {NULL, NULL}
};

struct sudo_rule ldap_rule2[] = {
    {"cn", "test2"},
    {"sudoUser", "ALL"},
    {"sudoHost", "ALL"},
    {"entryUSN", "8040"},
    {"sudoCommand", "ALL"},
    {NULL, NULL}
};
/* -------------------------------------------------------------------------- */

/* IPA sudo rule - multiple commands and commands groups */
struct sudo_rule ipa_rule3[] = {
    {"cn", "test4"},
    {"memberUser", "uid=admin,cn=users,cn=accounts,dc=example,dc=cz"},
    {"memberDenyCmd", "cn=group,cn=sudocmdgroups,cn=sudo,dc=example,dc=cz"},
    {"memberDenyCmd", "ipaUniqueID=fdfcaf84-5a87-11e3-b71d-080027eec4b0,cn=sudocmds,cn=sudo,dc=example,dc=cz"},
    {"memberAllowCmd", "cn=user,cn=sudocmdgroups,cn=sudo,dc=example,dc=cz"},
    {"memberAllowCmd", "ipaUniqueID=6f545188-6630-11e3-92be-0800274dc10b,cn=sudocmds,cn=sudo,dc=example,dc=cz"},
    {"memberHost", "fqdn=client1.example.cz,cn=computers,cn=accounts,dc=example,dc=cz"},
    {"entryUSN", "8040"},
    {NULL, NULL}
};

struct sudo_rule ldap_rule3[] = {
	{"sudoUser", "admin"},
	{"sudoHost", "client1.example.cz"},
	{"sudoCommand", "/bin/cat /etc/shadow"},
	{"sudoCommand", "/sbin/unix_update"},
	{"sudoCommand", "/sbin/useradd"},
	{"sudoCommand", "/sbin/userdel"},
	{"sudoCommand", "/sbin/usermod"},
	{"sudoCommand", "!/sbin/blkid"},
	{"sudoCommand", "!/sbin/groupadd"},
	{"sudoCommand", "!/sbin/groupdel"},
	{"sudoCommand", "!/sbin/groupmems"},
	{"sudoCommand", "!/sbin/groupmod"},
	{"cn", "test4"},
    {"entryUSN", "8040"},
    {NULL, NULL}
};

/* IPA sudo rule - multiple options */
struct sudo_rule ipa_rule4[] = {
    {"cn", "test4"},
    {"ipaSudoOpt", "passprompt=\"Sudo invoked by [%u] on [%H] - Cmd run as %U - Password for user %p:\""},
    {"ipaSudoOpt", "timestamp_timeout=0"},
    {"ipaSudoOpt", "logfile=/var/log/sudo.logf"},
    {"ipaSudoOpt", "visiblepw"},
    {"memberHost", "fqdn=client1.example.cz,cn=computers,cn=accounts,dc=example,dc=cz"},
    {"memberUser", "uid=admin,cn=users,cn=accounts,dc=example,dc=cz"},
    {"memberAllowCmd", "ipaUniqueID=c484ca28-c019-11e3-84b4-0800274dc10b,cn=sudocmds,cn=sudo,dc=example,dc=cz"},
    {"entryUSN", "84040"},
    {NULL, NULL}
};

struct sudo_rule ldap_rule4[] = {
    {"sudoUser", "admin"},
    {"sudoHost", "client1.example.cz"},
    {"sudoCommand", "/sbin/fdisk"},
    {"sudoOption", "passprompt=\"Sudo invoked by [%u] on [%H] - Cmd run as %U - Password for user %p:\""},
    {"sudoOption", "timestamp_timeout=0"},
    {"sudoOption", "logfile=/var/log/sudo.logf"},
    {"sudoOption", "visiblepw"},
    {"cn", "test4"},
    {"entryUSN", "84040"},
    {NULL, NULL}
};


/* WHAT TO TEST ? */
/* =================
 * - situation where there are no command needed for downloaded sudo rules
 * - projit vsechny mista, kde by se to mohlo padnout a zkusit je nasimulovat
 *   ... mozna v jinych testech?
 *
 */


bool __wrap_be_is_offline(struct be_ctx *ctx)
{
    /* Az budes chtit testovat offline podporu, tak sem staci dat misto
     * hardcodovaneho true hodnotu kterou specifikujes pomoci will_return
     */
    return (bool) mock();
}

/* A fake sdap_id_conn_data structure */
struct sdap_id_conn_data {
    /* sdap handle */
    struct sdap_handle *sh;
    /* connection request */
};

/* A fake sdap_id_op structure */
struct sdap_id_op {
    /* ID backend context */
    struct sdap_id_conn_cache *conn_cache;
    struct sdap_id_conn_data *conn_data;
    struct tevent_req *connect_req;
};

int __wrap__dp_opt_get_int(struct dp_option *opts,
                    int id, const char *location) {
    return mock_type(int);
}


int __wrap_dp_opt_get_int(struct dp_option *opts, int id) {
    return mock_type(int);
}

struct sdap_id_op *__wrap_sdap_id_op_create(TALLOC_CTX *memctx,
                                     struct sdap_id_conn_cache *conn_cache)
{
    return talloc_zero(memctx, struct sdap_id_op);
}

struct tevent_req *__wrap_sdap_id_op_connect_send(struct sdap_id_op *op,
                                           TALLOC_CTX *memctx,
                                           int *ret_out)
{
    /* Asi budes muset vytvorit i dummy conn_data a sdap_handle
     * aby ti fungovalo sdap_id_op_handle
     */
    *ret_out = EOK;
    return test_request_send(memctx, mock_ptr_type(struct tevent_context *), EOK);
}

int __wrap_sdap_id_op_connect_recv(struct tevent_req *req, int *dp_error)
{
    *dp_error = DP_ERR_OK;
    return test_request_recv(req);
}

struct sdap_handle *__wrap_sdap_id_op_handle(struct sdap_id_op *op)
{
    return NULL;
}

struct tevent_req *__wrap_sdap_get_generic_send(TALLOC_CTX *memctx,
                                         struct tevent_context *ev,
                                         struct sdap_options *opts,
                                         struct sdap_handle *sh,
                                         const char *search_base,
                                         int scope,
                                         const char *filter,
                                         const char **attrs,
                                         struct sdap_attr_map *map,
                                         int map_num_attrs,
                                         int timeout,
                                         bool allow_paging)
{
    return test_request_send(memctx, mock_ptr_type(struct tevent_context *), EOK);
}

int __wrap_sdap_get_generic_recv(struct tevent_req *req,
                                 TALLOC_CTX *mem_ctx,
                                 size_t *reply_count,
                                 struct sysdb_attrs ***reply)
{
    /* Volajici naplni *reply pomoci will_return() a ty
     * si ji tady seberes pomoci mock()
     */
    *reply_count = mock_type(size_t);
    *reply = mock_ptr_type(struct sysdb_attrs **);

    return test_request_recv(req);
}

int __wrap_build_attrs_from_map(TALLOC_CTX *memctx,
                         struct sdap_attr_map *map,
                         size_t size,
                         const char **filter,
                         const char ***_attrs,
                         size_t *attr_count)
{
    const char **attrs;
    int i, j;

    attrs = talloc_zero_array(memctx, const char *, size + 1);
    if (!attrs) {
        return ENOMEM;
    }

    /* first attribute is "objectclass" not the specifc one */
    attrs[0] = talloc_strdup(memctx, "objectClass");
    if (!attrs[0]) return ENOMEM;

    /* add the others */
    for (i = j = 1; i < size; i++) {
        if (map[i].def_name) {
            attrs[j] = map[i].name;
            j++;
        }
    }
    attrs[j] = NULL;

    *_attrs = attrs;
    if (attr_count) *attr_count = j;

    return EOK;
}

void __wrap_sdap_get_id_specific_filter(TALLOC_CTX *mem_ctx,
                                  const char *base_filter,
                                  const char *extra_filter)

{
    return;
}

static int _setup_sysdb_tests(struct sysdb_ctx **_sysdb, bool enumerate)
{
    struct sysdb_ctx *sysdb;
    char *conf_db;
    int ret;

    /* Create tests directory if it doesn't exist */
    /* (relative to current dir) */
    ret = mkdir(TESTS_PATH, 0775);
    if (ret == -1 && errno != EEXIST) {
        //fail("Could not create %s directory", TESTS_PATH);
        return EFAULT;
    }

    sysdb = talloc_zero(NULL, struct sysdb_ctx);
    if (sysdb == NULL) {
        //fail("Could not allocate memory for test context");
        return ENOMEM;
    }

    conf_db = talloc_asprintf(sysdb, "%s/%s", TESTS_PATH, TEST_CONF_FILE);
    if (conf_db == NULL) {
        //fail("Out of memory, aborting!");
        talloc_free(sysdb);
        return ENOMEM;
    }
    DEBUG(3, ("CONFDB: %s\n", conf_db));


    sysdb->ldb = ldb_init(NULL, NULL);
    if (sysdb->ldb == NULL) {
        return EIO;
    }

    /* flag 0 to create ldb if it doesn't exists yet? */
    ret = ldb_connect(sysdb->ldb, conf_db, 0, NULL);
    if (ret != LDB_SUCCESS) {
        DEBUG(0, ("Unable to open config database [%s]\n", conf_db));
        return EIO;
    }

    sysdb->ldb_file = talloc_strdup(sysdb, "/home/base/thesis/sssd/i686/tests_ipa_sudo_export/tests_conf.ldb");

    *_sysdb = sysdb;

    return EOK;
}
struct sysdb_attrs *create_entry(TALLOC_CTX *mem, struct sudo_rule *entry)
{
    struct ldb_message_element *new_el = NULL;
    int i;

    struct sysdb_attrs *sudoer = sysdb_new_attrs(mem);
    if (sudoer == NULL) {
        return NULL;
    }

    for (i = 0; entry[i].attr != NULL && entry[i].val != NULL; i++) {

        /* create attribute */
        if (sysdb_attrs_get_el_ext(sudoer, entry[i].attr, true, &new_el) != EOK) {
            return NULL;
        }

        /* add value */
        if (sysdb_attrs_add_string(sudoer, entry[i].attr, entry[i].val) != EOK) {
            return NULL;
        }
    }

    return sudoer;
}

/* take ldap sudo rules and return same result as IPA would have returned */
void get_sysdb_attrs(TALLOC_CTX *mem, struct sudo_rule *rule[], int count, 
                     struct sysdb_attrs **_sudoers[])
{
    int i;

    struct sysdb_attrs **sudoers;
    sudoers = talloc_zero_array(mem, struct sysdb_attrs *, count);

    for (i = 0; i < count; i++) {
        sudoers[i] = create_entry(mem, rule[i]);
    }

    *_sudoers = sudoers;
}

void compare_sudoers(struct sudo_rule **ldap, struct sysdb_attrs **exported, int count) {

    TALLOC_CTX *tmp = NULL;
    const char *attr, *val;
    const char **values;
    struct sudo_rule *ldap_rule;
    bool found = false;
    int k, j, i;

    /* for each entry */
    for (k = 0; k < count; k++) {

        j = 0;
        ldap_rule = ldap[k];
        attr = ldap_rule[0].attr;
        val = ldap_rule[0].val;

        while (attr != NULL && val != NULL) {
            
            sysdb_attrs_get_string_array(exported[k], attr, tmp, &values);

            /* attr name not found */
            assert_non_null(values);
            /* attr has no values */
            assert_non_null(*values);
            
            for (i = 0; values[i] != NULL; i++) {
                /* value found */
                if (strcmp(val, values[i]) == 0) {
                    found = true;
                    break;
                }
            }
            assert_true(found); found = false;

            j++;
            attr = ldap_rule[j].attr;
            val = ldap_rule[j].val;
        }
    }
}

struct sudo_test {
    struct sdap_sudo_load_sudoers_state *state;
    struct sss_test_ctx *test_ctx;
    struct sudo_rule **ldap_rules;
};

/* set up environment for sudo */
void setup_sudo_env(void **state) {

    TALLOC_CTX *mem = talloc_init(NULL);

    struct sudo_test *sudo_test_ctx;

    sudo_test_ctx = talloc_zero(mem, struct sudo_test);
    assert_non_null(sudo_test_ctx);

    /* sudo contexts */
    sudo_test_ctx->state = talloc_zero(mem, struct sdap_sudo_load_sudoers_state);
    assert_non_null(sudo_test_ctx->state);
    sudo_test_ctx->state->refresh_state = talloc_zero(mem, struct sdap_sudo_refresh_state);
    assert_non_null(sudo_test_ctx->state->refresh_state);

    /* tevent and sysdb */
    sudo_test_ctx->test_ctx = create_ev_test_ctx(mem);
    assert_non_null(sudo_test_ctx->test_ctx);
    _setup_sysdb_tests(&sudo_test_ctx->state->refresh_state->sysdb, false);
    assert_non_null(sudo_test_ctx->state->refresh_state->sysdb);

    /* sudo maps */
    sudo_test_ctx->state->opts = talloc_zero(mem, struct sdap_options);
    assert_non_null(sudo_test_ctx->state->opts);
    sudo_test_ctx->state->opts->sudorule_map =  native_sudorule_map;
    sudo_test_ctx->state->opts->ipa_sudorule_map = ipa_sudorule_map;
    sudo_test_ctx->state->opts->ipa_sudocmds_map = ipa_sudocmds_map;

    *state = sudo_test_ctx;
}

/* */
static void test_build_commands_filter_fail_send(void **state)
{
    struct tevent_req *req;
    struct sudo_test *test_ctx;
 
    test_ctx = *state;

    will_return(__wrap_be_is_offline, false);
    will_return(__wrap__dp_opt_get_int, 30);     /* timeout = 30s */
    will_return(__wrap_sdap_id_op_connect_send, test_ctx->test_ctx->ev);
    will_return(__wrap_sdap_get_generic_send, test_ctx->test_ctx->ev);

    struct be_ctx *be_ctx = talloc_zero(test_ctx, struct be_ctx);
    be_ctx->domain = talloc_zero(be_ctx, struct sss_domain_info);
    be_ctx->ev = test_ctx->test_ctx->ev;
    be_ctx->domain->sysdb = test_ctx->state->refresh_state->sysdb;

    req = ipa_sudo_get_cmds_send(test_ctx, NULL, 0, 
                                 be_ctx, NULL, test_ctx->state->opts);
    assert_non_null(req);

    tevent_req_set_callback(req, test_build_commands_filter_fail_done, test_ctx);

    test_ev_loop(test_ctx->test_ctx);
}

void test_build_commands_filter_fail_done(struct tevent_req *subreq)
{
    struct sudo_test *ctx; 
    struct ipa_sudo_get_cmds_state *state;
    int ret;

    /* req from ipa_sudo_load_sudoers_send() */
    ctx = tevent_req_callback_data(subreq, struct sudo_test);
    state = tevent_req_data(subreq, struct ipa_sudo_get_cmds_state);

    /* get EXPORTED sudoers */
    ret = ipa_sudo_get_cmds_recv(subreq, state, NULL, NULL);

    assert_int_equal(ret, EINVAL);

    /* end tevent loop */
    ctx->test_ctx->done = true;
    ctx->test_ctx->error = EOK;
}



/* simple IPA sudo rule with one command */
void test_simple_rule_send(void **state)
{
    struct tevent_req *req;
    struct sysdb_attrs **sudoers;
    struct sudo_rule **rules;
    struct sysdb_attrs **cmds;
    struct sudo_test *test_ctx;
    int count = 1;                  /* number of tested rules */
    int cmds_count = 1;            /* number of cmds */
 
    test_ctx = *state;

    /* create fake LDAP sudoers */
    test_ctx->ldap_rules = talloc_zero_array(test_ctx, struct sudo_rule *, count);
    assert_non_null(test_ctx->ldap_rules);
    test_ctx->ldap_rules[0] = ldap_rule1;
 
    /* create fake IPA sudoers */
    rules = talloc_zero_array(test_ctx, struct sudo_rule *, count);
    assert_non_null(rules);
    rules[0] = ipa_rule1;
    get_sysdb_attrs(test_ctx, rules, count, &sudoers);
    assert_non_null(sudoers);
 
    /* create fake IPA sudo commands for the rule */
    cmds = talloc_zero_array(test_ctx, struct sysdb_attrs *, cmds_count);
    assert_non_null(cmds);
    cmds[0] = create_entry(test_ctx, ipa_cmd1);
    //print_rules("ipa commands: ", cmds, cmds_count);
    print_rules("ipa_sudoers: ", sudoers, count);

    will_return(__wrap_sdap_get_generic_recv, cmds_count);
    will_return(__wrap_sdap_get_generic_recv, cmds);
    will_return(__wrap_be_is_offline, false);
    will_return(__wrap__dp_opt_get_int, 30);     /* timeout = 30s */
    will_return(__wrap_sdap_id_op_connect_send, test_ctx->test_ctx->ev);
    will_return(__wrap_sdap_get_generic_send, test_ctx->test_ctx->ev);

    struct be_ctx *be_ctx = talloc_zero(test_ctx, struct be_ctx);
    be_ctx->domain = talloc_zero(be_ctx, struct sss_domain_info);
    be_ctx->ev = test_ctx->test_ctx->ev;
    be_ctx->domain->sysdb = test_ctx->state->refresh_state->sysdb;

    /* we don't need search filters because we won't send any requests */
    req = ipa_sudo_get_cmds_send(test_ctx, sudoers, count, 
                                 be_ctx, NULL, test_ctx->state->opts);
    assert_non_null(req);

    tevent_req_set_callback(req, test_export_done, test_ctx);

    test_ev_loop(test_ctx->test_ctx);
}

/* test IPA sudo rule with NO command */
void test_no_commands_send(void **state)
{
    struct tevent_req *req;
    struct sysdb_attrs **sudoers;
    struct sudo_rule **rules;
    struct sudo_test *test_ctx;
    int count = 1;                  /* number of tested rules */
 
    test_ctx = *state;

    /* create fake LDAP sudoers */
    test_ctx->ldap_rules = talloc_zero_array(test_ctx, struct sudo_rule *, count);
    assert_non_null(test_ctx->ldap_rules);
    test_ctx->ldap_rules[0] = ldap_rule2;
 
    /* create fake IPA sudoers */
    rules = talloc_zero_array(test_ctx, struct sudo_rule *, count);
    assert_non_null(rules);
    rules[0] = ipa_rule2;
    get_sysdb_attrs(test_ctx, rules, count, &sudoers);
    assert_non_null(sudoers);
 
    //will_return(__wrap_be_is_offline, false);
    will_return(__wrap__dp_opt_get_int, 30);     /* timeout = 30s */
    //will_return(__wrap_sdap_id_op_connect_send, test_ctx->test_ctx->ev);
    //will_return(__wrap_sdap_get_generic_send, test_ctx->test_ctx->ev);

    struct be_ctx *be_ctx = talloc_zero(test_ctx, struct be_ctx);
    be_ctx->domain = talloc_zero(be_ctx, struct sss_domain_info);
    be_ctx->ev = test_ctx->test_ctx->ev;
    be_ctx->domain->sysdb = test_ctx->state->refresh_state->sysdb;

    /* we don't need search filters because we won't send any requests */
    req = ipa_sudo_get_cmds_send(test_ctx, sudoers, count, 
                                 be_ctx, NULL, test_ctx->state->opts);
    assert_non_null(req);

    tevent_req_set_callback(req, test_export_done, test_ctx);

    test_ev_loop(test_ctx->test_ctx);
}

/* IPA sudo rule multiple commands and commands groups */
void test_multiple_commands_send(void **state)
{
    struct tevent_req *req;
    struct sysdb_attrs **sudoers;
    struct sudo_rule **rules;
    struct sysdb_attrs **cmds;
    struct sudo_test *test_ctx;
    int count = 1;                  /* number of tested rules */
    int cmds_count = 12;            /* number of cmds */
 
    test_ctx = *state;

    /* create fake LDAP sudoers */
    test_ctx->ldap_rules = talloc_zero_array(test_ctx, struct sudo_rule *, count);
    assert_non_null(test_ctx->ldap_rules);
    test_ctx->ldap_rules[0] = ldap_rule3;
 
    /* create fake IPA sudoers */
    rules = talloc_zero_array(test_ctx, struct sudo_rule *, count);
    assert_non_null(rules);
    rules[0] = ipa_rule3;
    get_sysdb_attrs(test_ctx, rules, count, &sudoers);
    assert_non_null(sudoers);
 
    /* create fake IPA sudo commands for the rule */
    cmds = talloc_zero_array(test_ctx, struct sysdb_attrs *, cmds_count);
    assert_non_null(cmds);
    cmds[0] = create_entry(test_ctx, ipa_cmd1);
    cmds[1] = create_entry(test_ctx, ipa_cmd2);
    cmds[2] = create_entry(test_ctx, ipa_cmd3);
    cmds[3] = create_entry(test_ctx, ipa_cmd4);
    cmds[4] = create_entry(test_ctx, ipa_cmd5);
    cmds[5] = create_entry(test_ctx, ipa_cmd6);
    cmds[6] = create_entry(test_ctx, ipa_cmd7);
    cmds[7] = create_entry(test_ctx, ipa_cmd8);
    cmds[8] = create_entry(test_ctx, ipa_cmd9);
    cmds[9] = create_entry(test_ctx, ipa_cmd10);
    cmds[10] = create_entry(test_ctx, ipa_cmd11);
    cmds[11] = create_entry(test_ctx, ipa_cmd12);
    //print_rules("ipa commands: ", cmds, cmds_count);
    //print_rules("ipa_sudoers: ", sudoers, count);

    will_return(__wrap_sdap_get_generic_recv, cmds_count);
    will_return(__wrap_sdap_get_generic_recv, cmds);
    will_return(__wrap_be_is_offline, false);
    will_return(__wrap__dp_opt_get_int, 30);     /* timeout = 30s */
    will_return(__wrap_sdap_id_op_connect_send, test_ctx->test_ctx->ev);
    will_return(__wrap_sdap_get_generic_send, test_ctx->test_ctx->ev);

    struct be_ctx *be_ctx = talloc_zero(test_ctx, struct be_ctx);
    be_ctx->domain = talloc_zero(be_ctx, struct sss_domain_info);
    be_ctx->ev = test_ctx->test_ctx->ev;
    be_ctx->domain->sysdb = test_ctx->state->refresh_state->sysdb;

    /* we don't need search filters because we won't send any requests */
    req = ipa_sudo_get_cmds_send(test_ctx, sudoers, count, 
                                 be_ctx, NULL, test_ctx->state->opts);
    assert_non_null(req);

    tevent_req_set_callback(req, test_export_done, test_ctx);

    test_ev_loop(test_ctx->test_ctx);
}

/* IPA sudo rule multiple commands and commands groups */
void test_multiple_options_send(void **state)
{
    struct tevent_req *req;
    struct sysdb_attrs **sudoers;
    struct sudo_rule **rules;
    struct sysdb_attrs **cmds;
    struct sudo_test *test_ctx;
    int count = 1;                  /* number of tested rules */
    int cmds_count = 1;            /* number of cmds */
 
    test_ctx = *state;

    /* create fake LDAP sudoers */
    test_ctx->ldap_rules = talloc_zero_array(test_ctx, struct sudo_rule *, count);
    assert_non_null(test_ctx->ldap_rules);
    test_ctx->ldap_rules[0] = ldap_rule4;
 
    /* create fake IPA sudoers */
    rules = talloc_zero_array(test_ctx, struct sudo_rule *, count);
    assert_non_null(rules);
    rules[0] = ipa_rule4;
    get_sysdb_attrs(test_ctx, rules, count, &sudoers);
    assert_non_null(sudoers);
 
    /* create fake IPA sudo commands for the rule */
    cmds = talloc_zero_array(test_ctx, struct sysdb_attrs *, cmds_count);
    assert_non_null(cmds);
    cmds[0] = create_entry(test_ctx, ipa_cmd3);
    //print_rules("ipa commands: ", cmds, cmds_count);
    //print_rules("ipa_sudoers: ", sudoers, count);

    will_return(__wrap_sdap_get_generic_recv, cmds_count);
    will_return(__wrap_sdap_get_generic_recv, cmds);
    will_return(__wrap_be_is_offline, false);
    will_return(__wrap__dp_opt_get_int, 30);     /* timeout = 30s */
    will_return(__wrap_sdap_id_op_connect_send, test_ctx->test_ctx->ev);
    will_return(__wrap_sdap_get_generic_send, test_ctx->test_ctx->ev);

    struct be_ctx *be_ctx = talloc_zero(test_ctx, struct be_ctx);
    be_ctx->domain = talloc_zero(be_ctx, struct sss_domain_info);
    be_ctx->ev = test_ctx->test_ctx->ev;
    be_ctx->domain->sysdb = test_ctx->state->refresh_state->sysdb;

    /* we don't need search filters because we won't send any requests */
    req = ipa_sudo_get_cmds_send(test_ctx, sudoers, count, 
                                 be_ctx, NULL, test_ctx->state->opts);
    assert_non_null(req);

    tevent_req_set_callback(req, test_export_done, test_ctx);

    test_ev_loop(test_ctx->test_ctx);
}


/* test all defined IPA sudo rules */
void test_all_defined_ipa_rules_send(void **state)
{
    struct tevent_req *req;
    struct sysdb_attrs **sudoers;
    struct sudo_rule **rules;
    struct sysdb_attrs **cmds;
    struct sudo_test *test_ctx;
    int count = 4;                  /* number of tested rules */
    int cmds_count = 12;            /* number of cmds */
 
    test_ctx = *state;

    /* create fake LDAP sudoers */
    test_ctx->ldap_rules = talloc_zero_array(test_ctx, struct sudo_rule *, count);
    assert_non_null(test_ctx->ldap_rules);
    test_ctx->ldap_rules[0] = ldap_rule1;
    test_ctx->ldap_rules[1] = ldap_rule2;
    test_ctx->ldap_rules[2] = ldap_rule3;
    test_ctx->ldap_rules[3] = ldap_rule4;
 
    /* create fake IPA sudoers */
    rules = talloc_zero_array(test_ctx, struct sudo_rule *, count);
    assert_non_null(rules);
    rules[0] = ipa_rule1;
    rules[1] = ipa_rule2;
    rules[2] = ipa_rule3;
    rules[3] = ipa_rule4;
    get_sysdb_attrs(test_ctx, rules, count, &sudoers);
    assert_non_null(sudoers);
 
    /* create fake IPA sudo commands for the rule */
    cmds = talloc_zero_array(test_ctx, struct sysdb_attrs *, cmds_count);
    assert_non_null(cmds);
    cmds[0] = create_entry(test_ctx, ipa_cmd1);
    cmds[1] = create_entry(test_ctx, ipa_cmd2);
    cmds[2] = create_entry(test_ctx, ipa_cmd3);
    cmds[3] = create_entry(test_ctx, ipa_cmd4);
    cmds[4] = create_entry(test_ctx, ipa_cmd5);
    cmds[5] = create_entry(test_ctx, ipa_cmd6);
    cmds[6] = create_entry(test_ctx, ipa_cmd7);
    cmds[7] = create_entry(test_ctx, ipa_cmd8);
    cmds[8] = create_entry(test_ctx, ipa_cmd9);
    cmds[9] = create_entry(test_ctx, ipa_cmd10);
    cmds[10] = create_entry(test_ctx, ipa_cmd11);
    cmds[11] = create_entry(test_ctx, ipa_cmd12);

    will_return(__wrap_sdap_get_generic_recv, cmds_count);
    will_return(__wrap_sdap_get_generic_recv, cmds);
    will_return(__wrap_be_is_offline, false);
    will_return(__wrap__dp_opt_get_int, 30);     /* timeout = 30s */
    will_return(__wrap_sdap_id_op_connect_send, test_ctx->test_ctx->ev);
    will_return(__wrap_sdap_get_generic_send, test_ctx->test_ctx->ev);

    struct be_ctx *be_ctx = talloc_zero(test_ctx, struct be_ctx);
    be_ctx->domain = talloc_zero(be_ctx, struct sss_domain_info);
    be_ctx->ev = test_ctx->test_ctx->ev;
    be_ctx->domain->sysdb = test_ctx->state->refresh_state->sysdb;

    /* we don't need search filters because we won't send any requests */
    req = ipa_sudo_get_cmds_send(test_ctx, sudoers, count, 
                                 be_ctx, NULL, test_ctx->state->opts);
    assert_non_null(req);

    tevent_req_set_callback(req, test_export_done, test_ctx);

    test_ev_loop(test_ctx->test_ctx);
}



static void test_export_done(struct tevent_req *subreq)
{

    struct sudo_test *ctx; 
    struct ipa_sudo_get_cmds_state *state;
    struct sysdb_attrs **attrs = NULL;
    size_t count;
    int ret;

    /* req from ipa_sudo_load_sudoers_send() */
    ctx = tevent_req_callback_data(subreq, struct sudo_test);
    state = tevent_req_data(subreq, struct ipa_sudo_get_cmds_state);

    /* get EXPORTED sudoers */
    ret = ipa_sudo_get_cmds_recv(subreq, state, &count, &attrs);
    print_rules("exported sudores:", attrs, count);
    assert_int_equal(ret, EOK);

    compare_sudoers(ctx->ldap_rules, attrs, count);

    /* end tevent loop */
    ctx->test_ctx->done = true;
    ctx->test_ctx->error = EOK;
}

void setup_sudo_env_teardown(void **state)
{
    talloc_free(*state);
}

int main(int argc, const char *argv[])
{
    const UnitTest tests[] = {
        unit_test_setup_teardown(test_build_commands_filter_fail_send,
                                 setup_sudo_env,
                                 setup_sudo_env_teardown),
     
        unit_test_setup_teardown(test_simple_rule_send,
                                 setup_sudo_env,
                                 setup_sudo_env_teardown),
        unit_test_setup_teardown(test_no_commands_send,
                                 setup_sudo_env,
                                 setup_sudo_env_teardown),
        unit_test_setup_teardown(test_multiple_commands_send,
                                 setup_sudo_env,
                                 setup_sudo_env_teardown),
        unit_test_setup_teardown(test_multiple_options_send,
                                 setup_sudo_env,
                                 setup_sudo_env_teardown),
        unit_test_setup_teardown(test_all_defined_ipa_rules_send,
                                 setup_sudo_env,
                                 setup_sudo_env_teardown),
    };

    //TODO:
    // - two ipa rules which uses the same ipa commands
    run_tests(tests);
    return 0;
}
