/*
    Authors:
        Michal Šrubař <mmsrubar@gmail.com>

    Copyright (C) 2014 Michal Šrubař

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

#include "providers/ldap/ldap_common.h"
#include "providers/ldap/sdap_async_sudo.h"
#include "providers/ldap/sdap_sudo.h"
#include "providers/ldap/sdap_sudo_cache.h"
#include "providers/ldap/ldap_opts.h"
#include "providers/ipa/ipa_async_sudo.h"
#include "providers/ipa/ipa_async_sudo_cmds.h"
#include "providers/ipa/ipa_sudo_export.h"

#include "tests/common.h"

#define TESTS_PATH "tests_ipa_sudo_export"
#define TEST_CONF_FILE "tests_conf.ldb"

static void test_successful_export_done(struct tevent_req *subreq);
void test_build_commands_filter_fail_done(struct tevent_req *subreq);

struct sudo_ctx {
    struct sss_test_ctx *test_ctx;
    struct be_ctx *be_ctx;
    struct sdap_options *opts;

    struct sudo_rule **ldap;    /* sudoer in LDAP scheme */
    size_t ldap_count;

    struct sudo_rule **ipa;     /* sudoer in IPA scheme */
    struct sysdb_attrs **ipa_sudoers;
    size_t ipa_count;
    struct sysdb_attrs **cmds;  /* IPA sudo commands */
    size_t cmds_count;
};

//FIXME: substitute 'sudo_rule' with 'sudo_entry'
struct sudo_rule {
    const char *attr;
    const char *val;
};


// FIXME: put real entries into .ldif a file and read them from the file?

struct sudo_rule ipa_cmd1[] = {
    {"sudoCmd", "/sbin/blkid"},
    {"ipaUniqueID", "fdfcaf84-5a87-11e3-b71d-080027eec4b0"},
    {"memberOf", "cn=disc,cn=sudocmdgroups,cn=sudo,dc=example,dc=cz"},
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
    {"memberOf", "cn=disc,cn=sudocmdgroups,cn=sudo,dc=example,dc=cz"},
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
    {"memberOf", "cn=user_group,cn=sudocmdgroups,cn=sudo,dc=example,dc=cz"},
    {NULL, NULL}
};

struct sudo_rule ipa_cmd9[] = {
    {"sudoCmd", "/sbin/groupdel"},
    {"ipaUniqueID", "fcbf4276-c79c-11e3-b1f1-0800274dc10b"},
    {"memberOf", "cn=user_group,cn=sudocmdgroups,cn=sudo,dc=example,dc=cz"},
    {NULL, NULL}
};

struct sudo_rule ipa_cmd10[] = {
    {"sudoCmd", "/sbin/groupmems"},
    {"ipaUniqueID", "1708d444-c79d-11e3-ac02-0800274dc10b"},
    {"memberOf", "cn=user_group,cn=sudocmdgroups,cn=sudo,dc=example,dc=cz"},
    {NULL, NULL}
};

struct sudo_rule ipa_cmd11[] = {
    {"sudoCmd", "/sbin/groupmod"},
    {"ipaUniqueID", "26b070b4-c79d-11e3-b620-0800274dc10b"},
    {"memberOf", "cn=user_group,cn=sudocmdgroups,cn=sudo,dc=example,dc=cz"},
    {NULL, NULL}
};

struct sudo_rule ipa_cmd12[] = {
    {"sudoCmd", "/sbin/dumpcap"},
    {"ipaUniqueID", "48268de6-c79d-11e3-bdc6-0800274dc10b"},
    {"memberOf", "cn=network,cn=sudocmdgroups,cn=sudo,dc=example,dc=cz"},
    {NULL, NULL}
};

/* 1st IPA sudo rule -------------------------------------------------------- */
/* TODO: cn has to be first string in ldap rules! */
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
    {"cn", "test3"},
    {"memberUser", "uid=admin,cn=users,cn=accounts,dc=example,dc=cz"},
    {"memberDenyCmd", "cn=user_group,cn=sudocmdgroups,cn=sudo,dc=example,dc=cz"},
    {"memberDenyCmd", "ipaUniqueID=fdfcaf84-5a87-11e3-b71d-080027eec4b0,cn=sudocmds,cn=sudo,dc=example,dc=cz"},
    {"memberAllowCmd", "cn=user,cn=sudocmdgroups,cn=sudo,dc=example,dc=cz"},
    {"memberAllowCmd", "ipaUniqueID=6f545188-6630-11e3-92be-0800274dc10b,cn=sudocmds,cn=sudo,dc=example,dc=cz"},
    {"memberHost", "fqdn=client1.example.cz,cn=computers,cn=accounts,dc=example,dc=cz"},
    {"entryUSN", "8040"},
    {NULL, NULL}
};

struct sudo_rule ldap_rule3[] = {
	{"cn", "test3"},
	{"sudoUser", "admin"},
	{"sudoHost", "client1.example.cz"},
	{"sudoCommand", "!/sbin/blkid"},
	{"sudoCommand", "!/sbin/groupadd"},
	{"sudoCommand", "!/sbin/groupdel"},
	{"sudoCommand", "!/sbin/groupmems"},
	{"sudoCommand", "!/sbin/groupmod"},
	{"sudoCommand", "/bin/cat /etc/shadow"},
	{"sudoCommand", "/sbin/unix_update"},
	{"sudoCommand", "/sbin/useradd"},
	{"sudoCommand", "/sbin/userdel"},
	{"sudoCommand", "/sbin/usermod"},
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
    {"cn", "test4"},
    {"sudoUser", "admin"},
    {"sudoHost", "client1.example.cz"},
    {"sudoCommand", "/sbin/fdisk"},
    {"sudoOption", "passprompt=\"Sudo invoked by [%u] on [%H] - Cmd run as %U - Password for user %p:\""},
    {"sudoOption", "timestamp_timeout=0"},
    {"sudoOption", "logfile=/var/log/sudo.logf"},
    {"sudoOption", "visiblepw"},
    {"entryUSN", "84040"},
    {NULL, NULL}
};

/* IPA sudo rule 
 * command /sbin/blkid is twice in rule, once as a single commands and then as a
 * part of a command group but after the export it has to be in sudoCommand
 * attr just once, otherwise LDAP SUDO provider would save such rule!
 */
struct sudo_rule ipa_rule5[] = {
    {"cn", "test5"},
    {"memberHost", "fqdn=client1.example.cz,cn=computers,cn=accounts,dc=example,dc=cz"},
    {"memberUser", "uid=admin,cn=users,cn=accounts,dc=example,dc=cz"},
    {"memberAllowCmd", "ipaUniqueID=c484ca28-c019-11e3-84b4-0800274dc10b,cn=sudocmds,cn=sudo,dc=example,dc=cz"},
    {"memberAllowCmd", "cn=disc,cn=sudocmdgroups,cn=sudo,dc=example,dc=cz"},
    {"entryUSN", "43240"},
    {NULL, NULL}
};

struct sudo_rule ldap_rule5[] = {
    {"cn", "test5"},
    {"sudoUser", "admin"},
    {"sudoCommand", "/sbin/fdisk"},
    {"sudoCommand", "/sbin/blkid"},
    {"sudoHost", "client1.example.cz"},
    {"entryUSN", "43240"},
    {NULL, NULL}
};

struct sudo_rule ipa_rule6[] = {
    {"cn", "test6"},
    {"memberHost", "fqdn=client15.example.cz,cn=computers,cn=accounts,dc=example,dc=cz"},
    {"memberUser", "uid=ivan,cn=users,cn=accounts,dc=example,dc=cz"},
    {"memberAllowCmd", "ipaUniqueID=c484ca28-c019-11e3-84b4-0800274dc10b,cn=sudocmds,cn=sudo,dc=example,dc=cz"},
    {"memberAllowCmd", "cn=disc,cn=sudocmdgroups,cn=sudo,dc=example,dc=cz"},
    {"entryUSN", "43240"},
    {NULL, NULL}
};

struct sudo_rule ldap_rule6[] = {
    {"cn", "test6"},
    {"sudoUser", "ivan"},
    {"sudoCommand", "/sbin/fdisk"},
    {"sudoCommand", "/sbin/blkid"},
    {"sudoHost", "client115.example.cz"},
    {"entryUSN", "43240"},
    {NULL, NULL}
};

/* WHAT TO TEST ? */
/* =================
 * - situation where there are no command needed for downloaded sudo rules
 * - projit vsechny mista, kde by se to mohlo padnout a zkusit je nasimulovat
 *   ... mozna v jinych testech?
 *
 */

static void debug_printf(const char *format, ...)
                SSS_ATTRIBUTE_PRINTF(1, 2);

static void debug_printf(const char *format, ...)
{
    va_list ap;

    va_start(ap, format);

    vfprintf(stderr, format, ap);

    va_end(ap);
}

/* simple #undef WITH_JOURNALD didn't work :-( */
void __wrap_debug_fn(const char *file,
              long line,
              const char *function,
              int level,
              const char *format, ...)
{
    va_list ap;
    struct timeval tv;
    struct tm *tm;
    char datetime[20];
    int year;

    if (debug_timestamps) {
        gettimeofday(&tv, NULL);
        tm = localtime(&tv.tv_sec);
        year = tm->tm_year + 1900;
        /* get date time without year */
        memcpy(datetime, ctime(&tv.tv_sec), 19);
        datetime[19] = '\0';
        if (debug_microseconds) {
            debug_printf("(%s:%.6ld %d) [%s] [%s] (%#.4x): ",
                         datetime, tv.tv_usec,
                         year, debug_prg_name,
                         function, level);
        } else {
            debug_printf("(%s %d) [%s] [%s] (%#.4x): ",
                         datetime, year,
                         debug_prg_name, function, level);
        }
    } else {
        debug_printf("[%s] [%s] (%#.4x): ",
                     debug_prg_name, function, level);
    }

    va_start(ap, format);
    vfprintf(stderr, format, ap);
    va_end(ap);
    fflush(stderr);
}

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
    DEBUG(3, "CONFDB: %s\n", conf_db);


    sysdb->ldb = ldb_init(NULL, NULL);
    if (sysdb->ldb == NULL) {
        return EIO;
    }

    /* flag 0 to create ldb if it doesn't exists yet? */
    ret = ldb_connect(sysdb->ldb, conf_db, 0, NULL);
    if (ret != LDB_SUCCESS) {
        DEBUG(0, "Unable to open config database [%s]\n", conf_db);
        return EIO;
    }

    //FIXME:    :ta
    sysdb->ldb_file = talloc_strdup(sysdb, "/home/base/thesis/sssd/i686/tests_ipa_sudo_export/tests_conf.ldb");

    /* FIXME: clear sysdb if it already exists
    struct ldb_dn *sudo_dn;
    sudo_dn = ldb_dn_new(sysdb, sysdb->ldb, "cn=sudorules,cn=custom,cn=unit_tests,cn=sysdb");
    if (ldb_dn_validate(sudo_dn) == false) {
        DEBUG(0, "Invalid DN\n");
        return EIO;
    }
    if (ldb_delete(sysdb->ldb, sudo_dn) != LDB_SUCCESS) {
        DEBUG(0, "Error while removin sudo rules from test sysdb\n");
        return EIO;
    }
    */

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

int compare_sudoers(TALLOC_CTX *mem, struct sudo_ctx *sudo_ctx)
{
    struct ldb_result *resultMsg;
    struct sysdb_ctx *sysdb;
    struct sysdb_attrs *sysdb_attrs;
    const char *attr, *val;
    const char **values;
    bool found = false;
    int ret = EOK;
    int i, j, k, l;
    const char *str;

    sysdb = sudo_ctx->test_ctx->sysdb;

    ret = ldb_search(sysdb->ldb, sysdb, &resultMsg, NULL, LDB_SCOPE_DEFAULT, NULL, "(dn=*)");
    if (ret != LDB_SUCCESS) {
        return ENOMEM;
    }

    /* if a number of exported sudoers isn't the same as number of LDAP rules
     * then somthing went wrong. */
    assert_int_equal(resultMsg->count, sudo_ctx->ldap_count);


    sysdb_attrs = sysdb_new_attrs(mem);

    /* compare all LDAP rules with exported rules */
    for (i = 0; i < sudo_ctx->ldap_count; i++) {
        //printf("Comparing LDAP rule with cn=%s\n", sudo_ctx->ldap[i][0].val);

        /* find the LDAP rule in sysdb among the exported sudoers */
        for (j = 0; j < resultMsg->count; j++) {
            sysdb_attrs->num = resultMsg->msgs[j]->num_elements;
            sysdb_attrs->a = resultMsg->msgs[j]->elements;

            ret = sysdb_attrs_get_string(sysdb_attrs, "cn", &str);

            if (ret == EOK && strcmp(str, sudo_ctx->ldap[i][0].val) == 0) {
                /* we found the exported rule so we can compare attributes to
                 * find out if they were exported correctly */
                break;
            }
        }

        /* no such rule -> ipa sudoer wasn't exported correctly */
        assert_int_equal(ret, EOK);

        /* cn should be already ok but we can check it again */
        k = 0;
        attr = sudo_ctx->ldap[i][k].attr;
        val = sudo_ctx->ldap[i][k].val;

        while (attr != NULL && val != NULL) {
            
            sysdb_attrs_get_string_array(sysdb_attrs, attr, sudo_ctx, &values);

            /* attr name not found */
            assert_non_null(values);
            /* attr has no values */
            assert_non_null(*values);
            
            for (l = 0; values[l] != NULL; l++) {
                /* value found */
                if (strcmp(val, values[l]) == 0) {
                    found = true;
                    break;
                }
            }
            assert_true(found); 
            found = false;

            /* check next attribute */
            k++;
            attr = sudo_ctx->ldap[i][k].attr;
            val = sudo_ctx->ldap[i][k].val;
       }
    }

    return EOK;
}

int create_ldap_sudoers(TALLOC_CTX *mem, struct sudo_ctx *ctx, int count, ...)
{
    va_list rules;
    int i;

    /* create LDAP sudoers */
    ctx->ldap = talloc_zero_array(mem, struct sudo_rule *, count);
    if (ctx->ldap == NULL) {
        talloc_free(ctx);
        fail_msg("talloc_zero_array() failed\n");
    }

    va_start(rules, count);

    for (i = 0; i < count; i++) {
        /* put rule into array of LDAP rules */
        ctx->ldap[i] = va_arg(rules, struct sudo_rule *);
    }

    ctx->ldap_count = count;
    va_end(rules);

    return EOK;
}
 
int create_ipa_sudoers(TALLOC_CTX *mem, struct sudo_ctx *ctx, int count, ...)
{
    va_list rules;
    int i;

    /* create fake IPA sudoers */
    ctx->ipa = talloc_zero_array(mem, struct sudo_rule *, count);
    if (ctx->ipa == NULL) {
        talloc_free(ctx);
        fail_msg("talloc_zero_array() failed\n");
    }

    va_start(rules, count);

    for (i = 0; i < count; i++) {
        ctx->ipa[i] = va_arg(rules, struct sudo_rule *);
    }

    get_sysdb_attrs(ctx, ctx->ipa, count, &ctx->ipa_sudoers);

    ctx->ipa_count = count;
    va_end(rules);

    return EOK;
}

int create_ipa_sudo_cmds(TALLOC_CTX *mem, struct sudo_ctx *ctx, int count, ...)
{
    va_list cmds;
    int i;

    /* create IPA sudo cmds*/
    ctx->cmds = talloc_zero_array(mem, struct sysdb_attrs *, count);
    if (ctx->cmds == NULL) {
        talloc_free(ctx);
        fail_msg("talloc_zero_array() failed\n");
    }

    va_start(cmds, count);

    for (i = 0; i < count; i++) {
        ctx->cmds[i] = create_entry(ctx, va_arg(cmds, struct sudo_rule *));
    }

    ctx->cmds_count = count;
    va_end(cmds);

    return EOK;
}


/* set up environment for sudo */
void setup_sudo_env(void **state) {

    TALLOC_CTX *mem = talloc_init(NULL);

    struct sudo_ctx *sudo_ctx;

    sudo_ctx = talloc_zero(mem, struct sudo_ctx);
    assert_non_null(sudo_ctx);

    /* tevent and sysdb */
    sudo_ctx->test_ctx = create_ev_test_ctx(mem);
    assert_non_null(sudo_ctx->test_ctx);
    _setup_sysdb_tests(&sudo_ctx->test_ctx->sysdb, false);
    assert_non_null(sudo_ctx->test_ctx->sysdb);

    sudo_ctx->be_ctx = talloc_zero(sudo_ctx, struct be_ctx);
    assert_non_null(sudo_ctx->be_ctx);
    sudo_ctx->be_ctx->domain = talloc_zero(sudo_ctx->be_ctx, struct sss_domain_info);
    assert_non_null(sudo_ctx->be_ctx->domain);
    sudo_ctx->be_ctx->domain->name = talloc_strdup(sudo_ctx->be_ctx->domain, "unit_tests");
    // FIXME: na sysdb se odkazuji dvakrat, jak z domeny tak z kontextu sudo
    // ...!
    sudo_ctx->be_ctx->domain->sysdb = sudo_ctx->test_ctx->sysdb;
    sudo_ctx->be_ctx->domain->sudo_timeout = 60;

    sudo_ctx->be_ctx->ev = sudo_ctx->test_ctx->ev;
    sudo_ctx->be_ctx->domain->sysdb = sudo_ctx->test_ctx->sysdb;

    /* sudo maps, search bases, IPA SCHema */
    sudo_ctx->opts = talloc_zero(mem, struct sdap_options);
    assert_non_null(sudo_ctx->opts);
    sudo_ctx->opts->sudorule_map =  native_sudorule_map;
    sudo_ctx->opts->ipa_sudorule_map = ipa_sudorule_map;
    sudo_ctx->opts->ipa_sudocmds_map = ipa_sudocmds_map;
    sudo_ctx->opts->schema_type = SDAP_SCHEMA_IPA_V1;

    sudo_ctx->opts->sdom = talloc_zero(mem, struct sdap_domain);
    if (sudo_ctx->opts->sdom == NULL) {
        fail_msg("talloc_zero() failed\n");
        goto fail;
    }

    sudo_ctx->opts->sdom->sudo_search_bases = talloc_zero_array(mem, struct sdap_search_base *, 2);
    if (sudo_ctx->opts->sdom->sudo_search_bases == NULL) {
        fail_msg("talloc_zero_array() failed\n");
        goto fail;
    }

    sudo_ctx->opts->sdom->sudo_search_bases[0] = talloc_zero(mem, struct sdap_search_base);
    sudo_ctx->opts->sdom->sudo_search_bases[1] = NULL;
    if (sudo_ctx->opts->sdom->sudo_search_bases[0] == NULL) {
        fail_msg("talloc_zero() failed\n");
        goto fail;
    }

    *state = sudo_ctx;
    return;

fail:
    talloc_free(sudo_ctx);
}

/* simple IPA sudo rule with one command */
void test_simple_rule_send(void **state)
{
    struct tevent_req *req;
    struct sudo_ctx *sudo_ctx;
 
    sudo_ctx = *state;

    create_ldap_sudoers(sudo_ctx, sudo_ctx, 1, ldap_rule1);
    create_ipa_sudoers(sudo_ctx, sudo_ctx, 1, ipa_rule1);
    create_ipa_sudo_cmds(sudo_ctx, sudo_ctx, 1, ipa_cmd1);

    /* return IPA sudo rules for LDAP SUDO Provider */
    will_return(__wrap_sdap_get_generic_recv, sudo_ctx->ipa_count);
    will_return(__wrap_sdap_get_generic_recv, sudo_ctx->ipa_sudoers);
    will_return(__wrap_be_is_offline, false);
    will_return(__wrap__dp_opt_get_int, 30);     /* timeout = 30s */
    will_return(__wrap_sdap_id_op_connect_send, sudo_ctx->test_ctx->ev);
    will_return(__wrap_sdap_get_generic_send, sudo_ctx->test_ctx->ev);

    /* return IPA sudo cmds for IPA SUDO Provider */
    will_return(__wrap__dp_opt_get_int, 30);     /* timeout = 30s */
    will_return(__wrap_be_is_offline, false);
    will_return(__wrap_sdap_id_op_connect_send, sudo_ctx->test_ctx->ev);
    will_return(__wrap_sdap_get_generic_send, sudo_ctx->test_ctx->ev);
    will_return(__wrap_sdap_get_generic_recv, sudo_ctx->cmds_count);
    will_return(__wrap_sdap_get_generic_recv, sudo_ctx->cmds);
 
    /* we don't need search filters because we won't send any requests */
    req = ipa_sudo_refresh_send(sudo_ctx, 
                                sudo_ctx->be_ctx, 
                                sudo_ctx->opts,
                                NULL, "", "");
    assert_non_null(req);

    tevent_req_set_callback(req, test_successful_export_done, sudo_ctx);
    test_ev_loop(sudo_ctx->test_ctx);
}

/* test IPA sudo rule with NO command */
void test_no_commands_send(void **state)
{
    struct tevent_req *req;
    struct sudo_ctx *sudo_ctx;
 
    sudo_ctx = *state;

    create_ldap_sudoers(sudo_ctx, sudo_ctx, 1, ldap_rule2);
    create_ipa_sudoers(sudo_ctx, sudo_ctx, 1, ipa_rule2);

    /* return IPA sudo rules for LDAP SUDO Provider */
    will_return(__wrap_sdap_get_generic_recv, sudo_ctx->ipa_count);
    will_return(__wrap_sdap_get_generic_recv, sudo_ctx->ipa_sudoers);
    will_return(__wrap_be_is_offline, false);
    will_return(__wrap__dp_opt_get_int, 30);     /* timeout = 30s */
    will_return(__wrap_sdap_id_op_connect_send, sudo_ctx->test_ctx->ev);
    will_return(__wrap_sdap_get_generic_send, sudo_ctx->test_ctx->ev);

    /* return IPA sudo cmds for IPA SUDO Provider */
    will_return(__wrap__dp_opt_get_int, 30);     /* timeout = 30s */
 
    /* we don't need search filters because we won't send any requests */
    req = ipa_sudo_refresh_send(sudo_ctx, 
                                sudo_ctx->be_ctx, 
                                sudo_ctx->opts,
                                NULL, "", "");
    assert_non_null(req);

    tevent_req_set_callback(req, test_successful_export_done, sudo_ctx);
    test_ev_loop(sudo_ctx->test_ctx);
}

/* test more IPA sudo rules */
void test_more_ipa_rules_send(void **state)
{
    struct tevent_req *req;
    struct sudo_ctx *sudo_ctx;
 
    sudo_ctx = *state;

    create_ipa_sudoers(sudo_ctx, sudo_ctx, 4, ipa_rule1, ipa_rule2, 
                        ipa_rule3, ipa_rule4); 
    create_ipa_sudo_cmds(sudo_ctx, sudo_ctx, 11, ipa_cmd1, ipa_cmd8, ipa_cmd9, 
                         ipa_cmd10, ipa_cmd11, ipa_cmd4, ipa_cmd5, ipa_cmd6, 
                         ipa_cmd7, ipa_cmd2, ipa_cmd3);
    create_ldap_sudoers(sudo_ctx, sudo_ctx, 4, ldap_rule1, ldap_rule2, 
                        ldap_rule3, ldap_rule4);

    /* return IPA sudo rules for LDAP SUDO Provider */
    will_return(__wrap_sdap_get_generic_recv, sudo_ctx->ipa_count);
    will_return(__wrap_sdap_get_generic_recv, sudo_ctx->ipa_sudoers);
    will_return(__wrap_be_is_offline, false);
    will_return(__wrap__dp_opt_get_int, 30);     /* timeout = 30s */
    will_return(__wrap_sdap_id_op_connect_send, sudo_ctx->test_ctx->ev);
    will_return(__wrap_sdap_get_generic_send, sudo_ctx->test_ctx->ev);

    /* return IPA sudo cmds for IPA SUDO Provider */
    will_return(__wrap__dp_opt_get_int, 30);     /* timeout = 30s */
    will_return(__wrap_be_is_offline, false);
    will_return(__wrap_sdap_id_op_connect_send, sudo_ctx->test_ctx->ev);
    will_return(__wrap_sdap_get_generic_send, sudo_ctx->test_ctx->ev);
    will_return(__wrap_sdap_get_generic_recv, sudo_ctx->cmds_count);
    will_return(__wrap_sdap_get_generic_recv, sudo_ctx->cmds);
 
    /* we don't need search filters because we won't send any requests */
    req = ipa_sudo_refresh_send(sudo_ctx, 
                                sudo_ctx->be_ctx, 
                                sudo_ctx->opts,
                                NULL, "", "");
    assert_non_null(req);

    tevent_req_set_callback(req, test_successful_export_done, sudo_ctx);
    test_ev_loop(sudo_ctx->test_ctx);
}

/* IPA sudo rule multiple commands and commands groups */
void test_multiple_commands_send(void **state)
{
    struct tevent_req *req;
    struct sudo_ctx *sudo_ctx;

    sudo_ctx = *state;

    /* create LDAP sudoers */
    create_ldap_sudoers(sudo_ctx, sudo_ctx, 1, ldap_rule3);
    create_ipa_sudoers(sudo_ctx, sudo_ctx, 1, ipa_rule3);
    create_ipa_sudo_cmds(sudo_ctx, sudo_ctx, 12, ipa_cmd1, ipa_cmd2, ipa_cmd3,
                        ipa_cmd4, ipa_cmd5, ipa_cmd6, ipa_cmd7, ipa_cmd8, 
                        ipa_cmd9, ipa_cmd10,ipa_cmd11, ipa_cmd12);

    /* return IPA sudo rules for LDAP SUDO Provider */
    will_return(__wrap_sdap_get_generic_recv, sudo_ctx->ipa_count);
    will_return(__wrap_sdap_get_generic_recv, sudo_ctx->ipa_sudoers);
    will_return(__wrap_be_is_offline, false);
    will_return(__wrap__dp_opt_get_int, 30);     /* timeout = 30s */
    will_return(__wrap_sdap_id_op_connect_send, sudo_ctx->test_ctx->ev);
    will_return(__wrap_sdap_get_generic_send, sudo_ctx->test_ctx->ev);

    /* return IPA sudo cmds for IPA SUDO Provider */
    will_return(__wrap__dp_opt_get_int, 30);     /* timeout = 30s */
    will_return(__wrap_be_is_offline, false);
    will_return(__wrap_sdap_id_op_connect_send, sudo_ctx->test_ctx->ev);
    will_return(__wrap_sdap_get_generic_send, sudo_ctx->test_ctx->ev);
    will_return(__wrap_sdap_get_generic_recv, sudo_ctx->cmds_count);
    will_return(__wrap_sdap_get_generic_recv, sudo_ctx->cmds);

    /* we don't need search filters because we won't send any requests */
    req = ipa_sudo_refresh_send(sudo_ctx, 
                                sudo_ctx->be_ctx, 
                                sudo_ctx->opts,
                                NULL, "", "");
    assert_non_null(req);

    tevent_req_set_callback(req, test_successful_export_done, sudo_ctx);
    test_ev_loop(sudo_ctx->test_ctx);
}

void test_multiple_options_send(void **state)
{
    struct tevent_req *req;
    struct sudo_ctx *sudo_ctx;

    sudo_ctx = *state;

    /* create LDAP sudoers */
    create_ldap_sudoers(sudo_ctx, sudo_ctx, 1, ldap_rule4);
    create_ipa_sudoers(sudo_ctx, sudo_ctx, 1, ipa_rule4);
    create_ipa_sudo_cmds(sudo_ctx, sudo_ctx, 1, ipa_cmd3);

    /* return IPA sudo rules for LDAP SUDO Provider */
    will_return(__wrap_sdap_get_generic_recv, sudo_ctx->ipa_count);
    will_return(__wrap_sdap_get_generic_recv, sudo_ctx->ipa_sudoers);
    will_return(__wrap_be_is_offline, false);
    will_return(__wrap__dp_opt_get_int, 30);     /* timeout = 30s */
    will_return(__wrap_sdap_id_op_connect_send, sudo_ctx->test_ctx->ev);
    will_return(__wrap_sdap_get_generic_send, sudo_ctx->test_ctx->ev);

    /* return IPA sudo cmds for IPA SUDO Provider */
    will_return(__wrap__dp_opt_get_int, 30);     /* timeout = 30s */
    will_return(__wrap_be_is_offline, false);
    will_return(__wrap_sdap_id_op_connect_send, sudo_ctx->test_ctx->ev);
    will_return(__wrap_sdap_get_generic_send, sudo_ctx->test_ctx->ev);
    will_return(__wrap_sdap_get_generic_recv, sudo_ctx->cmds_count);
    will_return(__wrap_sdap_get_generic_recv, sudo_ctx->cmds);

    /* we don't need search filters because we won't send any requests */
    req = ipa_sudo_refresh_send(sudo_ctx, 
                                sudo_ctx->be_ctx, 
                                sudo_ctx->opts,
                                NULL, "", "");
    assert_non_null(req);

    tevent_req_set_callback(req, test_successful_export_done, sudo_ctx);
    test_ev_loop(sudo_ctx->test_ctx);
}

void test_none_sudo_rules_send(void **state)
{
    struct tevent_req *req;
    struct sudo_ctx *sudo_ctx;

    sudo_ctx = *state;

    /* create LDAP sudoers */
    create_ldap_sudoers(sudo_ctx, sudo_ctx, 0);
    create_ipa_sudoers(sudo_ctx, sudo_ctx, 0);

    /* return IPA sudo rules for LDAP SUDO Provider */
    will_return(__wrap_sdap_get_generic_recv, sudo_ctx->ipa_count);
    will_return(__wrap_sdap_get_generic_recv, sudo_ctx->ipa_sudoers);
    will_return(__wrap_be_is_offline, false);
    will_return(__wrap__dp_opt_get_int, 30);     /* timeout = 30s */
    will_return(__wrap_sdap_id_op_connect_send, sudo_ctx->test_ctx->ev);
    will_return(__wrap_sdap_get_generic_send, sudo_ctx->test_ctx->ev);

    /* we don't need search filters because we won't send any requests */
    req = ipa_sudo_refresh_send(sudo_ctx, 
                                sudo_ctx->be_ctx, 
                                sudo_ctx->opts,
                                NULL, "", "");
    assert_non_null(req);

    tevent_req_set_callback(req, test_successful_export_done, sudo_ctx);
    test_ev_loop(sudo_ctx->test_ctx);
}

/* if there are rules that has same commands that they don't need to be in the
 * LDAP filter multiple times */
void test_cmd_filter(void **state)
{
    struct tevent_req *req;
    struct sudo_ctx *sudo_ctx;
    const char *filter;
    const char *correct_filter;
    int cmds_ret;

    sudo_ctx = *state;

    /* create LDAP sudoers */
    create_ipa_sudoers(sudo_ctx, sudo_ctx, 2, ipa_rule5, ipa_rule6);
    correct_filter = "(&(objectClass=ipasudocmd)"
                     "(|(ipaUniqueID=c484ca28-c019-11e3-84b4-0800274dc10b)"
                     "(memberOf=cn=disc,cn=sudocmdgroups,cn=sudo,dc=example,dc=cz)))";

    cmds_ret = build_cmds_filter(sudo_ctx, 
                                 sudo_ctx->test_ctx->sysdb, 
                                 sudo_ctx->ipa_sudoers, 
                                 sudo_ctx->ipa_count, 
                                 &filter);

    assert_int_equal(cmds_ret, EOK);
    assert_string_equal(filter, correct_filter);
}


/* there is IPA SUDO rules but count of ipa rules is zero */
void test_fail1_send(void **state)
{
    struct tevent_req *req;
    struct sudo_ctx *sudo_ctx;

    sudo_ctx = *state;

    /* create LDAP sudoers */
    create_ldap_sudoers(sudo_ctx, sudo_ctx, 1, ldap_rule5);
    create_ipa_sudoers(sudo_ctx, sudo_ctx, 1, ipa_rule5);
    create_ipa_sudo_cmds(sudo_ctx, sudo_ctx, 2, ipa_cmd1, ipa_cmd3);

    /* return IPA sudo rules for LDAP SUDO Provider */
    will_return(__wrap_sdap_get_generic_recv, sudo_ctx->ipa_count);
    will_return(__wrap_sdap_get_generic_recv, sudo_ctx->ipa_sudoers);
    will_return(__wrap_be_is_offline, false);
    will_return(__wrap__dp_opt_get_int, 30);     /* timeout = 30s */
    will_return(__wrap_sdap_id_op_connect_send, sudo_ctx->test_ctx->ev);
    will_return(__wrap_sdap_get_generic_send, sudo_ctx->test_ctx->ev);

    /* return IPA sudo cmds for IPA SUDO Provider */
    will_return(__wrap__dp_opt_get_int, 30);     /* timeout = 30s */
    will_return(__wrap_be_is_offline, false);
    will_return(__wrap_sdap_id_op_connect_send, sudo_ctx->test_ctx->ev);
    will_return(__wrap_sdap_get_generic_send, sudo_ctx->test_ctx->ev);
    will_return(__wrap_sdap_get_generic_recv, sudo_ctx->cmds_count);
    will_return(__wrap_sdap_get_generic_recv, sudo_ctx->cmds);

    /* we don't need search filters because we won't send any requests */
    req = ipa_sudo_refresh_send(sudo_ctx, 
                                sudo_ctx->be_ctx, 
                                sudo_ctx->opts,
                                NULL, "", "");
    assert_non_null(req);

    tevent_req_set_callback(req, test_successful_export_done, sudo_ctx);
    test_ev_loop(sudo_ctx->test_ctx);
}

static void test_successful_export_done(struct tevent_req *subreq)
{

    struct sudo_ctx *ctx; 
    struct sdap_sudo_refresh_state *state;
    struct sysdb_attrs **attrs = NULL;
    size_t count;
    int ret;

    /* req from ipa_sudo_refresh_send() */
    ctx = tevent_req_callback_data(subreq, struct sudo_ctx);
    state = tevent_req_data(subreq, struct sdap_sudo_refresh_state);

    ret = ipa_sudo_refresh_recv(state, subreq, &state->dp_error,
                                &state->error, NULL, &count, &attrs);
    talloc_zfree(subreq);

    assert_int_equal(state->dp_error, DP_ERR_OK);
    assert_int_equal(state->error, EOK);

    compare_sudoers(ctx, ctx);

    /* end tevent loop */
    ctx->test_ctx->done = true;
    ctx->test_ctx->error = EOK;
}

// FIXME!
void setup_sudo_env_teardown(void **state)
{
    //printf("environment teardown function\n");
    //talloc_free(sudo_ctx); FIXME: SIGARBR :-(
}

int main(int argc, const char *argv[])
{
    const UnitTest tests[] = {
        /*
        unit_test_setup_teardown(test_build_commands_filter_fail_send,
                                 setup_sudo_env,
                                 setup_sudo_env_teardown),
                                 */
                                 
     
        /* FIXME: create sysdb only once and purge it before every test */

        /* test export of IPA sudo rules into native LDAP sudo scheme */
        unit_test_setup_teardown(test_simple_rule_send,
                                 setup_sudo_env,
                                 setup_sudo_env_teardown),
        unit_test_setup_teardown(test_no_commands_send,
                                 setup_sudo_env,
                                 setup_sudo_env_teardown),
        unit_test_setup_teardown(test_more_ipa_rules_send,
                                 setup_sudo_env,
                                 setup_sudo_env_teardown),
        unit_test_setup_teardown(test_multiple_commands_send,
                                 setup_sudo_env,
                                 setup_sudo_env_teardown),
        unit_test_setup_teardown(test_multiple_options_send,
                                 setup_sudo_env,
                                 setup_sudo_env_teardown),
        unit_test_setup_teardown(test_none_sudo_rules_send,
                                 setup_sudo_env,
                                 setup_sudo_env_teardown),
        unit_test_setup_teardown(test_fail1_send,
                                 setup_sudo_env,
                                 setup_sudo_env_teardown),
        unit_test_setup_teardown(test_cmd_filter,
                                 setup_sudo_env,
                                 setup_sudo_env_teardown),
    };

    //TODO:
    // - two ipa rules which uses the same ipa commands
    run_tests(tests);
    return 0;
}
