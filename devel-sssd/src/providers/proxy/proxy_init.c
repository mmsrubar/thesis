/*
    SSSD

    proxy_init.c

    Authors:
        Stephen Gallagher <sgallagh@redhat.com>

    Copyright (C) 2010 Red Hat

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

#include "config.h"

#include "util/sss_format.h"
#include "providers/proxy/proxy.h"

static int client_registration(struct sbus_request *dbus_req, void *data);

static struct data_provider_iface proxy_methods = {
    { &data_provider_iface_meta, 0 },
    .RegisterService = client_registration,
    .pamHandler = NULL,
    .sudoHandler = NULL,
    .autofsHandler = NULL,
    .hostHandler = NULL,
    .getDomains = NULL,
    .getAccountInfo = NULL,
};

static void proxy_shutdown(struct be_req *req)
{
    /* TODO: Clean up any internal data */
    be_req_terminate(req, DP_ERR_OK, EOK, NULL);
}

static void proxy_auth_shutdown(struct be_req *req)
{
    struct be_ctx *be_ctx = be_req_get_be_ctx(req);
    talloc_free(be_ctx->bet_info[BET_AUTH].pvt_bet_data);
    be_req_terminate(req, DP_ERR_OK, EOK, NULL);
}

struct bet_ops proxy_id_ops = {
    .handler = proxy_get_account_info,
    .finalize = proxy_shutdown,
    .check_online = NULL
};

struct bet_ops proxy_auth_ops = {
    .handler = proxy_pam_handler,
    .finalize = proxy_auth_shutdown
};

struct bet_ops proxy_access_ops = {
    .handler = proxy_pam_handler,
    .finalize = proxy_auth_shutdown
};

struct bet_ops proxy_chpass_ops = {
    .handler = proxy_pam_handler,
    .finalize = proxy_auth_shutdown
};

static void *proxy_dlsym(void *handle, const char *functemp, char *libname)
{
    char *funcname;
    void *funcptr;

    funcname = talloc_asprintf(NULL, functemp, libname);
    if (funcname == NULL) return NULL;

    funcptr = dlsym(handle, funcname);
    talloc_free(funcname);

    return funcptr;
}

int sssm_proxy_id_init(struct be_ctx *bectx,
                       struct bet_ops **ops, void **pvt_data)
{
    struct proxy_id_ctx *ctx;
    char *libname;
    char *libpath;
    int ret;

    ctx = talloc_zero(bectx, struct proxy_id_ctx);
    if (!ctx) {
        return ENOMEM;
    }
    ctx->be = bectx;

    ret = confdb_get_string(bectx->cdb, ctx, bectx->conf_path,
                            CONFDB_PROXY_LIBNAME, NULL, &libname);
    if (ret != EOK) goto done;
    if (libname == NULL) {
        ret = ENOENT;
        goto done;
    }

    ret = confdb_get_bool(bectx->cdb, bectx->conf_path,
                          CONFDB_PROXY_FAST_ALIAS, false, &ctx->fast_alias);
    if (ret != EOK) goto done;

    libpath = talloc_asprintf(ctx, "libnss_%s.so.2", libname);
    if (!libpath) {
        ret = ENOMEM;
        goto done;
    }

    ctx->handle = dlopen(libpath, RTLD_NOW);
    if (!ctx->handle) {
        DEBUG(SSSDBG_FATAL_FAILURE,
              "Unable to load %s module with path, error: %s\n",
                  libpath, dlerror());
        ret = ELIBACC;
        goto done;
    }

    ctx->ops.getpwnam_r = proxy_dlsym(ctx->handle, "_nss_%s_getpwnam_r",
                                      libname);
    if (!ctx->ops.getpwnam_r) {
        DEBUG(SSSDBG_FATAL_FAILURE,
              "Failed to load NSS fns, error: %s\n", dlerror());
        ret = ELIBBAD;
        goto done;
    }

    ctx->ops.getpwuid_r = proxy_dlsym(ctx->handle, "_nss_%s_getpwuid_r",
                                      libname);
    if (!ctx->ops.getpwuid_r) {
        DEBUG(SSSDBG_FATAL_FAILURE,
              "Failed to load NSS fns, error: %s\n", dlerror());
        ret = ELIBBAD;
        goto done;
    }

    ctx->ops.setpwent = proxy_dlsym(ctx->handle, "_nss_%s_setpwent", libname);
    if (!ctx->ops.setpwent) {
        DEBUG(SSSDBG_FATAL_FAILURE,
              "Failed to load NSS fns, error: %s\n", dlerror());
        ret = ELIBBAD;
        goto done;
    }

    ctx->ops.getpwent_r = proxy_dlsym(ctx->handle, "_nss_%s_getpwent_r",
                                      libname);
    if (!ctx->ops.getpwent_r) {
        DEBUG(SSSDBG_FATAL_FAILURE,
              "Failed to load NSS fns, error: %s\n", dlerror());
        ret = ELIBBAD;
        goto done;
    }

    ctx->ops.endpwent = proxy_dlsym(ctx->handle, "_nss_%s_endpwent", libname);
    if (!ctx->ops.endpwent) {
        DEBUG(SSSDBG_FATAL_FAILURE,
              "Failed to load NSS fns, error: %s\n", dlerror());
        ret = ELIBBAD;
        goto done;
    }

    ctx->ops.getgrnam_r = proxy_dlsym(ctx->handle, "_nss_%s_getgrnam_r",
                                      libname);
    if (!ctx->ops.getgrnam_r) {
        DEBUG(SSSDBG_FATAL_FAILURE,
              "Failed to load NSS fns, error: %s\n", dlerror());
        ret = ELIBBAD;
        goto done;
    }

    ctx->ops.getgrgid_r = proxy_dlsym(ctx->handle, "_nss_%s_getgrgid_r",
                                      libname);
    if (!ctx->ops.getgrgid_r) {
        DEBUG(SSSDBG_FATAL_FAILURE,
              "Failed to load NSS fns, error: %s\n", dlerror());
        ret = ELIBBAD;
        goto done;
    }

    ctx->ops.setgrent = proxy_dlsym(ctx->handle, "_nss_%s_setgrent", libname);
    if (!ctx->ops.setgrent) {
        DEBUG(SSSDBG_FATAL_FAILURE,
              "Failed to load NSS fns, error: %s\n", dlerror());
        ret = ELIBBAD;
        goto done;
    }

    ctx->ops.getgrent_r = proxy_dlsym(ctx->handle, "_nss_%s_getgrent_r",
                                      libname);
    if (!ctx->ops.getgrent_r) {
        DEBUG(SSSDBG_FATAL_FAILURE,
              "Failed to load NSS fns, error: %s\n", dlerror());
        ret = ELIBBAD;
        goto done;
    }

    ctx->ops.endgrent = proxy_dlsym(ctx->handle, "_nss_%s_endgrent", libname);
    if (!ctx->ops.endgrent) {
        DEBUG(SSSDBG_FATAL_FAILURE,
              "Failed to load NSS fns, error: %s\n", dlerror());
        ret = ELIBBAD;
        goto done;
    }

    ctx->ops.initgroups_dyn = proxy_dlsym(ctx->handle, "_nss_%s_initgroups_dyn",
                                          libname);
    if (!ctx->ops.initgroups_dyn) {
        DEBUG(SSSDBG_CRIT_FAILURE, "The '%s' library does not provides the "
                  "_nss_XXX_initgroups_dyn function!\n"
                  "initgroups will be slow as it will require "
                  "full groups enumeration!\n", libname);
    }

    ctx->ops.setnetgrent = proxy_dlsym(ctx->handle, "_nss_%s_setnetgrent",
                                       libname);
    if (!ctx->ops.setnetgrent) {
        DEBUG(SSSDBG_FATAL_FAILURE,
              "Failed to load _nss_%s_setnetgrent, error: %s. "
                  "The library does not support netgroups.\n", libname,
                                                               dlerror());
    }

    ctx->ops.getnetgrent_r = proxy_dlsym(ctx->handle, "_nss_%s_getnetgrent_r",
                                         libname);
    if (!ctx->ops.getgrent_r) {
        DEBUG(SSSDBG_FATAL_FAILURE,
              "Failed to load _nss_%s_getnetgrent_r, error: %s. "
                  "The library does not support netgroups.\n", libname,
                                                               dlerror());
    }

    ctx->ops.endnetgrent = proxy_dlsym(ctx->handle, "_nss_%s_endnetgrent",
                                       libname);
    if (!ctx->ops.endnetgrent) {
        DEBUG(SSSDBG_FATAL_FAILURE,
              "Failed to load _nss_%s_endnetgrent, error: %s. "
                  "The library does not support netgroups.\n", libname,
                                                               dlerror());
    }

    ctx->ops.getservbyname_r = proxy_dlsym(ctx->handle,
                                           "_nss_%s_getservbyname_r",
                                           libname);
    if (!ctx->ops.getservbyname_r) {
        DEBUG(SSSDBG_MINOR_FAILURE,
              "Failed to load _nss_%s_getservbyname_r, error: %s. "
               "The library does not support services.\n",
               libname,
               dlerror());
    }

    ctx->ops.getservbyport_r = proxy_dlsym(ctx->handle,
                                           "_nss_%s_getservbyport_r",
                                           libname);
    if (!ctx->ops.getservbyport_r) {
        DEBUG(SSSDBG_MINOR_FAILURE,
              "Failed to load _nss_%s_getservbyport_r, error: %s. "
               "The library does not support services.\n",
               libname,
               dlerror());
    }

    ctx->ops.setservent = proxy_dlsym(ctx->handle,
                                      "_nss_%s_setservent",
                                      libname);
    if (!ctx->ops.setservent) {
        DEBUG(SSSDBG_MINOR_FAILURE,
              "Failed to load _nss_%s_setservent, error: %s. "
               "The library does not support services.\n",
               libname,
               dlerror());
    }

    ctx->ops.getservent_r = proxy_dlsym(ctx->handle,
                                        "_nss_%s_getservent_r",
                                        libname);
    if (!ctx->ops.getservent_r) {
        DEBUG(SSSDBG_MINOR_FAILURE,
              "Failed to load _nss_%s_getservent_r, error: %s. "
               "The library does not support services.\n",
               libname,
               dlerror());
    }

    ctx->ops.endservent = proxy_dlsym(ctx->handle,
                                      "_nss_%s_endservent",
                                      libname);
    if (!ctx->ops.endservent) {
        DEBUG(SSSDBG_MINOR_FAILURE,
              "Failed to load _nss_%s_endservent, error: %s. "
               "The library does not support services.\n",
               libname,
               dlerror());
    }

    *ops = &proxy_id_ops;
    *pvt_data = ctx;
    ret = EOK;

done:
    if (ret != EOK) {
        talloc_free(ctx);
    }
    return ret;
}

struct proxy_client {
    struct proxy_auth_ctx *proxy_auth_ctx;
    struct sbus_connection *conn;
    struct tevent_timer *timeout;
    bool initialized;
};

static void init_timeout(struct tevent_context *ev,
                         struct tevent_timer *te,
                         struct timeval t, void *ptr);
static int proxy_client_init(struct sbus_connection *conn, void *data)
{
    struct proxy_auth_ctx *proxy_auth_ctx;
    struct proxy_client *proxy_cli;
    struct sbus_interface *intf;
    struct timeval tv;

    proxy_auth_ctx = talloc_get_type(data, struct proxy_auth_ctx);

    /* hang off this memory to the connection so that when the connection
     * is freed we can potentially call a destructor */

    proxy_cli = talloc_zero(conn, struct proxy_client);
    if (!proxy_cli) {
        DEBUG(SSSDBG_FATAL_FAILURE,"Out of memory?!\n");
        talloc_zfree(conn);
        return ENOMEM;
    }
    proxy_cli->proxy_auth_ctx = proxy_auth_ctx;
    proxy_cli->conn = conn;
    proxy_cli->initialized = false;

    /* 5 seconds should be plenty */
    tv = tevent_timeval_current_ofs(5, 0);

    proxy_cli->timeout = tevent_add_timer(proxy_auth_ctx->be->ev, proxy_cli,
                                          tv, init_timeout, proxy_cli);
    if (!proxy_cli->timeout) {
        DEBUG(SSSDBG_FATAL_FAILURE,"Out of memory?!\n");
        talloc_zfree(conn);
        return ENOMEM;
    }
    DEBUG(SSSDBG_CONF_SETTINGS,
          "Set-up proxy client ID timeout [%p]\n", proxy_cli->timeout);

    /* Attach the client context to the connection context, so that it is
     * always available when we need to manage the connection. */
    intf = sbus_new_interface(conn, DP_PATH, &proxy_methods.vtable, proxy_cli);
    if (!intf) {
        return ENOMEM;
    }

    return sbus_conn_add_interface(conn, intf);
}

static void init_timeout(struct tevent_context *ev,
                         struct tevent_timer *te,
                         struct timeval t, void *ptr)
{
    struct proxy_client *proxy_cli;

    DEBUG(SSSDBG_OP_FAILURE,
          "Client timed out before Identification [%p]!\n", te);

    proxy_cli = talloc_get_type(ptr, struct proxy_client);

    sbus_disconnect(proxy_cli->conn);
    talloc_zfree(proxy_cli);

    /* If we time out here, we will also time out to
     * pc_init_timeout(), so we'll finish the request
     * there.
     */
}

static int client_registration(struct sbus_request *dbus_req, void *data)
{
    dbus_uint16_t version = DATA_PROVIDER_VERSION;
    struct sbus_connection *conn;
    struct proxy_client *proxy_cli;
    dbus_uint16_t cli_ver;
    uint32_t cli_id;
    int hret;
    hash_key_t key;
    hash_value_t value;
    struct tevent_req *req;
    struct proxy_child_ctx *child_ctx;
    struct pc_init_ctx *init_ctx;
    int ret;

    conn = dbus_req->conn;
    proxy_cli = talloc_get_type(data, struct proxy_client);
    if (!proxy_cli) {
        DEBUG(SSSDBG_FATAL_FAILURE, "Connection holds no valid init data\n");
        return EINVAL;
    }

    /* First thing, cancel the timeout */
    DEBUG(SSSDBG_CONF_SETTINGS,
          "Cancel proxy client ID timeout [%p]\n", proxy_cli->timeout);
    talloc_zfree(proxy_cli->timeout);

    if (!sbus_request_parse_or_finish(dbus_req,
                                      DBUS_TYPE_UINT16, &cli_ver,
                                      DBUS_TYPE_UINT32, &cli_id,
                                      DBUS_TYPE_INVALID)) {
        sbus_disconnect(conn);
        return EOK; /* handled */
    }

    DEBUG(SSSDBG_FUNC_DATA, "Proxy client [%"PRIu32"] connected\n", cli_id);

    /* Check the hash table */
    key.type = HASH_KEY_ULONG;
    key.ul = cli_id;
    if (!hash_has_key(proxy_cli->proxy_auth_ctx->request_table, &key)) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Unknown child ID. Killing the connection\n");
        sbus_disconnect(proxy_cli->conn);
        return EIO;
    }

    /* reply that all is ok */
    ret = sbus_request_return_and_finish(dbus_req,
                                         DBUS_TYPE_UINT16, &version,
                                         DBUS_TYPE_INVALID);
    if (ret != EOK) {
        sbus_disconnect(conn);
        return ret;
    }

    hret = hash_lookup(proxy_cli->proxy_auth_ctx->request_table, &key, &value);
    if (hret != HASH_SUCCESS) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Hash error [%d][%s]\n", hret, hash_error_string(hret));
        sbus_disconnect(dbus_req->conn);
    }

    /* Signal that the child is up and ready to receive the request */
    req = talloc_get_type(value.ptr, struct tevent_req);
    child_ctx = tevent_req_data(req, struct proxy_child_ctx);

    if (!child_ctx->running) {
        /* This should hopefully be impossible, but protect
         * against it anyway. If we're not marked running, then
         * the init_req will be NULL below and things will
         * break.
         */
        DEBUG(SSSDBG_CRIT_FAILURE, "Client connection from a request "
                  "that's not marked as running\n");
        return EIO;
    }

    init_ctx = tevent_req_data(child_ctx->init_req, struct pc_init_ctx);
    init_ctx->conn = dbus_req->conn;
    tevent_req_done(child_ctx->init_req);
    child_ctx->init_req = NULL;

    return EOK;
}

int sssm_proxy_auth_init(struct be_ctx *bectx,
                         struct bet_ops **ops, void **pvt_data)
{
    struct proxy_auth_ctx *ctx;
    int ret;
    int hret;
    char *sbus_address;

    /* If we're already set up, just return that */
    if(bectx->bet_info[BET_AUTH].mod_name &&
       strcmp("proxy", bectx->bet_info[BET_AUTH].mod_name) == 0) {
        DEBUG(SSSDBG_TRACE_INTERNAL,
              "Re-using proxy_auth_ctx for this provider\n");
        *ops = bectx->bet_info[BET_AUTH].bet_ops;
        *pvt_data = bectx->bet_info[BET_AUTH].pvt_bet_data;
        return EOK;
    }

    ctx = talloc_zero(bectx, struct proxy_auth_ctx);
    if (!ctx) {
        return ENOMEM;
    }
    ctx->be = bectx;
    ctx->timeout_ms = SSS_CLI_SOCKET_TIMEOUT/4;
    ctx->next_id = 1;

    ret = confdb_get_string(bectx->cdb, ctx, bectx->conf_path,
                            CONFDB_PROXY_PAM_TARGET, NULL,
                            &ctx->pam_target);
    if (ret != EOK) goto done;
    if (!ctx->pam_target) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Missing option proxy_pam_target.\n");
        ret = EINVAL;
        goto done;
    }

    sbus_address = talloc_asprintf(ctx, "unix:path=%s/%s_%s", PIPE_PATH,
                                   PROXY_CHILD_PIPE, bectx->domain->name);
    if (sbus_address == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "talloc_asprintf failed.\n");
        ret = ENOMEM;
        goto done;
    }

    ret = sbus_new_server(ctx, bectx->ev, sbus_address,
                          false, &ctx->sbus_srv, proxy_client_init, ctx);
    if (ret != EOK) {
        DEBUG(SSSDBG_FATAL_FAILURE, "Could not set up sbus server.\n");
        goto done;
    }

    /* Set up request hash table */
    /* FIXME: get max_children from configuration file */
    ctx->max_children = 10;

    hret = hash_create(ctx->max_children * 2, &ctx->request_table,
                       NULL, NULL);
    if (hret != HASH_SUCCESS) {
        DEBUG(SSSDBG_FATAL_FAILURE, "Could not initialize request table\n");
        ret = EIO;
        goto done;
    }

    *ops = &proxy_auth_ops;
    *pvt_data = ctx;

done:
    if (ret != EOK) {
        talloc_free(ctx);
    }
    return ret;
}

int sssm_proxy_access_init(struct be_ctx *bectx,
                           struct bet_ops **ops, void **pvt_data)
{
    int ret;
    ret = sssm_proxy_auth_init(bectx, ops, pvt_data);
    *ops = &proxy_access_ops;
    return ret;
}

int sssm_proxy_chpass_init(struct be_ctx *bectx,
                           struct bet_ops **ops, void **pvt_data)
{
    int ret;
    ret = sssm_proxy_auth_init(bectx, ops, pvt_data);
    *ops = &proxy_chpass_ops;
    return ret;
}
