/*
   SSSD

   PAM Responder

   Copyright (C) Simo Sorce <ssorce@redhat.com>	2009
   Copyright (C) Sumit Bose <sbose@redhat.com>	2009

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

#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <string.h>
#include <sys/time.h>
#include <errno.h>
#include <popt.h>
#include <dbus/dbus.h>

#include "util/util.h"
#include "db/sysdb.h"
#include "confdb/confdb.h"
#include "sbus/sssd_dbus.h"
#include "responder/common/responder_packet.h"
#include "providers/data_provider.h"
#include "monitor/monitor_interfaces.h"
#include "sbus/sbus_client.h"
#include "responder/pam/pamsrv.h"
#include "responder/common/negcache.h"
#include "responder/common/responder_sbus.h"

#define DEFAULT_PAM_FD_LIMIT 8192

struct sbus_method monitor_pam_methods[] = {
    { MON_CLI_METHOD_PING, monitor_common_pong },
    { MON_CLI_METHOD_RES_INIT, monitor_common_res_init },
    { MON_CLI_METHOD_ROTATE, responder_logrotate },
    { NULL, NULL }
};

struct sbus_interface monitor_pam_interface = {
    MONITOR_INTERFACE,
    MONITOR_PATH,
    SBUS_DEFAULT_VTABLE,
    monitor_pam_methods,
    NULL
};

static struct sbus_method pam_dp_methods[] = {
        { NULL, NULL }
};

struct sbus_interface pam_dp_interface = {
    DP_INTERFACE,
    DP_PATH,
    SBUS_DEFAULT_VTABLE,
    pam_dp_methods,
    NULL
};


static void pam_dp_reconnect_init(struct sbus_connection *conn, int status, void *pvt)
{
    struct be_conn *be_conn = talloc_get_type(pvt, struct be_conn);
    int ret;

    /* Did we reconnect successfully? */
    if (status == SBUS_RECONNECT_SUCCESS) {
        DEBUG(1, ("Reconnected to the Data Provider.\n"));

        /* Identify ourselves to the data provider */
        ret = dp_common_send_id(be_conn->conn,
                                DATA_PROVIDER_VERSION,
                                "PAM");
        /* all fine */
        if (ret == EOK) {
            handle_requests_after_reconnect(be_conn->rctx);
            return;
        }
    }

    /* Handle failure */
    DEBUG(0, ("Could not reconnect to %s provider.\n",
              be_conn->domain->name));

    /* FIXME: kill the frontend and let the monitor restart it ? */
    /* pam_shutdown(rctx); */
}

static int pam_process_init(TALLOC_CTX *mem_ctx,
                            struct tevent_context *ev,
                            struct confdb_ctx *cdb)
{
    struct resp_ctx *rctx;
    struct sss_cmd_table *pam_cmds;
    struct be_conn *iter;
    struct pam_ctx *pctx;
    int ret, max_retries;
    int id_timeout;
    int fd_limit;

    pam_cmds = get_pam_cmds();
    ret = sss_process_init(mem_ctx, ev, cdb,
                           pam_cmds,
                           SSS_PAM_SOCKET_NAME,
                           SSS_PAM_PRIV_SOCKET_NAME,
                           CONFDB_PAM_CONF_ENTRY,
                           SSS_PAM_SBUS_SERVICE_NAME,
                           SSS_PAM_SBUS_SERVICE_VERSION,
                           &monitor_pam_interface,
                           "PAM", &pam_dp_interface,
                           &rctx);
    if (ret != EOK) {
        DEBUG(SSSDBG_FATAL_FAILURE, ("sss_process_init() failed\n"));
        return ret;
    }

    pctx = talloc_zero(rctx, struct pam_ctx);
    if (!pctx) {
        ret = ENOMEM;
        goto done;
    }

    pctx->rctx = rctx;
    pctx->rctx->pvt_ctx = pctx;

    /* Enable automatic reconnection to the Data Provider */

    /* FIXME: "retries" is too generic, either get it from a global config
     * or specify these retries are about the sbus connections to DP */
    ret = confdb_get_int(pctx->rctx->cdb, CONFDB_PAM_CONF_ENTRY,
                         CONFDB_SERVICE_RECON_RETRIES, 3, &max_retries);
    if (ret != EOK) {
        DEBUG(0, ("Failed to set up automatic reconnection\n"));
        goto done;
    }

    for (iter = pctx->rctx->be_conns; iter; iter = iter->next) {
        sbus_reconnect_init(iter->conn, max_retries,
                            pam_dp_reconnect_init, iter);
    }

    /* Set up the negative cache */
    ret = confdb_get_int(cdb, CONFDB_NSS_CONF_ENTRY,
                         CONFDB_NSS_ENTRY_NEG_TIMEOUT, 15,
                         &pctx->neg_timeout);
    if (ret != EOK) goto done;

    /* Set up the PAM identity timeout */
    ret = confdb_get_int(cdb, CONFDB_PAM_CONF_ENTRY,
                         CONFDB_PAM_ID_TIMEOUT, 5,
                         &id_timeout);
    if (ret != EOK) goto done;

    pctx->id_timeout = (size_t)id_timeout;

    ret = sss_ncache_init(pctx, &pctx->ncache);
    if (ret != EOK) {
        DEBUG(0, ("fatal error initializing negative cache\n"));
        goto done;
    }

    ret = sss_ncache_prepopulate(pctx->ncache, cdb, pctx->rctx);
    if (ret != EOK) {
        goto done;
    }

    /* Create table for initgroup lookups */
    ret = sss_hash_create(pctx, 10, &pctx->id_table);
    if (ret != EOK) {
        DEBUG(SSSDBG_FATAL_FAILURE,
              ("Could not create initgroups hash table: [%s]",
               strerror(ret)));
        goto done;
    }

    /* Set up file descriptor limits */
    ret = confdb_get_int(pctx->rctx->cdb,
                         CONFDB_PAM_CONF_ENTRY,
                         CONFDB_SERVICE_FD_LIMIT,
                         DEFAULT_PAM_FD_LIMIT,
                         &fd_limit);
    if (ret != EOK) {
        DEBUG(SSSDBG_FATAL_FAILURE,
              ("Failed to set up file descriptor limit\n"));
        goto done;
    }
    responder_set_fd_limit(fd_limit);

    ret = schedule_get_domains_task(rctx, rctx->ev, rctx);
    if (ret != EOK) {
        DEBUG(SSSDBG_FATAL_FAILURE, ("schedule_get_domains_tasks failed.\n"));
        goto done;
    }

    ret = EOK;

done:
    if (ret != EOK) {
        talloc_free(rctx);
    }
    return ret;
}

int main(int argc, const char *argv[])
{
    int opt;
    poptContext pc;
    struct main_context *main_ctx;
    int ret;

    struct poptOption long_options[] = {
        POPT_AUTOHELP
        SSSD_MAIN_OPTS
        POPT_TABLEEND
    };

    /* Set debug level to invalid value so we can deside if -d 0 was used. */
    debug_level = SSSDBG_INVALID;

    pc = poptGetContext(argv[0], argc, argv, long_options, 0);
    while((opt = poptGetNextOpt(pc)) != -1) {
        switch(opt) {
        default:
            fprintf(stderr, "\nInvalid option %s: %s\n\n",
                             poptBadOption(pc, 0), poptStrerror(opt));
            poptPrintUsage(pc, stderr, 0);
            return 1;
        }
    }

    poptFreeContext(pc);

    DEBUG_INIT(debug_level);

    /* set up things like debug, signals, daemonization, etc... */
    debug_log_file = "sssd_pam";

    ret = server_setup("sssd[pam]", 0, CONFDB_PAM_CONF_ENTRY, &main_ctx);
    if (ret != EOK) return 2;

    ret = die_if_parent_died();
    if (ret != EOK) {
        /* This is not fatal, don't return */
        DEBUG(2, ("Could not set up to exit when parent process does\n"));
    }

    ret = pam_process_init(main_ctx,
                           main_ctx->event_ctx,
                           main_ctx->confdb_ctx);
    if (ret != EOK) return 3;

    /* loop on main */
    server_loop(main_ctx);

    return 0;
}

