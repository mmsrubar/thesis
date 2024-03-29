/*
    SSSD

    Kerberos 5 Backend Module -- tgt_req and changepw child

    Authors:
        Sumit Bose <sbose@redhat.com>

    Copyright (C) 2009-2010 Red Hat

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

#include <sys/types.h>
#include <unistd.h>
#include <sys/stat.h>
#include <popt.h>

#include <security/pam_modules.h>

#include "util/util.h"
#include "util/sss_krb5.h"
#include "util/user_info_msg.h"
#include "util/child_common.h"
#include "providers/dp_backend.h"
#include "providers/krb5/krb5_auth.h"
#include "providers/krb5/krb5_utils.h"
#include "sss_cli.h"

#define SSSD_KRB5_CHANGEPW_PRINCIPAL "kadmin/changepw"

struct krb5_req {
    krb5_context ctx;
    krb5_principal princ;
    char* name;
    krb5_creds *creds;
    bool otp;
    krb5_get_init_creds_opt *options;

    struct pam_data *pd;

    char *realm;
    char *ccname;
    char *keytab;
    bool validate;
    bool send_pac;
    bool use_enterprise_princ;
    char *fast_ccname;

    const char *upn;
    uid_t uid;
    gid_t gid;
};

static krb5_context krb5_error_ctx;
#define KRB5_CHILD_DEBUG(level, error) KRB5_DEBUG(level, krb5_error_ctx, error)

static krb5_error_code set_lifetime_options(krb5_get_init_creds_opt *options)
{
    char *lifetime_str;
    krb5_error_code kerr;
    krb5_deltat lifetime;

    lifetime_str = getenv(SSSD_KRB5_RENEWABLE_LIFETIME);
    if (lifetime_str == NULL) {
        DEBUG(SSSDBG_CONF_SETTINGS, "Cannot read [%s] from environment.\n",
              SSSD_KRB5_RENEWABLE_LIFETIME);

        /* Unset option flag to make sure defaults from krb5.conf are used. */
        options->flags &= ~(KRB5_GET_INIT_CREDS_OPT_RENEW_LIFE);
    } else {
        kerr = krb5_string_to_deltat(lifetime_str, &lifetime);
        if (kerr != 0) {
            DEBUG(SSSDBG_CRIT_FAILURE,
                  "krb5_string_to_deltat failed for [%s].\n",
                      lifetime_str);
            KRB5_CHILD_DEBUG(SSSDBG_CRIT_FAILURE, kerr);
            return kerr;
        }
        DEBUG(SSSDBG_CONF_SETTINGS, "%s is set to [%s]\n",
              SSSD_KRB5_RENEWABLE_LIFETIME, lifetime_str);
        krb5_get_init_creds_opt_set_renew_life(options, lifetime);
    }

    lifetime_str = getenv(SSSD_KRB5_LIFETIME);
    if (lifetime_str == NULL) {
        DEBUG(SSSDBG_CONF_SETTINGS, "Cannot read [%s] from environment.\n",
              SSSD_KRB5_LIFETIME);

        /* Unset option flag to make sure defaults from krb5.conf are used. */
        options->flags &= ~(KRB5_GET_INIT_CREDS_OPT_TKT_LIFE);
    } else {
        kerr = krb5_string_to_deltat(lifetime_str, &lifetime);
        if (kerr != 0) {
            DEBUG(SSSDBG_CRIT_FAILURE,
                  "krb5_string_to_deltat failed for [%s].\n",
                      lifetime_str);
            KRB5_CHILD_DEBUG(SSSDBG_CRIT_FAILURE, kerr);
            return kerr;
        }
        DEBUG(SSSDBG_CONF_SETTINGS,
              "%s is set to [%s]\n", SSSD_KRB5_LIFETIME, lifetime_str);
        krb5_get_init_creds_opt_set_tkt_life(options, lifetime);
    }

    return 0;
}

static void set_canonicalize_option(krb5_get_init_creds_opt *opts)
{
    int canonicalize = 0;
    char *tmp_str;

    tmp_str = getenv(SSSD_KRB5_CANONICALIZE);
    if (tmp_str != NULL && strcasecmp(tmp_str, "true") == 0) {
        canonicalize = 1;
    }
    DEBUG(SSSDBG_CONF_SETTINGS, "%s is set to [%s]\n",
          SSSD_KRB5_CANONICALIZE, tmp_str ? tmp_str : "not set");
    sss_krb5_get_init_creds_opt_set_canonicalize(opts, canonicalize);
}

static void set_changepw_options(krb5_get_init_creds_opt *options)
{
    sss_krb5_get_init_creds_opt_set_canonicalize(options, 0);
    krb5_get_init_creds_opt_set_forwardable(options, 0);
    krb5_get_init_creds_opt_set_proxiable(options, 0);
    krb5_get_init_creds_opt_set_renew_life(options, 0);
    krb5_get_init_creds_opt_set_tkt_life(options, 5*60);
}

static void revert_changepw_options(krb5_get_init_creds_opt *options)
{
    krb5_error_code kerr;

    set_canonicalize_option(options);

    /* Currently we do not set forwardable and proxiable explicitly, the flags
     * must be removed so that libkrb5 can take the defaults from krb5.conf */
    options->flags &= ~(KRB5_GET_INIT_CREDS_OPT_FORWARDABLE);
    options->flags &= ~(KRB5_GET_INIT_CREDS_OPT_PROXIABLE);

    kerr = set_lifetime_options(options);
    if (kerr != 0) {
        DEBUG(SSSDBG_OP_FAILURE, ("set_lifetime_options failed.\n"));
    }
}


static errno_t sss_send_pac(krb5_authdata **pac_authdata)
{
    struct sss_cli_req_data sss_data;
    int ret;
    int errnop;

    sss_data.len = pac_authdata[0]->length;
    sss_data.data = pac_authdata[0]->contents;

    ret = sss_pac_make_request(SSS_PAC_ADD_PAC_USER, &sss_data,
                               NULL, NULL, &errnop);
    if (ret != NSS_STATUS_SUCCESS || errnop != 0) {
        DEBUG(SSSDBG_OP_FAILURE, "sss_pac_make_request failed [%d][%d].\n",
                                  ret, errnop);
        return EIO;
    }

    return EOK;
}

static void sss_krb5_expire_callback_func(krb5_context context, void *data,
                                          krb5_timestamp password_expiration,
                                          krb5_timestamp account_expiration,
                                          krb5_boolean is_last_req)
{
    int ret;
    uint32_t *blob;
    long exp_time;
    struct krb5_req *kr = talloc_get_type(data, struct krb5_req);

    if (password_expiration == 0) {
        return;
    }

    exp_time = password_expiration - time(NULL);
    if (exp_time < 0 || exp_time > UINT32_MAX) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Time to expire out of range.\n");
        return;
    }
    DEBUG(SSSDBG_TRACE_INTERNAL, "exp_time: [%ld]\n", exp_time);

    blob = talloc_array(kr->pd, uint32_t, 2);
    if (blob == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "talloc_size failed.\n");
        return;
    }

    blob[0] = SSS_PAM_USER_INFO_EXPIRE_WARN;
    blob[1] = (uint32_t) exp_time;

    ret = pam_add_response(kr->pd, SSS_PAM_USER_INFO, 2 * sizeof(uint32_t),
                           (uint8_t *) blob);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "pam_add_response failed.\n");
    }

    return;
}

#ifdef HAVE_KRB5_GET_INIT_CREDS_OPT_SET_RESPONDER
/*
 * TODO: These features generally would requires a significant refactoring
 * of SSSD and MIT krb5 doesn't support them anyway. They are listed here
 * simply as a reminder of things that might become future feature potential.
 *
 *   1. tokeninfo selection
 *   2. challenge
 *   3. discreet token/pin prompting
 *   4. interactive otp format correction
 *   5. nextOTP
 *
 */
typedef int (*checker)(int c);

static inline checker pick_checker(int format)
{
    switch (format) {
    case KRB5_RESPONDER_OTP_FORMAT_DECIMAL:
        return isdigit;
    case KRB5_RESPONDER_OTP_FORMAT_HEXADECIMAL:
        return isxdigit;
    case KRB5_RESPONDER_OTP_FORMAT_ALPHANUMERIC:
        return isalnum;
    }

    return NULL;
}

static int token_pin_destructor(char *mem)
{
    safezero(mem, strlen(mem));
    return 0;
}

static krb5_error_code tokeninfo_matches(TALLOC_CTX *mem_ctx,
                                         const krb5_responder_otp_tokeninfo *ti,
                                         const char *pwd, size_t len,
                                         char **out_token, char **out_pin)
{
    char *token = NULL, *pin = NULL;
    checker check = NULL;
    int i;


    if (ti->flags & KRB5_RESPONDER_OTP_FLAGS_NEXTOTP) {
        return ENOTSUP;
    }

    if (ti->challenge != NULL) {
        return ENOTSUP;
    }

    /* This is a non-sensical value. */
    if (ti->length == 0) {
        return EPROTO;
    }

    if (ti->flags & KRB5_RESPONDER_OTP_FLAGS_COLLECT_TOKEN) {
        /* ASSUMPTION: authtok has one of the following formats:
         *   1. TokenValue
         *   2. PIN+TokenValue
         */
        token = talloc_strndup(mem_ctx, pwd, len);
        if (token == NULL) {
            return ENOMEM;
        }
        talloc_set_destructor(token, token_pin_destructor);

        if (ti->flags & KRB5_RESPONDER_OTP_FLAGS_COLLECT_PIN) {
            /* If the server desires a separate pin, we will split it.
             * ASSUMPTION: Format of authtok is PIN+TokenValue. */
            if (ti->flags & KRB5_RESPONDER_OTP_FLAGS_SEPARATE_PIN) {
                if (ti->length < 1) {
                    talloc_free(token);
                    return ENOTSUP;
                }

                if (ti->length >= len) {
                    talloc_free(token);
                    return EMSGSIZE;
                }

                /* Copy the PIN from the front of the value. */
                pin = talloc_strndup(NULL, pwd, len - ti->length);
                if (pin == NULL) {
                    talloc_free(token);
                    return ENOMEM;
                }
                talloc_set_destructor(pin, token_pin_destructor);

                /* Remove the PIN from the front of the token value. */
                memmove(token, token + len - ti->length, ti->length + 1);

                check = pick_checker(ti->format);
            } else {
                if (ti->length > 0 && ti->length > len) {
                    talloc_free(token);
                    return EMSGSIZE;
                }
            }
        } else {
            if (ti->length > 0 && ti->length != len) {
                talloc_free(token);
                return EMSGSIZE;
            }

            check = pick_checker(ti->format);
        }
    } else {
        pin = talloc_strndup(mem_ctx, pwd, len);
        if (pin == NULL) {
            return ENOMEM;
        }
        talloc_set_destructor(pin, token_pin_destructor);
    }

    /* If check is set, we need to verify the contents of the token. */
    for (i = 0; check != NULL && token[i] != '\0'; i++) {
        if (!check(token[i])) {
            talloc_free(token);
            talloc_free(pin);
            return EBADMSG;
        }
    }

    *out_token = token;
    *out_pin = pin;
    return 0;
}

static krb5_error_code answer_otp(krb5_context ctx,
                                  struct krb5_req *kr,
                                  krb5_responder_context rctx)
{
    krb5_responder_otp_challenge *chl;
    char *token = NULL, *pin = NULL;
    const char *pwd = NULL;
    krb5_error_code ret;
    size_t i, len;

    ret = krb5_responder_otp_get_challenge(ctx, rctx, &chl);
    if (ret != EOK || chl == NULL) {
        /* Either an error, or nothing to do. */
        return ret;
    }

    if (chl->tokeninfo == NULL || chl->tokeninfo[0] == NULL) {
        /* No tokeninfos? Absurd! */
        ret = EINVAL;
        goto done;
    }

    kr->otp = true;

    /* Validate our assumptions about the contents of authtok. */
    ret = sss_authtok_get_password(kr->pd->authtok, &pwd, &len);
    if (ret != EOK)
        goto done;

    /* Find the first supported tokeninfo which matches our authtoken. */
    for (i = 0; chl->tokeninfo[i] != NULL; i++) {
        ret = tokeninfo_matches(kr, chl->tokeninfo[i], pwd, len, &token, &pin);
        if (ret == EOK) {
            break;
        }

        switch (ret) {
        case EBADMSG:
        case EMSGSIZE:
        case ENOTSUP:
        case EPROTO:
            break;
        default:
            goto done;
        }
    }
    if (chl->tokeninfo[i] == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "No tokeninfos found which match our credentials.\n");
        ret = EOK;
        goto done;
    }

    if (chl->tokeninfo[i]->flags & KRB5_RESPONDER_OTP_FLAGS_COLLECT_TOKEN) {
        /* Don't let SSSD cache the OTP authtok since it is single-use. */
        ret = pam_add_response(kr->pd, SSS_OTP, 0, NULL);
        if (ret != EOK) {
            DEBUG(SSSDBG_CRIT_FAILURE, "pam_add_response failed.\n");
            goto done;
        }
    }

    /* Respond with the appropriate answer. */
    ret = krb5_responder_otp_set_answer(ctx, rctx, i, token, pin);
done:
    talloc_free(token);
    talloc_free(pin);
    krb5_responder_otp_challenge_free(ctx, rctx, chl);
    return ret;
}

static krb5_error_code sss_krb5_responder(krb5_context ctx,
                                          void *data,
                                          krb5_responder_context rctx)
{
    struct krb5_req *kr = talloc_get_type(data, struct krb5_req);

    if (kr == NULL) {
        return EINVAL;
    }

    return answer_otp(ctx, kr, rctx);
}
#endif

static krb5_error_code sss_krb5_prompter(krb5_context context, void *data,
                                         const char *name, const char *banner,
                                         int num_prompts, krb5_prompt prompts[])
{
    int ret;
    struct krb5_req *kr = talloc_get_type(data, struct krb5_req);

    if (num_prompts != 0) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Cannot handle password prompts.\n");
        return KRB5_LIBOS_CANTREADPWD;
    }

    if (banner == NULL || *banner == '\0') {
        DEBUG(SSSDBG_FUNC_DATA,
              "Prompter called with empty banner, nothing to do.\n");
        return EOK;
    }

    DEBUG(SSSDBG_FUNC_DATA, "Prompter called with [%s].\n", banner);

    ret = pam_add_response(kr->pd, SSS_PAM_TEXT_MSG, strlen(banner)+1,
                           (const uint8_t *) banner);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "pam_add_response failed.\n");
    }

    return EOK;
}


static krb5_error_code create_empty_cred(krb5_context ctx, krb5_principal princ,
                                         krb5_creds **_cred)
{
    krb5_error_code kerr;
    krb5_creds *cred = NULL;
    krb5_data *krb5_realm;

    cred = calloc(sizeof(krb5_creds), 1);
    if (cred == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "calloc failed.\n");
        return ENOMEM;
    }

    kerr = krb5_copy_principal(ctx, princ, &cred->client);
    if (kerr != 0) {
        DEBUG(SSSDBG_CRIT_FAILURE, "krb5_copy_principal failed.\n");
        goto done;
    }

    krb5_realm = krb5_princ_realm(ctx, princ);

    kerr = krb5_build_principal_ext(ctx, &cred->server,
                                    krb5_realm->length, krb5_realm->data,
                                    KRB5_TGS_NAME_SIZE, KRB5_TGS_NAME,
                                    krb5_realm->length, krb5_realm->data, 0);
    if (kerr != 0) {
        DEBUG(SSSDBG_CRIT_FAILURE, "krb5_build_principal_ext failed.\n");
        goto done;
    }

    DEBUG(SSSDBG_TRACE_INTERNAL, "Created empty krb5_creds.\n");

done:
    if (kerr != 0) {
        krb5_free_cred_contents(ctx, cred);
        free(cred);
    } else {
        *_cred = cred;
    }

    return kerr;
}


static errno_t handle_randomized(char *in)
{
    size_t ccname_len;
    char *ccname = NULL;
    int ret;
    int fd;
    mode_t old_umask;

    /* We only treat the FILE type case in a special way due to the history
     * of storing FILE type ccache in /tmp and associated security issues */
    if (in[0] == '/') {
        ccname = in;
    } else if (strncmp(in, "FILE:", 5) == 0) {
        ccname = in + 5;
    } else {
        return EOK;
    }

    ccname_len = strlen(ccname);
    if (ccname_len >= 6 && strcmp(ccname + (ccname_len - 6), "XXXXXX") == 0) {
        /* NOTE: this call is only used to create a unique name, as later
         * krb5_cc_initialize() will unlink and recreate the file.
         * This is ok because this part of the code is called with
         * privileges already dropped when handling user ccache, or the ccache
         * is stored in a private directory. So we do not have huge issues if
         * something races, we mostly care only about not accidentally use
         * an existing name and thus failing in the process of saving the
         * cache. Malicious races can only be avoided by libkrb5 itself. */
        old_umask = umask(077);
        fd = mkstemp(ccname);
        umask(old_umask);
        if (fd == -1) {
            ret = errno;
            DEBUG(SSSDBG_CRIT_FAILURE, "mkstemp(\"%s\") failed!\n", ccname);
            return ret;
        }
    }

    return EOK;
}

/* NOTE: callers rely on 'name' being *changed* if it needs to be randomized,
 * as they will then send the name back to the new name via the return call
 * k5c_attach_ccname_msg(). Callers will send in a copy of the name if they
 * do not care for changes. */
static krb5_error_code create_ccache(char *ccname, krb5_creds *creds)
{
    krb5_context kctx = NULL;
    krb5_ccache kcc = NULL;
    const char *type;
    krb5_error_code kerr;
#ifdef HAVE_KRB5_CC_COLLECTION
    krb5_ccache cckcc;
    bool switch_to_cc = false;
#endif

    /* Set a restrictive umask, just in case we end up creating any file */
    umask(077);

    /* we create a new context here as the main process one may have been
     * opened as root and contain possibly references (even open handles ?)
     * to resources we do not have or do not want to have access to */
    kerr = krb5_init_context(&kctx);
    if (kerr) {
        KRB5_CHILD_DEBUG(SSSDBG_CRIT_FAILURE, kerr);
        return ERR_INTERNAL;
    }

    kerr = handle_randomized(ccname);
    if (kerr) goto done;

    kerr = krb5_cc_resolve(kctx, ccname, &kcc);
    if (kerr) goto done;

    type = krb5_cc_get_type(kctx, kcc);
    DEBUG(SSSDBG_TRACE_ALL, "Initializing ccache of type [%s]\n", type);

#ifdef HAVE_KRB5_CC_COLLECTION
    if (krb5_cc_support_switch(kctx, type)) {
        kerr = krb5_cc_set_default_name(kctx, ccname);
        if (kerr) goto done;

        kerr = krb5_cc_cache_match(kctx, creds->client, &cckcc);
        if (kerr == KRB5_CC_NOTFOUND) {
            kerr = krb5_cc_new_unique(kctx, type, NULL, &cckcc);
            switch_to_cc = true;
        }
        if (kerr) goto done;
        krb5_cc_close(kctx, kcc);
        kcc = cckcc;
    }
#endif

    kerr = krb5_cc_initialize(kctx, kcc, creds->client);
    if (kerr) goto done;

    kerr = krb5_cc_store_cred(kctx, kcc, creds);
    if (kerr) goto done;

#ifdef HAVE_KRB5_CC_COLLECTION
    if (switch_to_cc) {
        kerr = krb5_cc_switch(kctx, kcc);
        if (kerr) goto done;
    }
#endif

done:
    if (kcc) {
        /* FIXME: should we krb5_cc_destroy in case of error ? */
        krb5_cc_close(kctx, kcc);
    }
    return kerr;
}

static errno_t pack_response_packet(TALLOC_CTX *mem_ctx, errno_t error,
                                    struct response_data *resp_list,
                                    uint8_t **_buf, size_t *_len)
{
    uint8_t *buf;
    size_t size = 0;
    size_t p = 0;
    struct response_data *pdr;

    /* A buffer with the following structure must be created:
     * int32_t status of the request (required)
     * message (zero or more)
     *
     * A message consists of:
     * int32_t type of the message
     * int32_t length of the following data
     * uint8_t[len] data
     */

    size = sizeof(int32_t);

    for (pdr = resp_list; pdr != NULL; pdr = pdr->next) {
        size += 2*sizeof(int32_t) + pdr->len;
    }

    buf = talloc_array(mem_ctx, uint8_t, size);
    if (!buf) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Insufficient memory to create message.\n");
        return ENOMEM;
    }

    SAFEALIGN_SET_INT32(&buf[p], error, &p);

    for (pdr = resp_list; pdr != NULL; pdr = pdr->next) {
        SAFEALIGN_SET_INT32(&buf[p], pdr->type, &p);
        SAFEALIGN_SET_INT32(&buf[p], pdr->len, &p);
        safealign_memcpy(&buf[p], pdr->data, pdr->len, &p);
    }

    DEBUG(SSSDBG_TRACE_INTERNAL, "response packet size: [%zu]\n", p);

    *_buf = buf;
    *_len = p;
    return EOK;
}

static errno_t k5c_attach_ccname_msg(struct krb5_req *kr)
{
    char *msg = NULL;
    int ret;

    if (kr->ccname == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Error obtaining ccname.\n");
        return ERR_INTERNAL;
    }

    msg = talloc_asprintf(kr, "%s=%s",CCACHE_ENV_NAME, kr->ccname);
    if (msg == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "talloc_asprintf failed.\n");
        return ENOMEM;
    }

    ret = pam_add_response(kr->pd, SSS_PAM_ENV_ITEM,
                           strlen(msg) + 1, (uint8_t *)msg);
    talloc_zfree(msg);

    return ret;
}

static errno_t k5c_send_data(struct krb5_req *kr, int fd, errno_t error)
{
    size_t written;
    uint8_t *buf;
    size_t len;
    int ret;

    DEBUG(SSSDBG_FUNC_DATA, "Received error code %d\n", error);

    ret = pack_response_packet(kr, error, kr->pd->resp_list, &buf, &len);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "pack_response_packet failed.\n");
        return ret;
    }

    errno = 0;
    written = sss_atomic_write_s(fd, buf, len);
    if (written == -1) {
        ret = errno;
        DEBUG(SSSDBG_CRIT_FAILURE,
              "write failed [%d][%s].\n", ret, strerror(ret));
        return ret;
    }

    if (written != len) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Write error, wrote [%zu] bytes, expected [%zu]\n",
               written, len);
        return EOK;
    }

    DEBUG(SSSDBG_TRACE_ALL, "Response sent.\n");

    return EOK;
}

static errno_t add_ticket_times_and_upn_to_response(struct krb5_req *kr)
{
    int ret;
    int64_t t[4];
    krb5_error_code kerr;
    char *upn = NULL;
    unsigned int upn_len = 0;

    t[0] = (int64_t) kr->creds->times.authtime;
    t[1] = (int64_t) kr->creds->times.starttime;
    t[2] = (int64_t) kr->creds->times.endtime;
    t[3] = (int64_t) kr->creds->times.renew_till;

    ret = pam_add_response(kr->pd, SSS_KRB5_INFO_TGT_LIFETIME,
                           4*sizeof(int64_t), (uint8_t *) t);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "pack_response_packet failed.\n");
        goto done;
    }

    kerr = krb5_unparse_name_ext(kr->ctx, kr->creds->client, &upn, &upn_len);
    if (kerr != 0) {
        DEBUG(SSSDBG_OP_FAILURE, "krb5_unparse_name failed.\n");
        goto done;
    }

    ret = pam_add_response(kr->pd, SSS_KRB5_INFO_UPN, upn_len,
                           (uint8_t *) upn);
    krb5_free_unparsed_name(kr->ctx, upn);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "pack_response_packet failed.\n");
        goto done;
    }

done:
    return ret;
}

static krb5_error_code validate_tgt(struct krb5_req *kr)
{
    krb5_error_code kerr;
    krb5_error_code kt_err;
    char *principal = NULL;
    krb5_keytab keytab;
    krb5_kt_cursor cursor;
    krb5_keytab_entry entry;
    krb5_verify_init_creds_opt opt;
    krb5_principal validation_princ = NULL;
    bool realm_entry_found = false;
    krb5_ccache validation_ccache = NULL;
    krb5_authdata **pac_authdata = NULL;

    memset(&keytab, 0, sizeof(keytab));
    kerr = krb5_kt_resolve(kr->ctx, kr->keytab, &keytab);
    if (kerr != 0) {
        DEBUG(SSSDBG_CRIT_FAILURE, "error resolving keytab [%s], " \
                                    "not verifying TGT.\n", kr->keytab);
        return kerr;
    }

    memset(&cursor, 0, sizeof(cursor));
    kerr = krb5_kt_start_seq_get(kr->ctx, keytab, &cursor);
    if (kerr != 0) {
        DEBUG(SSSDBG_CRIT_FAILURE, "error reading keytab [%s], " \
                                    "not verifying TGT.\n", kr->keytab);
        return kerr;
    }

    /* We look for the first entry from our realm or take the last one */
    memset(&entry, 0, sizeof(entry));
    while ((kt_err = krb5_kt_next_entry(kr->ctx, keytab, &entry, &cursor)) == 0) {
        if (validation_princ != NULL) {
            krb5_free_principal(kr->ctx, validation_princ);
            validation_princ = NULL;
        }
        kerr = krb5_copy_principal(kr->ctx, entry.principal,
                                   &validation_princ);
        if (kerr != 0) {
            DEBUG(SSSDBG_CRIT_FAILURE, "krb5_copy_principal failed.\n");
            goto done;
        }

        kerr = sss_krb5_free_keytab_entry_contents(kr->ctx, &entry);
        if (kerr != 0) {
            DEBUG(SSSDBG_MINOR_FAILURE, "Failed to free keytab entry.\n");
        }
        memset(&entry, 0, sizeof(entry));

        if (krb5_realm_compare(kr->ctx, validation_princ, kr->creds->client)) {
            DEBUG(SSSDBG_TRACE_INTERNAL,
                  "Found keytab entry with the realm of the credential.\n");
            realm_entry_found = true;
            break;
        }
    }

    if (!realm_entry_found) {
        DEBUG(SSSDBG_TRACE_INTERNAL,
                "Keytab entry with the realm of the credential not found "
                 "in keytab. Using the last entry.\n");
    }

    /* Close the keytab here.  Even though we're using cursors, the file
     * handle is stored in the krb5_keytab structure, and it gets
     * overwritten when the verify_init_creds() call below creates its own
     * cursor, creating a leak. */
    kerr = krb5_kt_end_seq_get(kr->ctx, keytab, &cursor);
    if (kerr != 0) {
        DEBUG(SSSDBG_CRIT_FAILURE, "krb5_kt_end_seq_get failed, " \
                                    "not verifying TGT.\n");
        goto done;
    }

    /* check if we got any errors from krb5_kt_next_entry */
    if (kt_err != 0 && kt_err != KRB5_KT_END) {
        DEBUG(SSSDBG_CRIT_FAILURE, "error reading keytab [%s], " \
                                    "not verifying TGT.\n", kr->keytab);
        goto done;
    }

    /* Get the principal to which the key belongs, for logging purposes. */
    principal = NULL;
    kerr = krb5_unparse_name(kr->ctx, validation_princ, &principal);
    if (kerr != 0) {
        DEBUG(SSSDBG_CRIT_FAILURE, "internal error parsing principal name, "
                                    "not verifying TGT.\n");
        KRB5_CHILD_DEBUG(SSSDBG_CRIT_FAILURE, kerr);
        goto done;
    }


    krb5_verify_init_creds_opt_init(&opt);
    kerr = krb5_verify_init_creds(kr->ctx, kr->creds, validation_princ, keytab,
                                  &validation_ccache, &opt);

    if (kerr == 0) {
        DEBUG(SSSDBG_TRACE_FUNC, "TGT verified using key for [%s].\n",
                                  principal);
    } else {
        DEBUG(SSSDBG_CRIT_FAILURE ,"TGT failed verification using key " \
                                    "for [%s].\n", principal);
        goto done;
    }

    /* Try to find and send the PAC to the PAC responder.
     * Failures are not critical. */
    if (kr->send_pac) {
        kerr = sss_extract_pac(kr->ctx, validation_ccache, validation_princ,
                               kr->creds->client, keytab, &pac_authdata);
        if (kerr != 0) {
            DEBUG(SSSDBG_OP_FAILURE, "sss_extract_and_send_pac failed, group " \
                                      "membership for user with principal [%s] " \
                                      "might not be correct.\n", kr->name);
            kerr = 0;
            goto done;
        }

        kerr = sss_send_pac(pac_authdata);
        krb5_free_authdata(kr->ctx, pac_authdata);
        if (kerr != 0) {
            DEBUG(SSSDBG_OP_FAILURE, "sss_send_pac failed, group " \
                                      "membership for user with principal [%s] " \
                                      "might not be correct.\n", kr->name);
            kerr = 0;
        }
    }

done:
    if (validation_ccache != NULL) {
        krb5_cc_destroy(kr->ctx, validation_ccache);
    }

    if (krb5_kt_close(kr->ctx, keytab) != 0) {
        DEBUG(SSSDBG_MINOR_FAILURE, "krb5_kt_close failed");
    }
    if (validation_princ != NULL) {
        krb5_free_principal(kr->ctx, validation_princ);
    }
    if (principal != NULL) {
        sss_krb5_free_unparsed_name(kr->ctx, principal);
    }

    return kerr;

}

static krb5_error_code get_and_save_tgt_with_keytab(krb5_context ctx,
                                                    krb5_principal princ,
                                                    krb5_keytab keytab,
                                                    char *ccname)
{
    krb5_error_code kerr = 0;
    krb5_creds creds;
    krb5_get_init_creds_opt options;

    memset(&creds, 0, sizeof(creds));
    memset(&options, 0, sizeof(options));

    krb5_get_init_creds_opt_set_address_list(&options, NULL);
    krb5_get_init_creds_opt_set_forwardable(&options, 0);
    krb5_get_init_creds_opt_set_proxiable(&options, 0);
    set_canonicalize_option(&options);

    kerr = krb5_get_init_creds_keytab(ctx, &creds, princ, keytab, 0, NULL,
                                      &options);
    if (kerr != 0) {
        KRB5_CHILD_DEBUG(SSSDBG_CRIT_FAILURE, kerr);
        return kerr;
    }

    /* Use the updated principal in the creds in case canonicalized */
    kerr = create_ccache(ccname, &creds);
    if (kerr != 0) {
        KRB5_CHILD_DEBUG(SSSDBG_CRIT_FAILURE, kerr);
        goto done;
    }
    kerr = 0;

done:
    krb5_free_cred_contents(ctx, &creds);

    return kerr;

}

static krb5_error_code get_and_save_tgt(struct krb5_req *kr,
                                        const char *password)
{
    const char *realm_name;
    int realm_length;
    krb5_error_code kerr;
    char *cc_name;

    kerr = sss_krb5_get_init_creds_opt_set_expire_callback(kr->ctx, kr->options,
                                                  sss_krb5_expire_callback_func,
                                                  kr);
    if (kerr != 0) {
        KRB5_CHILD_DEBUG(SSSDBG_CRIT_FAILURE, kerr);
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Failed to set expire callback, continue without.\n");
    }

    sss_krb5_princ_realm(kr->ctx, kr->princ, &realm_name, &realm_length);

    DEBUG(SSSDBG_TRACE_FUNC,
          "Attempting kinit for realm [%s]\n",realm_name);
    kerr = krb5_get_init_creds_password(kr->ctx, kr->creds, kr->princ,
                                        discard_const(password),
                                        sss_krb5_prompter, kr, 0,
                                        NULL, kr->options);
    if (kerr != 0) {
        KRB5_CHILD_DEBUG(SSSDBG_CRIT_FAILURE, kerr);
        return kerr;
    }

    if (kr->validate) {
        kerr = validate_tgt(kr);
        if (kerr != 0) {
            KRB5_CHILD_DEBUG(SSSDBG_CRIT_FAILURE, kerr);
            return kerr;
        }

    } else {
        DEBUG(SSSDBG_CONF_SETTINGS, "TGT validation is disabled.\n");
    }

    if (kr->validate || kr->fast_ccname != NULL) {
        /* We drop root privileges which were needed to read the keytab file
         * for the validation of the credentials or for FAST here to run the
         * ccache I/O operations with user privileges. */
        kerr = become_user(kr->uid, kr->gid);
        if (kerr != 0) {
            DEBUG(SSSDBG_CRIT_FAILURE, "become_user failed.\n");
            return kerr;
        }
    }

    /* If kr->ccname is cache collection (DIR:/...), we want to work
     * directly with file ccache (DIR::/...), but cache collection
     * should be returned back to back end.
     */
    cc_name = sss_get_ccache_name_for_principal(kr->pd, kr->ctx,
                                                kr->creds->client,
                                                kr->ccname);
    if (cc_name == NULL) {
        cc_name = kr->ccname;
    }

    /* Use the updated principal in the creds in case canonicalized */
    kerr = create_ccache(cc_name, kr->creds);
    if (kerr != 0) {
        KRB5_CHILD_DEBUG(SSSDBG_CRIT_FAILURE, kerr);
        goto done;
    }

    kerr = add_ticket_times_and_upn_to_response(kr);
    if (kerr != 0) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "add_ticket_times_and_upn_to_response failed.\n");
    }

    kerr = 0;

done:
    krb5_free_cred_contents(kr->ctx, kr->creds);

    return kerr;

}

static errno_t map_krb5_error(krb5_error_code kerr)
{
    if (kerr != 0) {
        KRB5_CHILD_DEBUG(SSSDBG_CRIT_FAILURE, kerr);
    }

    switch (kerr) {
    case 0:
        return ERR_OK;

    case KRB5_LIBOS_CANTREADPWD:
        return ERR_NO_CREDS;

    case KRB5KRB_ERR_GENERIC:
    case KRB5KRB_AP_ERR_SKEW:
    case KRB5_KDC_UNREACH:
    case KRB5_REALM_CANT_RESOLVE:
        return ERR_NETWORK_IO;

    case KRB5KDC_ERR_CLIENT_REVOKED:
        return ERR_ACCOUNT_EXPIRED;

    case KRB5KDC_ERR_KEY_EXP:
        return ERR_CREDS_EXPIRED;

    case KRB5KRB_AP_ERR_BAD_INTEGRITY:
        return ERR_AUTH_FAILED;

    /* ERR_CREDS_INVALID is used to indicate to the IPA provider that trying
     * password migration would make sense. All Kerberos error codes which can
     * be seen while migrating LDAP users to IPA should be added here. */
    case KRB5_PROG_ETYPE_NOSUPP:
    case KRB5_PREAUTH_FAILED:
    case KRB5KDC_ERR_PREAUTH_FAILED:
        return ERR_CREDS_INVALID;

    default:
        return ERR_INTERNAL;
    }
}

static errno_t changepw_child(struct krb5_req *kr, bool prelim)
{
    int ret;
    krb5_error_code kerr = 0;
    const char *password = NULL;
    const char *newpassword = NULL;
    int result_code = -1;
    krb5_data result_code_string;
    krb5_data result_string;
    char *user_error_message = NULL;
    size_t user_resp_len;
    uint8_t *user_resp;
    krb5_prompter_fct prompter = NULL;
    const char *realm_name;
    int realm_length;
    size_t msg_len;
    uint8_t *msg;

    DEBUG(SSSDBG_TRACE_LIBS, "Password change operation\n");

    ret = sss_authtok_get_password(kr->pd->authtok, &password, NULL);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Failed to fetch current password [%d] %s.\n",
                  ret, strerror(ret));
        return ERR_NO_CREDS;
    }

    if (!prelim) {
        /* We do not need a password expiration warning here. */
        prompter = sss_krb5_prompter;
    }

    set_changepw_options(kr->options);
    sss_krb5_princ_realm(kr->ctx, kr->princ, &realm_name, &realm_length);

    DEBUG(SSSDBG_TRACE_FUNC,
          "Attempting kinit for realm [%s]\n",realm_name);
    kerr = krb5_get_init_creds_password(kr->ctx, kr->creds, kr->princ,
                                        discard_const(password),
                                        prompter, kr, 0,
                                        SSSD_KRB5_CHANGEPW_PRINCIPAL,
                                        kr->options);
    DEBUG(SSSDBG_TRACE_INTERNAL,
          "chpass is%s using OTP\n", kr->otp ? "" : " not");
    if (kerr != 0) {
        ret = pack_user_info_chpass_error(kr->pd, "Old password not accepted.",
                                          &msg_len, &msg);
        if (ret != EOK) {
            DEBUG(SSSDBG_CRIT_FAILURE,
                  "pack_user_info_chpass_error failed.\n");
        } else {
            ret = pam_add_response(kr->pd, SSS_PAM_USER_INFO, msg_len,
                                   msg);
            if (ret != EOK) {
                DEBUG(SSSDBG_CRIT_FAILURE,
                      "pam_add_response failed.\n");
            }
        }
        return kerr;
    }

    sss_authtok_set_empty(kr->pd->authtok);

    if (prelim) {
        DEBUG(SSSDBG_TRACE_LIBS,
              "Initial authentication for change password operation "
               "successful.\n");
        krb5_free_cred_contents(kr->ctx, kr->creds);
        return EOK;
    }

    ret = sss_authtok_get_password(kr->pd->newauthtok, &newpassword, NULL);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Failed to fetch new password [%d] %s.\n",
                  ret, strerror(ret));
        return ERR_NO_CREDS;
    }

    memset(&result_code_string, 0, sizeof(krb5_data));
    memset(&result_string, 0, sizeof(krb5_data));
    kerr = krb5_change_password(kr->ctx, kr->creds,
                                discard_const(newpassword), &result_code,
                                &result_code_string, &result_string);

    if (kerr == KRB5_KDC_UNREACH) {
        return ERR_NETWORK_IO;
    }

    if (kerr != 0 || result_code != 0) {
        if (kerr != 0) {
            KRB5_CHILD_DEBUG(SSSDBG_CRIT_FAILURE, kerr);
        }

        if (result_code_string.length > 0) {
            DEBUG(SSSDBG_CRIT_FAILURE,
                  "krb5_change_password failed [%d][%.*s].\n", result_code,
                      result_code_string.length, result_code_string.data);
            user_error_message = talloc_strndup(kr->pd, result_code_string.data,
                                                result_code_string.length);
            if (user_error_message == NULL) {
                DEBUG(SSSDBG_CRIT_FAILURE, "talloc_strndup failed.\n");
            }
        }

        if (result_string.length > 0 && result_string.data[0] != '\0') {
            DEBUG(SSSDBG_CRIT_FAILURE,
                  "krb5_change_password failed [%d][%.*s].\n", result_code,
                      result_string.length, result_string.data);
            talloc_free(user_error_message);
            user_error_message = talloc_strndup(kr->pd, result_string.data,
                                                result_string.length);
            if (user_error_message == NULL) {
                DEBUG(SSSDBG_CRIT_FAILURE, "talloc_strndup failed.\n");
            }
        } else if (result_code == KRB5_KPASSWD_SOFTERROR) {
            user_error_message = talloc_strdup(kr->pd, "Please make sure the "
                                 "password meets the complexity constraints.");
            if (user_error_message == NULL) {
                DEBUG(SSSDBG_CRIT_FAILURE, "talloc_strndup failed.\n");
            }
        }

        if (user_error_message != NULL) {
            ret = pack_user_info_chpass_error(kr->pd, user_error_message,
                                              &user_resp_len, &user_resp);
            if (ret != EOK) {
                DEBUG(SSSDBG_CRIT_FAILURE,
                      "pack_user_info_chpass_error failed.\n");
            } else {
                ret = pam_add_response(kr->pd, SSS_PAM_USER_INFO, user_resp_len,
                                       user_resp);
                if (ret != EOK) {
                    DEBUG(SSSDBG_CRIT_FAILURE,
                          "pack_response_packet failed.\n");
                }
            }
        }

        return ERR_CHPASS_FAILED;
    }

    krb5_free_cred_contents(kr->ctx, kr->creds);

    if (kr->otp == true) {
        sss_authtok_set_empty(kr->pd->newauthtok);
        return map_krb5_error(kerr);
    }

    /* We changed some of the gic options for the password change, now we have
     * to change them back to get a fresh TGT. */
    revert_changepw_options(kr->options);

    kerr = get_and_save_tgt(kr, newpassword);

    sss_authtok_set_empty(kr->pd->newauthtok);

    if (kerr == 0) {
        kerr = k5c_attach_ccname_msg(kr);
    }
    return map_krb5_error(kerr);
}

static errno_t tgt_req_child(struct krb5_req *kr)
{
    const char *password = NULL;
    krb5_error_code kerr;
    int ret;

    DEBUG(SSSDBG_TRACE_LIBS, "Attempting to get a TGT\n");

    ret = sss_authtok_get_password(kr->pd->authtok, &password, NULL);
    switch (ret) {
        case EOK:
            break;

        case EACCES:
            DEBUG(SSSDBG_OP_FAILURE, "Invalid authtok type\n");
            return ERR_INVALID_CRED_TYPE;
            break;

        default:
            DEBUG(SSSDBG_OP_FAILURE, "No credentials available\n");
            return ERR_NO_CREDS;
            break;
    }

    kerr = get_and_save_tgt(kr, password);

    if (kerr != KRB5KDC_ERR_KEY_EXP) {
        if (kerr == 0) {
            kerr = k5c_attach_ccname_msg(kr);
        }
        ret = map_krb5_error(kerr);
        goto done;
    }

    /* If the password is expired the KDC will always return
       KRB5KDC_ERR_KEY_EXP regardless if the supplied password is correct or
       not. In general the password can still be used to get a changepw ticket.
       So we validate the password by trying to get a changepw ticket. */
    DEBUG(SSSDBG_TRACE_LIBS, "Password was expired\n");
    kerr = sss_krb5_get_init_creds_opt_set_expire_callback(kr->ctx,
                                                           kr->options,
                                                           NULL, NULL);
    if (kerr != 0) {
        KRB5_CHILD_DEBUG(SSSDBG_CRIT_FAILURE, kerr);
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Failed to unset expire callback, continue ...\n");
    }

    set_changepw_options(kr->options);
    kerr = krb5_get_init_creds_password(kr->ctx, kr->creds, kr->princ,
                                        discard_const(password),
                                        sss_krb5_prompter, kr, 0,
                                        SSSD_KRB5_CHANGEPW_PRINCIPAL,
                                        kr->options);

    krb5_free_cred_contents(kr->ctx, kr->creds);
    if (kerr == 0) {
        ret = ERR_CREDS_EXPIRED;
    } else {
        ret = map_krb5_error(kerr);
    }

done:
    sss_authtok_set_empty(kr->pd->authtok);
    return ret;
}

static errno_t kuserok_child(struct krb5_req *kr)
{
    krb5_boolean access_allowed;
    krb5_error_code kerr;

    DEBUG(SSSDBG_TRACE_LIBS, "Verifying if principal can log in as user\n");

    /* krb5_kuserok tries to verify that kr->pd->user is a locally known
     * account, so we have to unset _SSS_LOOPS to make getpwnam() work. */
    if (unsetenv("_SSS_LOOPS") != 0) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Failed to unset _SSS_LOOPS, "
                  "krb5_kuserok will most certainly fail.\n");
    }

    kerr = krb5_set_default_realm(kr->ctx, kr->realm);
    if (kerr != 0) {
        DEBUG(SSSDBG_CRIT_FAILURE, "krb5_set_default_realm failed, "
                  "krb5_kuserok may fail.\n");
    }

    access_allowed = krb5_kuserok(kr->ctx, kr->princ, kr->pd->user);
    DEBUG(SSSDBG_TRACE_LIBS,
          "Access was %s\n", access_allowed ? "allowed" : "denied");

    if (access_allowed) {
        return EOK;
    }

    return ERR_AUTH_DENIED;
}

static errno_t renew_tgt_child(struct krb5_req *kr)
{
    const char *ccname;
    krb5_ccache ccache = NULL;
    krb5_error_code kerr;
    int ret;

    DEBUG(SSSDBG_TRACE_LIBS, "Renewing a ticket\n");

    ret = sss_authtok_get_ccfile(kr->pd->authtok, &ccname, NULL);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Unsupported authtok type for TGT renewal [%d].\n",
               sss_authtok_get_type(kr->pd->authtok));
        return ERR_INVALID_CRED_TYPE;
    }

    kerr = krb5_cc_resolve(kr->ctx, ccname, &ccache);
    if (kerr != 0) {
        KRB5_CHILD_DEBUG(SSSDBG_CRIT_FAILURE, kerr);
        goto done;
    }

    kerr = krb5_get_renewed_creds(kr->ctx, kr->creds, kr->princ, ccache, NULL);
    if (kerr != 0) {
        goto done;
    }

    if (kr->validate) {
        kerr = validate_tgt(kr);
        if (kerr != 0) {
            KRB5_CHILD_DEBUG(SSSDBG_CRIT_FAILURE, kerr);
            goto done;
        }

    } else {
        DEBUG(SSSDBG_CONF_SETTINGS, "TGT validation is disabled.\n");
    }

    if (kr->validate || kr->fast_ccname != NULL) {
        /* We drop root privileges which were needed to read the keytab file
         * for the validation of the credentials or for FAST here to run the
         * ccache I/O operations with user privileges. */
        kerr = become_user(kr->uid, kr->gid);
        if (kerr != 0) {
            DEBUG(SSSDBG_CRIT_FAILURE, "become_user failed.\n");
            goto done;
        }
    }

    kerr = krb5_cc_initialize(kr->ctx, ccache, kr->princ);
    if (kerr != 0) {
        KRB5_CHILD_DEBUG(SSSDBG_CRIT_FAILURE, kerr);
        goto done;
    }

    kerr = krb5_cc_store_cred(kr->ctx, ccache, kr->creds);
    if (kerr != 0) {
        KRB5_CHILD_DEBUG(SSSDBG_CRIT_FAILURE, kerr);
        goto done;
    }

    kerr = add_ticket_times_and_upn_to_response(kr);
    if (kerr != 0) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "add_ticket_times_and_upn_to_response failed.\n");
    }

    kerr = k5c_attach_ccname_msg(kr);

done:
    krb5_free_cred_contents(kr->ctx, kr->creds);

    if (ccache != NULL) {
        krb5_cc_close(kr->ctx, ccache);
    }

    return map_krb5_error(kerr);
}

static errno_t create_empty_ccache(struct krb5_req *kr)
{
    krb5_creds *creds = NULL;
    krb5_error_code kerr;

    DEBUG(SSSDBG_TRACE_LIBS, "Creating empty ccache\n");

    kerr = create_empty_cred(kr->ctx, kr->princ, &creds);
    if (kerr == 0) {
        kerr = create_ccache(kr->ccname, creds);
    }
    if (kerr != 0) {
        KRB5_CHILD_DEBUG(SSSDBG_CRIT_FAILURE, kerr);
    } else {
        kerr = k5c_attach_ccname_msg(kr);
    }

    krb5_free_creds(kr->ctx, creds);

    return map_krb5_error(kerr);
}

static errno_t unpack_authtok(struct sss_auth_token *tok,
                              uint8_t *buf, size_t size, size_t *p)
{
    uint32_t auth_token_type;
    uint32_t auth_token_length;
    errno_t ret = EOK;

    SAFEALIGN_COPY_UINT32_CHECK(&auth_token_type, buf + *p, size, p);
    SAFEALIGN_COPY_UINT32_CHECK(&auth_token_length, buf + *p, size, p);
    if ((*p + auth_token_length) > size) {
        return EINVAL;
    }
    switch (auth_token_type) {
    case SSS_AUTHTOK_TYPE_EMPTY:
        sss_authtok_set_empty(tok);
        break;
    case SSS_AUTHTOK_TYPE_PASSWORD:
        ret = sss_authtok_set_password(tok, (char *)(buf + *p), 0);
        break;
    case SSS_AUTHTOK_TYPE_CCFILE:
        ret = sss_authtok_set_ccfile(tok, (char *)(buf + *p), 0);
        break;
    default:
        return EINVAL;
    }

    if (ret == EOK) {
        *p += auth_token_length;
    }
    return ret;
}

static errno_t unpack_buffer(uint8_t *buf, size_t size,
                             struct krb5_req *kr, uint32_t *offline)
{
    size_t p = 0;
    uint32_t len;
    uint32_t validate;
    uint32_t send_pac;
    uint32_t use_enterprise_princ;
    struct pam_data *pd;
    errno_t ret;

    DEBUG(SSSDBG_TRACE_LIBS, "total buffer size: [%zu]\n", size);

    if (!offline || !kr) return EINVAL;

    pd = create_pam_data(kr);
    if (pd == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "talloc_zero failed.\n");
        return ENOMEM;
    }
    kr->pd = pd;

    SAFEALIGN_COPY_UINT32_CHECK(&pd->cmd, buf + p, size, &p);
    SAFEALIGN_COPY_UINT32_CHECK(&kr->uid, buf + p, size, &p);
    SAFEALIGN_COPY_UINT32_CHECK(&kr->gid, buf + p, size, &p);
    SAFEALIGN_COPY_UINT32_CHECK(&validate, buf + p, size, &p);
    kr->validate = (validate == 0) ? false : true;
    SAFEALIGN_COPY_UINT32_CHECK(offline, buf + p, size, &p);
    SAFEALIGN_COPY_UINT32_CHECK(&send_pac, buf + p, size, &p);
    kr->send_pac = (send_pac == 0) ? false : true;
    SAFEALIGN_COPY_UINT32_CHECK(&use_enterprise_princ, buf + p, size, &p);
    kr->use_enterprise_princ = (use_enterprise_princ == 0) ? false : true;
    SAFEALIGN_COPY_UINT32_CHECK(&len, buf + p, size, &p);
    if ((p + len ) > size) return EINVAL;
    kr->upn = talloc_strndup(pd, (char *)(buf + p), len);
    if (kr->upn == NULL) return ENOMEM;
    p += len;

    DEBUG(SSSDBG_CONF_SETTINGS,
          "cmd [%d] uid [%llu] gid [%llu] validate [%s] "
           "enterprise principal [%s] offline [%s] UPN [%s]\n",
           pd->cmd, (unsigned long long) kr->uid,
           (unsigned long long) kr->gid, kr->validate ? "true" : "false",
           kr->use_enterprise_princ ? "true" : "false",
           *offline ? "true" : "false", kr->upn ? kr->upn : "none");

    if (pd->cmd == SSS_PAM_AUTHENTICATE ||
        pd->cmd == SSS_CMD_RENEW ||
        pd->cmd == SSS_PAM_CHAUTHTOK_PRELIM || pd->cmd == SSS_PAM_CHAUTHTOK) {
        SAFEALIGN_COPY_UINT32_CHECK(&len, buf + p, size, &p);
        if ((p + len ) > size) return EINVAL;
        kr->ccname = talloc_strndup(pd, (char *)(buf + p), len);
        if (kr->ccname == NULL) return ENOMEM;
        p += len;

        SAFEALIGN_COPY_UINT32_CHECK(&len, buf + p, size, &p);
        if ((p + len ) > size) return EINVAL;
        kr->keytab = talloc_strndup(pd, (char *)(buf + p), len);
        if (kr->keytab == NULL) return ENOMEM;
        p += len;

        ret = unpack_authtok(pd->authtok, buf, size, &p);
        if (ret) {
            return ret;
        }

        DEBUG(SSSDBG_CONF_SETTINGS, "ccname: [%s] keytab: [%s]\n",
              kr->ccname, kr->keytab);
    } else {
        kr->ccname = NULL;
        kr->keytab = NULL;
        sss_authtok_set_empty(pd->authtok);
    }

    if (pd->cmd == SSS_PAM_CHAUTHTOK) {
        ret = unpack_authtok(pd->newauthtok, buf, size, &p);
        if (ret) {
            return ret;
        }
    } else {
        sss_authtok_set_empty(pd->newauthtok);
    }

    if (pd->cmd == SSS_PAM_ACCT_MGMT) {
        SAFEALIGN_COPY_UINT32_CHECK(&len, buf + p, size, &p);
        if ((p + len ) > size) return EINVAL;
        pd->user = talloc_strndup(pd, (char *)(buf + p), len);
        if (pd->user == NULL) return ENOMEM;
        p += len;
        DEBUG(SSSDBG_CONF_SETTINGS, "user: [%s]\n", pd->user);
    } else {
        pd->user = NULL;
    }

    return EOK;
}

static int krb5_cleanup(struct krb5_req *kr)
{
    if (kr == NULL) return EOK;

    if (kr->options != NULL) {
        sss_krb5_get_init_creds_opt_free(kr->ctx, kr->options);
    }

    if (kr->creds != NULL) {
        krb5_free_cred_contents(kr->ctx, kr->creds);
        krb5_free_creds(kr->ctx, kr->creds);
    }
    if (kr->name != NULL)
        sss_krb5_free_unparsed_name(kr->ctx, kr->name);
    if (kr->princ != NULL)
        krb5_free_principal(kr->ctx, kr->princ);
    if (kr->ctx != NULL)
        krb5_free_context(kr->ctx);

    memset(kr, 0, sizeof(struct krb5_req));

    return EOK;
}

static krb5_error_code get_tgt_times(krb5_context ctx, const char *ccname,
                                     krb5_principal server_principal,
                                     krb5_principal client_principal,
                                     sss_krb5_ticket_times *tgtt)
{
    krb5_error_code krberr;
    krb5_ccache ccache = NULL;
    krb5_creds mcred;
    krb5_creds cred;

    krberr = krb5_cc_resolve(ctx, ccname, &ccache);
    if (krberr != 0) {
        DEBUG(SSSDBG_CRIT_FAILURE, "krb5_cc_resolve failed.\n");
        goto done;
    }

    memset(&mcred, 0, sizeof(mcred));
    memset(&cred, 0, sizeof(mcred));

    mcred.server = server_principal;
    mcred.client = client_principal;

    krberr = krb5_cc_retrieve_cred(ctx, ccache, 0, &mcred, &cred);
    if (krberr != 0) {
        DEBUG(SSSDBG_CRIT_FAILURE, "krb5_cc_retrieve_cred failed.\n");
        krberr = 0;
        goto done;
    }

    tgtt->authtime = cred.times.authtime;
    tgtt->starttime = cred.times.starttime;
    tgtt->endtime = cred.times.endtime;
    tgtt->renew_till = cred.times.renew_till;

    krb5_free_cred_contents(ctx, &cred);

    krberr = 0;

done:
    if (ccache != NULL) {
        krb5_cc_close(ctx, ccache);
    }

    return krberr;
}

static krb5_error_code check_fast_ccache(TALLOC_CTX *mem_ctx,
                                         krb5_context ctx,
                                         const char *primary,
                                         const char *realm,
                                         const char *keytab_name,
                                         char **fast_ccname)
{
    TALLOC_CTX *tmp_ctx = NULL;
    krb5_error_code kerr;
    char *ccname;
    char *server_name;
    sss_krb5_ticket_times tgtt;
    krb5_keytab keytab = NULL;
    krb5_principal client_princ = NULL;
    krb5_principal server_princ = NULL;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "talloc_new failed.\n");
        return ENOMEM;
    }

    ccname = talloc_asprintf(tmp_ctx, "FILE:%s/fast_ccache_%s", DB_PATH, realm);
    if (ccname == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "talloc_asprintf failed.\n");
        kerr = ENOMEM;
        goto done;
    }

    if (keytab_name != NULL) {
        kerr = krb5_kt_resolve(ctx, keytab_name, &keytab);
    } else {
        kerr = krb5_kt_default(ctx, &keytab);
    }
    if (kerr) {
        DEBUG(SSSDBG_FATAL_FAILURE,
              "Failed to read keytab file [%s]: %s\n",
               KEYTAB_CLEAN_NAME,
               sss_krb5_get_error_message(ctx, kerr));
        goto done;
    }

    kerr = find_principal_in_keytab(ctx, keytab, primary, realm, &client_princ);
    if (kerr != 0) {
        DEBUG(SSSDBG_MINOR_FAILURE,
              "find_principal_in_keytab failed for principal %s@%s.\n",
               primary, realm);
        goto done;
    }

    server_name = talloc_asprintf(tmp_ctx, "krbtgt/%s@%s", realm, realm);
    if (server_name == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "talloc_asprintf failed.\n");
        kerr = ENOMEM;
        goto done;
    }

    kerr = krb5_parse_name(ctx, server_name, &server_princ);
    if (kerr != 0) {
        DEBUG(SSSDBG_CRIT_FAILURE, "krb5_parse_name failed.\n");
        goto done;
    }

    memset(&tgtt, 0, sizeof(tgtt));
    kerr = get_tgt_times(ctx, ccname, server_princ, client_princ, &tgtt);
    if (kerr == 0) {
        if (tgtt.endtime > time(NULL)) {
            DEBUG(SSSDBG_FUNC_DATA, "FAST TGT is still valid.\n");
            goto done;
        }
    }

    kerr = get_and_save_tgt_with_keytab(ctx, client_princ, keytab, ccname);
    if (kerr != 0) {
        DEBUG(SSSDBG_CRIT_FAILURE, "get_and_save_tgt_with_keytab failed.\n");
        goto done;
    }

    kerr = 0;

done:
    if (client_princ != NULL) {
        krb5_free_principal(ctx, client_princ);
    }
    if (server_princ != NULL) {
        krb5_free_principal(ctx, server_princ);
    }

    if (kerr == 0) {
        *fast_ccname = talloc_steal(mem_ctx, ccname);
    }
    talloc_free(tmp_ctx);

    if (keytab != NULL) {
        krb5_kt_close(ctx, keytab);
    }

    return kerr;
}

static errno_t k5c_recv_data(struct krb5_req *kr, int fd, uint32_t *offline)
{
    uint8_t buf[IN_BUF_SIZE];
    ssize_t len;
    errno_t ret;

    errno = 0;
    len = sss_atomic_read_s(fd, buf, IN_BUF_SIZE);
    if (len == -1) {
        ret = errno;
        ret = (ret == 0) ? EINVAL: ret;
        DEBUG(SSSDBG_CRIT_FAILURE,
              "read failed [%d][%s].\n", ret, strerror(ret));
        return ret;
    }

    ret = unpack_buffer(buf, len, kr, offline);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "unpack_buffer failed.\n");
    }

    return ret;
}

static int k5c_setup_fast(struct krb5_req *kr, bool demand)
{
    krb5_principal fast_princ_struct;
    krb5_data *realm_data;
    char *fast_principal_realm;
    char *fast_principal;
    krb5_error_code kerr;
    char *tmp_str;

    tmp_str = getenv(SSSD_KRB5_FAST_PRINCIPAL);
    if (tmp_str) {
        DEBUG(SSSDBG_CONF_SETTINGS, "%s is set to [%s]\n",
                                     SSSD_KRB5_FAST_PRINCIPAL, tmp_str);
        kerr = krb5_parse_name(kr->ctx, tmp_str, &fast_princ_struct);
        if (kerr) {
            DEBUG(SSSDBG_CRIT_FAILURE, "krb5_parse_name failed.\n");
            return kerr;
        }
        kerr = sss_krb5_unparse_name_flags(kr->ctx, fast_princ_struct,
                                       KRB5_PRINCIPAL_UNPARSE_NO_REALM,
                                       &tmp_str);
        if (kerr) {
            DEBUG(SSSDBG_CRIT_FAILURE, "sss_krb5_unparse_name_flags failed.\n");
            return kerr;
        }
        fast_principal = talloc_strdup(kr, tmp_str);
        if (!fast_principal) {
            DEBUG(SSSDBG_CRIT_FAILURE, "talloc_strdup failed.\n");
            return KRB5KRB_ERR_GENERIC;
        }
        free(tmp_str);
        realm_data = krb5_princ_realm(kr->ctx, fast_princ_struct);
        fast_principal_realm = talloc_asprintf(kr, "%.*s", realm_data->length, realm_data->data);
        if (!fast_principal_realm) {
            DEBUG(SSSDBG_CRIT_FAILURE, "talloc_asprintf failed.\n");
            return ENOMEM;
        }
    } else {
        fast_principal_realm = kr->realm;
        fast_principal = NULL;
    }

    kerr = check_fast_ccache(kr, kr->ctx, fast_principal, fast_principal_realm,
                             kr->keytab, &kr->fast_ccname);
    if (kerr != 0) {
        DEBUG(SSSDBG_CRIT_FAILURE, "check_fast_ccache failed.\n");
        KRB5_CHILD_DEBUG(SSSDBG_CRIT_FAILURE, kerr);
        return kerr;
    }

    kerr = sss_krb5_get_init_creds_opt_set_fast_ccache_name(kr->ctx,
                                                            kr->options,
                                                            kr->fast_ccname);
    if (kerr != 0) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "sss_krb5_get_init_creds_opt_set_fast_ccache_name "
                  "failed.\n");
        KRB5_CHILD_DEBUG(SSSDBG_CRIT_FAILURE, kerr);
        return kerr;
    }

    if (demand) {
        kerr = sss_krb5_get_init_creds_opt_set_fast_flags(kr->ctx,
                                                kr->options,
                                                SSS_KRB5_FAST_REQUIRED);
        if (kerr != 0) {
            DEBUG(SSSDBG_CRIT_FAILURE,
                  "sss_krb5_get_init_creds_opt_set_fast_flags "
                      "failed.\n");
            KRB5_CHILD_DEBUG(SSSDBG_CRIT_FAILURE, kerr);
            return kerr;
        }
    }

    return EOK;
}

static int k5c_setup(struct krb5_req *kr, uint32_t offline)
{
    krb5_error_code kerr;
    char *use_fast_str;
    int parse_flags;

    kr->realm = getenv(SSSD_KRB5_REALM);
    if (kr->realm == NULL) {
        DEBUG(SSSDBG_MINOR_FAILURE,
              "Cannot read [%s] from environment.\n", SSSD_KRB5_REALM);
    }

    kerr = krb5_init_context(&kr->ctx);
    if (kerr != 0) {
        KRB5_CHILD_DEBUG(SSSDBG_CRIT_FAILURE, kerr);
        return kerr;
    }

    /* Set the global error context */
    krb5_error_ctx = kr->ctx;

    if (debug_level & SSSDBG_TRACE_ALL) {
        kerr = sss_child_set_krb5_tracing(kr->ctx);
        if (kerr != 0) {
            KRB5_CHILD_DEBUG(SSSDBG_MINOR_FAILURE, kerr);
            return EIO;
        }
    }

    /* Enterprise principals require that a default realm is available. To
     * make SSSD more robust in the case that the default realm option is
     * missing in krb5.conf or to allow SSSD to work with multiple unconnected
     * realms (e.g. AD domains without trust between them) the default realm
     * will be set explicitly. */
    if (kr->use_enterprise_princ) {
        kerr = krb5_set_default_realm(kr->ctx, kr->realm);
        if (kerr != 0) {
            DEBUG(SSSDBG_CRIT_FAILURE, "krb5_set_default_realm failed.\n");
        }
    }

    parse_flags = kr->use_enterprise_princ ? KRB5_PRINCIPAL_PARSE_ENTERPRISE : 0;
    kerr = sss_krb5_parse_name_flags(kr->ctx, kr->upn, parse_flags, &kr->princ);
    if (kerr != 0) {
        KRB5_CHILD_DEBUG(SSSDBG_CRIT_FAILURE, kerr);
        return kerr;
    }

    kerr = krb5_unparse_name(kr->ctx, kr->princ, &kr->name);
    if (kerr != 0) {
        KRB5_CHILD_DEBUG(SSSDBG_CRIT_FAILURE, kerr);
        return kerr;
    }

    kr->creds = calloc(1, sizeof(krb5_creds));
    if (kr->creds == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "talloc_zero failed.\n");
        return ENOMEM;
    }

    kerr = sss_krb5_get_init_creds_opt_alloc(kr->ctx, &kr->options);
    if (kerr != 0) {
        KRB5_CHILD_DEBUG(SSSDBG_CRIT_FAILURE, kerr);
        return kerr;
    }

#ifdef HAVE_KRB5_GET_INIT_CREDS_OPT_SET_RESPONDER
    kerr = krb5_get_init_creds_opt_set_responder(kr->ctx, kr->options,
                                                 sss_krb5_responder, kr);
    if (kerr != 0) {
        KRB5_CHILD_DEBUG(SSSDBG_CRIT_FAILURE, kerr);
        return kerr;
    }
#endif

#ifdef HAVE_KRB5_GET_INIT_CREDS_OPT_SET_CHANGE_PASSWORD_PROMPT
    /* A prompter is used to catch messages about when a password will
     * expired. The library shall not use the prompter to ask for a new password
     * but shall return KRB5KDC_ERR_KEY_EXP. */
    krb5_get_init_creds_opt_set_change_password_prompt(kr->options, 0);
#endif

    kerr = set_lifetime_options(kr->options);
    if (kerr != 0) {
        DEBUG(SSSDBG_OP_FAILURE, ("set_lifetime_options failed.\n"));
        return kerr;
    }

    if (!offline) {
        set_canonicalize_option(kr->options);

        use_fast_str = getenv(SSSD_KRB5_USE_FAST);
        if (use_fast_str == NULL || strcasecmp(use_fast_str, "never") == 0) {
            DEBUG(SSSDBG_CONF_SETTINGS, "Not using FAST.\n");
        } else if (strcasecmp(use_fast_str, "try") == 0) {
            kerr = k5c_setup_fast(kr, false);
        } else if (strcasecmp(use_fast_str, "demand") == 0) {
            kerr = k5c_setup_fast(kr, true);
        } else {
            DEBUG(SSSDBG_CRIT_FAILURE,
                  "Unsupported value [%s] for krb5_use_fast.\n",
                   use_fast_str);
            return EINVAL;
        }
    }

/* TODO: set options, e.g.
 *  krb5_get_init_creds_opt_set_forwardable
 *  krb5_get_init_creds_opt_set_proxiable
 *  krb5_get_init_creds_opt_set_etype_list
 *  krb5_get_init_creds_opt_set_address_list
 *  krb5_get_init_creds_opt_set_preauth_list
 *  krb5_get_init_creds_opt_set_salt
 *  krb5_get_init_creds_opt_set_change_password_prompt
 *  krb5_get_init_creds_opt_set_pa
 */

    return kerr;
}

int main(int argc, const char *argv[])
{
    struct krb5_req *kr = NULL;
    uint32_t offline;
    int opt;
    poptContext pc;
    int debug_fd = -1;
    errno_t ret;

    struct poptOption long_options[] = {
        POPT_AUTOHELP
        {"debug-level", 'd', POPT_ARG_INT, &debug_level, 0,
         _("Debug level"), NULL},
        {"debug-timestamps", 0, POPT_ARG_INT, &debug_timestamps, 0,
         _("Add debug timestamps"), NULL},
        {"debug-microseconds", 0, POPT_ARG_INT, &debug_microseconds, 0,
         _("Show timestamps with microseconds"), NULL},
        {"debug-fd", 0, POPT_ARG_INT, &debug_fd, 0,
         _("An open file descriptor for the debug logs"), NULL},
        POPT_TABLEEND
    };

    /* Set debug level to invalid value so we can decide if -d 0 was used. */
    debug_level = SSSDBG_INVALID;

    pc = poptGetContext(argv[0], argc, argv, long_options, 0);
    while((opt = poptGetNextOpt(pc)) != -1) {
        switch(opt) {
        default:
        fprintf(stderr, "\nInvalid option %s: %s\n\n",
                  poptBadOption(pc, 0), poptStrerror(opt));
            poptPrintUsage(pc, stderr, 0);
            _exit(-1);
        }
    }

    poptFreeContext(pc);

    DEBUG_INIT(debug_level);

    debug_prg_name = talloc_asprintf(NULL, "[sssd[krb5_child[%d]]]", getpid());
    if (!debug_prg_name) {
        debug_prg_name = "[sssd[krb5_child]]";
        DEBUG(SSSDBG_CRIT_FAILURE, "talloc_asprintf failed.\n");
        ret = ENOMEM;
        goto done;
    }

    if (debug_fd != -1) {
        ret = set_debug_file_from_fd(debug_fd);
        if (ret != EOK) {
            DEBUG(SSSDBG_CRIT_FAILURE, "set_debug_file_from_fd failed.\n");
        }
    }

    DEBUG(SSSDBG_TRACE_FUNC, "krb5_child started.\n");

    kr = talloc_zero(NULL, struct krb5_req);
    if (kr == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "talloc failed.\n");
        ret = ENOMEM;
        goto done;
    }
    talloc_steal(kr, debug_prg_name);

    ret = k5c_recv_data(kr, STDIN_FILENO, &offline);
    if (ret != EOK) {
        goto done;
    }

    close(STDIN_FILENO);

    ret = k5c_setup(kr, offline);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "krb5_child_setup failed.\n");
        goto done;
    }

    switch(kr->pd->cmd) {
    case SSS_PAM_AUTHENTICATE:
        /* If we are offline, we need to create an empty ccache file */
        if (offline) {
            DEBUG(SSSDBG_TRACE_FUNC, "Will perform offline auth\n");
            ret = create_empty_ccache(kr);
        } else {
            DEBUG(SSSDBG_TRACE_FUNC, "Will perform online auth\n");
            ret = tgt_req_child(kr);
        }
        break;
    case SSS_PAM_CHAUTHTOK:
        DEBUG(SSSDBG_TRACE_FUNC, "Will perform password change\n");
        ret = changepw_child(kr, false);
        break;
    case SSS_PAM_CHAUTHTOK_PRELIM:
        DEBUG(SSSDBG_TRACE_FUNC, "Will perform password change checks\n");
        ret = changepw_child(kr, true);
        break;
    case SSS_PAM_ACCT_MGMT:
        DEBUG(SSSDBG_TRACE_FUNC, "Will perform account management\n");
        ret = kuserok_child(kr);
        break;
    case SSS_CMD_RENEW:
        if (offline) {
            DEBUG(SSSDBG_CRIT_FAILURE, "Cannot renew TGT while offline\n");
            ret = KRB5_KDC_UNREACH;
            goto done;
        }
        DEBUG(SSSDBG_TRACE_FUNC, "Will perform ticket renewal\n");
        ret = renew_tgt_child(kr);
        break;
    default:
        DEBUG(SSSDBG_CRIT_FAILURE,
              "PAM command [%d] not supported.\n", kr->pd->cmd);
        ret = EINVAL;
        goto done;
    }

    ret = k5c_send_data(kr, STDOUT_FILENO, ret);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Failed to send reply\n");
    }

done:
    if (ret == EOK) {
        DEBUG(SSSDBG_TRACE_FUNC, "krb5_child completed successfully\n");
        ret = 0;
    } else {
        DEBUG(SSSDBG_CRIT_FAILURE, "krb5_child failed!\n");
        ret = -1;
    }
    krb5_cleanup(kr);
    talloc_free(kr);
    exit(ret);
}
