/*
    SSSD

    IPA Helper routines - external users and groups with s2n plugin

    Copyright (C) Sumit Bose <sbose@redhat.com> - 2011

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

#include "util/util.h"
#include "util/sss_nss.h"
#include "db/sysdb.h"
#include "providers/ldap/sdap_async_private.h"
#include "providers/ldap/ldap_common.h"
#include "providers/ipa/ipa_id.h"
#include "providers/ipa/ipa_subdomains.h"

enum input_types {
    INP_SID = 1,
    INP_NAME,
    INP_POSIX_UID,
    INP_POSIX_GID
};

enum request_types {
    REQ_SIMPLE = 1,
    REQ_FULL
};

enum response_types {
    RESP_SID = 1,
    RESP_NAME,
    RESP_USER,
    RESP_GROUP
};

/* ==Sid2Name Extended Operation============================================= */
#define EXOP_SID2NAME_OID "2.16.840.1.113730.3.8.10.4"

struct ipa_s2n_exop_state {
    struct sdap_handle *sh;

    struct sdap_op *op;

    char *retoid;
    struct berval *retdata;
};

static void ipa_s2n_exop_done(struct sdap_op *op,
                           struct sdap_msg *reply,
                           int error, void *pvt);

static struct tevent_req *ipa_s2n_exop_send(TALLOC_CTX *mem_ctx,
                                            struct tevent_context *ev,
                                            struct sdap_handle *sh,
                                            struct berval *bv)
{
    struct tevent_req *req = NULL;
    struct ipa_s2n_exop_state *state;
    int ret;
    int msgid;

    req = tevent_req_create(mem_ctx, &state, struct ipa_s2n_exop_state);
    if (!req) return NULL;

    state->sh = sh;
    state->retoid = NULL;
    state->retdata = NULL;

    DEBUG(SSSDBG_TRACE_FUNC, ("Executing extended operation\n"));

    ret = ldap_extended_operation(state->sh->ldap, EXOP_SID2NAME_OID,
                                  bv, NULL, NULL, &msgid);
    if (ret == -1 || msgid == -1) {
        DEBUG(SSSDBG_CRIT_FAILURE, ("ldap_extended_operation failed\n"));
        ret = ERR_NETWORK_IO;
        goto fail;
    }
    DEBUG(SSSDBG_TRACE_INTERNAL, ("ldap_extended_operation sent, msgid = %d\n", msgid));

    /* FIXME: get timeouts from configuration, for now 10 secs. */
    ret = sdap_op_add(state, ev, state->sh, msgid, ipa_s2n_exop_done, req, 10,
                      &state->op);
    if (ret) {
        DEBUG(SSSDBG_CRIT_FAILURE, ("Failed to set up operation!\n"));
        ret = ERR_INTERNAL;
        goto fail;
    }

    return req;

fail:
    tevent_req_error(req, ret);
    tevent_req_post(req, ev);
    return req;
}

static void ipa_s2n_exop_done(struct sdap_op *op,
                               struct sdap_msg *reply,
                               int error, void *pvt)
{
    struct tevent_req *req = talloc_get_type(pvt, struct tevent_req);
    struct ipa_s2n_exop_state *state = tevent_req_data(req,
                                                    struct ipa_s2n_exop_state);
    int ret;
    char *errmsg = NULL;
    char *retoid = NULL;
    struct berval *retdata = NULL;
    int result;

    if (error) {
        tevent_req_error(req, error);
        return;
    }

    ret = ldap_parse_result(state->sh->ldap, reply->msg,
                            &result, &errmsg, NULL, NULL,
                            NULL, 0);
    if (ret != LDAP_SUCCESS) {
        DEBUG(SSSDBG_OP_FAILURE, ("ldap_parse_result failed (%d)\n", state->op->msgid));
        ret = ERR_NETWORK_IO;
        goto done;
    }

    DEBUG(SSSDBG_TRACE_FUNC, ("ldap_extended_operation result: %s(%d), %s\n",
            sss_ldap_err2string(result), result, errmsg));

    if (result != LDAP_SUCCESS) {
        ret = ERR_NETWORK_IO;
        goto done;
    }

    ret = ldap_parse_extended_result(state->sh->ldap, reply->msg,
                                      &retoid, &retdata, 0);
    if (ret != LDAP_SUCCESS) {
        DEBUG(SSSDBG_OP_FAILURE, ("ldap_parse_extendend_result failed (%d)\n", ret));
        ret = ERR_NETWORK_IO;
        goto done;
    }

    state->retoid = talloc_strdup(state, retoid);
    if (state->retoid == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, ("talloc_strdup failed.\n"));
        ret = ENOMEM;
        goto done;
    }

    state->retdata = talloc(state, struct berval);
    if (state->retdata == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, ("talloc failed.\n"));
        ret = ENOMEM;
        goto done;
    }
    state->retdata->bv_len = retdata->bv_len;
    state->retdata->bv_val = talloc_memdup(state->retdata, retdata->bv_val,
                                           retdata->bv_len);
    if (state->retdata->bv_val == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, ("talloc_memdup failed.\n"));
        ret = ENOMEM;
        goto done;
    }

    ret = EOK;

done:
    ldap_memfree(errmsg);
    ldap_memfree(retoid);
    ber_bvfree(retdata);
    if (ret == EOK) {
        tevent_req_done(req);
    } else {
        tevent_req_error(req, ret);
    }
}

static int ipa_s2n_exop_recv(struct tevent_req *req, TALLOC_CTX *mem_ctx,
                             char **retoid, struct berval **retdata)
{
    struct ipa_s2n_exop_state *state = tevent_req_data(req,
                                                    struct ipa_s2n_exop_state);

    TEVENT_REQ_RETURN_ON_ERROR(req);

    *retoid = talloc_steal(mem_ctx, state->retoid);
    *retdata = talloc_steal(mem_ctx, state->retdata);

    return EOK;
}

static errno_t talloc_ber_flatten(TALLOC_CTX *mem_ctx, BerElement *ber,
                                  struct berval **_bv)
{
    int ret;
    struct berval *bv = NULL;
    struct berval *tbv = NULL;

    ret = ber_flatten(ber, &bv);
    if (ret == -1) {
        ret = EFAULT;
        goto done;
    }

    tbv = talloc_zero(mem_ctx, struct berval);
    if (tbv == NULL) {
        ret = ENOMEM;
        goto done;
    }

    tbv->bv_len = bv->bv_len;
    tbv->bv_val = talloc_memdup(tbv, bv->bv_val, bv->bv_len);
    if (tbv->bv_val == NULL) {
        ret = ENOMEM;
        goto done;
    }

    ret = EOK;

done:
    ber_bvfree(bv);
    if (ret == EOK) {
        *_bv = tbv;
    } else  {
        talloc_free(tbv);
    }

    return ret;
}

/* The extended operation expect the following ASN.1 encoded request data:
 *
 * ExtdomRequestValue ::= SEQUENCE {
 *    inputType ENUMERATED {
 *        sid (1),
 *        name (2),
 *        posix uid (3),
 *        posix gid (3)
 *    },
 *    requestType ENUMERATED {
 *        simple (1),
 *        full (2)
 *    },
 *    data InputData
 * }
 *
 * InputData ::= CHOICE {
 *    sid OCTET STRING,
 *    name NameDomainData
 *    uid PosixUid,
 *    gid PosixGid
 * }
 *
 * NameDomainData ::= SEQUENCE {
 *    domain_name OCTET STRING,
 *    object_name OCTET STRING
 * }
 *
 * PosixUid ::= SEQUENCE {
 *    domain_name OCTET STRING,
 *    uid INTEGER
 * }
 *
 * PosixGid ::= SEQUENCE {
 *    domain_name OCTET STRING,
 *    gid INTEGER
 * }
 *
 */

static errno_t s2n_encode_request(TALLOC_CTX *mem_ctx,
                                  const char *domain_name,
                                  int entry_type,
                                  enum request_types request_type,
                                  struct req_input *req_input,
                                  struct berval **_bv)
{
    BerElement *ber = NULL;
    int ret;

    ber = ber_alloc_t( LBER_USE_DER );
    if (ber == NULL) {
        return ENOMEM;
    }

    switch (entry_type) {
        case BE_REQ_USER:
        case BE_REQ_USER_AND_GROUP:  /* the extdom exop does not care if the
                                        ID belongs to a user or a group */
            if (req_input->type == REQ_INP_NAME) {
                ret = ber_printf(ber, "{ee{ss}}", INP_NAME, request_type,
                                                  domain_name,
                                                  req_input->inp.name);
            } else if (req_input->type == REQ_INP_ID) {
                ret = ber_printf(ber, "{ee{si}}", INP_POSIX_UID, request_type,
                                                  domain_name,
                                                  req_input->inp.id);
            } else {
                DEBUG(SSSDBG_OP_FAILURE, ("Unexpected input type [%d].\n",
                                          req_input->type == REQ_INP_ID));
                ret = EINVAL;
                goto done;
            }
            break;
        case BE_REQ_GROUP:
            if (req_input->type == REQ_INP_NAME) {
                ret = ber_printf(ber, "{ee{ss}}", INP_NAME, request_type,
                                                  domain_name,
                                                  req_input->inp.name);
            } else if (req_input->type == REQ_INP_ID) {
                ret = ber_printf(ber, "{ee{si}}", INP_POSIX_GID, request_type,
                                                  domain_name,
                                                  req_input->inp.id);
            } else {
                DEBUG(SSSDBG_OP_FAILURE, ("Unexpected input type [%d].\n",
                                          req_input->type == REQ_INP_ID));
                ret = EINVAL;
                goto done;
            }
            break;
        case BE_REQ_BY_SECID:
            if (req_input->type == REQ_INP_SECID) {
            ret = ber_printf(ber, "{ees}", INP_SID, request_type,
                                           req_input->inp.secid);
            } else {
                DEBUG(SSSDBG_OP_FAILURE, ("Unexpected input type [%d].\n",
                                          req_input->type == REQ_INP_ID));
                ret = EINVAL;
                goto done;
            }
            break;
        default:
            ret = EINVAL;
            goto done;
    }
    if (ret == -1) {
        ret = EFAULT;
        goto done;
    }

    ret = talloc_ber_flatten(mem_ctx, ber, _bv);
    if (ret == -1) {
        ret = EFAULT;
        goto done;
    }

    ret = EOK;

done:
    ber_free(ber, 1);

    return ret;
}

/* If the extendend operation is successful it returns the following ASN.1
 * encoded response:
 *
 * ExtdomResponseValue ::= SEQUENCE {
 *    responseType ENUMERATED {
 *        sid (1),
 *        name (2),
 *        posix_user (3),
 *        posix_group (4)
 *    },
 *    data OutputData
 * }
 *
 * OutputData ::= CHOICE {
 *    sid OCTET STRING,
 *    name NameDomainData,
 *    user PosixUser,
 *    group PosixGroup
 * }
 *
 * NameDomainData ::= SEQUENCE {
 *    domain_name OCTET STRING,
 *    object_name OCTET STRING
 * }
 *
 * PosixUser ::= SEQUENCE {
 *    domain_name OCTET STRING,
 *    user_name OCTET STRING,
 *    uid INTEGER
 *    gid INTEGER
 * }
 *
 * PosixGroup ::= SEQUENCE {
 *    domain_name OCTET STRING,
 *    group_name OCTET STRING,
 *    gid INTEGER
 * }
 *
 */

struct resp_attrs {
    enum response_types response_type;
    char *domain_name;
    union {
        struct passwd user;
        struct group group;
        char *sid_str;
        char *name;
    } a;
};

static errno_t s2n_response_to_attrs(TALLOC_CTX *mem_ctx,
                                     char *retoid,
                                     struct berval *retdata,
                                     struct resp_attrs **resp_attrs)
{
    BerElement *ber = NULL;
    ber_tag_t tag;
    int ret;
    enum response_types type;
    char *domain_name = NULL;
    char *name = NULL;
    uid_t uid;
    gid_t gid;
    struct resp_attrs *attrs = NULL;
    char *sid_str;

    if (retoid == NULL || retdata == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, ("Missing OID or data.\n"));
        return EINVAL;
    }

    if (strcmp(retoid, EXOP_SID2NAME_OID) != 0) {
        DEBUG(SSSDBG_OP_FAILURE,
              ("Result has wrong OID, expected [%s], got [%s].\n",
              EXOP_SID2NAME_OID, retoid));
        return EINVAL;
    }

    ber = ber_init(retdata);
    if (ber == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, ("ber_init failed.\n"));
        return EINVAL;
    }

    tag = ber_scanf(ber, "{e", &type);
    if (tag == LBER_ERROR) {
        DEBUG(SSSDBG_OP_FAILURE, ("ber_scanf failed.\n"));
        ret = EINVAL;
        goto done;
    }

    attrs = talloc_zero(mem_ctx, struct resp_attrs);
    if (attrs == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, ("talloc_zero failed.\n"));
        ret = ENOMEM;
        goto done;
    }

    switch (type) {
        case RESP_USER:
            tag = ber_scanf(ber, "{aaii}}", &domain_name, &name, &uid, &gid);
            if (tag == LBER_ERROR) {
                DEBUG(SSSDBG_OP_FAILURE, ("ber_scanf failed.\n"));
                ret = EINVAL;
                goto done;
            }

            /* Winbind is not consistent with the case of the returned user
             * name. In general all names should be lower case but there are
             * bug in some version of winbind which might lead to upper case
             * letters in the name. To be on the safe side we explicitly
             * lowercase the name. */
            attrs->a.user.pw_name = sss_tc_utf8_str_tolower(attrs, name);
            if (attrs->a.user.pw_name == NULL) {
                DEBUG(SSSDBG_OP_FAILURE, ("talloc_strdup failed.\n"));
                ret = ENOMEM;
                goto done;
            }

            attrs->a.user.pw_uid = uid;
            attrs->a.user.pw_gid = gid;

            break;
        case RESP_GROUP:
            tag = ber_scanf(ber, "{aai}}", &domain_name, &name, &gid);
            if (tag == LBER_ERROR) {
                DEBUG(SSSDBG_OP_FAILURE, ("ber_scanf failed.\n"));
                ret = EINVAL;
                goto done;
            }

            /* Winbind is not consistent with the case of the returned user
             * name. In general all names should be lower case but there are
             * bug in some version of winbind which might lead to upper case
             * letters in the name. To be on the safe side we explicitly
             * lowercase the name. */
            attrs->a.group.gr_name = sss_tc_utf8_str_tolower(attrs, name);
            if (attrs->a.group.gr_name == NULL) {
                DEBUG(SSSDBG_OP_FAILURE, ("talloc_strdup failed.\n"));
                ret = ENOMEM;
                goto done;
            }

            attrs->a.group.gr_gid = gid;

            break;
        case RESP_SID:
            tag = ber_scanf(ber, "a}", &sid_str);
            if (tag == LBER_ERROR) {
                DEBUG(SSSDBG_OP_FAILURE, ("ber_scanf failed.\n"));
                ret = EINVAL;
                goto done;
            }

            attrs->a.sid_str = talloc_strdup(attrs, sid_str);
            if (attrs->a.sid_str == NULL) {
                DEBUG(SSSDBG_OP_FAILURE, ("talloc_strdup failed.\n"));
                ret = ENOMEM;
                goto done;
            }
            break;
        case RESP_NAME:
            tag = ber_scanf(ber, "{aa}", &domain_name, &name);
            if (tag == LBER_ERROR) {
                DEBUG(SSSDBG_OP_FAILURE, ("ber_scanf failed.\n"));
                ret = EINVAL;
                goto done;
            }

            attrs->a.name = sss_tc_utf8_str_tolower(attrs, name);
            if (attrs->a.name == NULL) {
                DEBUG(SSSDBG_OP_FAILURE, ("sss_tc_utf8_str_tolower failed.\n"));
                ret = ENOMEM;
                goto done;
            }
            break;
        default:
            DEBUG(SSSDBG_OP_FAILURE, ("Unexpected response type [%d].\n",
                                      type));
            ret = EINVAL;
            goto done;
    }

    attrs->response_type = type;
    if (type != RESP_SID) {
        attrs->domain_name = talloc_strdup(attrs, domain_name);
        if (attrs->domain_name == NULL) {
            DEBUG(SSSDBG_OP_FAILURE, ("talloc_strdup failed.\n"));
            ret = ENOMEM;
            goto done;
        }
    }

    ret = EOK;

done:
    ber_memfree(domain_name);
    ber_memfree(name);
    ber_free(ber, 1);

    if (ret == EOK) {
        *resp_attrs = attrs;
    } else {
        talloc_free(attrs);
    }

    return ret;
}

struct ipa_s2n_get_user_state {
    struct tevent_context *ev;
    struct sdap_options *opts;
    struct sss_domain_info *dom;
    struct sdap_handle *sh;
    struct req_input *req_input;
    int entry_type;
    enum request_types request_type;
    struct resp_attrs *attrs;
};

static void ipa_s2n_get_user_done(struct tevent_req *subreq);

struct tevent_req *ipa_s2n_get_acct_info_send(TALLOC_CTX *mem_ctx,
                                              struct tevent_context *ev,
                                              struct sdap_options *opts,
                                              struct sss_domain_info *dom,
                                              struct sdap_handle *sh,
                                              int entry_type,
                                              struct req_input *req_input)
{
    struct ipa_s2n_get_user_state *state;
    struct tevent_req *req;
    struct tevent_req *subreq;
    struct berval *bv_req = NULL;
    int ret = EFAULT;

    req = tevent_req_create(mem_ctx, &state, struct ipa_s2n_get_user_state);
    if (req == NULL) {
        return NULL;
    }

    state->ev = ev;
    state->opts = opts;
    state->dom = dom;
    state->sh = sh;
    state->req_input = req_input;
    state->entry_type = entry_type;
    state->request_type = REQ_FULL;

    ret = s2n_encode_request(state, dom->name, entry_type, state->request_type,
                             req_input, &bv_req);
    if (ret != EOK) {
        goto fail;
    }

    subreq = ipa_s2n_exop_send(state, state->ev, state->sh, bv_req);
    if (subreq == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, ("ipa_s2n_exop_send failed.\n"));
        ret = ENOMEM;
        goto fail;
    }
    tevent_req_set_callback(subreq, ipa_s2n_get_user_done, req);

    return req;

fail:
    tevent_req_error(req, ret);
    tevent_req_post(req, ev);

    return req;
}

static void ipa_s2n_get_user_done(struct tevent_req *subreq)
{
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);
    struct ipa_s2n_get_user_state *state = tevent_req_data(req,
                                                struct ipa_s2n_get_user_state);
    int ret;
    char *retoid = NULL;
    struct berval *retdata = NULL;
    struct resp_attrs *attrs = NULL;
    struct resp_attrs *simple_attrs = NULL;
    time_t now;
    uint64_t timeout = 10*60*60; /* FIXME: find a better timeout ! */
    const char *homedir = NULL;
    struct sysdb_attrs *user_attrs = NULL;
    struct sysdb_attrs *group_attrs = NULL;
    char *name;
    char *realm;
    char *upn;
    struct berval *bv_req = NULL;
    gid_t gid;

    ret = ipa_s2n_exop_recv(subreq, state, &retoid, &retdata);
    talloc_zfree(subreq);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, ("s2n exop request failed.\n"));
        goto done;
    }

    switch (state->request_type) {
    case REQ_FULL:
        ret = s2n_response_to_attrs(state, retoid, retdata, &attrs);
        if (ret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE, ("s2n_response_to_attrs failed.\n"));
            goto done;
        }

        if (!(strcasecmp(state->dom->name, attrs->domain_name) == 0 ||
              (state->dom->flat_name != NULL &&
               strcasecmp(state->dom->flat_name, attrs->domain_name) == 0))) {
            DEBUG(SSSDBG_OP_FAILURE, ("Unexpected domain name returned, "
                                      "expected [%s] or [%s], got [%s].\n",
                         state->dom->name,
                         state->dom->flat_name == NULL ? "" :
                                                         state->dom->flat_name,
                         attrs->domain_name));
            ret = EINVAL;
            goto done;
        }

        state->attrs = attrs;

        if (state->req_input->type == REQ_INP_SECID) {
            /* We already know the SID, we do not have to read it. */
            break;
        }

        state->request_type = REQ_SIMPLE;

        ret = s2n_encode_request(state, state->dom->name, state->entry_type,
                                 state->request_type, state->req_input,
                                 &bv_req);
        if (ret != EOK) {
            goto done;
        }

        subreq = ipa_s2n_exop_send(state, state->ev, state->sh, bv_req);
        if (subreq == NULL) {
            DEBUG(SSSDBG_OP_FAILURE, ("ipa_s2n_exop_send failed.\n"));
            ret = ENOMEM;
            goto done;
        }
        tevent_req_set_callback(subreq, ipa_s2n_get_user_done, req);

        return;

    case REQ_SIMPLE:
        ret = s2n_response_to_attrs(state, retoid, retdata, &simple_attrs);
        if (ret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE, ("s2n_response_to_attrs failed.\n"));
            goto done;
        }

        break;
    default:
        DEBUG(SSSDBG_CRIT_FAILURE, ("Unexpected request type.\n"));
        ret = EINVAL;
        goto done;
    }

    if (state->attrs == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, ("Missing data of full request.\n"));
        ret = EINVAL;
        goto done;
    } else {
        attrs = state->attrs;
    }

    now = time(NULL);

    switch (attrs->response_type) {
        case RESP_USER:
            if (state->dom->subdomain_homedir) {
                homedir =  expand_homedir_template(state,
                                                   state->dom->subdomain_homedir,
                                                   attrs->a.user.pw_name,
                                                   attrs->a.user.pw_uid,
                                                   NULL,
                                                   state->dom->name,
                                                   state->dom->flat_name);
                if (homedir == NULL) {
                    ret = ENOMEM;
                    goto done;
                }
            }

            user_attrs = sysdb_new_attrs(state);
            if (user_attrs == NULL) {
                DEBUG(SSSDBG_OP_FAILURE, ("sysdb_new_attrs failed.\n"));
                ret = ENOMEM;
                goto done;
            }

            /* we always use the fully qualified name for subdomain users */
            name = sss_tc_fqname(state, state->dom->names, state->dom,
                                 attrs->a.user.pw_name);
            if (!name) {
                DEBUG(SSSDBG_OP_FAILURE, ("failed to format user name.\n"));
                ret = ENOMEM;
                goto done;
            }

            ret = sysdb_attrs_add_lc_name_alias(user_attrs, name);
            if (ret != EOK) {
                DEBUG(SSSDBG_OP_FAILURE,
                      ("sysdb_attrs_add_lc_name_alias failed.\n"));
                goto done;
            }

            /* We also have to store a fake UPN here, because otherwise the
             * krb5 child later won't be able to properly construct one as
             * the username is fully qualified but the child doesn't have
             * access to the regex to deconstruct it */
            /* FIXME: The real UPN is available from the PAC, we should get
             * it from there. */
            realm = get_uppercase_realm(state, state->dom->name);
            if (!realm) {
                DEBUG(SSSDBG_OP_FAILURE, ("failed to get realm.\n"));
                ret = ENOMEM;
                goto done;
            }
            upn = talloc_asprintf(state, "%s@%s",
                                  attrs->a.user.pw_name, realm);
            if (!upn) {
                DEBUG(SSSDBG_OP_FAILURE, ("failed to format UPN.\n"));
                ret = ENOMEM;
                goto done;
            }

            ret = sysdb_attrs_add_string(user_attrs, SYSDB_UPN, upn);
            if (ret != EOK) {
                DEBUG(SSSDBG_OP_FAILURE, ("sysdb_attrs_add_string failed.\n"));
                goto done;
            }

            if (state->req_input->type == REQ_INP_SECID) {
                ret = sysdb_attrs_add_string(user_attrs, SYSDB_SID_STR,
                                             state->req_input->inp.secid);
                if (ret != EOK) {
                    DEBUG(SSSDBG_OP_FAILURE, ("sysdb_attrs_add_string failed.\n"));
                    goto done;
                }
            }

            if (simple_attrs != NULL && simple_attrs->response_type == RESP_SID) {
                ret = sysdb_attrs_add_string(user_attrs, SYSDB_SID_STR,
                                             simple_attrs->a.sid_str);
                if (ret != EOK) {
                    DEBUG(SSSDBG_OP_FAILURE, ("sysdb_attrs_add_string failed.\n"));
                    goto done;
                }
            }

            gid = 0;
            if (state->dom->mpg == false) {
                gid = attrs->a.user.pw_gid;
            }

            ret = sysdb_store_user(state->dom, name, NULL,
                                   attrs->a.user.pw_uid,
                                   gid, NULL, /* gecos */
                                   homedir, NULL, NULL, user_attrs, NULL,
                                   timeout, now);
            break;
        case RESP_GROUP:
            /* we always use the fully qualified name for subdomain users */
            name = sss_tc_fqname(state, state->dom->names, state->dom,
                                 attrs->a.group.gr_name);
            if (!name) {
                DEBUG(SSSDBG_OP_FAILURE, ("failed to format user name,\n"));
                ret = ENOMEM;
                goto done;
            }

            group_attrs = sysdb_new_attrs(state);
            if (group_attrs == NULL) {
                DEBUG(SSSDBG_OP_FAILURE, ("sysdb_new_attrs failed.\n"));
                ret = ENOMEM;
                goto done;
            }

            ret = sysdb_attrs_add_lc_name_alias(group_attrs, name);
            if (ret != EOK) {
                DEBUG(SSSDBG_OP_FAILURE,
                      ("sysdb_attrs_add_lc_name_alias failed.\n"));
                goto done;
            }

            if (state->req_input->type == REQ_INP_SECID) {
                ret = sysdb_attrs_add_string(group_attrs, SYSDB_SID_STR,
                                             state->req_input->inp.secid);
                if (ret != EOK) {
                    DEBUG(SSSDBG_OP_FAILURE, ("sysdb_attrs_add_string failed.\n"));
                    goto done;
                }
            }

            if (simple_attrs != NULL && simple_attrs->response_type == RESP_SID) {
                ret = sysdb_attrs_add_string(group_attrs, SYSDB_SID_STR,
                                             simple_attrs->a.sid_str);
                if (ret != EOK) {
                    DEBUG(SSSDBG_OP_FAILURE, ("sysdb_attrs_add_string failed.\n"));
                    goto done;
                }
            }

            ret = sysdb_store_group(state->dom, name, attrs->a.group.gr_gid,
                                    group_attrs, timeout, now);
            break;
        default:
            DEBUG(SSSDBG_OP_FAILURE, ("Unexpected response type [%d].\n",
                                      attrs->response_type));
            ret = EINVAL;
            goto done;
    }

done:
    talloc_free(user_attrs);
    talloc_free(group_attrs);
    if (ret == EOK) {
        tevent_req_done(req);
    } else {
        tevent_req_error(req, ret);
    }
    return;
}

int ipa_s2n_get_acct_info_recv(struct tevent_req *req)
{
    TEVENT_REQ_RETURN_ON_ERROR(req);

    return EOK;
}
