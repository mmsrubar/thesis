#ifdef NO

#define USER    "memberUser"
#define HOST    "memberHost"

enum ipa_sudo_attr_type {
    DN = 0,
    COMMAND,
    COPY,       /* value of the attribute doesn't need to be exported */
};


struct export_properties {
    enum ipa_sudo_attr_type type;
    struct rdn *first;
    struct rdn *second;
    struct rdn *third;

    char sing;
};

void get_member_cmd_value(TALLOC_CTX *mem, 
                            const char *name, 
                            const char *value,
                            const char **cmd_val)
{
    const char *val;
    errno_t = EOK;

    if (strcasecmp(value, "cn=sudocmds,cn=sudo") == 0) {

       /* get value of ipaUniqueID */
       ret = get_third_rdn_value(mem, sysdb, properties->value, properties, &val);
       if (ret != EOK) {
           goto fail;
       }
    }
    else if (strcasecmp(value, "cn=sudocmdgroups,cn=sudo") == 0) {
        val = value;
    } else {
        /* FIXME: weird value of member{Allow,Deny}Cmd */
    }

    *cmd_val = val;

fail:
    return ret;
}

static errno_t ipa_sudo_export_attr_name(TALLOC_CTX *mem,
                                         const char *ipa_name, 
                                         const char **sysdb_name)
{
    errno_t ret = EOK;

    // FIXME: use map or think through something smarter
    // FIXME: cover ilegal attribute case
    if (strncmp(ipa_name, "userCategory", strlen("userCategory")) == 0) {
        *sysdb_name = talloc_strdup(mem, "sudoUser");
    } else if (strncmp(ipa_name, "memberUser", strlen("memberUser")) == 0) {
        *sysdb_name = talloc_strdup(mem, "sudoUser");
    } else if (strncmp(ipa_name, "hostCategory", strlen("hostCategory")) == 0) {
        *sysdb_name = talloc_strdup(mem, "sudoHost");
    } else if (strncmp(ipa_name, "memberHost", strlen("memberHost")) == 0) {
        *sysdb_name = talloc_strdup(mem, "sudoHost");
    } else if (strncmp(ipa_name, "memberAllowCmd", strlen("memberAllowCmd")) == 0) {
        *sysdb_name = talloc_strdup(mem, "sudoCommand");
    } else if (strncmp(ipa_name, "memberDenyCmd", strlen("memberDenyCmd")) == 0) {
        *sysdb_name = talloc_strdup(mem, "sudoCommand");
    } else if (strncmp(ipa_name, "originalDN", strlen("memberHost")) == 0) {
        *sysdb_name = talloc_strdup(mem, "originalDN");
    } else {
        *sysdb_name = talloc_strdup(mem, ipa_name);
    }

    return ret;
}

void ipa_sudo_export_value(TALLOC_CTX *mem,
                            struct ipa_sudo_export *properties,
                            struct sysdb_ctx *sysdb,
                            const char **new_name,
                            const char **new_value)
{
    const char *exported_val;
    const char *exported_name;
    errno_t ret = EOK;
    
    switch (properties->type) {
        case DN:
            ret = get_third_rdn_value(mem, sysdb, orig_val, 
                                      properties, 
                                      &exported_val);
            ipa_sudo_export_attr_name(mem, 
                                      properties->orig_name, 
                                      &exported_name);
            break;
        case COMMAND:
            ret = get_member_cmd_value(mem, properties->orig_name, 
                                       properties->orig_value, 
                                       &exported_val);
    }

    if (ret != EOK) {

    }

    *new_name = 
}




static errno_t set_export_properties(TALLOC_CTX *mem, 
                                     struct sysdb_ctx *sysdb, 
                                     const char *name, 
                                     const char *value, 
                                     struct export_properties **new_prop)
{
    TALLOC_CTX *tmp = talloc_init(NULL);
    errno_t ret = EOK;
    char *tmp_value = NULL;
 
    if (strcasecmp(name, "originalDN") == 0 ||
            strcasecmp(name, "cn") == 0 ||
            strcasecmp(name, "sudoUser") == 0 ||
            strcasecmp(name, "sudoHost") == 0 ||
            strcasecmp(name, "sudoOption") == 0 ||
            strcasecmp(name, "ipaUniqueID") == 0
            ) {
        new_prop = NULL;
        return ret;
    }

    struct export_properties *prop = talloc_zero(tmp, struct export_properties);

    prop->first   = talloc_zero(tmp, struct rdn);
    prop->second  = talloc_zero(tmp, struct rdn);
    prop->third   = talloc_zero(tmp, struct rdn);
    prop->sing = '\0';

  
    if (strncmp(name, "memberHost", strlen("memberHost")) == 0) {

        /* fqdn=client.example.com,cn=computers,cn=accounts,dc=example,dc=com */
        if (strstr(value, "cn=computers") != NULL) {
            prop->first->attr = talloc_strdup(tmp, "fqdn");
            prop->first->val = NULL;

            prop->second->attr = talloc_strdup(tmp, "cn");
            prop->second->val = talloc_strdup(tmp, "computers");
        } 
        /* cn=clients,cn=hostgroups,cn=accounts,dc=example,dc=com */
        else if (strstr(value, "cn=hostgroups") != NULL) {
            prop->first->attr = talloc_strdup(tmp, "cn");
            prop->first->val = NULL;

            prop->second->attr = talloc_strdup(tmp, "cn");
            prop->second->val = talloc_strdup(tmp, "hostgroups");
            prop->sing = SUDO_HOSTGROUP_SING;
        }
        else {
            ret = ENOENT;
            goto fail;
        }
        
        prop->third->attr = talloc_strdup(tmp, "cn");
        prop->third->val = talloc_strdup(tmp, "accounts");
    }
    else if (strncmp(name, "memberUser", strlen("memberUser")) == 0) {

        /* uid=admin,cn=users,cn=accounts,dc=example,dc=cz */
        if (strstr(value, "cn=users") != NULL) {
            prop->first->attr = talloc_strdup(tmp, "uid");
            prop->first->val = NULL;      

            prop->second->attr = talloc_strdup(tmp, "cn");
            prop->second->val = talloc_strdup(tmp, "users");
        } 
        /* cn=ipausers,cn=groups,cn=accounts,dc=example,dc=com */
        else if (strstr(value, "cn=groups") != NULL) {
            prop->first->attr = talloc_strdup(tmp, "cn");
            prop->first->val = NULL;

            prop->second->attr = talloc_strdup(tmp, "cn");
            prop->second->val = talloc_strdup(tmp, "groups");
            prop->sing = SUDO_USER_GROUP_SING;
        }
        else {
            ret = ENOENT;
            goto fail;
        }
        
        prop->third->attr = talloc_strdup(tmp, "cn");
        prop->third->val = talloc_strdup(tmp, "accounts");
    }

    *new_prop = talloc_steal(mem, prop);

fail:
    talloc_free(tmp);
    return ret;

}


void ipa_sudo_export_attr_value(TALLOC_CTX *mem,
                            struct sysdb_ctx *sysdb,
                            struct export_properties *prop, 
                            const char *orig_val,
                            const char **exported_val)
{
    TALLOC_CTX *tmp = talloc_init(NULL);
    const char *val;

    switch (prop->type) {
        case DN:
            get_third_rdn_value(tmp, sysdb, orig_val, prop, &val);
            break;
        case COMMAND:
            printf("exporting cmd\n");
            break;
        case COPY:
            /* no need to export the value */
            val = orig_val;
            break;
        default:
            break;
            // FIXME: wrong type of the attribute
    }

    /* add sign */
    if (prop->sing != '\0') {
        val = talloc_asprintf_append_buffer(tmp, "%c%s", prop->sing, val);
    }
 
    *exported_val = talloc_steal(mem, val);
    talloc_free(tmp);
}

/* create new attr */
// FIXME: if it return ENOMEM -> 
        //DEBUG(SSSDBG_CRIT_FAILURE, ("talloc() failed\n"));
errno_t ipa_sudo_create_new_attr(TALLOC_CTX *mem, 
                                    struct sysdb_ctx *sysdb,
                                        struct ldb_message_element *ipa_el,
                                        const char *value_prefix,
                                        struct ldb_message_element **new_el)
{
    TALLOC_CTX *tmp = talloc_init(NULL);
    errno_t ret = EOK;
    int i;
    const char *new_name;
    const char *new_value;

    /* create new element */
    struct ldb_message_element *el;
    el = talloc_zero(tmp, struct ldb_message_element);
    if (el == NULL) {
        ret = ENOMEM;
        goto fail;
    }

    /* copy data for the new attribute */
    el->flags = ipa_el->flags;

    if (ipa_sudo_export_attr_name(tmp, ipa_el->name, &new_name) != EOK) {
        goto fail;
    }

    el->name = talloc_strndup(tmp, new_name, strlen(new_name));
    if (el->name == NULL) {
        ret = ENOMEM;
        goto fail;
    }

    /* create array of values */
    el->values = talloc_zero_array(tmp, struct ldb_val, el->num_values);
    if (el->values == NULL) {
        ret = ENOMEM;
        goto fail;
    }

    /* copy new values */
    for (i = 0; i < ipa_el->num_values; i++) {

        if (strcmp(ipa_el->name, "memberAllowCmd") == 0 ||
            strcmp(ipa_el->name, "memberDenyCmd") == 0) {

            el->values[i].data = (uint8_t *)talloc_strdup(tmp, "/usr/sbin/blkid");
            el->values[i].length = strlen("/usr/sbin/blkid");
            el->num_values++;

            continue;
        }

        /* set export properties based on name of the attribute */
        struct export_properties *prop = NULL;
        set_export_properties(tmp, sysdb, ipa_el->name, ipa_el->values[i].data, &prop);

        /* no need to export value of this attribute */
        if (prop == NULL) {
            new_value = ipa_el->values[i].data;
        } else {
            /* export value (uid=admin,cn=accounts,$DN --> admin) */
            ipa_sudo_export_attr_value(tmp, sysdb, prop, ipa_el->values[i].data, &new_value);
        }
 
        el->values[i].data = (uint8_t *)talloc_strdup(tmp, new_value);
        el->values[i].length = strlen(new_value);

        if (el->values[i].length == NULL || el->values[i].data == NULL) {
            ret = ENOMEM;
            goto fail;
        }

        el->num_values++;
    }

    *new_el = el;
    //*new_el = talloc_steal(mem, el);

fail:
    talloc_free(tmp);
    return ret;
}
#endif


