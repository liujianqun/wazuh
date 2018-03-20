/* Copyright (C) 2009 Trend Micro Inc.
 * All right reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include "shared.h"
#include "execd.h"

char ** wcom_ca_store;
int is_disabled;

/* Read the config file */
int ExecdConfig(const char *cfgfile)
{
    is_disabled = 0;

    const char *(xmlf[]) = {"ossec_config", "active-response", "disabled", NULL};
    const char *(blocks[]) = {"ossec_config", "active-response", "repeated_offenders", NULL};
    const char *(castore[]) = {"ossec_config", "active-response", "ca_store", NULL};
    char *disable_entry;
    char *repeated_t;
    char **repeated_a;
    int i;

    OS_XML xml;

    /* Read XML file */
    if (OS_ReadXML(cfgfile, &xml) < 0) {
        merror_exit(XML_ERROR, cfgfile, xml.err, xml.err_line);
    }

    /* We do not validate the xml in here. It is done by other processes. */
    disable_entry = OS_GetOneContentforElement(&xml, xmlf);
    if (disable_entry) {
        if (strcmp(disable_entry, "yes") == 0) {
            is_disabled = 1;
        } else if (strcmp(disable_entry, "no") == 0) {
            is_disabled = 0;
        } else {
            merror(XML_VALUEERR, "disabled", disable_entry);
            free(disable_entry);
            return (-1);
        }

        free(disable_entry);
    }

    repeated_t = OS_GetOneContentforElement(&xml, blocks);
    if (repeated_t) {
        int i = 0;
        int j = 0;
        repeated_a = OS_StrBreak(',', repeated_t, 5);
        if (!repeated_a) {
            merror(XML_VALUEERR, "repeated_offenders", repeated_t);
            free(repeated_t);
            return (-1);
        }

        while (repeated_a[i] != NULL) {
            char *tmpt = repeated_a[i];
            while (*tmpt != '\0') {
                if (*tmpt == ' ' || *tmpt == '\t') {
                    tmpt++;
                } else {
                    break;
                }
            }

            if (*tmpt == '\0') {
                i++;
                continue;
            }

            repeated_offenders_timeout[j] = atoi(tmpt);
            minfo("Adding offenders timeout: %d (for #%d)",
                    repeated_offenders_timeout[j], j + 1);
            j++;
            repeated_offenders_timeout[j] = 0;
            if (j >= 6) {
                break;
            }
            i++;
        }

        free(repeated_t);

        for (i = 0; repeated_a[i]; i++) {
            free(repeated_a[i]);
        }

        free(repeated_a);
    }

    if (wcom_ca_store = OS_GetContents(&xml, castore), wcom_ca_store) {
        for (i = 0; wcom_ca_store[i]; i++) {
            mdebug1("Added CA store '%s'.", wcom_ca_store[i]);
        }
    } else {
        mdebug1("No CA store defined.");
    }

    OS_ClearXML(&xml);

    return (is_disabled);
}


cJSON *getARConfig(void) {

    cJSON *root = cJSON_CreateObject();
    cJSON *ar = cJSON_CreateObject();
    unsigned int i;

    if (is_disabled) cJSON_AddStringToObject(ar,"disabled","yes"); else cJSON_AddStringToObject(ar,"disabled","no");
    if (wcom_ca_store) {
        cJSON *calist = cJSON_CreateArray();
        for (i=0;wcom_ca_store[i];i++) {
            cJSON_AddItemToArray(calist,cJSON_CreateString(wcom_ca_store[i]));
        }
        cJSON_AddItemToObject(ar,"ca_store",calist);
    }
    if (*repeated_offenders_timeout) {
        cJSON *rot = cJSON_CreateArray();
        for (i=0;repeated_offenders_timeout[i];i++) {
            cJSON_AddItemToArray(rot,cJSON_CreateNumber(repeated_offenders_timeout[i]));
        }
        cJSON_AddItemToObject(ar,"repeated_offenders",rot);
    }

    cJSON_AddItemToObject(root,"active-response",ar);

    return root;
}


cJSON *getExecdInternalOptions(void) {

    cJSON *root = cJSON_CreateObject();
    cJSON *internals = cJSON_CreateObject();

    cJSON_AddNumberToObject(internals,"execd.request_timeout",req_timeout);
    cJSON_AddNumberToObject(internals,"execd.max_restart_lock",max_restart_lock);
#ifdef WIN32
    cJSON_AddNumberToObject(internals,"agent.debug",debug_level);
    cJSON_AddNumberToObject(internals,"agent.warn_level",warn_level);
    cJSON_AddNumberToObject(internals,"agent.normal_level",normal_level);
    cJSON_AddNumberToObject(internals,"agent.tolerance",tolerance);
    cJSON_AddNumberToObject(internals,"agent.recv_timeout",timeout);
    cJSON_AddNumberToObject(internals,"agent.state_interval",interval);
    cJSON_AddNumberToObject(internals,"agent.min_eps",min_eps);
    cJSON_AddNumberToObject(internals,"agent.remote_conf",remote_conf);
    cJSON_AddNumberToObject(internals,"monitord.rotate_log",rotate_log);
    cJSON_AddNumberToObject(internals,"monitord.request_pool",request_pool);
    cJSON_AddNumberToObject(internals,"monitord.request_rto_sec",rto_sec);
    cJSON_AddNumberToObject(internals,"monitord.request_rto_msec",rto_msec);
    cJSON_AddNumberToObject(internals,"monitord.max_attempts",max_attempts);
    cJSON_AddNumberToObject(internals,"monitord.compress",log_compress);
    cJSON_AddNumberToObject(internals,"monitord.keep_log_days",keep_log_days);
    cJSON_AddNumberToObject(internals,"monitord.day_wait",day_wait);
    cJSON_AddNumberToObject(internals,"monitord.size_rotate",size_rotate_read);
    cJSON_AddNumberToObject(internals,"monitord.daily_rotations",daily_rotations);
    cJSON_AddNumberToObject(internals,"logcollector.remote_commands",accept_remote);
    cJSON_AddNumberToObject(internals,"logcollector.loop_timeout",loop_timeout);
    cJSON_AddNumberToObject(internals,"logcollector.open_attempts",open_file_attempts);
    cJSON_AddNumberToObject(internals,"logcollector.vcheck_files",vcheck_files);
    cJSON_AddNumberToObject(internals,"logcollector.max_lines",maximum_lines);
    cJSON_AddNumberToObject(internals,"logcollector.debug",debug_level);
    cJSON_AddNumberToObject(internals,"syscheck.sleep",syscheck.tsleep);
    cJSON_AddNumberToObject(internals,"syscheck.sleep_after",syscheck.sleep_after);
    cJSON_AddNumberToObject(internals,"syscheck.debug",debug_level);
    cJSON_AddNumberToObject(internals,"rootcheck.sleep",rootcheck.tsleep);
    cJSON_AddNumberToObject(internals,"wazuh_modules.task_nice",wm_task_nice);
    cJSON_AddNumberToObject(internals,"wazuh_modules.max_eps",wm_max_eps);
    cJSON_AddNumberToObject(internals,"wazuh_modules.kill_timeout",wm_kill_timeout);
    cJSON_AddNumberToObject(internals,"wazuh_modules.debug",wm_debug);
#endif
    cJSON_AddItemToObject(root,"internal_options",internals);

    return root;
}
