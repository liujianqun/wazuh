/*
 * Local Authd server
 * Copyright (C) 2017 Wazuh Inc.
 * May 20, 2017.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include <external/cJSON/cJSON.h>
#include <pthread.h>
#include <sys/wait.h>
#include "auth.h"

#define EINTERNAL   0
#define EJSON       1
#define ENOFUNCTION 2
#define ENOARGUMENT 3
#define ENONAME     4
#define ENOIP       5
#define EDUPIP      6
#define EDUPNAME    7
#define EKEY        8
#define ENOID       9
#define ENOAGENT    10
#define EDUPID      11
#define EAGLIM      12

static const struct {
    int code;
    char *message;
} ERRORS[] = {
    { 9001, "Internal error" },
    { 9002, "Parsing JSON input" },
    { 9003, "No such function" },
    { 9004, "No such argument" },
    { 9005, "No such name" },
    { 9006, "No such IP" },
    { 9007, "Duplicated IP" },
    { 9008, "Duplicated name" },
    { 9009, "Issue generating key" },
    { 9010, "No such agent ID" },
    { 9011, "Agent ID not found" },
    { 9012, "Duplicated ID" },
    { 9013, "Maximum number of agents reached" }
};

// Dispatch local request
static char* local_dispatch(const char *input);

// Add a new agent
static cJSON* local_add(const char *id, const char *name, const char *ip, const char *key, int force);

// Remove an agent
static cJSON* local_remove(const char *id, int purge);

// Get agent data
static cJSON* local_get(const char *id);

// Thread for internal server
void* run_local_server(__attribute__((unused)) void *arg) {
    int sock;
    int peer;
    char buffer[OS_MAXSTR + 1];
    char *response;
    ssize_t length;
    fd_set fdset;
    struct timeval timeout;

    authd_sigblock();

    mdebug1("Local server thread ready.");

    if (sock = OS_BindUnixDomain(AUTH_LOCAL_SOCK, SOCK_STREAM, OS_MAXSTR), sock < 0) {
        merror("Unable to bind to socket '%s'. Closing local server.", AUTH_LOCAL_SOCK);
        return NULL;
    }

    while (running) {

        // Wait for socket
        FD_ZERO(&fdset);
        FD_SET(sock, &fdset);
        timeout.tv_sec = 1;
        timeout.tv_usec = 0;

        switch (select(sock + 1, &fdset, NULL, NULL, &timeout)) {
        case -1:
            if (errno != EINTR) {
                merror_exit("at run_local_server(): select(): %s", strerror(errno));
            }

            continue;

        case 0:
            continue;
        }

        if (peer = accept(sock, NULL, NULL), peer < 0) {
            if ((errno == EBADF && running) || (errno != EBADF && errno != EINTR)) {
                merror("at run_local_server(): accept(): %s", strerror(errno));
            }

            continue;
        }

        switch (length = recv(peer, buffer, OS_MAXSTR, 0), length) {
        case -1:
            merror("recv(): %s", strerror(errno));
            break;

        case 0:
            mdebug1("Empty message from local client.");
            close(peer);
            break;

        default:
            buffer[length] = '\0';

            if (response = local_dispatch(buffer), response) {
                send(peer, response, strlen(response), 0);
                free(response);
            }

            close(peer);
        }
    }

    mdebug1("Local server thread finished");

    close(sock);
    return NULL;
}

// Dispatch local request
char* local_dispatch(const char *input) {
    cJSON *request;
    cJSON *function;
    cJSON *arguments;
    cJSON *response = NULL;
    char *output = NULL;
    int ierror;

    if (request = cJSON_Parse(input), !request) {
        ierror = EJSON;
        goto fail;
    }

    if (function = cJSON_GetObjectItem(request, "function"), !function) {
        ierror = ENOFUNCTION;
        goto fail;
    }

    if (!strcmp(function->valuestring, "add")) {
        cJSON *item;
        char *id;
        char *name;
        char *ip;
        char *key = NULL;
        int force = 0;

        if (arguments = cJSON_GetObjectItem(request, "arguments"), !arguments) {
            ierror = ENOARGUMENT;
            goto fail;
        }

        id = (item = cJSON_GetObjectItem(arguments, "id"), item) ? item->valuestring : NULL;

        if (item = cJSON_GetObjectItem(arguments, "name"), !item) {
            ierror = ENONAME;
            goto fail;
        }

        name = item->valuestring;

        if (item = cJSON_GetObjectItem(arguments, "ip"), !item) {
            ierror = ENOIP;
            goto fail;
        }

        ip = item->valuestring;
        key = (item = cJSON_GetObjectItem(arguments, "key"), item) ? item->valuestring : NULL;
        force = (item = cJSON_GetObjectItem(arguments, "force"), item) ? item->valueint : -1;
        response = local_add(id, name, ip, key, force);
    } else if (!strcmp(function->valuestring, "remove")) {
        cJSON *item;
        int purge;

        if (arguments = cJSON_GetObjectItem(request, "arguments"), !arguments) {
            ierror = ENOARGUMENT;
            goto fail;
        }

        if (item = cJSON_GetObjectItem(arguments, "id"), !item) {
            ierror = ENOID;
            goto fail;
        }

        purge = cJSON_IsTrue(cJSON_GetObjectItem(arguments, "purge"));
        response = local_remove(item->valuestring, purge);
    } else if (!strcmp(function->valuestring, "get")) {
        cJSON *item;

        if (arguments = cJSON_GetObjectItem(request, "arguments"), !arguments) {
            ierror = ENOARGUMENT;
            goto fail;
        }

        if (item = cJSON_GetObjectItem(arguments, "id"), !item) {
            ierror = ENOID;
            goto fail;
        }

        response = local_get(item->valuestring);
    }

    if (!response) {
        merror("at local_dispatch(): response is null.");
        ierror = EINTERNAL;
        goto fail;
    }

    if (response) {
        output = cJSON_PrintUnformatted(response);
        cJSON_Delete(response);
    }

    cJSON_Delete(request);
    return output;

fail:
    merror("ERROR %d: %s.", ERRORS[ierror].code, ERRORS[ierror].message);
    response = cJSON_CreateObject();
    cJSON_AddNumberToObject(response, "error", ERRORS[ierror].code);
    cJSON_AddStringToObject(response, "message", ERRORS[ierror].message);
    output = cJSON_PrintUnformatted(response);
    cJSON_Delete(response);
    cJSON_Delete(request);
    return output;
}

cJSON* local_add(const char *id, const char *name, const char *ip, const char *key, int force) {
    int index;
    char *id_exist;
    cJSON *response;
    cJSON *data;
    int ierror;
    double antiquity;

    mdebug2("add(%s)", name);
    pthread_mutex_lock(&mutex_keys);

    // Check for duplicated ID

    if (id && OS_IsAllowedID(&keys, id) >= 0) {
        ierror = EDUPID;
        goto fail;
    }

    /* Check for duplicated IP */

    if (strcmp(ip, "any")) {
        if (index = OS_IsAllowedIP(&keys, ip), index >= 0) {
            if (force >= 0 && (antiquity = OS_AgentAntiquity(keys.keyentries[index]->name, keys.keyentries[index]->ip->ip), antiquity >= force || antiquity < 0)) {
                id_exist = keys.keyentries[index]->id;
                minfo("Duplicated IP '%s' (%s). Saving backup.", ip, id_exist);
                add_backup(keys.keyentries[index]);
                OS_DeleteKey(&keys, id_exist, 0);
            } else {
                ierror = EDUPIP;
                goto fail;
            }
        }
    }

    /* Check whether the agent name is the same as the manager */

    if (!strcmp(name, shost)) {
        ierror = EDUPNAME;
        goto fail;
    }

    /* Check for duplicated names */

    if (index = OS_IsAllowedName(&keys, name), index >= 0) {
        if (force >= 0 && (antiquity = OS_AgentAntiquity(keys.keyentries[index]->name, keys.keyentries[index]->ip->ip), antiquity >= force || antiquity < 0)) {
            id_exist = keys.keyentries[index]->id;
            minfo("Duplicated name '%s' (%s). Saving backup.", name, id_exist);
            add_backup(keys.keyentries[index]);
            OS_DeleteKey(&keys, id_exist, 0);
        } else {
            ierror = EDUPNAME;
            goto fail;
        }
    }

    /* Check for agents limit */

    if (config.flags.register_limit && keys.keysize >= (MAX_AGENTS - 2) ) {
        ierror = EAGLIM;
        goto fail;
    }

    if (index = OS_AddNewAgent(&keys, id, name, ip, key), index < 0) {
        ierror = EKEY;
        goto fail;
    }

    /* Add pending key to write */
    add_insert(keys.keyentries[index],NULL);
    write_pending = 1;
    pthread_cond_signal(&cond_pending);

    response = cJSON_CreateObject();
    cJSON_AddNumberToObject(response, "error", 0);
    cJSON_AddItemToObject(response, "data", data = cJSON_CreateObject());
    cJSON_AddStringToObject(data, "id", keys.keyentries[index]->id);
    cJSON_AddStringToObject(data, "name", name);
    cJSON_AddStringToObject(data, "ip", ip);
    cJSON_AddStringToObject(data, "key", keys.keyentries[index]->key);
    pthread_mutex_unlock(&mutex_keys);

    minfo("Agent key generated for agent '%s' (requested locally)", name);
    return response;

fail:
    pthread_mutex_unlock(&mutex_keys);
    merror("ERROR %d: %s.", ERRORS[ierror].code, ERRORS[ierror].message);
    response = cJSON_CreateObject();
    cJSON_AddNumberToObject(response, "error", ERRORS[ierror].code);
    cJSON_AddStringToObject(response, "message", ERRORS[ierror].message);
    return response;
}

// Remove an agent
cJSON* local_remove(const char *id, int purge) {
    int index;
    cJSON *response = cJSON_CreateObject();

    mdebug2("local_remove(id='%s', purge=%d)", id, purge);

    pthread_mutex_lock(&mutex_keys);

    if (index = OS_IsAllowedID(&keys, id), index < 0) {
        merror("ERROR %d: %s.", ERRORS[ENOAGENT].code, ERRORS[ENOAGENT].message);
        cJSON_AddNumberToObject(response, "error", ERRORS[ENOAGENT].code);
        cJSON_AddStringToObject(response, "message", ERRORS[ENOAGENT].message);
    } else {
        minfo("Agent '%s' (%s) deleted (requested locally)", id, keys.keyentries[index]->name);
        /* Add pending key to write */
        add_remove(keys.keyentries[index]);
        OS_DeleteKey(&keys, id, purge);
        write_pending = 1;
        pthread_cond_signal(&cond_pending);

        cJSON_AddNumberToObject(response, "error", 0);
        cJSON_AddStringToObject(response, "data", "Agent deleted successfully.");
    }

    pthread_mutex_unlock(&mutex_keys);
    return response;
}

// Get agent data
cJSON* local_get(const char *id) {
    int index;
    cJSON *data;
    cJSON *response = cJSON_CreateObject();

    mdebug2("local_get(%s)", id);
    pthread_mutex_lock(&mutex_keys);

    if (index = OS_IsAllowedID(&keys, id), index < 0) {
        merror("ERROR %d: %s.", ERRORS[ENOAGENT].code, ERRORS[ENOAGENT].message);
        cJSON_AddNumberToObject(response, "error", ERRORS[ENOAGENT].code);
        cJSON_AddStringToObject(response, "message", ERRORS[ENOAGENT].message);
    } else {
        cJSON_AddNumberToObject(response, "error", 0);
        cJSON_AddItemToObject(response, "data", data = cJSON_CreateObject());
        cJSON_AddStringToObject(data, "id", id);
        cJSON_AddStringToObject(data, "name", keys.keyentries[index]->name);
        cJSON_AddStringToObject(data, "ip", keys.keyentries[index]->ip->ip);
        cJSON_AddStringToObject(data, "key", keys.keyentries[index]->key);
    }

    pthread_mutex_unlock(&mutex_keys);
    return response;
}
