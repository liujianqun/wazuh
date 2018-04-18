#include "wmodules.h"
#include <sys/stat.h>
#include <pthread.h>
#include <time.h>
#include <sys/types.h>
#include <signal.h>
#include <stdio.h>

void *wm_osquery_monitor_main(wm_osquery_monitor_t *osquery_monitor);
void wm_osquery_monitor_destroy(wm_osquery_monitor_t *osquery_monitor);
pthread_mutex_t mutex1 = PTHREAD_MUTEX_INITIALIZER;
pthread_cond_t  active   = PTHREAD_COND_INITIALIZER;
int stopped;
int unlock = 0;

const wm_context WM_OSQUERYMONITOR_CONTEXT =
{
    "osquery-monitor",
    (wm_routine)wm_osquery_monitor_main,
    (wm_routine)wm_osquery_monitor_destroy
};

int get_inode (int fd)
{
    struct stat buf;
    int ret;
    ret = fstat(fd, &buf);
    if ( ret < 0 )
    {
        perror ("fstat");
        return -1;
    }
    return buf.st_ino;
}


void *Read_Log(wm_osquery_monitor_t *osquery_monitor)
{
    int i;
    int lenght;
    int queue_fd;
    int current_inode;
    int usec = 1000000 / wm_max_eps;
    char line[OS_MAXSTR];
    FILE *result_log = NULL;

    for (i = 0; queue_fd = StartMQ(DEFAULTQPATH, WRITE), queue_fd < 0 && i < WM_MAX_ATTEMPTS; i++)
    {
        //Trying to connect to queue
        sleep(WM_MAX_WAIT);
    }
    if (i == WM_MAX_ATTEMPTS)
    {
        mterror(WM_OSQUERYMONITOR_LOGTAG, "Can't connect to queue.");
        pthread_exit(NULL);
    }
    //Critical section
    // Lock mutex and then wait for signal to relase mutex

    pthread_mutex_lock( &mutex1 );

    while(!unlock)
    {
        pthread_cond_wait( &active, &mutex1 );
    }

    while(1)
    {
        for (i = 0; i < WM_MAX_ATTEMPTS && (result_log = fopen(osquery_monitor->log_path, "r"), !result_log); i++)
        {
            sleep(1);
        }
        if(!result_log)
        {
            mterror(WM_OSQUERYMONITOR_LOGTAG, "osQuery log has not been created or bad path");
            pthread_exit(NULL);
        }
        else
        {
            current_inode = get_inode(fileno(result_log));
            fseek(result_log, 0, SEEK_END);
            //Read the file
            while(1)
            {
                if(lenght = fgets(line, OS_MAXSTR, result_log), lenght)
                {
                    mdebug2("Sending... '%s'", line);
                    if (wm_sendmsg(usec, queue_fd, line, "osquery-monitor", LOCALFILE_MQ) < 0)
                    {
                        mterror(WM_OSQUERYMONITOR_LOGTAG, QUEUE_ERROR, DEFAULTQUEUE, strerror(errno));
                    }
                }
                else
                {
                    //check if result path inode has changed.
                    if(get_inode(fileno(result_log)) != current_inode)
                    {
                        for (i = 0; i < WM_MAX_ATTEMPTS && (result_log = fopen(osquery_monitor->log_path, "r"), !result_log); i++)
                        {
                            sleep(1);
                        }
                        if(!result_log)
                        {
                            mterror(WM_OSQUERYMONITOR_LOGTAG, "osQuery log has not been created");
                        }
                        else
                        {
                            current_inode = get_inode(fileno(result_log));
                        }
                    }

                    if(stopped)
                    {
                        pthread_mutex_unlock( &mutex1 );
                        pthread_exit(NULL);
                    }
                }
            }
            pthread_mutex_unlock( &mutex1 );
        }
    }
}

void *Execute_Osquery(wm_osquery_monitor_t *osquery_monitor)
{
    pthread_mutex_lock( &mutex1 );
    int down = 1;
    int daemon_pid = 0;
    int status;
    int pid;
    //We check that the osquery demon is not down, in which case we run it again.
    while(1)
    {
        if(down)
        {
            pid = fork();
            switch(pid)
            {
            case 0: //Child
                
                daemon_pid = getpid();
                if (execl(osquery_monitor->bin_path, "osqueryd", (char *)NULL) < 0)
                {
                    mterror(WM_OSQUERYMONITOR_LOGTAG, "cannot execute osquery daemon");
                }
                setsid();
                break;
            case -1: //ERROR
                mterror(WM_OSQUERYMONITOR_LOGTAG, "child has not been created");
            default:
                wm_append_sid(daemon_pid);
                switch (waitpid(daemon_pid, &status, WNOHANG))
                {
                case 0:               
                    //OSQUERY IS WORKING, wake up the other thread to read the log file
                    down = 0;
                    unlock = 1;
                    pthread_cond_signal( &active );
                    pthread_mutex_unlock( &mutex1 );
                    break;
                case -1:
                    if (errno == ECHILD)
                    {
                        down = 1;
                    }
                    // Finished. Bad Configuration
                    stopped = 1;
                    mterror(WM_OSQUERYMONITOR_LOGTAG, "Bad Configuration!");
                    pthread_exit(NULL);
                    break;
                }
            }
        }
        while(down==0)
        {
            //CHECK PERIODICALLY THE DAEMON STATUS
            int status;
            pid_t return_pid = waitpid(pid, &status, WNOHANG); /* WNOHANG def'd in wait.h */
            if (return_pid == -1) {
                if(errno == ECHILD)
                    down = 1;
            } else if (return_pid == 0) {
                if(errno==ECHILD)
                    down = 0;
            } else if (return_pid == daemon_pid) {
               down = 0;
            }
            sleep(1);
        }
        sleep(1);
    }
}

void wm_osquery_decorators(wm_osquery_monitor_t *osquery_monitor)
{
    char * LINE = strdup("");
    char * select=strdup("SELECT ");
    char * as = strdup(" AS ");
    char * key = NULL;
    char * value = NULL;
    char * coma = strdup(", ");
    char * osq_conf_file = strdup("/etc/osquery/osquery.conf");
    
    //PATH CREATION
    char * firstPath = strdup(DEFAULTDIR);
    char * lastpath = strdup("/etc/ossec.conf");
    char * configPath = NULL;
    configPath = malloc(strlen(firstPath)+strlen(lastpath));
    strcpy(configPath,firstPath);
    strcat(configPath,lastpath);
    char * json_block = NULL;

    //CJSON OBJECTS
    int i=0;
    cJSON *root;
    cJSON *decorators;
    cJSON *always;
    wlabel_t* labels;
    os_calloc(1, sizeof(wlabel_t), labels);
    ReadConfig(CLABELS, configPath, &labels, NULL);
    int len=0;
    root = cJSON_CreateObject();
    cJSON_AddItemToObject(root,"decorators",decorators = cJSON_CreateObject());
    cJSON_AddItemToObject(decorators,"always",always = cJSON_CreateArray());

    //OPEN OSQUERY CONF
    FILE * osquery_conf = NULL;
    osquery_conf = fopen(osq_conf_file,"r");
    struct stat stp = { 0 };  
    char *content;
    stat(osq_conf_file, &stp);
    int filesize = stp.st_size;
    content = (char *) malloc(sizeof(char) * filesize);
    json_block = cJSON_PrintUnformatted(root);
 
    if (fread(content, 1, filesize - 1, osquery_conf) == -1) {
        mterror(WM_OSQUERYMONITOR_LOGTAG,"error in reading");
        /**close the read file*/
        fclose(osquery_conf);
        //free input string
        free(content);
    }
        
    //CHECK IF CONF HAVE DECORATORS
    int decorated=0;
    if(strstr(content, "decorators")!=NULL)
        decorated = 1;
    else
        decorated = 0;

    //ADD DECORATORS FROM AGENT LABELS
    if(!decorated){
        
        for(i;labels[i].key!=NULL;i++){  
            key = strdup(labels[i].key);
            value = strdup(labels[i].value); 
            LINE = strdup(select);
            int newlen = sizeof(char)*(strlen(LINE)+strlen(key)+strlen(as)+strlen(value)+(6*sizeof(char)));
            LINE = (char*)realloc(LINE, newlen);
            strcat(LINE,"'");  
            strcat(LINE,key);
            strcat(LINE,"'");
            strcat(LINE,as);
            strcat(LINE,"'");
            strcat(LINE,value);
            strcat(LINE,"';");
            mdebug2("VALUE: %s",value);
            cJSON_AddStringToObject(always,"line",LINE);
        }
        
        json_block = cJSON_PrintUnformatted(root);
        content[strlen(content)-1]=',';
        content = realloc(content,sizeof(char)*(strlen(content)+strlen(json_block))); 
        strcat(content,json_block);
        


        fclose(osquery_conf);

        //Escribir contenido en el fichero
        osquery_conf = fopen("/var/ossec/tmp/osquery.conf.tmp","w");
        fprintf(osquery_conf,"%s}",content);
        fclose(osquery_conf);
    }

        //FREE MEMORY
         free(LINE);
         free(select);
         free(as);
         free(key);
         free(value);
         free(coma);
         free(firstPath);
         free(lastpath);
         free(configPath);
        free(root);
        free(json_block);
        cJSON_Delete(root);
}

void *wm_osquery_monitor_main(wm_osquery_monitor_t *osquery_monitor)
{
    wm_osquery_decorators(osquery_monitor);
    pthread_t thread1, thread2;
    pthread_create( &thread1, NULL, &Read_Log, osquery_monitor);
    pthread_create( &thread2, NULL, &Execute_Osquery, osquery_monitor);
    pthread_join( thread2, NULL);
    pthread_join( thread1, NULL);
}
void wm_osquery_monitor_destroy(wm_osquery_monitor_t *osquery_monitor)
{
    free(osquery_monitor);
}

