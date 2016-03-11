/*
 * Copyright (c) 2012 Bruce Geng <gengw2000[at]163[dot]com>.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 * notice, this list of conditions and the following disclaimer in the
 * documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <syslog.h>
#include <getopt.h>
#include <time.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#ifdef  _ENABLE_THREADS
#include <pthread.h>
#endif
#include <errno.h>
#include "pcap.h"

#pragma pack(1)

#include "config.h"
#include "main.h"

typedef struct
{
    unsigned short ar_hrd;      	/* format of hardware address	*/
    unsigned short ar_pro;      	/* format of protocol address	*/
    unsigned char ar_hln;       	/* length of hardware address	*/
    unsigned char ar_pln;       	/* length of protocol address	*/
    unsigned short ar_op;       	/* ARP opcode (command)		*/
    unsigned char ar_sha[ETH_ALEN]; 	/* sender hardware address	*/
    unsigned int ar_sip;            	/* sender IP address		*/
    unsigned char ar_tha[ETH_ALEN]; 	/* target hardware address	*/
    unsigned int ar_tip;            	/* target IP address		*/
}ARPHDR;

typedef struct
{
    ETHHDR ethhdr;
    ARPHDR arphdr;
}ARPPACKET;

struct pm_cfg cfg;  /* program-wide settings, initialized in init() */

#ifdef  _ENABLE_THREADS
pthread_mutex_t mutex1 = PTHREAD_MUTEX_INITIALIZER;
#endif

int loadCfg(const char *fpath)
{
    FILE* fp = fopen(fpath, "r");
    char  sline[LINEBUF_MAX];

    if (fp == NULL)
    {
        return -1;
    }
    memset(sline, 0, sizeof(sline));
    while (fgets(sline, sizeof(sline), fp) != NULL) {
        char option[OPTION_MAX] = {0};
        char value[OPTION_MAX]  = {0};
        if (sline[0] == '#' || sline[0] == '\0')
        {
            continue;
        }
        if (getUCIConf(sline, option, value) == 0)
        {
            if (strcmp(option, "target") == 0)
            {
                cfg.dst_ip = inet_addr(value);
                if (cfg.dst_ip != INADDR_NONE)
                {
                    cfg.flags |= PM_DST_IP;
                }
                else
                {
                    snprintf(cfg.dst_if, IFNAMSIZ, "%s", value);
                    cfg.flags |= PM_DST_IF;
                }
            }
            else if (strcmp(option, "source_ports") == 0)
            {
                char* token = strtok(value, ",");
                while (token != NULL) {
                    snprintf(cfg.src[cfg.src_count++], IFNAMSIZ, "%s", token);
                    token = strtok(NULL, ",");
                }
            }
            else if (strcmp(option, "filter") == 0)
            {
                snprintf(cfg.pfe, PFE_MAX, "%s", value);
            }
            else if (strcmp(option, "promiscuous") == 0)
            {
                if (atoi(value) == 1)
                {
                    cfg.flags |= PM_PROMISC;
                }
            }
            else if (strcmp(option, "protocol") == 0)
            {
                if (strcasecmp(value, "TZSP") == 0)
                {
                    cfg.flags |= PM_TZSP;
                }
            }
        }
        memset(sline, 0, sizeof(sline));
    }

    fclose(fp);
    return 0;
}

/*
 * Initialize program-wide configuration settings 
 */
int init()
{
    cfg.cfg_file = calloc(PATH_MAX, sizeof(char));
    if (cfg.cfg_file == NULL)
    {
        syslog(LOG_ERR, "unable to allocate memory for configuration path");
        return -1;
    }
    cfg.flags = 0x00;
    memset(cfg.dst_if, 0, IFNAMSIZ);
    cfg.dst_ip = INADDR_NONE;
    memset(cfg.pfe, 0, PFE_MAX);
    cfg.pid_file = calloc(PATH_MAX, sizeof(char));
    if (cfg.pid_file == NULL)
    {
        syslog(LOG_ERR, "unable to allocate memory for process id path");
        return -1;
    }
    snprintf(cfg.pid_file, PATH_MAX, "%s", PID_PATH);
    cfg.src_count = 0;
    memset(cfg.src_mac, 0, MACADDRLEN);
    memset(cfg.dst_mac, 0, MACADDRLEN);
    cfg.packet_count = 0;

    return 0;
}

int reopenSendHandle(const char* device, pcap_t *handle)
{
    char errbuf[PCAP_ERRBUF_SIZE] = {0};
    if (handle != NULL)
    {
        syslog(LOG_DEBUG, "re-opening target device '%s'", cfg.dst_if);
        pcap_close(handle);
    }
    handle = pcap_open_live(device, SNAP_LEN, 0, 100, errbuf);
    if (handle == NULL)
    {
        syslog(LOG_ERR, "could not open target device '%s': %s", cfg.dst_if, errbuf);
        return -1;
    }
    else
    {
        syslog(LOG_DEBUG, "re-opened target device '%s'", device);
    }
    return 0;
}

int getRemoteARP(unsigned int targetIP, const char *device, char *mac)
{
    unsigned int        localIP;
    char                errbuf[PCAP_ERRBUF_SIZE] = {0};
    ARPPACKET           arp;
    struct bpf_program  fp;
    struct pcap_pkthdr  *header;
    const u_char        *pkt_data;
    int                 sent        = 0;
    int                 found       = 1;
    char                filter[100] = {0};
    struct in_addr      addr;
    pcap_t              *pHandle = pcap_open_live(device, SNAP_LEN, 0, ARP_WAIT_TIME, errbuf);

    if (pHandle == NULL)
    {
        syslog(LOG_ERR, "unable to open capture device %s: %s", device, errbuf);
        return -1;
    }
    if (getInterfaceIP(device, &localIP) < 0)
    {
        syslog(LOG_ERR, "unable to get IP address for %s", device);
        pcap_close(pHandle);
        return -1;
    }
    //send arp request to an IP.
    memset(&arp, 0, sizeof(arp));
    memset(arp.ethhdr.h_dest, 0xFF, ETH_ALEN);
    arp.ethhdr.h_proto = htons(ETH_P_ARP);
    arp.arphdr.ar_hrd  = htons(ETH_P_802_3);
    arp.arphdr.ar_pro  = htons(ETH_P_IP);
    arp.arphdr.ar_hln  = ETH_ALEN;              // Hardware size: 6(0x06)
    arp.arphdr.ar_pln  = 4;                     // Protocol size; 4
    arp.arphdr.ar_op   = htons(ARPOP_REQUEST);  // Opcode: request (0x0001)
    memset(arp.arphdr.ar_tha, 0, ETH_ALEN);
    arp.arphdr.ar_tip = targetIP;
    memcpy(arp.ethhdr.h_source, cfg.src_mac, ETH_ALEN);
    memcpy(arp.arphdr.ar_sha, cfg.src_mac, ETH_ALEN);
    arp.arphdr.ar_sip = localIP;

    addr.s_addr = targetIP;
    sprintf(filter, "arp host %s", inet_ntoa(addr));
    pcap_compile(pHandle, &fp, filter, 0, 0);
    pcap_setfilter(pHandle, &fp);

    pcap_sendpacket(pHandle, (unsigned char *)&arp, sizeof(arp));

    while (1) {
        int res = pcap_next_ex(pHandle, &header, &pkt_data);
        if (res == 1)
        {
            if (*(unsigned short *)(pkt_data + 12) == htons(0x0806) &&
                header->len >= sizeof(ARPPACKET))
            {
                ARPPACKET* p = (ARPPACKET *)pkt_data;
                if (p->arphdr.ar_op == htons(ARPOP_REPLY) && p->arphdr.ar_sip == targetIP)
                {
                    memcpy(mac, (const char *)p->ethhdr.h_source, ETH_ALEN);
                    found = 0;
                    if (cfg.flags & PM_DEBUG)
                    {
                        syslog(LOG_INFO, "ARP reply on '%s'['%s'] filter '%s'",
                                 device,
                                 printMACStr(mac),
                                 filter);
                    }
                    break;
                }
            }
        }
        if (res == 0)
        {
            if (sent++ < 2)
            {
                pcap_sendpacket(pHandle, (unsigned char *)&arp, sizeof(arp));
            }
            else
            {
                break;
            }
        }
        if (res == -1)
        {
            syslog(LOG_ERR, "error reading packet: %s", pcap_geterr(pHandle));
            break;
        }
    }
    pcap_close(pHandle);

    return found;
}

int initSendHandle(pcap_t *handle, int *sock)
{
    time(&cfg.init_time);

    if (cfg.flags & PM_DST_IF)
    {
        reopenSendHandle(cfg.dst_if, handle);
    }

    if (cfg.flags & PM_DST_IP)
    {
        if (cfg.flags & PM_TZSP)
        {
            /* TZSP format */
            int sendBufSize = SNAP_LEN;
            *sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
            if (*sock == -1)
            {
                syslog(LOG_ERR, "unable to create socket: '%s'", strerror(errno));
                return -1;
            }
            if (setsockopt(*sock, SOL_SOCKET, SO_SNDBUF, (char *)&sendBufSize, sizeof(sendBufSize)))
            {
                syslog(LOG_ERR, "unable to set socket options: '%s'", strerror(errno));
                return -1;
            }
        }

        if (!(cfg.flags & PM_TZSP))
        {
            /* TEE format */
            char device[IF_NAMESIZE] = {0};
            if (getSenderInterface(cfg.dst_ip, device, cfg.src_mac) == 0)
            {
                if (getRemoteARP(cfg.dst_ip, device, cfg.dst_mac) == 0)
                {
                    reopenSendHandle(device, handle);
                }
                else
                {
                    syslog(LOG_ERR, "unable to get MAC for destination IP address");
                    return -1;
                }
            }
            else
            {
                syslog(LOG_ERR, "unable to get sender interface for destination IP address");
                return -1;
            }
        }
    }

    return 0;
}

void packet_handler_ex(const struct pcap_pkthdr* header, const u_char* pkt_data,
                        pcap_t *handle, int *sock)
{
    static uint8_t buf[2048];

    if (header->len <= 2 * MACADDRLEN)
    {
        return;
    }
    #ifdef  _ENABLE_THREADS
    pthread_mutex_lock(&mutex1);
    #endif

    if (cfg.flags & PM_DST_IF)
    {
        if (handle == NULL || pcap_sendpacket(handle, pkt_data, header->len) != 0)
        {
            //error detected
            long nowTime;
            time(&nowTime);
            if (nowTime - cfg.init_time > ERRTIMEOUT && header->len < 1500)
            {
                if (cfg.flags & PM_DEBUG)
                {
                    if (handle != NULL)
                    {
                        syslog(LOG_ERR, "error sending packet: '%s'", pcap_geterr(handle));
                    }
                    else
                    {
                        syslog(LOG_ERR, "sendHandle is NULL");
                    }
                }
                initSendHandle(handle, sock);
            }
        }
    }
    else if (!(cfg.flags & PM_TZSP))
    {
        //TEE
        if (memcmp(pkt_data, cfg.dst_mac, MACADDRLEN))
        {
            memcpy(buf, cfg.dst_mac, MACADDRLEN);
            memcpy(buf + MACADDRLEN, cfg.src_mac, MACADDRLEN);
            memcpy(buf + 2 * MACADDRLEN, pkt_data + 2 * MACADDRLEN, header->len - 2 * MACADDRLEN);
            if (handle == NULL || pcap_sendpacket(handle, buf, header->len) != 0)
            {
                //error detected
                long nowTime;
                time(&nowTime);
                if (nowTime - cfg.init_time > ERRTIMEOUT && header->len < 1500)
                {
                    if (cfg.flags & PM_DEBUG)
                    {
                        if (handle != NULL)
                        {
                            syslog(LOG_ERR, "unable to send TEE packet: '%s'", pcap_geterr(handle));
                        }
                        else
                        {
                            syslog(LOG_ERR, "handle is null");
                        }
                    }
                    initSendHandle(handle, sock);
                }
            }
        }
        else
        {
            //ignore packets sent to the remote mac address
        }
    }
    else if (cfg.flags & PM_TZSP)
    {
        //TSZP
        if (header->len > 14 + sizeof(IP_HEADER))
        {
            IP_HEADER* pIPHead = NULL;
            if (*(unsigned short *)(pkt_data + 12) == htons(0x0800))
            {
                pIPHead = (IP_HEADER *)(pkt_data + 14);
            }
            else if (*(unsigned short *)(pkt_data + 12) == htons(0x8100))
            {
                pIPHead = (IP_HEADER *)(pkt_data + 18);
            }
            else
            {
                #ifdef  _ENABLE_THREADS
                pthread_mutex_unlock(&mutex1);
                #endif
                return;
            }
            if (pIPHead != NULL && pIPHead->destIP == cfg.dst_ip && pIPHead->proto == IPPROTO_UDP)
            {
                UDP_HEADER* pUDPHead = (UDP_HEADER * )((u_char *)pIPHead + sizeof(unsigned long) * (pIPHead->h_lenver & 0xf));
                //printf("iphlen=[%d], dport=[%u], TSZP=[%u].\n", sizeof(unsigned long) * ( pIPHead->h_lenver & 0xf), pUDPHead->uh_dport, htons(TZSP_PORT));
                if (pUDPHead->uh_dport == htons(TZSP_PORT))
                {
                    //printf("TZSP ignored.\n");
                    #ifdef  _ENABLE_THREADS
                    pthread_mutex_unlock(&mutex1);
                    #endif
                    return;
                }
            }
            if (*sock != -1)
            {
                TZSP_HEAD* pHead = (TZSP_HEAD *)buf;
                int        dataLen;

                struct sockaddr_in sa;
                sa.sin_family      = AF_INET;
                sa.sin_port        = htons(TZSP_PORT);
                sa.sin_addr.s_addr = cfg.dst_ip;

                pHead->ver    = 0x01;
                pHead->type   = 0x00;
                pHead->proto  = htons(0x01);
                pHead->tagend = 0x01;
                if (header->len < sizeof(buf) - sizeof(TZSP_HEAD))
                {
                    dataLen = header->len;
                }
                else
                {
                    dataLen = sizeof(buf) - sizeof(TZSP_HEAD);
                }
                if (dataLen > 0)
                {
                    memcpy(buf + sizeof(TZSP_HEAD), pkt_data, dataLen);
                    while (sendto(*sock, buf, dataLen + sizeof(TZSP_HEAD), 0, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
                        if (errno == EINTR || errno == EWOULDBLOCK)
                        {
                            //printf("packet_handler_ex, send failed, ERRNO is EINTR or EWOULDBLOCK.\n");
                        }
                        else
                        {
                            //printf("packet_handler_ex, send failed.\n");
                            break;
                        }
                    }
                }
            }
        }
    }
    #ifdef  _ENABLE_THREADS
    pthread_mutex_unlock(&mutex1);
    #endif

    cfg.packet_count++;
}

void * start_mirroring(void *dev, int *sock)
{
    pcap_t*             handle;                   /* Session handle */
    char                errbuf[PCAP_ERRBUF_SIZE]; /* Error string */
    struct bpf_program  fp;                       /* The compiled filter expression */
    int                 res = 0;
    struct pcap_pkthdr* header;
    const u_char*       pkt_data;

#ifdef  _ENABLE_THREADS
    sigset_t mask;
    sigaddset(&mask, SIGINT);
    sigaddset(&mask, SIGTERM);
    pthread_sigmask(SIG_BLOCK, &mask, NULL);
#endif

start_handle:
    handle = pcap_open_live((const char *)dev, SNAP_LEN, cfg.flags & PM_PROMISC, 100, errbuf);
    if (handle == NULL)
    {
        syslog(LOG_ERR, "unable to open target device '%s': %s", (const char *) dev, errbuf);
        return NULL;
    }

    if (cfg.pfe[0] != '\0')
    {
        if (pcap_compile(handle, &fp, cfg.pfe, 0, 0) == -1)
        {
            syslog(LOG_ERR, "unable to parse filter '%s': '%s'", cfg.pfe, pcap_geterr(handle));
            pcap_close(handle);
            return NULL;
        }
        if (pcap_setfilter(handle, &fp) == -1)
        {
            syslog(LOG_ERR, "unable to set filter '%s': '%s'", cfg.pfe, pcap_geterr(handle));
            pcap_close(handle);
            return NULL;
        }
    }
    //start the capture
    while (handle != NULL) {
        res = pcap_next_ex(handle, &header, &pkt_data);
        if (res > 0)
        {
            packet_handler_ex(header, pkt_data, handle, sock);
        }
        else if (res == 0)              // Timeout elapsed
        {
            continue;
        }
        else
        {
            break;
        }
    }
    if (res == -1 && handle != NULL)
    {
        syslog(LOG_ERR, "unable to read packets from '%s': '%s'", (const char *)dev, pcap_geterr(handle));
        pcap_close(handle);
        sleep(ERRTIMEOUT);
        syslog(LOG_INFO, "re-open device '%s'", (const char *)dev);
        goto start_handle;
    }
    return NULL;
}

int fork_daemon()
{
    /* Our process ID and Session ID */
    pid_t pid, sid;

    /* Fork off the parent process */
    pid = fork();
    if (pid == -1)
    {
        syslog(LOG_ERR, "unable to fork child process: '%s'", strerror(errno));
        return -1;
    }

    /* If we got a good PID, then we can exit the parent process. */
    if (pid > 0)
    {
        syslog(LOG_DEBUG, "forked parent process with pid: %d", pid);
        exit(EXIT_SUCCESS);
    }

    /* Change the file mode mask */
    umask(0);

    /* Create a new SID for the child process */
    sid = setsid();
    if (sid < 0)
    {
        syslog(LOG_ERR, "unable to create new SID: '%s'", strerror(errno));
        return -1;
    }
    /* Change the current working directory */
    if ((chdir("/")) < 0) {
        /* Log the failure */
        exit(EXIT_FAILURE);
    }

    /* Close out the standard file descriptors */
    close(STDIN_FILENO);
    close(STDOUT_FILENO);
    close(STDERR_FILENO);
    return 0;
}

void sig_handler(int signum)
{
    if (cfg.flags & PM_DEBUG)
    {
        fprintf(stderr, "signal captured, pid_file=[%s],signum=[%d].\n", 
            cfg.pid_file, signum);
    }
    syslog(LOG_DEBUG, "received signal %d", signum);
    if ((cfg.flags & PM_DAEMON) && cfg.pid_file[0] != '\0')
    {
        unlink(cfg.pid_file);
    }
    syslog(LOG_INFO, "program exiting: %d packets mirrored", cfg.packet_count);
    closelog();
    exit(1);
}

int main(int argc, char *argv[])
{
    // start logging at the INFO level 
    openlog(LOG_IDENT, LOG_CONS || LOG_PID, LOG_DAEMON);
    setlogmask(LOG_UPTO(LOG_INFO));
    syslog(LOG_INFO, "%s starting", LOG_IDENT);

    // initialize program-wide configuration settings
    if (init() != 0)
    {
        syslog(LOG_ERR, "unable to initialize settings, exiting");
        return -1;
    }
    
    // log command-line arguments
    int i; 
    for (i = 1; i < argc; i++)
    {
        syslog(LOG_INFO, "command-line argument[%d]: %s", i, argv[i]);
    }

    // parse command-line arguments
    int c = 0, option_index = 0;
    static struct option long_options[] = {
        {"config", required_argument, 0, 'c'},
        {"pid", required_argument, 0, 'p'},
        {"daemon", no_argument, 0, 'b'},
        {"debug", no_argument, 0, 'd' },
        {NULL, 0, NULL, 0}
    };
    while ((c = getopt_long(argc, argv, "c:p:bd",
                            long_options, &option_index)) != -1) {
        switch (c)
        {
            case 'c':
                if (optarg)
                {
                    snprintf(cfg.cfg_file, PATH_MAX, "%s", optarg);
                }
                break;
            case 'p':
                if (optarg)
                {
                    snprintf(cfg.pid_file, PATH_MAX, "%s", optarg);
                    syslog(LOG_INFO, "process pid file %s selected", cfg.pid_file); 
                }
                break;
            case 'b':
                cfg.flags |= PM_DAEMON;
                syslog(LOG_INFO, "background process mode selected"); 
                break;
            case 'd':
                cfg.flags |= PM_DEBUG;
                setlogmask(LOG_UPTO(LOG_DEBUG));
                syslog(LOG_INFO, "debugging mode selected");
                break;
            default:
                break;
        }
    }

    // locate the configuration file to use  
    find_cfg(&cfg);
    if (cfg.cfg_file == NULL)
    {
        syslog(LOG_ERR, "could not locate a configuration file, exiting");
        return -1;
    }

    // read and parse the configuration file 
    if (loadCfg(cfg.cfg_file) == 0)
    {
        syslog(LOG_INFO, "successfully read config file '%s'", cfg.cfg_file);
        free(cfg.cfg_file);
    } 
    else
    {
        syslog(LOG_ERR, "unable to read config file '%s', exiting", cfg.cfg_file);
        return -1;
    }

    // run as a background process if selected 
    if ((cfg.flags & PM_DAEMON) && (fork_daemon() != 0))
    {
        syslog(LOG_ERR, "unable to run as a background process, exiting");
        return -1;
    }

    // create the process id file
    if (cfg.flags & PM_DAEMON)
    {
        FILE* fp = fopen(cfg.pid_file, "w");
        if (fp != NULL)
        {
            fprintf(fp, "%d\n", getpid());
            syslog(LOG_INFO, "using process id %d", getpid());
            fclose(fp);
        }
    }

    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    for (i = 0; i < cfg.src_count; i++)
    {
        syslog(LOG_INFO, "settings: src=%s dst=%s proto=%s promisc=%s filter='%s'",
                cfg.src[i],
                cfg.dst_if,
                cfg.flags & PM_TZSP ? "TZSP" : "TEE",
                cfg.flags & PM_PROMISC ? "on" : "off",
                cfg.pfe);
    }

    int    sock = -1;
    pcap_t *handle = NULL;
    if (initSendHandle(handle, &sock) != 0)
    {
        sig_handler(SIGTERM);
        return -1;
    }
    #ifdef  _ENABLE_THREADS
    int i;
    for (i = 0; i < cfg.src_count; i++) {
        if ((cfg.flags & PM_DST_IF) && strcmp(cfg.dst_if, cfg.src[i]) == 0)
        {
            syslog(LOG_INFO, "src %s ignored", cfg.dst_if);
        }
        else
        {
            pthread_t thread1;
            pthread_create(&thread1, NULL, start_mirroring, (void *) cfg.src[i]);
            pthread_join(thread1, NULL);
        }
    }
    syslog(LOG_INFO, "POSIX threads available, running multiple-threaded");
    while (1) {
        sleep(1000);
    }
    #else

    syslog(LOG_INFO, "POSIX threads unavailable, running single-threaded");
    start_mirroring(cfg.src[0], &sock);

    #endif

    return 0;
}

