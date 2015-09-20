/*
 * Copyright (c) 2012 Bruce Geng <gengw2000@163.com>.
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
#ifdef	_ENABLE_THREADS
#include <pthread.h>
#endif
#include <errno.h>
#include "pcap.h"

#pragma pack(1)

#define ETH_ALEN	6		/* Octets in one ethernet addr	*/
#define ETH_P_ARP	0x0806		/* Address Resolution packet	*/
#define ETH_P_802_3	0x0001		/* Dummy type for 802.3 frames  */
#define ETH_P_IP	0x0800		/* Internet Protocol packet	*/
#define	ARPOP_REQUEST	1		/* ARP request			*/
#define	ARPOP_REPLY	2		/* ARP reply			*/
#define	ARP_WAIT_TIME	500		/* Arp Response waiting time (ms) */
#define ARP_ETH_PADDING	18		/* 18 bytes ethernet padding */

#define MAX_SOURCE_IF	4	/* maxium four source interfaces */
#define LINEBUF_MAX	1024
#define OPTION_MAX 	255
#define TZSP_PORT	37008
#define ERRTIMEOUT	20
#define MACADDRLEN	6
#define BUFSIZE 8192

typedef enum{
	MYLOG_INFO = 0,	//info
	MYLOG_ERROR	//error
}MYLOG_LEVEL;

typedef struct{
	unsigned char	ver;
	unsigned char	type;
	unsigned short	proto;
	unsigned char	tagend;
}TZSP_HEAD;

typedef struct{
	unsigned char h_lenver;
	unsigned char tos;
	unsigned short total_len;
	unsigned short ident;
	unsigned short frag_and_flags;
	unsigned char ttl;
	unsigned char proto;
	unsigned short checksum;
	unsigned int sourceIP;
	unsigned int destIP;
}IP_HEADER;

typedef struct{
	unsigned short uh_sport;
	unsigned short uh_dport;
	unsigned short uh_len;
	unsigned short uh_sum;
}UDP_HEADER;

typedef struct
{
	unsigned char	h_dest[ETH_ALEN];	/* destination eth addr	*/
	unsigned char	h_source[ETH_ALEN];	/* source ether addr	*/
	unsigned short	h_proto;		/* packet type ID field	*/
}ETHHDR; 

typedef struct
{
	unsigned short	ar_hrd;		/* format of hardware address	*/
	unsigned short	ar_pro;		/* format of protocol address	*/
	unsigned char	ar_hln;		/* length of hardware address	*/
	unsigned char	ar_pln;		/* length of protocol address	*/
	unsigned short	ar_op;		/* ARP opcode (command)		*/

	unsigned char	ar_sha[ETH_ALEN];	/* sender hardware address	*/
	unsigned int	ar_sip;			/* sender IP address		*/
	unsigned char	ar_tha[ETH_ALEN];	/* target hardware address	*/
	unsigned int	ar_tip;			/* target IP address		*/
}ARPHDR;

typedef struct
{
	ETHHDR	ethhdr;
	ARPHDR	arphdr;
}ARPPACKET;

//options:
char opt_config[OPTION_MAX];
char opt_pid[OPTION_MAX];
int opt_daemon = 0;
int opt_syslog = 0;
int opt_debug = 0;
int opt_promiscuous = 0;
int opt_protocol = 1;		//0 - TZSP, 1 - TEE

int debug_packets = 0;

int  mirroring_type = 0; 	/* 0 - to interface, 1 - to remote ip address */
char mirroring_target_if[OPTION_MAX];
unsigned int mirroring_target_ip;
int  mirroring_source_num = 0;
char mirroring_source[MAX_SOURCE_IF][OPTION_MAX];
char mirroring_filter[OPTION_MAX];
pcap_t * sendHandle = NULL;	//send pcap handle
int	sendSocket = -1;	//send raw socket
struct	sockaddr_in	sendSocket_sa;
char	senderMac[MACADDRLEN];
char	remoteMac[MACADDRLEN];
unsigned long tLastInit = 0;

#ifdef	_ENABLE_THREADS
pthread_mutex_t mutex1 = PTHREAD_MUTEX_INITIALIZER;
#endif

char*	getCurrentTime(){
	time_t	tt;
	struct  tm    	*vtm;
	static  char	MacTime[20];

	time( &tt );
	vtm = localtime( &tt );
	
	sprintf(MacTime, "%.4d-%.2d-%.2d %.2d:%.2d:%.2d",
            (1900+vtm->tm_year),vtm->tm_mon+1,
            vtm->tm_mday, vtm->tm_hour,
            vtm->tm_min, vtm->tm_sec);
	MacTime[19]=0;	
	return MacTime;
}

void writeLog( MYLOG_LEVEL ll, const char *message , ...){
#ifdef _WIN32
	FILE *fp;
	fp = fopen(".\\port-mirroring.log","a");
	if( fp!= NULL){
		if( ll == MYLOG_INFO ){
			fprintf(fp,"%s[info] " , getCurrentTime());
		}else if( ll == MYLOG_ERROR ){
			fprintf(fp,"%s[error] " , getCurrentTime());
		}
		va_list arg_ptr;
		va_start(arg_ptr, message);
		vfprintf(fp, message, arg_ptr);
		fflush(fp);
		fclose(fp);
		va_end(arg_ptr);
	}
#else
	va_list arg_ptr;
	va_start(arg_ptr, message);
	if( ll == MYLOG_INFO ){
		if( opt_syslog ){
			vsyslog( LOG_MAKEPRI( LOG_LOCAL1, LOG_INFO), message, arg_ptr );
		}else{
			fprintf( stderr,"%s[info] " , getCurrentTime());
			vfprintf( stderr, message, arg_ptr);
		}
	}else if( ll == MYLOG_ERROR ){
		if( opt_syslog ){
			vsyslog( LOG_MAKEPRI( LOG_LOCAL1, LOG_ERR), message, arg_ptr );
		}else{
			fprintf( stderr,"%s[error] " , getCurrentTime());
			vfprintf( stderr, message, arg_ptr);
		}
	}
	va_end(arg_ptr);
#endif
}

void addMonitoringSource( const char * s ){
	if( mirroring_source_num < MAX_SOURCE_IF ){
		strncpy( mirroring_source[mirroring_source_num], s, OPTION_MAX);
		mirroring_source_num++;
	}
}

char * getUCIItem( char * buf, char * item ){
	char * p1 = buf;
	char * p2;
	char delim;
	while( *p1 == '\t' || *p1 == ' ' ){
		p1++;
	}
	if( *p1 == '\'' || *p1 == '"' ){
		delim = *p1++;
		p2 = strchr( p1, delim );
	}else{
		p2 = strchr( p1, ' ' );
		if( p2 == NULL ){
			p2 = strchr( p1, '\t');
		}
	}
	if( p2 != NULL ){
		*p2 = '\0';
		strncpy( item, p1, OPTION_MAX );
		return p2+1;
	}else{
		return NULL;
	}
}

int getUCIConf( char * buf, char * option, char * value ){
	
	char * p = strstr( buf, "option" );
	
	if( p != NULL ){
		p += 6;
		if( (p = getUCIItem( p, option )) != NULL ){
			if( getUCIItem( p, value ) != NULL ){
				return 0;
			}
		}
	}
	return -1;
}

int loadCfg( const char * fpath ){
	FILE * fp = fopen( fpath, "r" );
	char sline[LINEBUF_MAX];
	
	if( fp == NULL ){
		return -1;
	}
	memset( sline, 0, sizeof(sline));
	while( fgets( sline, sizeof(sline), fp )!=NULL ){
		char option[OPTION_MAX] = {0};
		char value[OPTION_MAX] = {0};
		if( sline[0] == '#' || sline[0] == '\0' ){
			continue;
		}
		if( getUCIConf( sline, option, value ) == 0 ){
			if( strcmp( option, "target" ) == 0 ){
				strcpy( mirroring_target_if, value );
				if( inet_addr(value) != INADDR_NONE ){
					mirroring_type = 1;
					mirroring_target_ip = inet_addr(value);
				}else{
					mirroring_type = 0;
					strcpy( mirroring_target_if, value );
				}
			}else if( strcmp( option, "source_ports" ) == 0 ){
				char	*token = strtok( value, "," );
				while( token != NULL){
					addMonitoringSource( token );
					token = strtok( NULL, "," );
				}
			}else if( strcmp( option, "filter" ) == 0 ){
				strcpy( mirroring_filter, value );
			}else if( strcmp( option, "promiscuous" ) == 0 ){
				if( atoi(value) == 1 ){
					opt_promiscuous = 1;
				}
			}else if( strcmp( option, "protocol" ) == 0 ){
				if( strcmp( value, "TEE" ) == 0 ){
					opt_protocol = 1;
				}else if( strcmp( value, "TZSP" ) == 0 ){
					opt_protocol = 0;
				}else{
					writeLog( MYLOG_ERROR, "port-mirroring::loadCfg, protocol [%s] syntax error.\n", value );
				}
			}
		}
		memset( sline, 0, sizeof(sline));
	}

	fclose( fp );
	return 0;
}

void init(){
	int i;
	
	mirroring_type = 0; 	/* 0 - to interface, 1 - to remote ip address */
	memset( mirroring_target_if, 0, sizeof(mirroring_target_if));
	mirroring_target_ip = 0;
	mirroring_source_num = 0;
	memset( mirroring_filter, 0, sizeof(mirroring_filter));
	for( i=0; i<MAX_SOURCE_IF; i++ ){
		memset( mirroring_source[i], 0, OPTION_MAX );
	}
	memset( senderMac, 0, MACADDRLEN );
	memset( remoteMac, 0, MACADDRLEN );
	memset( opt_config, 0, sizeof(opt_config));
	strcpy( opt_pid, "/var/run/port-mirroring.pid" );
}

int reopenSendHandle( const char * device ){
	char	errbuf[PCAP_ERRBUF_SIZE] = {0};
	if( sendHandle != NULL ){
		if( opt_debug ){
			writeLog( MYLOG_ERROR, "port-mirroring::reopenSendHandle, reopen send handle, dev=\"%s\".\n", mirroring_target_if );
		}
		pcap_close( sendHandle );
	}
	sendHandle = pcap_open_live( device, 65536, 0, 100, errbuf );
	if (sendHandle == NULL ) {
		writeLog( MYLOG_ERROR, "port-mirroring::reopenSendHandle, couldn't open device \"%s\": %s\n", mirroring_target_if, errbuf);
		return -1;
	}else{
		if( opt_debug ){
			writeLog( MYLOG_INFO, "port-mirroring::reopenSendHandle %s success.\n", device );
		}
	}
}

char*	printMACStr( const char *mac){
	static char	macStr[20]={0};
	sprintf( macStr , "%02x%02x%02x%02x%02x%02x" , 
		(unsigned char)mac[0], (unsigned char)mac[1] , (unsigned char)mac[2] , 
		(unsigned char)mac[3] , (unsigned char)mac[4] , (unsigned char)mac[5]);
	return	macStr;
}

int readNlSock(int sockFd, char *bufPtr, int seqNum, int pId){
	struct nlmsghdr *nlHdr;
	int readLen = 0, msgLen = 0;

  	do{
   		/* Recieve response from the kernel */
   		if((readLen = recv(sockFd, bufPtr, BUFSIZE - msgLen, 0)) < 0){
    			writeLog( MYLOG_ERROR, "readNlSock, socket read error.");
    			return -1;
   		}

		nlHdr = (struct nlmsghdr *)bufPtr;

		/* Check if the header is valid */
   		if((NLMSG_OK(nlHdr, readLen) == 0) || (nlHdr->nlmsg_type == NLMSG_ERROR)){
   			writeLog( MYLOG_ERROR, "readNlSock, error in recieved packet.");
    			return -1;
   		}
   		/* Check if the its the last message */
		if(nlHdr->nlmsg_type == NLMSG_DONE) {
   			break;
   		}else{	
   			/* Else move the pointer to buffer appropriately */
   			bufPtr += readLen;
   			msgLen += readLen;
   		}
		/* Check if its a multi part message */
   		if((nlHdr->nlmsg_flags & NLM_F_MULTI) == 0) {
   			/* return if its not */
   			break;
   		}
	} while( (nlHdr->nlmsg_seq != seqNum) || (nlHdr->nlmsg_pid != pId) );

	return msgLen;
}

int getInterfaceMac( const char * device, char * mac ){
	int s;
	struct ifreq buffer;

	if( (s = socket( PF_INET, SOCK_DGRAM, 0)) < 0 ){
		writeLog( MYLOG_ERROR, "getInterfaceMac, create socket error.");
		return -1;
	}
	memset(&buffer, 0x00, sizeof(buffer));
    	strncpy( buffer.ifr_name, device, sizeof(buffer.ifr_name));

	if( ioctl(s, SIOCGIFHWADDR, &buffer) < 0 ){
		writeLog( MYLOG_ERROR, "getInterfaceMac, unable to query mac address of [%s].\n", device );
		close( s );
		return -1;
	}

    	close(s);

	memcpy( mac, buffer.ifr_hwaddr.sa_data, MACADDRLEN );
	
	return 0;
}

int getInterfaceIP( const char * device, unsigned int * ip ){
	int s;
	struct ifreq buffer;

	if( (s = socket( PF_INET, SOCK_DGRAM, 0)) < 0 ){
		writeLog( MYLOG_ERROR, "getInterfaceIP, create socket error.");
		return -1;
	}
	memset(&buffer, 0x00, sizeof(buffer));
	buffer.ifr_addr.sa_family = AF_INET;
    	strncpy( buffer.ifr_name, device, sizeof(buffer.ifr_name));

	if( ioctl(s, SIOCGIFADDR, &buffer) < 0 ){
		writeLog( MYLOG_ERROR, "getInterfaceIP, unable to query mac address of [%s].\n", device );
		close( s );
		return -1;
	}

    	close(s);

	*ip = ((struct sockaddr_in *)&buffer.ifr_addr)->sin_addr.s_addr;
	
	return 0;
}

int getSenderInterface( unsigned int targetIP, char * device, char * mac ){
	struct nlmsghdr *nlMsg;
	struct rtmsg *rtMsg;

	struct route_info *rtInfo;
	char msgBuf[BUFSIZE];

	int sock, len, msgSeq = 0;

	if((sock = socket(PF_NETLINK, SOCK_DGRAM, NETLINK_ROUTE)) < 0){
		writeLog( MYLOG_ERROR, "getSenderInterface, create socket error.");
		return -1;
	}

	/* Initialize the buffer */
	memset(msgBuf, 0, BUFSIZE);

	/* point the header and the msg structure pointers into the buffer */
	nlMsg = (struct nlmsghdr *)msgBuf;
	rtMsg = (struct rtmsg *)NLMSG_DATA(nlMsg);
	/* Fill in the nlmsg header*/
	nlMsg->nlmsg_len = NLMSG_LENGTH(sizeof(struct rtmsg)); // Length of message.
	nlMsg->nlmsg_type = RTM_GETROUTE; // Get the routes from kernel routing table .
	nlMsg->nlmsg_flags = NLM_F_DUMP | NLM_F_REQUEST; // The message is a request for dump.
	nlMsg->nlmsg_seq = msgSeq++; // Sequence of the message packet.
	nlMsg->nlmsg_pid = getpid(); // PID of process sending the request.

	/* Send the request */
  	if(send(sock, nlMsg, nlMsg->nlmsg_len, 0) < 0){
		writeLog( MYLOG_ERROR, "getSenderInterface, write to socket failed.");
		close( sock );
   		return -1;
  	}

  	/* Read the response */
  	if((len = readNlSock(sock, msgBuf, msgSeq, getpid())) < 0) {
   		writeLog( MYLOG_ERROR, "getSenderInterface, readNlSock failed.");
   		return -1;
  	}
  	
  	for( ; NLMSG_OK(nlMsg,len); nlMsg = NLMSG_NEXT(nlMsg,len) ){
   		struct rtmsg *rtMsg = (struct rtmsg *)NLMSG_DATA( nlMsg );
   		struct rtattr *rtAttr;
		unsigned int rtLen, dstMask;
		char ifName[IF_NAMESIZE] = {0};
		unsigned int gateway, srcAddr, dstAddr;
		
   		if( rtMsg->rtm_family == AF_INET || rtMsg->rtm_table == RT_TABLE_MAIN ){
			struct rtattr *rtAttr = (struct rtattr *)RTM_RTA( rtMsg );
			int rtLen = RTM_PAYLOAD( nlMsg );
			for( ;RTA_OK(rtAttr,rtLen); rtAttr = RTA_NEXT(rtAttr,rtLen)){
				switch( rtAttr->rta_type ) {
			   	case RTA_OIF:
			     		if_indextoname(*(int *)RTA_DATA(rtAttr), ifName );
			     		break;
			   	case RTA_GATEWAY:
			     		gateway = *(u_int *)RTA_DATA(rtAttr);
			     		break;
			   	case RTA_PREFSRC:
			     		srcAddr = *(u_int *)RTA_DATA(rtAttr);
					break;
			   	case RTA_DST:
			     		dstAddr = *(u_int *)RTA_DATA(rtAttr);
			     		dstMask = rtLen;
					break;
			   	}
			}
			if( dstMask <= 32 ){
				dstMask = htonl(ntohl(inet_addr("255.255.255.255")) << (32 - dstMask));
				if( (dstAddr & dstMask) == ( targetIP & dstMask )){
					if( getInterfaceMac( ifName, mac ) == 0 ){
						close( sock );
						strcpy( device, ifName );
						if( opt_debug ){
							writeLog( MYLOG_INFO, "getSenderInterface, device=[%s], mac=[%s].\n", device, printMACStr( mac ) );
						}
						return 0;
					}
				}
			}
   		}
  	}
  	close(sock);
	return 1;
}

int getRemoteARP( unsigned int targetIP, const char * device, char * mac){
	unsigned int localIP;
	char	errbuf[PCAP_ERRBUF_SIZE] = {0};
	ARPPACKET arp;
	struct bpf_program fp;
	struct pcap_pkthdr *header;
	const u_char *pkt_data;
	int sent = 0;
	int found = 1;
	int res = 0;
	char filter[100] = {0};
	struct in_addr addr;
	pcap_t * pHandle = pcap_open_live( device, 65536, 0, 500, errbuf );
	
	if (pHandle == NULL ) {
		writeLog( MYLOG_ERROR, "port-mirroring::sendARP, couldn't open device \"%s\": %s\n", device, errbuf );
		return -1;
	}
	if( getInterfaceIP( device, &localIP ) < 0 ){
		writeLog( MYLOG_ERROR, "port-mirroring::sendARP, couldn't get ip of device \"%s\".\n", device );
		pcap_close(pHandle);
		return -1;
	}
	//send arp request to an IP.
	memset( &arp , 0 , sizeof(arp));
	memset( arp.ethhdr.h_dest , 0xFF ,  ETH_ALEN );
	arp.ethhdr.h_proto = htons(ETH_P_ARP);
	arp.arphdr.ar_hrd = htons(ETH_P_802_3);
	arp.arphdr.ar_pro = htons(ETH_P_IP);
	arp.arphdr.ar_hln = ETH_ALEN;				// Hardware size: 6(0x06)
	arp.arphdr.ar_pln = 4;						// Protocol size; 4
	arp.arphdr.ar_op  = htons(ARPOP_REQUEST);	// Opcode: request (0x0001)
	memset( arp.arphdr.ar_tha , 0 , ETH_ALEN);
	arp.arphdr.ar_tip = targetIP;
	memcpy( arp.ethhdr.h_source, senderMac, ETH_ALEN);
	memcpy( arp.arphdr.ar_sha , senderMac, ETH_ALEN);
	arp.arphdr.ar_sip = localIP;
	
	addr.s_addr = targetIP;
	sprintf( filter, "arp host %s", inet_ntoa(addr));
	pcap_compile( pHandle, &fp, filter, 0, 0 );
	pcap_setfilter(pHandle, &fp);

	pcap_sendpacket( pHandle, (unsigned char*)&arp, sizeof(arp));
	
	while( 1 ){
		res = pcap_next_ex( pHandle, &header, &pkt_data );
        	if( res > 0 ){
        		if( *(unsigned short *)(pkt_data + 12) == htons(0x0806) && 
				header->len >= sizeof(ARPPACKET)){
				ARPPACKET * p = (ARPPACKET *)pkt_data;
				if( p->arphdr.ar_op == htons(ARPOP_REPLY) && p->arphdr.ar_sip == targetIP ){
					memcpy( mac, (const char*)p->ethhdr.h_source, ETH_ALEN);
					found = 0;
					if( opt_debug ){
						writeLog( MYLOG_INFO, "getRemoteARP, filter=[%s], device=[%s], remote mac=[%s].\n", 
							filter,
							device,
							printMACStr( mac ) );
					}
					break;
				}
			}
		}else if( res == 0 ){
			if( sent++ < 2 ){
				pcap_sendpacket( pHandle, (unsigned char*)&arp, sizeof(arp));
			}else{
				break;
			}	
            	}else{
			if( opt_debug ){
				writeLog( MYLOG_INFO, "getRemoteARP, capture packets error occured.\n");
			}
            		break;
        	}
    	}
	pcap_close(pHandle);
	
	return found;
}

int initSendHandle(){

	time( &tLastInit );

	if( mirroring_type == 0 ){
		reopenSendHandle( mirroring_target_if );
	}else{
		if( opt_protocol == 0 ){
			/* TZSP format */
			int sendBufSize = 65536;
			sendSocket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP );
			if( sendSocket == -1 ){
				writeLog( MYLOG_ERROR, "port-mirroring::initSendHandle, couldn't create socket.\n" );
				return -1;
			}
			setsockopt( sendSocket, SOL_SOCKET, SO_SNDBUF, (char*)&sendBufSize, sizeof(sendBufSize));
			sendSocket_sa.sin_family	= AF_INET;
			sendSocket_sa.sin_port		= htons(TZSP_PORT);
			sendSocket_sa.sin_addr.s_addr	= mirroring_target_ip;
		}else if( opt_protocol == 1 ){
			/* TEE format */
			char device[IF_NAMESIZE] = {0};
			if( getSenderInterface( mirroring_target_ip, device, senderMac ) == 0 ){
				if( getRemoteARP( mirroring_target_ip, device, remoteMac ) == 0 ){
					reopenSendHandle( device );
				}else{
					writeLog( MYLOG_ERROR, "port-mirroring::initSendHandle, can not get mac address of remote host.\n");
				}
			}else{
				writeLog( MYLOG_ERROR, "port-mirroring::initSendHandle, can not get sender interface.\n");
			}
		}else{
			writeLog( MYLOG_ERROR, "port-mirroring::initSendHandle, unknown protocol.\n");
		}
	}
	
	return 0;
}

void packet_handler_ex( const struct pcap_pkthdr *header, const u_char *pkt_data){
	static char buf[2048];
	
	if( header->len <= 2 * MACADDRLEN ){
		return;
	}
	#ifdef	_ENABLE_THREADS
	pthread_mutex_lock( &mutex1 );
	#endif
	
	if( mirroring_type == 0 ){
		if( sendHandle == NULL || pcap_sendpacket( sendHandle, pkt_data, header->len) != 0 ){
			//error detected
			long nowTime;
			time( &nowTime );
			if( nowTime - tLastInit > ERRTIMEOUT && header->len < 1500 ){
				if( opt_debug ){
					if( sendHandle != NULL ){
						writeLog( MYLOG_ERROR, "port-mirroring::packet_handler_ex, transmit packet error: \"%s\".\n", pcap_geterr(sendHandle));
					}else	writeLog( MYLOG_ERROR, "port-mirroring::packet_handler_ex, sendHandle is null.\n");
				}
				initSendHandle();
			}
		}
	}else if( opt_protocol == 1 ){
		//TEE
		if( memcmp( pkt_data, remoteMac, MACADDRLEN ) ){
			memcpy( buf, remoteMac, MACADDRLEN );
			memcpy( buf + MACADDRLEN, senderMac, MACADDRLEN );
			memcpy( buf + 2 * MACADDRLEN, pkt_data + 2 * MACADDRLEN, header->len - 2 * MACADDRLEN );
			if( sendHandle == NULL || pcap_sendpacket( sendHandle, buf, header->len) != 0 ){
				//error detected
				long nowTime;
				time( &nowTime );
				if( nowTime - tLastInit > ERRTIMEOUT && header->len < 1500 ){
					if( opt_debug ){
						if( sendHandle != NULL ){
							writeLog( MYLOG_ERROR, "port-mirroring::packet_handler_ex, transmit packet error(TEE): \"%s\".\n", pcap_geterr(sendHandle));
						}else	writeLog( MYLOG_ERROR, "port-mirroring::packet_handler_ex, sendHandle is null(TEE).\n");
					}
					initSendHandle();
				}
			}
		}else{
			//ignore packets sent to the remote mac address
		}
	}else if( opt_protocol == 0 ){
		//TSZP
		if( header->len > 14 + sizeof(IP_HEADER) ){
			IP_HEADER * pIPHead = NULL;
			if( *(unsigned short *)(pkt_data + 12) == htons(0x0800)){
				pIPHead = (IP_HEADER *)(pkt_data+14);
			}else if(  *(unsigned short *)(pkt_data + 12) == htons(0x8100)){
				pIPHead = (IP_HEADER *)(pkt_data+18);
			}else{
				#ifdef	_ENABLE_THREADS
				pthread_mutex_unlock( &mutex1 );
				#endif
				return;
			}
			if( pIPHead != NULL && pIPHead->destIP == mirroring_target_ip && pIPHead->proto == IPPROTO_UDP ){
				UDP_HEADER * pUDPHead   = (UDP_HEADER * )((u_char*)pIPHead + sizeof(unsigned long) * ( pIPHead->h_lenver & 0xf));
				//printf("iphlen=[%d], dport=[%u], TSZP=[%u].\n", sizeof(unsigned long) * ( pIPHead->h_lenver & 0xf), pUDPHead->uh_dport, htons(TZSP_PORT));
				if( pUDPHead->uh_dport == htons(TZSP_PORT)){
					//printf("TZSP ignored.\n");
					#ifdef	_ENABLE_THREADS
					pthread_mutex_unlock( &mutex1 );
					#endif
					return;
				}
			}
			if( sendSocket != -1 ){
				TZSP_HEAD * pHead = (TZSP_HEAD *)buf;
				int dataLen;
	
				pHead->ver = 0x01;
				pHead->type = 0x00;
				pHead->proto = htons(0x01);
				pHead->tagend = 0x01;
				if( header->len <  sizeof(buf)-sizeof(TZSP_HEAD)){
					dataLen = header->len;
				}else{
					dataLen = sizeof(buf)-sizeof(TZSP_HEAD);
				}
				if( dataLen > 0 ){
					memcpy( buf+sizeof(TZSP_HEAD), pkt_data, dataLen );
					while( sendto( sendSocket, buf, dataLen+sizeof(TZSP_HEAD), 0, (struct sockaddr *)&sendSocket_sa, sizeof(sendSocket_sa)) < 0 ){
						if( errno == EINTR || errno == EWOULDBLOCK){
							//printf("packet_handler_ex, send failed, ERRNO is EINTR or EWOULDBLOCK.\n");
						}else{
							//printf("packet_handler_ex, send failed.\n");
							break;
						}
					}
				}
			}
		}
	}
	#ifdef	_ENABLE_THREADS
	pthread_mutex_unlock( &mutex1 );
	#endif
	if( opt_debug ){
		debug_packets++;
		if( debug_packets >= 1000 ){
			writeLog( MYLOG_INFO, "port-mirroring, 1000 packets mirrored.\n");
			debug_packets = 0;
		}
	}
}

void* start_mirroring( void * dev ){
	pcap_t *handle;		/* Session handle */
	char errbuf[PCAP_ERRBUF_SIZE];	/* Error string */
	struct bpf_program fp;		/* The compiled filter expression */
	int res = 0;
	struct pcap_pkthdr *header;
	const u_char *pkt_data;
#ifdef	_ENABLE_THREADS
	sigset_t mask;

	sigaddset(&mask, SIGINT);
	sigaddset(&mask, SIGTERM);
	pthread_sigmask(SIG_BLOCK, &mask, NULL);
#endif

start_handle:
	handle = pcap_open_live( (const char*)dev, 65536, opt_promiscuous, 100, errbuf );
	if (handle == NULL ) {
		writeLog( MYLOG_ERROR, "port-mirroring::start_mirroring, couldn't open device \"%s\": %s\n", (const char*)dev, errbuf);
		return;
	}
	
	if( mirroring_filter[0] != '\0' ){
		if( pcap_compile(handle, &fp, mirroring_filter, 0, 0 ) == -1) {
			writeLog( MYLOG_ERROR, "port-mirroring::start_mirroring, couldn't parse filter \"%s\": %s\n", mirroring_filter, pcap_geterr(handle));
			pcap_close(handle);
			return;
	 	}
	 	if (pcap_setfilter(handle, &fp) == -1) {
	 		writeLog( MYLOG_ERROR, "port-mirroring::start_mirroring, couldn't install filter \"%s\": %s\n", mirroring_filter, pcap_geterr(handle));
			pcap_close(handle);
			return;
		}
	}
	//start the capture
	while( handle != NULL ){
		res = pcap_next_ex( handle, &header, &pkt_data );
        	if( res > 0 ){
            		packet_handler_ex( header, pkt_data );
            	}else if( res == 0 ){	// Timeout elapsed
            		continue;
            	}else{
            		break;
        	}
    	}
    	if( res == -1 && handle != NULL ){
    		writeLog( MYLOG_ERROR, "port-mirroring::start_mirroring, error reading the packets from \"%s\": %s\n", (const char*)dev, pcap_geterr(handle));
    		pcap_close(handle);
    		sleep( ERRTIMEOUT );
    		writeLog( MYLOG_ERROR, "port-mirroring::start_mirroring, reopen device \"%s\".\n", (const char *)dev);
    		goto start_handle;
        }
	return;
}

void write_pid(){
	if( opt_daemon && opt_pid[0] != '\0' ){
		FILE * fp = fopen( opt_pid, "w" );
		if( fp != NULL ){
			fprintf( fp , "%d\n", getpid());
			fclose(fp);
		}
	}
}

int fork_daemon(){
	/* Our process ID and Session ID */
        pid_t pid, sid;
        
        /* Fork off the parent process */
        pid = fork();
        if (pid < 0) {
        	writeLog( MYLOG_ERROR, "port-mirroring::fork_daemon, fork failed.\n");
                return -1;
        }
        /* If we got a good PID, then
           we can exit the parent process. */
        if (pid > 0) {
                exit(EXIT_SUCCESS);
        }

        /* Change the file mode mask */
        umask(0);
                
        /* Open any logs here */
        
        /* Create a new SID for the child process */
        sid = setsid();
        if (sid < 0) {
                /* Log the failure */
                writeLog( MYLOG_ERROR, "port-mirroring::fork_daemon, setsid failed.\n");
                return -1;
        }
        
        /* Change the current working directory */
        chdir("/");
        
        /* Close out the standard file descriptors */
        close(STDIN_FILENO);
        close(STDOUT_FILENO);
        close(STDERR_FILENO);
        return 0;
}

void sig_handler( int signum ){
	if( opt_debug ){
		fprintf( stderr, "signal captured, opt_pid=[%s],signum=[%d].\n", opt_pid, signum );
	}
	writeLog( MYLOG_INFO, "port-mirroring stopped.\n");
	if( opt_daemon && opt_pid[0] != '\0' ){
		unlink( opt_pid );
	}
	exit(1);
}

int main( int argc, char **argv ){
	int i;
	int c;
	int option_index = 0;
	
	static struct option long_options[] = {
        	{"config", required_argument, 0, 'c'},
        	{"pid", required_argument, 0, 'p'},
        	{"daemon", no_argument, 0, 'b'},
        	{"debug", no_argument, 0, 'd' },
        	{"syslog", no_argument, 0, 's'},
        	{NULL, 0, NULL, 0}
    	};
    	
    	init();
	
    	while ((c = getopt_long( argc, argv, "c:p:bds",
                 long_options, &option_index)) != -1) {
        	int this_option_optind = optind ? optind : 1;
        	switch (c) {
        		case 'c':
        			if( optarg ){
        				strncpy( opt_config, optarg, sizeof(opt_config));
        			}
        			break;
        		case 'p':
        			if( optarg ){
        				strncpy( opt_pid, optarg, sizeof(opt_pid));
        			}
        			break;
        		case 'b':
        			opt_daemon = 1;
        			break;
        		case 'd':
        			opt_debug = 1;
        			break;
        		case 's':
        			opt_syslog = 1;
        			break;
        		default:
        			break;
        	}
	}
	
	if( opt_daemon && fork_daemon() == -1 ){
		//fork_daemon failed.
		return -1;
	}
	
	write_pid();	//write pid file
	
	signal( SIGINT, sig_handler );
    	signal( SIGTERM, sig_handler );

	if( opt_config[0] != '\0' ){
		if( loadCfg( opt_config ) == -1 ){
			writeLog( MYLOG_ERROR, "port-mirroring::main, can not find configure file[%s].\n", opt_config );
			return -1;
		}
	}else{
		if( loadCfg( "/etc/config/port-mirroring" ) == -1 ){
			if( loadCfg( "/etc/port-mirroring" ) == -1 ){
				#ifdef _WIN32
				if( loadCfg( "./port-mirroring" ) == -1 ){
				#endif
					writeLog( MYLOG_ERROR, "port-mirroring::main, can not find configure file.\n");
					return -1;
				#ifdef _WIN32
				}
				#endif
			}
		}
	}
	
	writeLog( MYLOG_INFO, "port-mirroring::main, mirroring_type:[%s][%s], mirroring_source_num:[%d], target:[%s], filter:[%s], opt_promiscuous:[%d].\n",
		mirroring_type == 0 ? "interface" : "remote", 
		opt_protocol == 0 ? "TZSP" : "TEE",		
		mirroring_source_num,
		mirroring_target_if,
		mirroring_filter,
		opt_promiscuous );
	
	if( initSendHandle() != 0 ){
		sig_handler( SIGTERM );
		return -1;
	}
	#ifdef	_ENABLE_THREADS
	for( i = 0 ; i < mirroring_source_num; i++){
		if( mirroring_type == 0 && strcmp( mirroring_target_if, mirroring_source[i] ) == 0 ){
			writeLog( MYLOG_INFO, "port-mirroring::main, source interface[%s] is ignored.\n", mirroring_target_if );
		}else{
			pthread_t thread1;
			pthread_create( &thread1, NULL, start_mirroring, (void*) mirroring_source[i]);
			pthread_join( thread1, NULL );
		}
	}
	while(1){
		sleep(1000);
	}
	#else
	
	writeLog( MYLOG_INFO, "port-mirroring::main, thread disabled.\n");
	
	start_mirroring( mirroring_source[0] );
	
	#endif
	
	return 0;
}
