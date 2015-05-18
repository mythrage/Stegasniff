#include <pcap.h>
#include <netinet/in.h> /* needs to be before <arpa/inet.h> on OpenBSD */
#include <netinet/ip.h>
#define __FAVOR_BSD
#include <netinet/tcp.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdio.h>
#include <signal.h>
#include <time.h>
#include <sys/wait.h>
#include <mysql/mysql.h>

#include "stegasniff.h"

#define SNAPLEN 1000000      /* largest chunk of data we accept from pcap */

// slots for storing information about connections
connection *slots;
unsigned int slotsused, slotsalloc;

// print all output
int verbose;

// retrieved from network packet
char mailfrom[100];
char mailto[100];
char *from = NULL;
char *to = NULL;

char attachment[999999999];

char filename[30];
char output[200];
char detect[200];

char logs[100];

// time struct
time_t     now;
struct tm  *ts;
char       buf[80];

//Database pointer
MYSQL *conn;
    
//Connection variable
char *server = "localhost";
char *user = "root";
char *password = "";
char *database = "stegasniff";
   


pcap_t *pc;

/* alloc_connection:
 * Find a free slot in which to allocate a connection object. */
connection *alloc_connection(void) {
    connection *C;
    for (C = slots; C < slots + slotsalloc; ++C) {
        if (!*C) return C;
    }
    /* No connection slots left. */
    slots = (connection*)realloc(slots, slotsalloc * 2 * sizeof(connection));
    memset(slots + slotsalloc, 0, slotsalloc * sizeof(connection));
    C = slots + slotsalloc;
    slotsalloc *= 2;
    return C;
}

/* find_connection:
 * Find a connection running between the two named addresses. */
connection *find_connection(const struct in_addr *src, const struct in_addr *dst, const short int sport, const short int dport) {
    connection *C;
    for (C = slots; C < slots + slotsalloc; ++C) {
        connection c = *C;
        if (c && c->sport == sport && c->dport == dport
            && memcmp(&(c->src), src, sizeof(struct in_addr)) == 0
            && memcmp(&(c->dst), dst, sizeof(struct in_addr)) == 0)
            return C;
    }
    return NULL;
}

/* get_link_level_hdr_length:
 * Find out how long the link-level header is, based on the datalink layer
 * type. This is based on init_linktype in the libpcap distribution*/
int get_link_level_hdr_length(int type)
{
    switch (type) {
        case DLT_EN10MB:
            return 14;

        case DLT_SLIP:
            return 16;

        case DLT_SLIP_BSDOS:
            return 24;

        case DLT_NULL:
#ifdef DLT_LOOP
        case DLT_LOOP:
#endif
            return 4;

        case DLT_PPP:
#ifdef DLT_C_HDLC
        case DLT_C_HDLC:
#endif
#ifdef DLT_PPP_SERIAL
        case DLT_PPP_SERIAL:
#endif
            return 4;

        case DLT_PPP_BSDOS:
            return 24;

        case DLT_FDDI:
            return 21;

        case DLT_IEEE802:
            return 22;

        case DLT_ATM_RFC1483:
            return 8;

        case DLT_RAW:
            return 0;

#ifdef DLT_ATM_CLIP
        case DLT_ATM_CLIP:	/* Linux ATM defines this */
            return 8;
#endif

#ifdef DLT_LINUX_SLL
        case DLT_LINUX_SLL:	/* fake header for Linux cooked socket */
            return 16;
#endif

        default:;
    }
    sprintf(logs, PROGNAME": unknown data link type %d", type);
    fprintf(stderr, "%s", logs);
    save_event(logs);
    exit(1);
}

/* terminate_on_signal:
 * Terminate on receipt of an appropriate signal*/
sig_atomic_t foad;

/* setup_signals:
 * Set up signal handlers. */
void setup_signals(void) {
    int *p;
    /* Signals to ignore. */
    int ignore_signals[] = {SIGPIPE, 0};
    int terminate_signals[] = {SIGTERM, SIGINT, /*SIGSEGV,*/ SIGBUS, SIGCHLD, 0};
    struct sigaction sa;

    sa.sa_flags = SA_RESTART | SA_NOCLDSTOP;
    
    for (p = ignore_signals; *p; ++p) {
        memset(&sa, 0, sizeof(sa));
        sa.sa_handler = SIG_IGN;
        sigaction(*p, &sa, NULL);
    }

    for (p = terminate_signals; *p; ++p) {
        memset(&sa, 0, sizeof(sa));
        sigaction(*p, &sa, NULL);
    }
}

/* connection_string:
 * Return a string of the form w.x.y.z:foo -> a.b.c.d:bar for a pair of
 * addresses and ports. */
char *connection_string(const struct in_addr s, const unsigned short s_port, const struct in_addr d, const unsigned short d_port) {
    static char buf[50] = {0};
    sprintf(buf, "%s:%d -> ", inet_ntoa(s), (int)s_port);
    sprintf(buf + strlen(buf), "%s:%d", inet_ntoa(d), (int)d_port);
    return buf;
}

/* connection_new:
 * Allocate a new connection structure between the given addresses. */
connection connection_new(const struct in_addr *src, const struct in_addr *dst, const short int sport, const short int dport) {
    connection c = (connection)calloc(1, sizeof(struct _connection));
    c->src = *src;
    c->dst = *dst;
    c->sport = sport;
    c->dport = dport;
    c->alloc = 16384;
    c->last = time(NULL);
    c->blocks = NULL;
    return c;
}

/* connection_delete:
 * Free the named connection structure. */
void connection_delete(connection c) {
    free(c);
}

/* process_packet:
 * Callback which processes a packet captured by libpcap. */
int pkt_offset; /* offset of IP packet within wire packet */

void process_packet(u_char *user, const struct pcap_pkthdr *hdr, const u_char *pkt) {
    struct ip ip;
    struct tcphdr tcp;
    struct in_addr s, d;
    int off, len, delta, pkt_num;
    const u_char *payload;
     
    connection *C, c;
    
    memcpy(&ip, pkt + pkt_offset, sizeof(ip));
    memcpy(&s, &ip.ip_src, sizeof(ip.ip_src));
    memcpy(&d, &ip.ip_dst, sizeof(ip.ip_dst));

    memcpy(&tcp, pkt + pkt_offset + (ip.ip_hl << 2), sizeof(tcp));
    
    
    off = pkt_offset + (ip.ip_hl << 2) + (tcp.th_off << 2);
    len = hdr->caplen - off;

    payload = (u_char *)(pkt + pkt_offset + (ip.ip_hl << 2) + (tcp.th_off << 2));
    char information[len];
    memcpy(&information, payload, len);
      
    /* try to find the connection slot associated with this. */
    C = find_connection(&s, &d, ntohs(tcp.th_sport), ntohs(tcp.th_dport));

    /* no connection at all, so we need to allocate one. */
    if (!C) {
        if (verbose){
            sprintf(logs, PROGNAME": new connection: %s\n", connection_string(s, ntohs(tcp.th_sport), d, ntohs(tcp.th_dport)));
            fprintf(stderr, "%s", logs);
            save_event(logs);
		}
        
        C = alloc_connection();
        *C = connection_new(&s, &d, ntohs(tcp.th_sport), ntohs(tcp.th_dport));
        /* This might or might not be an entirely new connection (SYN flag
         * set). Either way we need a sequence number to start at. */
        (*C)->isn = ntohl(tcp.th_seq);
        pkt_num = 0;
    }

    /* Now we need to process this segment. */
    c = *C;
    delta = 0;/*tcp.syn ? 1 : 0;*/

    /* NB (STD0007):
     *    SEG.LEN = the number of octets occupied by the data in the
     *    segment (counting SYN and FIN) */
#if 0
    if (tcp.syn)
        /* getting a new isn. */
        c->isn = htonl(tcp.seq);
#endif

    if (tcp.th_flags & TH_RST) {
        /* Looks like this connection is bogus, and so might be a
         * connection going the other way. */
        if (verbose){
            sprintf(logs, PROGNAME": connection reset: %s\n", connection_string(s, ntohs(tcp.th_sport), d, ntohs(tcp.th_dport)));
        	fprintf(stderr, "%s", logs);
        	save_event(logs);
        }
        connection_delete(c);
        *C = NULL;

        if ((C = find_connection(&d, &s, ntohs(tcp.th_dport), ntohs(tcp.th_sport)))) {
            connection_delete(*C);
            *C = NULL;
        }
        return;
    }

    if (len > 0) {
        /* We have some data in the packet. If this data occurred after
         * the first data we collected for this connection, then save it
         * so that we can look for images. Otherwise, discard it. */
        unsigned int offset;
        offset = ntohl(tcp.th_seq);
        
        /* Modulo 2**32 arithmetic; offset = seq - isn + delta. */
        if (offset < (c->isn + delta))
            offset = 0xffffffff - (c->isn + delta - offset);
        else
            offset -= c->isn + delta;

      	fprintf(stderr, "Packet offset : %d\t\t",offset);
       	fprintf(stderr, "Length : %d bytes\n",len);
       	//fprintf(stderr, "%s\n\n", payload);
       	//FILE *fp;
       	//fp = fopen("/home/administrator/capture", "a");
       	//fprintf(fp, "%s", payload);
       	//fclose(fp);
       	
       	// capture second packet for MAIL FROM
 		if(pkt_num == 1){
			memcpy(mailfrom ,information ,len);
			strncpy(mailfrom, mailfrom+11, len);
		}
		// capture second packet for RCPT TO
		if(pkt_num == 2){
			memcpy(mailto ,information ,len);
			strncpy(mailto, mailto+9, len);
		}
		
		if(pkt_num == 4){
			char *name1;
			name1 = strstr(information, "/9j/");
			strcat(attachment, name1);
		}
		
		if(pkt_num > 4){
			strcat(attachment, information);
		}
		pkt_num++;
	}
    if (tcp.th_flags & TH_FIN) {
        /* Connection closing; mark it as closed*/
        strtok(attachment, "-");
        char *pch;
        pch = strtok (attachment,"\r");
        FILE *fp = fopen("/tmp/txtpic","a");
        while (pch != NULL){
        	//printf ("%s",pch);
        	fprintf(fp, "%s", pch);
        	pch = strtok (NULL, "\r");
        	}
        fclose(fp);
        now = time(NULL);
        ts = localtime(&now);
        //char filename[30];
        //strftime(filename, sizeof(filename), "%d_%m_%Y__%H_%M_%S", ts);
        //sprintf(buf, "/usr/bin/base64 -d /tmp/txtpic > /home/administrator/Stegasniff/public/images/%s.jpg",filename);
        //system(buf);
        //system("/bin/rm /tmp/txtpic");
        if (verbose){
        	char delims[] = ">";
			from = strtok(mailfrom, delims);
			to = strtok(mailto, delims);
        	strftime(buf, sizeof(buf), "%a %d-%m-%Y %H:%M:%S %Z", ts);
            sprintf(logs, PROGNAME": One mail captured: %s on %s\n", connection_string(s, ntohs(tcp.th_sport), d, ntohs(tcp.th_dport)), buf);
            fprintf(stderr, "%s", logs);
        	save_event(logs);
        	strftime(filename, sizeof(filename), "%d_%m__%H_%M_%S", ts);
        	sprintf(output, "/usr/bin/base64 -d /tmp/txtpic > /home/administrator/Stegasniff/public/detect/%s.jpg",filename);
        	system(output);
        	system("/bin/rm /tmp/txtpic");
			FILE *fp;
			
			// For testing, comment this and...
			
			sprintf(detect, "cd public/detect/;/usr/bin/stegdetect %s.jpg", filename);
			fp = popen(detect,"r");
			
			// uncomment belows code
			//fp = popen("cd public/images/;/usr/bin/stegdetect gambar.jpg","r");
			
			char pic[256], software[256];
			fscanf(fp, "%s : %s", pic, software);
			sprintf(logs, "%s -> %s : %s -> %s \n", from, to, pic, software);
			fprintf(stderr, "%s", logs);
        	save_event(logs);
            char constring[500] = "INSERT INTO captures VALUES ('','";
            strcat(constring, inet_ntoa(s));
            strcat(constring, "','");
            strcat(constring, inet_ntoa(d));
            strcat(constring, "','");
            strcat(constring, from);
            strcat(constring, "','");
            strcat(constring, to);
            strcat(constring, "','");
            strftime(buf, sizeof(buf), "%H:%M:%S", ts);
            strcat(constring, buf);
            strcat(constring, "','");
            strftime(buf, sizeof(buf), "%a %d-%m-%Y", ts);
            strcat(constring, buf);
            strcat(constring, "','");
            strcat(constring, pic);
            strcat(constring, "','");
            strcat(constring, software);
            strcat(constring, "')");
            if (mysql_query(conn, constring)) {
            	sprintf(logs, "%s\n", mysql_error(conn));
            	fprintf(stderr, "%s", logs);
        		save_event(logs);
   			}
   			strcpy(attachment, "");
		}
        c->fin = 1;
    }
}

void save_event(char saved[100]){
	now = time(NULL);
	ts = localtime(&now);
	char constring[500] = "INSERT INTO histories VALUES ('', '";
	strcat(constring, saved);
	strcat(constring, "','");
	strftime(buf, sizeof(buf), "%H:%M:%S", ts);
	strcat(constring, buf);
	strcat(constring, "','");
	strftime(buf, sizeof(buf), "%a %d-%m-%Y", ts);
	strcat(constring, buf);
	strcat(constring, "')");
	if (mysql_query(conn, constring)){
		sprintf(logs, "%s\n", mysql_error(conn));
		fprintf(stderr, "%s", logs);
        save_event(logs);
	}
}


/* packet_capture_thread:
 * Thread in which packet capture runs. */
void *packet_capture_thread(void *v) {
    while (!foad)
        pcap_dispatch(pc, -1, process_packet, NULL);
    return NULL;
}

/* main:
 * Entry point. Process command line options, start up pcap and enter capture
 * loop. */
char optstring[] = "hi:psSMvam:d:x:";

int main(int argc, char *argv[]) {
    char *interface = NULL, *filterexpr;
    int promisc = 1;
    struct bpf_program filter;
    char ebuf[PCAP_ERRBUF_SIZE];
    int c;

    pthread_t packetth;
    verbose = 1;
    
    conn = mysql_init(NULL);
    
    if (conn == NULL){
    	fprintf (stderr, "mysql_init() failed (probably out of memory)\n");
    	exit (1);
    	}
    	
    if (mysql_real_connect (conn, server, user, password, database, 0, NULL, 0) == NULL){
    	fprintf (stderr, "mysql_real_connect() failed\n");
    	mysql_close (conn);
	}
   
    /* Handle command-line options. */
    opterr = 0;
    while ((c = getopt(argc, argv, optstring)) != -1) {
        switch(c) {
            case 'i':
                interface = optarg;
                break;

            case '?':
            default:
                if (strchr(optstring, optopt)){
                    sprintf(logs, PROGNAME": option -%c requires an argument\n", optopt);
                    fprintf(stderr, "%s", logs);
        			save_event(logs);
				}
                else
                    sprintf(logs, PROGNAME": unrecognised option -%c\n", optopt);
                    fprintf(stderr, "%s", logs);
        			save_event(logs);
                return 1;
        }
    }
    
    if (!interface && !(interface = pcap_lookupdev(ebuf))) {
        sprintf(logs, PROGNAME": pcap_lookupdev: %s\n", ebuf);
        fprintf(stderr, "%s", logs);
        save_event(logs);
        sprintf(logs, PROGNAME": try specifying an interface with -i\n");
        fprintf(stderr, "%s", logs);
        save_event(logs);
        return -1;
    }

    if (verbose){
        sprintf(logs, PROGNAME": listening on %s%s\n", interface ? interface : "all interfaces", promisc ? " in promiscuous mode" : "");
		fprintf(stderr, "%s", logs);
        save_event(logs);
	}

    /* Build up filter. */
    if (optind < argc) {
        char **a;
        int l;
        for (a = argv + optind, l = sizeof("tcp and ()"); *a; l += strlen(*a) + 1, ++a);
        filterexpr = calloc(l, 1);
        strcpy(filterexpr, "tcp and (");
        for (a = argv + optind; *a; ++a) {
            strcat(filterexpr, *a);
            if (*(a + 1)) strcat(filterexpr, " ");
        }
        strcat(filterexpr, ")");
    } else filterexpr = "dst port 25";

    if (verbose){
        sprintf(logs, PROGNAME": using filter expression (%s)\n", filterexpr);
        fprintf(stderr, "%s", logs);
        save_event(logs);
        }
    
    setup_signals();
    
    /* Start up pcap. */

    pc = pcap_open_live(interface, SNAPLEN, promisc, 1000, ebuf);
    if (!pc) {
        sprintf(logs, PROGNAME": pcap_open_live: %s\n", ebuf);
        fprintf(stderr, "%s", logs);
        save_event(logs);

        if (getuid() != 0){
            sprintf(logs, PROGNAME": perhaps you need to be root?\n");
            fprintf(stderr, "%s", logs);
        	save_event(logs);
		}
        else if (!interface){
            sprintf(logs, PROGNAME": perhaps try selecting an interface with the -i option?\n");
            fprintf(stderr, "%s", logs);
        	save_event(logs);
		}
            
        return -1;
    }
    
    if (pcap_compile(pc, &filter, (char*)filterexpr, 1, 0) == -1) {
        sprintf(logs, PROGNAME": pcap_compile: %s\n", pcap_geterr(pc));
        fprintf(stderr, "%s", logs);
        save_event(logs);
        return -1;
    }
    
    if (pcap_setfilter(pc, &filter) == -1) {
        sprintf(logs, PROGNAME": pcap_setfilter: %s\n", pcap_geterr(pc));
        fprintf(stderr, "%s", logs);
        save_event(logs);
        return -1;
    }

    /* Figure out the offset from the start of a returned packet to the data in
     * it. */
    pkt_offset = get_link_level_hdr_length(pcap_datalink(pc));
    if (verbose){
        sprintf(logs, PROGNAME": link-level header length is %d bytes\n", pkt_offset);
        fprintf(stderr, "%s", logs);
        save_event(logs);
	}

    slotsused = 0;
    slotsalloc = 64;
    slots = (connection*)calloc(slotsalloc, sizeof(connection));
    
    /* Actually start the capture stuff up. Unfortunately, on many platforms,
     * libpcap doesn't have read timeouts, so we start the thing up in a
     * separate thread. Yay! */
    pthread_create(&packetth, NULL, packet_capture_thread, NULL);

    while (!foad)
        sleep(1);

    if (verbose) {
        if (foad == SIGCHLD) {
            pid_t pp;
            int st;
            while ((pp = waitpid(-1, &st, WNOHANG)) > 0) {
                if (WIFEXITED(st)){
                    sprintf(logs, PROGNAME": child process %d exited with status %d\n", (int)pp, WEXITSTATUS(st));
                    fprintf(stderr, "%s", logs);
        			save_event(logs);
				}
                else if (WIFSIGNALED(st)){
                    sprintf(logs, PROGNAME": child process %d killed by signal %d\n", (int)pp, WTERMSIG(st));
                    fprintf(stderr, "%s", logs);
        			save_event(logs);
				}
                else{
                    sprintf(logs, PROGNAME": child process %d died, not sure why\n", (int)pp);
                    fprintf(stderr, "%s", logs);
        			save_event(logs);
				}
                    
            }
            
        } else{
            sprintf(logs, PROGNAME": caught signal %d\n", foad);
            fprintf(stderr, "%s", logs);
        	save_event(logs);
		}
    }
    
    pthread_cancel(packetth); /* make sure thread quits even if it's stuck in pcap_dispatch */
    pthread_join(packetth, NULL);
    
    /* Clean up. */
    pcap_close(pc);
    mysql_close(conn);
    FILE *fp;
    fp = popen("rm /home/administrator/capture","r");

    return 0;
}


