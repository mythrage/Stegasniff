#define PROGNAME    "Stegasniff"

#include <sys/types.h> /* added 20020604 edobbs for OpenBSD */
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/time.h>
#include <stdio.h>

/* struct datablock:
 * Represents an extent in a captured stream. */
struct datablock {
    int off, len, dirty;
    struct datablock *next;
};

/* connection:
 * Object representing one half of a TCP stream connection. */
typedef struct _connection {
    struct in_addr src, dst;
    short int sport, dport;
    uint32_t isn;
    unsigned int len, off, alloc;
    unsigned char *data;
    int fin;
    time_t last;
    struct datablock *blocks;
} *connection;

char *connection_string(const struct in_addr s, const unsigned short s_port, const struct in_addr d, const unsigned short d_port);

connection connection_new(const struct in_addr *src, const struct in_addr *dst, const short int sport, const short int dport);

void connection_delete(connection c);

void connection_push(connection c, const unsigned char *data, unsigned int off, unsigned int len);

connection *alloc_connection(void);

connection *find_connection(const struct in_addr *src, const struct in_addr *dst, const short int sport, const short int dport);

void save_event(char saved[100]);

#define TMPNAMELEN      64
