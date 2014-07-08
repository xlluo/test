/**************************************************************************
 *
 *       Copyright (c) 2011 by iCatch Technology, Inc.
 *
 *  This software is copyrighted by and is the property of iCatch Technology,
 *  Inc.. All rights are reserved by iCatch Technology, Inc..
 *  This software may only be used in accordance with the corresponding
 *  license agreement. Any unauthorized use, duplication, distribution,
 *  or disclosure of this software is expressly forbidden.
 *
 *  This Copyright notice MUST not be removed or modified without prior
 *  written consent of iCatch Technology, Inc..
 *
 *  iCatch Technology, Inc. reserves the right to modify this software
 *  without notice.
 *
 *  iCatch Technology, Inc.
 *  19-1, Innovation First Road, Science-Based Industrial Park,
 *  Hsin-Chu, Taiwan, R.O.C.
 *
 *  Author: Andy.Li
 *
 **************************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <ctype.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>

typedef char BOOL;
enum { TRUE = 1, FALSE = 0 };

#define ttcp_error(args...)		do { fprintf(stderr, "" args); fprintf(stderr, "\n"); } while(0)

enum { TCP_MSS_BYTES = 1460 };

typedef struct {
	const char * prefix;
	void *buffer;
	unsigned int buflen;	/* length of buffer */
	unsigned int bufcnt;	/* number of buffers to send in sinkmode */
	int options;		/* socket options */
	int nodelay;		/* set TCP_NODELAY socket option */
	int socket_buffer_size;	/* socket buffer size to use */
	unsigned short port;	/* TCP port number */
	unsigned int udp:1,		/* 0 = tcp, !0 = udp */
	       trans:1;		/* 0=receive, !0=transmit mode */

	char fmt;		/* output format: k = kilobits, K = kilobytes,
				 *  m = megabits, M = megabytes,
				 *  g = gigabits, G = gigabytes */

	int skfd_data, skfd_main;
	struct sockaddr_in sin_local, sin_peer;
	int interval_bytes;

	unsigned long call_nr;	/* # of I/O system calls */
	uint64_t total_bytes;
	double real_time;
	struct timeval tm0;

	// throughput control
	unsigned long throughput; // enable throughput control. Unit is milli-seconds for 16 buffers.
} ttcp_state_t ;

static void ttcp_state_init(ttcp_state_t* ttcp)
{
	memset(ttcp, 0, sizeof(*ttcp));
	ttcp->buflen = 8 * TCP_MSS_BYTES;
	ttcp->bufcnt = 2 * 1024;
	ttcp->nodelay = 1;
	ttcp->port = 5001;
	ttcp->fmt = 'm';
	ttcp->interval_bytes = 1000000;
	ttcp->skfd_data = -1;
	ttcp->skfd_main = -1;
}

static void pattern( char *cp, int cnt )
{
	char c = 0;

	while ( cnt-- > 0 )  {
		while ( !isprint((c & 0x7F)) ) {
			c++;
		}

		*cp++ = (c++ & 0x7F);
	}
}

static char * outfmt(char* obuf, char fmt, double b)
{
	switch (fmt) {
	case 'G':
		sprintf(obuf, "%.2f GB", b / 1000.0 / 1000.0 / 1000.0);
		break;

	default:
	case 'K':
		sprintf(obuf, "%.2f KB", b / 1000.0);
		break;

	case 'M':
		sprintf(obuf, "%.2f MB", b / 1000.0 / 1000.0);
		break;

	case 'g':
		sprintf(obuf, "%.2f G", b * 8.0 / 1000.0 / 1000.0 / 1000.0);
		break;

	case 'k':
		sprintf(obuf, "%.2f K", b * 8.0 / 1000.0);
		break;

	case 'm':
		sprintf(obuf, "%.2f M", b * 8.0 / 1000.0 / 1000.0);
		break;
	}

	return obuf;
}

static void tvsub(struct timeval *tdiff, struct timeval *t1, struct timeval *t0)
{
	tdiff->tv_sec = t1->tv_sec - t0->tv_sec;
	tdiff->tv_usec = t1->tv_usec - t0->tv_usec;

	if (tdiff->tv_usec < 0) {
		tdiff->tv_sec--, tdiff->tv_usec += 1000000;
	}
}

static inline void timeval_get_time(struct timeval *tp)
{
	gettimeofday(tp, NULL);
}

static void trace_end(ttcp_state_t* ttcp)
{
	struct timeval td;
	struct timeval tm_now;

	timeval_get_time(&tm_now);
	tvsub( &td, &tm_now, &ttcp->tm0 );
	double real_time = td.tv_sec + ((double)td.tv_usec) / 1000000;

	ttcp->real_time += real_time;
	if (ttcp->real_time <= 0.001 ) {
		ttcp->real_time = 0.001;
	}

	char obuf[50];
	printf("=======================================================\n");
	printf("%s: Bytes = %.2f M, Time = %.2f Sec, bps = %s\n"
	       , ttcp->prefix, (double)ttcp->total_bytes / (1000.0 * 1000.0), ttcp->real_time
	       , outfmt(obuf, ttcp->fmt, ttcp->total_bytes / ttcp->real_time));

	printf("%s: I/O calls = %lu, msec/call = %.2f, calls/sec = %.2f\n",
	       ttcp->prefix, ttcp->call_nr,
	       1000.0 * ttcp->real_time / ((double)ttcp->call_nr),
	       ((double)ttcp->call_nr) / ttcp->real_time);
}

static void trace_interval(ttcp_state_t* ttcp, int nbytes)
{
	struct timeval td;
	struct timeval tm_now;

	timeval_get_time(&tm_now);
	tvsub( &td, &tm_now, &ttcp->tm0 );
	double real_time = td.tv_sec + ((double)td.tv_usec) / 1000000;

	if (real_time <= 0.001) {
		real_time = 0.001;
	}

	char obuf[50];
	printf("%s: Bytes = %.2f M, Time = %.2f Sec, bps = %s\n"
	       , ttcp->prefix, (float)nbytes / (1000.0 * 1000.0), real_time
	       , outfmt(obuf, ttcp->fmt, nbytes / real_time));

	ttcp->real_time += real_time;
	timeval_get_time(&ttcp->tm0);
}

static int
ttcp_write(ttcp_state_t* ttcp
	, int skfd
	, struct sockaddr_in* sin_peer
	, void *buf
	, int count)
{
	unsigned char *pbuf = (unsigned char *)buf;
	int nbytes, remainder = count;

	while (remainder > 0) {
		if (ttcp->udp) {
			nbytes = sendto(skfd, pbuf, remainder, 0, (struct sockaddr *)sin_peer, sizeof(*sin_peer));
			//usleep(1000*10);
		}
		else
			nbytes = write(skfd, pbuf, remainder);

		++ttcp->call_nr;

		if (nbytes <= 0)
			goto fail;

		pbuf += nbytes;
		remainder -= nbytes;
	}

	return count;

fail:
	ttcp_error("ttcp_write err %d", nbytes);
	return -1;
}

static int ttcp_read(ttcp_state_t* ttcp, int skfd, void *buf, int count)
{
	struct sockaddr_in from;
	socklen_t len = sizeof(from);

	int nbytes;
	if (ttcp->udp)
		nbytes = recvfrom(skfd, buf, count, 0, (struct sockaddr*)&from, &len);
	else
		nbytes = read(skfd, buf, count);

	++ttcp->call_nr;

	return nbytes;
}

static void usage()
{
	printf("Usage: ttcp -t [-options] host [ < in ]\n");
	printf("       ttcp -r [-options > out]\n");
	printf("Common options:\n");
	printf("	-l ##	length of bufs read from or written to network (default 8192)\n");
	printf("	-u	use UDP instead of TCP\n");
	printf("	-p ##	port number to send to or listen at (default 5001)\n");
	printf("	-A	align the start of buffers to this modulus (default 16384)\n");
	printf("	-d	set SO_DEBUG socket option\n");
	printf("	-b ##	set socket buffer size (if supported)\n");
	printf("	-f X	format for rate: k,K = kilo{bit,byte}; m,M = mega; g,G = giga\n");
	printf("	-i ##   interval bytes (in MBytes) between two prompts\n");
	printf("	-P      Enable ps-dump\n");
	printf("	-g ##   Enable throughput control, valid only for UDP. Unit Mbps\n");
	printf("Options specific to -t:\n");
	printf("	-n ##	number of source bufs written to network (default 2048), set to 0 as infinite\n");
	printf("	-D	don't buffer TCP writes (sets TCP_NODELAY socket option)\n");
	printf("Options specific to -r:\n");
}

static char parse_options(ttcp_state_t *ttcp, int argc, char **argv)
{
	int c, trans = -1, throughput = 0;

	while ((c = getopt(argc, argv, "drtuDb:f:l:n:p:i:g:")) != -1) {
		switch (c) {
		case 't':
			trans = 1;
			break;

		case 'r':
			trans = 0;
			break;

		case 'd':
			ttcp->options |= SO_DEBUG;
			break;

		case 'D':
			ttcp->nodelay = 1;
			break;

		case 'n':
			ttcp->bufcnt = atoi(optarg);
			break;

		case 'l':
			ttcp->buflen = atoi(optarg);
			break;

		case 'p':
			ttcp->port = atoi(optarg);
			break;

		case 'u':
			ttcp->udp = 1;
			break;

		case 'b':
			ttcp->socket_buffer_size = atoi(optarg);
			break;

		case 'f':
			ttcp->fmt = *optarg;
			break;

		case 'i':
			ttcp->interval_bytes = atoi(optarg) * 1000000;
			break;

		case 'g':
			throughput = atoi(optarg);
			break;

		default:
			usage();
			return FALSE;
		}
	}

	if (throughput > 0) {
		// time spent for sending 16 buffers
		ttcp->throughput = (16*8*ttcp->buflen)/(throughput*1000);
	}

	if (trans == -1) {
		printf("Missing -t or -r option\n");
		return FALSE;
	}
	ttcp->trans  = trans ? 1 : 0;
	ttcp->prefix = trans ? "ttcp-t" : "ttcp-r";
	return TRUE;
}

static BOOL ttcp_init0(ttcp_state_t *ttcp, int argc, char **argv)
{
	bzero((char *)&ttcp->sin_local, sizeof(ttcp->sin_local));
	ttcp->sin_local.sin_addr.s_addr = INADDR_ANY;
	ttcp->sin_local.sin_family = AF_INET;

	if (ttcp->trans)  {
		if (optind == argc) {
			usage();
			return FALSE;
		}

		bzero((char *)&ttcp->sin_peer, sizeof(ttcp->sin_peer));
		ttcp->sin_peer.sin_port = htons(ttcp->port);

		char *host = argv[optind];

		if (atoi(host) > 0 )  {
			ttcp->sin_peer.sin_family = AF_INET;
			ttcp->sin_peer.sin_addr.s_addr = inet_addr(host);
		} else {
#if 0
			struct hostent *addr;

			if ((addr = gethostbyname(host)) == NULL) {
				ttcp_error("bad hostname");
				return FALSE;
			}

			unsigned long addr_tmp;
			sin_peer.sin_family = addr->h_addrtype;
			bcopy(addr->h_addr_list[0], (char*)&addr_tmp, addr->h_length);
			sin_peer.sin_addr.s_addr = addr_tmp;
#endif
			ttcp_error("hostname");
			return FALSE;
		}

		ttcp->sin_local.sin_port = 0;

		printf("ttcp-t: buflen=%d, bufcnt=%d, port=%d", ttcp->buflen, ttcp->bufcnt, ttcp->port);

		if (ttcp->socket_buffer_size) {
			printf(", socket_buffer_size=%d", ttcp->socket_buffer_size);
		}

		printf("  %s  -> %s\n", ttcp->udp ? "udp" : "tcp", host);
	} else {
		ttcp->sin_local.sin_port = htons(ttcp->port);

		printf("ttcp-r: buflen=%d, bufcnt=%d, port=%d", ttcp->buflen, ttcp->bufcnt, ttcp->port);

		if (ttcp->socket_buffer_size) {
			printf(", socket_buffer_size=%d", ttcp->socket_buffer_size);
		}

		printf("  %s\n", ttcp->udp ? "udp" : "tcp");
	}

	if (ttcp->udp && ttcp->buflen < 5) {
		ttcp->buflen = 5;		/* send more than the sentinel size */
	}

	if ((ttcp->buffer = malloc(ttcp->buflen)) == NULL) {
		ttcp_error("malloc");
		return FALSE;
	}

	return TRUE;
}

static BOOL ttcp_init1(ttcp_state_t *ttcp)
{
	if (ttcp->socket_buffer_size) {
		if (ttcp->trans) {
			if (setsockopt(ttcp->skfd_main, SOL_SOCKET, SO_SNDBUF, &ttcp->socket_buffer_size, sizeof(ttcp->socket_buffer_size)) < 0) {
				ttcp_error("setsockopt: sndbuf");
				return FALSE;
			}
		} else {
			if (setsockopt(ttcp->skfd_main, SOL_SOCKET, SO_RCVBUF, &ttcp->socket_buffer_size, (sizeof ttcp->socket_buffer_size)) < 0) {
				ttcp_error("setsockopt: rcvbuf");
				return FALSE;
			}
		}
	}

	if (ttcp->udp) {
		return TRUE;
	}

	if (ttcp->trans) {
		int one = 1;

		if (ttcp->options)  {
			if (setsockopt(ttcp->skfd_main, SOL_SOCKET, ttcp->options, &one, sizeof(one)) < 0) {
				ttcp_error("setsockopt");
				return FALSE;
			}
		}

#ifdef TCP_NODELAY

		if (ttcp->nodelay) {
			if (setsockopt(ttcp->skfd_main, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one)) < 0) {
				ttcp_error("nodelay");
				return FALSE;
			}
		}
#endif
	}

	return TRUE;
}

static BOOL ttcp_create_connection(ttcp_state_t *ttcp)
{
	if (ttcp->udp) {
		ttcp->skfd_data = ttcp->skfd_main;
		ttcp->skfd_main = -1;
		return TRUE;
	}

	if (ttcp->trans) {
		if (connect(ttcp->skfd_main, (struct sockaddr*)&ttcp->sin_peer, sizeof(ttcp->sin_peer)) < 0) {
			ttcp_error("connect");
			return FALSE;
		}
		ttcp->skfd_data = ttcp->skfd_main;
		ttcp->skfd_main = -1;
	}
	else {
		if (ttcp->options)  {
			int one = 1;

			if (setsockopt(ttcp->skfd_main, SOL_SOCKET, ttcp->options, &one, sizeof(one)) < 0) {
				ttcp_error("setsockopt");
				return FALSE;
			}
		}

		/* otherwise, we are the server and should listen for the connections */
		if (listen(ttcp->skfd_main, 1) < 0) {
			ttcp_error("listen");
			return FALSE;
		}

		fd_set rfds;
		FD_ZERO(&rfds);
		FD_SET(ttcp->skfd_main, &rfds);

		if (select(ttcp->skfd_main+ 1, &rfds, NULL, NULL, NULL) < 0) {
			ttcp_error("select");
			return FALSE;
		}

		if (FD_ISSET(ttcp->skfd_main, &rfds)) {
			struct sockaddr_in frominet;
			socklen_t fromlen = sizeof(frominet);
			int fd0 = -1;

			printf("ttcp-r: accept 0\n");
			if ((fd0 = accept(ttcp->skfd_main, (struct sockaddr * )&frominet, &fromlen)) < 0) {
				ttcp_error("accept");
				return FALSE;
			}

			printf("ttcp-r: accept %d from %s\n", fd0, inet_ntoa(frominet.sin_addr));

			ttcp->skfd_data = fd0;
		} else {
			ttcp_error("FD_ISSET");
			return FALSE;
		}

		#if 0
		struct sockaddr_in peer;
		socklen_t peerlen = sizeof(peer);
		if (getpeername(ttcp->skfd, (struct sockaddr *) &peer, &peerlen) < 0) {
			ttcp_error("getpeername");
			return FALSE;
		}
		else {
			printf("ttcp-r: accept from %s\n", inet_ntoa(peer.sin_addr));
		}
		#endif
	}

	return TRUE;
}

static void ttcp_release(ttcp_state_t *ttcp)
{
	if (ttcp) {
		if (ttcp->skfd_data >= 0) {
			close(ttcp->skfd_data);
		}

		if (ttcp->skfd_main >= 0) {
			close(ttcp->skfd_main);
		}

		if (ttcp->buffer) {
			free(ttcp->buffer);
		}
	}
}

static void ttcp_handle_tx(ttcp_state_t *ttcp)
{
	int interval_bytes = 0;

	// throughput control
	int buffer_count = 0;
	struct timeval tv_0, tv_1, tv_diff;
	int time_elapsed, sleep_time;
	int64_t total_bytes;

	if (ttcp->bufcnt == 0)
		total_bytes = 0x7FFFFFFFFFFFFFFFll;
	else {
		total_bytes  = ttcp->buflen;
		total_bytes *= ttcp->bufcnt;
	}

	pattern(ttcp->buffer, ttcp->buflen);

	ttcp_write(ttcp, ttcp->skfd_data, &ttcp->sin_peer, &total_bytes, sizeof(total_bytes));

	timeval_get_time(&tv_0);
	while (total_bytes > 0) {
		if (ttcp_write(ttcp, ttcp->skfd_data, &ttcp->sin_peer, ttcp->buffer, ttcp->buflen) == -1) {
			ttcp_error("Write failed");
			break;
		}

		ttcp->total_bytes += ttcp->buflen;
		interval_bytes += ttcp->buflen;
		total_bytes -= ttcp->buflen;

		if (interval_bytes >= ttcp->interval_bytes) {
			trace_interval(ttcp, interval_bytes);
			interval_bytes -= ttcp->interval_bytes;
		}

		if (ttcp->throughput && ++buffer_count == 16) {
			timeval_get_time(&tv_1);

			tvsub(&tv_diff, &tv_1, &tv_0);
			time_elapsed = tv_diff.tv_sec * 1000 + tv_diff.tv_usec/1000;
			sleep_time = ttcp->throughput - time_elapsed;

			if (sleep_time > 0) {
				usleep(sleep_time*1000);
			}

			buffer_count = 0;
			timeval_get_time(&tv_0);
		}
	}
}

static void ttcp_handle_rx(ttcp_state_t *ttcp)
{
	int64_t remainder = 1;
	int  interval_bytes = 0, nbytes, status;
	char got_total_bytes = 0;
	fd_set rfds;

	while (remainder > 0) {
		FD_ZERO(&rfds);
		FD_SET(ttcp->skfd_data, &rfds);

		status = select(ttcp->skfd_data+1, &rfds, NULL, NULL, NULL);
		if (status <= 0) {
			ttcp_error("select %d", status);
			break;
		}

		if (!FD_ISSET(ttcp->skfd_data, &rfds))
			continue;

		if (!got_total_bytes) {
			ttcp_read(ttcp, ttcp->skfd_data, &remainder, sizeof(remainder));
			printf("total bytes = %ld\n", remainder);
			++got_total_bytes;
			continue;
		}

		nbytes = ttcp_read(ttcp, ttcp->skfd_data, ttcp->buffer, ttcp->buflen);
		if (nbytes <= 0)
			break;

		ttcp->total_bytes += nbytes;
		interval_bytes += nbytes;
		remainder -= nbytes;

		if (interval_bytes >= ttcp->interval_bytes) {
			trace_interval(ttcp, interval_bytes);
			interval_bytes = 0;
		}
	}

	if (interval_bytes)
		trace_interval(ttcp, interval_bytes);
}

int main(int argc, char **argv)
{
	if (argc < 2) {
		usage();
		return -1;
	}

	int exit_code = -1;
	int main_skfd;

	ttcp_state_t ttcp0, *ttcp = &ttcp0;

	ttcp_state_init(ttcp);

	if (!parse_options(ttcp, argc, argv)) {
		ttcp_error("opt");
		goto lEXIT;
	}

	if (!ttcp_init0(ttcp, argc, argv)) {
		ttcp_error("init0");
		goto lEXIT;
	}

	if ((main_skfd = socket(PF_INET, ttcp->udp ? SOCK_DGRAM : SOCK_STREAM, 0)) < 0) {
		ttcp_error("socket");
		goto lEXIT;
	}
	printf("main socket %d\n", main_skfd);
	ttcp->skfd_main = main_skfd;

	if (bind(main_skfd, (struct sockaddr * )&ttcp->sin_local, sizeof(ttcp->sin_local)) < 0) {
		ttcp_error("bind");
		goto lEXIT;
	}

	if (!ttcp_init1(ttcp)) {
		ttcp_error("init1");
		goto lEXIT;
	}

	if (!ttcp_create_connection(ttcp)) {
		ttcp_error("connection");
		goto lEXIT;
	}

	timeval_get_time(&ttcp->tm0);
	ttcp->real_time = 0.0f;

	if (ttcp->trans) {
		ttcp_handle_tx(ttcp);
	}
	else {
		ttcp_handle_rx(ttcp);
	}

	trace_end(ttcp);

	exit_code = 0;

lEXIT:
	ttcp_release(ttcp);

	return exit_code;
}
