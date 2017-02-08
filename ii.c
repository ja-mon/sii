/* (C)opyright MMV-MMVI Anselm R. Garbe <garbeam at gmail dot com>
 * (C)opyright MMV-MMXI Nico Golde <nico at ngolde dot de>
 * See LICENSE file for license details. */
#include <errno.h>
#include <netdb.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <limits.h>
#include <fcntl.h>
#include <string.h>
#include <pwd.h>
#include <signal.h>
#include <ctype.h>
#include <time.h>
#include <unistd.h>
#include <tls.h>
#include <arpa/inet.h>

#define EXIT_TIMEOUT 2

#ifndef PIPE_BUF /* For OS that doesn't includes PIPE_BUF in limits.h, FreeBSD? */
#define PIPE_BUF _POSIX_PIPE_BUF
#endif
#define PING_TIMEOUT 300
#define SERVER_PORT "6697"

enum { TOK_NICKSRV = 0, TOK_USER, TOK_CMD, TOK_CHAN, TOK_ARG, TOK_TEXT, TOK_LAST };

typedef struct Channel Channel;
struct Channel {
	int fd;
	char *name;
	Channel *next;
};

static struct tls *irc = NULL;
static int irc_fd;
static struct tls_config *tlsconf = NULL;
static time_t last_response;
static Channel *channels = NULL;
static char *host = "irc.freenode.net";
static char nick[32];			/* might change while running */
static char _nick[32];			/* might change while running */
static char path[_POSIX_PATH_MAX];
static char message[PIPE_BUF]; /* message buf used for communication */

static void usage() {
	fputs("ii - irc it - " VERSION "\n"
	      "(C)opyright MMV-MMVI Anselm R. Garbe\n"
	      "(C)opyright MMV-MMXI Nico Golde\n"
	      "usage: ii [-i <irc dir>] [-s <host>] [-p <port>]\n"
	      "          [-n <nick>] [-k <password>] [-f <fullname>]\n", stderr);
	exit(EXIT_FAILURE);
}

static char *striplower(char *s) {
	char *p = NULL;
	for(p = s; p && *p; p++) {
		if(*p == '/') *p = ',';
		*p = tolower(*p);
	}
	return s;
}

/* creates directories top-down, if necessary */
static void create_dirtree(const char *dir) {
	char tmp[256];
	char *p = NULL;
	size_t len;
	snprintf(tmp, sizeof(tmp),"%s",dir);
	len = strlen(tmp);
	if(tmp[len - 1] == '/')
		tmp[len - 1] = 0;
	for(p = tmp + 1; *p; p++)
		if(*p == '/') {
			*p = 0;
			mkdir(tmp, S_IRWXU);
			*p = '/';
		}
	mkdir(tmp, S_IRWXU);
}

static int get_filepath(char *filepath, size_t len, char *channel, char *file) {
	if(channel) {
		if(!snprintf(filepath, len, "%s/%s", path, channel))
			return 0;
		create_dirtree(filepath);
		return snprintf(filepath, len, "%s/%s/%s", path, channel, file);
	}
	return snprintf(filepath, len, "%s/%s", path, file);
}

static void create_filepath(char *filepath, size_t len, char *channel, char *suffix) {
	if(!get_filepath(filepath, len, striplower(channel), suffix)) {
		fputs("ii: path to irc directory too long\n", stderr);
		exit(EXIT_FAILURE);
	}
}

static int open_channel(char *name) {
	static char infile[256];
	create_filepath(infile, sizeof(infile), name, "in");
	if(access(infile, F_OK) == -1)
		mkfifo(infile, S_IRWXU);
	return open(infile, O_RDONLY | O_NONBLOCK, 0);
}

static void add_channel(char *cname) {
	Channel *c;
	int fd;
	char *name = striplower(cname);

	for(c = channels; c; c = c->next)
		if(!strcmp(name, c->name))
			return; /* already handled */

	fd = open_channel(name);
	if(fd == -1) {
		printf("ii: exiting, cannot create in channel: %s\n", name);
		exit(EXIT_FAILURE);
	}
	c = calloc(1, sizeof(Channel));
	if(!c) {
		perror("ii: cannot allocate memory");
		exit(EXIT_FAILURE);
	}
	if(!channels) channels = c;
	else {
		c->next = channels;
		channels = c;
	}
	c->fd = fd;
	c->name = strdup(name);
}

static void rm_channel(Channel *c) {
	Channel *p;
	if(channels == c) channels = channels->next;
	else {
		for(p = channels; p && p->next != c; p = p->next);
		if(p->next == c)
			p->next = c->next;
	}
	free(c->name);
	free(c);
}

static void tls_write_all(struct tls *conn, const char *buf, size_t len) {
	while(len > 0) {
		ssize_t ret = tls_write(conn, buf, len);
		if(ret == TLS_WANT_POLLIN || ret == TLS_WANT_POLLOUT)
			continue;
		if(ret < 0) {
			fprintf(stderr, "tls_write: %s\n", tls_error(conn));
			exit(EXIT_FAILURE);
		}
		buf += ret;
		len -= ret;
	}
}

static void login(char *key, char *fullname) {
	if(key) snprintf(message, PIPE_BUF,
				"PASS %s\r\nNICK %s\r\nUSER %s localhost %s :%s\r\n", key,
				nick, nick, host, fullname ? fullname : nick);
	else snprintf(message, PIPE_BUF, "NICK %s\r\nUSER %s localhost %s :%s\r\n",
				nick, nick, host, fullname ? fullname : nick);

	tls_write_all(irc, message, strlen(message)); /* login */
}

static struct tls *tcpopen(const char *port) {
	struct tls *conn = tls_client();
	if(!conn) {
		fputs("ii: tls_client() failed\n", stderr);
		exit(EXIT_FAILURE);
	}
	if(tls_configure(conn, tlsconf) != 0) {
		fprintf(stderr, "ii: tls_configure() failed: %s\n", tls_config_error(tlsconf));
		exit(EXIT_FAILURE);
	}

	struct addrinfo hints;
	memset(&hints, 0, sizeof hints);
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_protocol = 0;
	hints.ai_flags = AI_ADDRCONFIG;
	int errorCode;
	struct addrinfo *addresses;
	do {
		errorCode = getaddrinfo(host, port, &hints, &addresses);
	} while(errorCode == EAI_AGAIN);

	if(errorCode != 0) {
		fprintf(stderr, "ii: getaddrinfo() failed: %s\n", gai_strerror(errorCode));
		exit(EXIT_FAILURE);
	}

	struct addrinfo *addr;
	for(addr = addresses; addr; addr = addr->ai_next) {
		char addr_string_buffer[INET6_ADDRSTRLEN];
		const char *str_addr = inet_ntop(addr->ai_family, addr->ai_addr, addr_string_buffer, sizeof addr_string_buffer);

		irc_fd = socket(addr->ai_family, addr->ai_socktype, addr->ai_protocol);
		if(irc_fd == -1) {
			fprintf(stderr, "ii: socket() on %s failed: %s\n",
				str_addr,
				strerror(errno));
			continue;
		}

		if(connect(irc_fd, addr->ai_addr, addr->ai_addrlen) != 0) {
			fprintf(stderr, "ii: connect() to %s failed: %s\n",
				str_addr,
				strerror(errno));
			continue;
		}

		if(tls_connect_socket(conn, irc_fd, host) != 0) {
			fprintf(stderr, "ii: tls_connect_socket() to %s failed: %s\n",
				str_addr,
				tls_error(conn));
			continue;
		}

		if(tls_handshake(conn) == 0) {
			break;
		} else {
			fprintf(stderr, "ii: tls_handshake() with %s failed: %s\n",
				str_addr,
				tls_error(conn));
		}
	}

	if(!addr)
		exit(EXIT_FAILURE); // All addresses failed

	freeaddrinfo(addresses);
	return conn;
}

static size_t tokenize(char **result, size_t reslen, char *str, char delim) {
	char *p = NULL, *n = NULL;
	size_t i;

	if(!str)
		return 0;
	for(n = str; *n == ' '; n++);
	p = n;
	for(i = 0; *n != 0;) {
		if(i == reslen)
			return 0;
		if(i > TOK_CHAN - TOK_CMD && strtol(result[0], NULL, 10) > 0) delim=':'; /* workaround non-RFC compliant messages */
		if(*n == delim) {
			*n = 0;
			result[i++] = p;
			p = ++n;
		} else
			n++;
	}
	if(i<reslen && p < n && strlen(p))
		result[i++] = p;
	return i;				/* number of tokens */
}

static void print_out(char *channel, char *buf) {
	static char outfile[256], server[256], buft[18];
	FILE *out = NULL;
	time_t t = time(0);

	if(channel) snprintf(server, sizeof(server), "-!- %s", channel);
	if(strstr(buf, server)) channel="";
	create_filepath(outfile, sizeof(outfile), channel, "out");
	if(!(out = fopen(outfile, "a"))) return;
	if(channel && channel[0]) add_channel(channel);

	strftime(buft, sizeof(buft), "%F %R", localtime(&t));
	fprintf(out, "%s %s\n", buft, buf);
	fclose(out);
}

static void proc_channels_privmsg(char *channel, char *buf) {
	snprintf(message, PIPE_BUF, "<%s> %s", nick, buf);
	print_out(channel, message);
	snprintf(message, PIPE_BUF, "PRIVMSG %s :%s\r\n", channel, buf);
	tls_write_all(irc, message, strlen(message));
}

static void proc_channels_input(Channel *c, char *buf) {
	/* static char infile[256]; */
	char *p = NULL;

	if(buf[0] != '/' && buf[0] != 0) {
		proc_channels_privmsg(c->name, buf);
		return;
	}
	message[0] = '\0';
	if(buf[2] == ' ' || buf[2] == '\0') switch (buf[1]) {
		case 'j':
			p = strchr(&buf[3], ' ');
			if(p) *p = 0;
			if((buf[3]=='#')||(buf[3]=='&')||(buf[3]=='+')||(buf[3]=='!')){
				if(p) snprintf(message, PIPE_BUF, "JOIN %s %s\r\n", &buf[3], p + 1); /* password protected channel */
				else snprintf(message, PIPE_BUF, "JOIN %s\r\n", &buf[3]);
				add_channel(&buf[3]);
			}
			else if(p){
				add_channel(&buf[3]);
				proc_channels_privmsg(&buf[3], p + 1);
				return;
			}
			break;
		case 't':
			if(strlen(buf)>=3) snprintf(message, PIPE_BUF, "TOPIC %s :%s\r\n", c->name, &buf[3]);
			break;
		case 'a':
			if(strlen(buf)>=3){
				snprintf(message, PIPE_BUF, "-!- %s is away \"%s\"", nick, &buf[3]);
				print_out(c->name, message);
			}
			if(buf[2] == 0 || strlen(buf)<3) /* or used to make else part safe */
				snprintf(message, PIPE_BUF, "AWAY\r\n");
			else
				snprintf(message, PIPE_BUF, "AWAY :%s\r\n", &buf[3]);
			break;
		case 'n':
			if(strlen(buf)>=3){
				snprintf(_nick, sizeof(nick),"%s", &buf[3]);
				snprintf(message, PIPE_BUF, "NICK %s\r\n", &buf[3]);
			}
			break;
		case 'l':
			if(c->name[0] == 0)
				return;
			if(buf[2] == ' ' && strlen(buf)>=3)
				snprintf(message, PIPE_BUF, "PART %s :%s\r\n", c->name, &buf[3]);
			else
				snprintf(message, PIPE_BUF,
						"PART %s :ii - 500 SLOC are too much\r\n", c->name);
			tls_write_all(irc, message, strlen(message));

			close(c->fd);
			/*create_filepath(infile, sizeof(infile), c->name, "in");
			unlink(infile); */
			rm_channel(c);
			return;
			break;
		default:
			snprintf(message, PIPE_BUF, "%s\r\n", &buf[1]);
			break;
		}
	else
		snprintf(message, PIPE_BUF, "%s\r\n", &buf[1]);

	if (message[0] != '\0')
		tls_write_all(irc, message, strlen(message));
}

static void proc_server_cmd(char *buf) {
	char *argv[TOK_LAST], *cmd = NULL, *p = NULL;
	int i;

	if(!buf || *buf=='\0')
		return;

	for(i = 0; i < TOK_LAST; i++)
		argv[i] = NULL;
	/* <message>  ::= [':' <prefix> <SPACE> ] <command> <params> <crlf>
	   <prefix>   ::= <servername> | <nick> [ '!' <user> ] [ '@' <host> ]
	   <command>  ::= <letter> { <letter> } | <number> <number> <number>
	   <SPACE>    ::= ' ' { ' ' }
	   <params>   ::= <SPACE> [ ':' <trailing> | <middle> <params> ]
	   <middle>   ::= <Any *non-empty* sequence of octets not including SPACE
	   or NUL or CR or LF, the first of which may not be ':'>
	   <trailing> ::= <Any, possibly *empty*, sequence of octets not including NUL or CR or LF>
	   <crlf>     ::= CR LF */

	if(buf[0] == ':') {		/* check prefix */
		if (!(p = strchr(buf, ' '))) return;
		*p = 0;
		for(++p; *p == ' '; p++);
		cmd = p;
		argv[TOK_NICKSRV] = &buf[1];
		if((p = strchr(buf, '!'))) {
			*p = 0;
			argv[TOK_USER] = ++p;
		}
	} else
		cmd = buf;

	/* remove CRLFs */
	for(p = cmd; p && *p != 0; p++)
		if(*p == '\r' || *p == '\n')
			*p = 0;

	if((p = strchr(cmd, ':'))) {
		*p = 0;
		argv[TOK_TEXT] = ++p;
	}

	tokenize(&argv[TOK_CMD], TOK_LAST - TOK_CMD, cmd, ' ');

	if(!argv[TOK_CMD] || !strncmp("PONG", argv[TOK_CMD], 5)) {
		return;
	} else if(!strncmp("PING", argv[TOK_CMD], 5)) {
		snprintf(message, PIPE_BUF, "PONG %s\r\n", argv[TOK_TEXT]);
		tls_write_all(irc, message, strlen(message));

		return;
	} else if(!argv[TOK_NICKSRV] || !argv[TOK_USER]) {	/* server command */
		snprintf(message, PIPE_BUF, "%s%s", argv[TOK_ARG] ? argv[TOK_ARG] : "", argv[TOK_TEXT] ? argv[TOK_TEXT] : "");
		print_out(0, message);
		return;
	} else if(!strncmp("ERROR", argv[TOK_CMD], 6))
		snprintf(message, PIPE_BUF, "-!- error %s", argv[TOK_TEXT] ? argv[TOK_TEXT] : "unknown");
	else if(!strncmp("JOIN", argv[TOK_CMD], 5) && (argv[TOK_CHAN] || argv[TOK_TEXT])) {
		if (argv[TOK_TEXT] != NULL)
			argv[TOK_CHAN] = argv[TOK_TEXT];
		snprintf(message, PIPE_BUF, "-!- %s(%s) has joined %s", argv[TOK_NICKSRV], argv[TOK_USER], argv[TOK_CHAN]);
	} else if(!strncmp("PART", argv[TOK_CMD], 5) && argv[TOK_CHAN]) {
		snprintf(message, PIPE_BUF, "-!- %s(%s) has left %s", argv[TOK_NICKSRV], argv[TOK_USER], argv[TOK_CHAN]);
	} else if(!strncmp("MODE", argv[TOK_CMD], 5))
		snprintf(message, PIPE_BUF, "-!- %s changed mode/%s -> %s %s", argv[TOK_NICKSRV], argv[TOK_CMD + 1] ? argv[TOK_CMD + 1] : "" , argv[TOK_CMD + 2]? argv[TOK_CMD + 2] : "", argv[TOK_CMD + 3] ? argv[TOK_CMD + 3] : "");
	else if(!strncmp("QUIT", argv[TOK_CMD], 5))
		snprintf(message, PIPE_BUF, "-!- %s(%s) has quit \"%s\"", argv[TOK_NICKSRV], argv[TOK_USER], argv[TOK_TEXT] ? argv[TOK_TEXT] : "");
	else if(!strncmp("NICK", argv[TOK_CMD], 5) && argv[TOK_TEXT] && !strcmp(_nick, argv[TOK_TEXT])) {
		snprintf(nick, sizeof(nick), "%s", _nick);
		snprintf(message, PIPE_BUF, "-!- changed nick to \"%s\"", nick);
		print_out(NULL, message);
	} else if(!strncmp("NICK", argv[TOK_CMD], 5) && argv[TOK_TEXT])
		snprintf(message, PIPE_BUF, "-!- %s changed nick to %s", argv[TOK_NICKSRV], argv[TOK_TEXT]);
	else if(!strncmp("TOPIC", argv[TOK_CMD], 6))
		snprintf(message, PIPE_BUF, "-!- %s changed topic to \"%s\"", argv[TOK_NICKSRV], argv[TOK_TEXT] ? argv[TOK_TEXT] : "");
	else if(!strncmp("KICK", argv[TOK_CMD], 5) && argv[TOK_ARG])
		snprintf(message, PIPE_BUF, "-!- %s kicked %s (\"%s\")", argv[TOK_NICKSRV], argv[TOK_ARG], argv[TOK_TEXT] ? argv[TOK_TEXT] : "");
	else if(!strncmp("NOTICE", argv[TOK_CMD], 7))
		snprintf(message, PIPE_BUF, "-!- \"%s\")", argv[TOK_TEXT] ? argv[TOK_TEXT] : "");
	else if(!strncmp("PRIVMSG", argv[TOK_CMD], 8))
		snprintf(message, PIPE_BUF, "<%s> %s", argv[TOK_NICKSRV], argv[TOK_TEXT] ? argv[TOK_TEXT] : "");
	else
		return;	/* can't read this message */

	if(!argv[TOK_CHAN] || !strncmp(argv[TOK_CHAN], nick, strlen(nick)))
		print_out(argv[TOK_NICKSRV], message);
	else
		print_out(argv[TOK_CHAN], message);
}

static int read_line(int fd, size_t res_len, char *buf) {
	size_t i = 0;
	char c = 0;
	do {
		if(read(fd, &c, sizeof(char)) != sizeof(char))
			return -1;
		buf[i++] = c;
	}
	while(c != '\n' && i < res_len);
	buf[i - 1] = 0;			/* eliminates '\n' */
	return 0;
}

static int tls_read_line(struct tls *conn, size_t res_len, char *buf) {
	size_t i = 0;
	char c = 0;
	do {
		if(tls_read(conn, &c, sizeof(char)) != sizeof(char))
			return -1;
		buf[i++] = c;
	}
	while(c != '\n' && i < res_len);
	buf[i - 1] = 0;			/* eliminates '\n' */
	return 0;
}

static void handle_channels_input(Channel *c) {
	static char buf[PIPE_BUF];
	if(read_line(c->fd, PIPE_BUF, buf) == -1) {
		close(c->fd);
		int fd = open_channel(c->name);
		if(fd != -1)
			c->fd = fd;
		else
			rm_channel(c);
		return;
	}
	proc_channels_input(c, buf);
}

static void handle_server_output() {
	static char buf[PIPE_BUF];
	if(tls_read_line(irc, PIPE_BUF, buf) == -1) {
		fprintf(stderr, "ii: remote host closed connection: %s\n", tls_error(irc));
		exit(EXIT_FAILURE);
	}
	proc_server_cmd(buf);
}

static void run() {
	Channel *c, *n;
	int r, maxfd;
	fd_set rd;
	struct timeval tv;
	char ping_msg[512];

	snprintf(ping_msg, sizeof(ping_msg), "PING %s\r\n", host);
	for(;;) {
		FD_ZERO(&rd);
		maxfd = irc_fd;
		FD_SET(irc_fd, &rd);
		for(c = channels; c; c = c->next) {
			if(maxfd < c->fd)
				maxfd = c->fd;
			FD_SET(c->fd, &rd);
		}

		tv.tv_sec = 120;
		tv.tv_usec = 0;
		r = select(maxfd + 1, &rd, 0, 0, &tv);
		if(r < 0) {
			if(errno == EINTR)
				continue;
			perror("ii: error on select()");
			exit(EXIT_FAILURE);
		} else if(r == 0) {
			if(time(NULL) - last_response >= PING_TIMEOUT) {
				print_out(NULL, "-!- ii shutting down: ping timeout");
				exit(EXIT_TIMEOUT);
			}
			tls_write_all(irc, ping_msg, strlen(ping_msg));
			continue;
		}
		if(FD_ISSET(irc_fd, &rd)) {
			handle_server_output();
			last_response = time(NULL);
		}
		for(c = channels; c; c = n) {
			n = c->next;
			if(FD_ISSET(c->fd, &rd))
				handle_channels_input(c);
		}
	}
}

int main(int argc, char *argv[]) {
	int i;
	const char *port = SERVER_PORT;
	struct passwd *spw = getpwuid(getuid());
	char *key = NULL, *fullname = NULL;
	char prefix[_POSIX_PATH_MAX];

	if(!spw) {
		fputs("ii: getpwuid() failed\n", stderr);
		exit(EXIT_FAILURE);
	}
	snprintf(nick, sizeof(nick), "%s", spw->pw_name);
	snprintf(prefix, sizeof(prefix),"%s/irc", spw->pw_dir);
	if(argc <= 1 || (argc == 2 && argv[1][0] == '-' && argv[1][1] == 'h')) usage();

	if(tls_init() != 0) {
		fputs("ii: tls_init() failed\n", stderr);
		exit(EXIT_FAILURE);
	}
	tlsconf = tls_config_new();
	if(!tlsconf) {
		fputs("ii: tls_config_new() failed\n", stderr);
		exit(EXIT_FAILURE);
	}


	uint32_t tls_protocols;
	if(tls_config_parse_protocols(&tls_protocols, "legacy") != 0) {
		fputs("ii: tls_config_parse_protocols() failed\n", stderr);
		exit(EXIT_FAILURE);
	}

	// void return, wtf?
	tls_config_set_protocols(tlsconf, tls_protocols);
//	tls_config_set_protocols(tlsconf, TLS_PROTOCOL_TLSv1_2);
	/*
	if(tls_config_set_protocols(tlsconf, tls_protocols) != 0) {
		fprintf(stderr, "ii: tls_config_set_protocols() failed: %s\n", tls_config_error(tlsconf));
		exit(EXIT_FAILURE);
	}
	*/

	for(i = 1; (i + 1 < argc) && (argv[i][0] == '-'); i++) {
		switch (argv[i][1]) {
			case 'i': snprintf(prefix,sizeof(prefix),"%s", argv[++i]); break;
			case 's': host = argv[++i]; break;
			case 'p': port = argv[++i]; break;
			case 'n': snprintf(nick,sizeof(nick),"%s", argv[++i]); break;
			case 'k': key = getenv(argv[++i]); break;
			case 'f': fullname = argv[++i]; break;
			default: usage(); break;
		}
	}
	irc = tcpopen(port);

	#ifdef __OpenBSD__	/* OpenBSD pledge(2) support */
		if(pledge("stdio rpath wpath cpath dpath", NULL) == -1) {
			fprintf(stderr, "ii pledge: %s\n", strerror(errno));
			exit(EXIT_FAILURE);
		}
	#endif

	if(!snprintf(path, sizeof(path), "%s/%s", prefix, host)) {
		fputs("ii: path to irc directory too long\n", stderr);
		exit(EXIT_FAILURE);
	}
	create_dirtree(path);

	add_channel(""); /* master channel */
	login(key, fullname);
	run();

	return EXIT_SUCCESS;
}
