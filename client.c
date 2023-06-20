/*
 * ECE361 Text Conference Lab - client.c
 * Authors: Anthony Duong & Uttkarsh Mishra
 * Parts inspired by "Beej's Guide to Network Programming" Ch. 7.2
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <poll.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <errno.h>
#include <arpa/inet.h>
#include <netdb.h>
#include "main.h"

int get_sockfd(char *node, char *server_port, struct addrinfo* dst);
void send_message(int sockfd, struct message* msg);
int num_spaces(char *buf);

void handle_input(unsigned char input_buf[], struct pollfd pfds[], int* fd_count, unsigned char* cur_client_id, int* session);
void login(int sockfd, unsigned char* client_id, unsigned char* password);
void register_account(int sockfd, unsigned char* client_id, unsigned char* password);
void logout(int sockfd, unsigned char* client_id, int* fd_count);
void join_session(int sockfd, unsigned char* session_id, unsigned char* cur_client_id);
void leave_session(int sockfd, unsigned char* client_id);
void create_session(int sockfd, unsigned char* session_id, unsigned char* cur_client_id);
void message_session(int sockfd, unsigned char* message_data, unsigned char* cur_client_id);
void list(int sockfd, unsigned char* client_id);

void handle_message(unsigned char* msg_buf, struct pollfd pfds[], int* fd_count, int* session);

int main() {
	unsigned char input_buf[MAX_BUF];
	unsigned char serv_buf[MAX_BUF];
	int bytes_read = 0;
	unsigned char cur_client_id[MAX_NAME];
	cur_client_id[0] = '\0';
	int session = 0;

	int fd_count = 1;
	struct pollfd pfds[2];
	pfds[0].fd = STDIN_FILENO;
	pfds[0].events = POLLIN;

	for (;;) {
		int poll_count = poll(pfds, fd_count, -1);

		if (poll_count == -1) {
			perror("poll");
			exit(1);
		}
		if (pfds[0].revents & POLLIN) {
			int nbytes = read(pfds[0].fd, input_buf, MAX_BUF);
			input_buf[nbytes - 1] = '\0';
			handle_input(input_buf, pfds, &fd_count, cur_client_id, &session);
		} else if (fd_count == 2 && pfds[1].revents & POLLIN) {
			int sockfd = pfds[1].fd;
			if (bytes_read < 4) {
				int nbytes = recv(sockfd, serv_buf + bytes_read, 4, 0);
				if (nbytes == -1) {
					perror("recv");
				} else if (nbytes == 0) {
					cur_client_id[0] = '\0';
					close(sockfd);
					fd_count--;
				} else {
					bytes_read += nbytes;
				}
			}
			if (bytes_read >= 4) {
				unsigned int msg_size = *(unsigned int *)serv_buf;
				int nbytes = recv(sockfd, serv_buf + bytes_read, 
						msg_size - (bytes_read - 4), 0);
				if (nbytes == -1) {
					perror("recv");
				} else if (nbytes == 0) {
					cur_client_id[0] = '\0';
					close(sockfd);
					fd_count--;
				} else {
					bytes_read += nbytes;
					if (msg_size == bytes_read - 4) { // entire message has been read
						handle_message(serv_buf, pfds, &fd_count, &session);
						// reset buf
						memset(serv_buf, 0, bytes_read);
						bytes_read = 0;
					}
					if (fd_count == 1) {
						cur_client_id[0] = '\0';
					}
				}
			}
		}


	}
	return 0;
}

void handle_input(unsigned char input_buf[], struct pollfd pfds[], int* fd_count, unsigned char* cur_client_id, int* session) {
	int sockfd = pfds[1].fd;
	if (input_buf[0] == '/') {
		int num_args = num_spaces(input_buf);
		unsigned char *cmd = strtok(input_buf, " ");
		if (strcmp(cmd, "/login") == 0) {
			if (num_args < 4) {
				printf("Incorrect format: /login <client_id> <password> <server_ip> <server_port>\n");
				return;
			}
			unsigned char* client_id = strtok(NULL, " ");
			unsigned char* password = strtok(NULL, " ");
			unsigned char* server_ip = strtok(NULL, " ");
			unsigned char* server_port = strtok(NULL, " ");
			strcpy(cur_client_id, client_id);
			struct addrinfo dst;
			int new_sockfd = get_sockfd(server_ip, server_port, &dst);
			pfds[1].fd = new_sockfd;
			pfds[1].events = POLLIN;
			(*fd_count)++;

			login(new_sockfd, client_id, password);
		} else if (strcmp(cmd, "/register") == 0) {
			if (num_args < 4) {
				printf("Incorrect format: /register <client_id> <password> <server_ip> <server_port>\n");
				return;
			}
			unsigned char* client_id = strtok(NULL, " ");
			unsigned char* password = strtok(NULL, " ");
			unsigned char* server_ip = strtok(NULL, " ");
			unsigned char* server_port = strtok(NULL, " ");
			strcpy(cur_client_id, client_id);
			struct addrinfo dst;
			int new_sockfd = get_sockfd(server_ip, server_port, &dst);
			pfds[1].fd = new_sockfd;
			pfds[1].events = POLLIN;
			(*fd_count)++;

			register_account(new_sockfd, client_id, password);
		} else if (strcmp(cmd, "/quit") == 0) {
			if(strcmp(cur_client_id, "") != 0){
				logout(sockfd, cur_client_id, fd_count);
			}
			exit(0);
		} else if(strcmp(cur_client_id, "") != 0) {
			if (strcmp(cmd, "/logout") == 0) {
				logout(sockfd, cur_client_id, fd_count);
				*session = 0;
			} else if (strcmp(cmd, "/joinsession") == 0) {
				if (num_args < 1) {
					printf("Incorrect format: /joinsession <session_id>\n");
					return;
				}
				unsigned char* session_id = strtok(NULL, " ");
				join_session(sockfd, session_id, cur_client_id);
			} else if (strcmp(cmd, "/leavesession") == 0) {
				leave_session(pfds[1].fd, cur_client_id);
				*session = 0;
				printf("Left session.\n");
			} else if (strcmp(cmd, "/createsession") == 0) {
				if (num_args < 1) {
					printf("Incorrect format: /createsession <session_id>\n");
					return;
				}
				unsigned char* session_id = strtok(NULL, " ");
				create_session(sockfd, session_id, cur_client_id);
			} else if (strcmp(cmd, "/list") == 0) {
				list(sockfd, cur_client_id);
			} else {
				printf("Invalid command\n");
			}
		} else {
			printf("Please Login. No user is logged in currently\n");
		}
	} else {
		if (strcmp(cur_client_id, "") == 0) {
			printf("Please Login. No user is logged in currently\n");
		} else if (session == 0) {
			printf("Please join a session.\n");
		} else {
			message_session(sockfd, input_buf, cur_client_id);
		}
	}
}

void login(int sockfd, unsigned char* client_id, unsigned char* password) {
	struct message msg;
	msg.type = LOGIN;
	strcpy(msg.source, client_id);
	strcpy(msg.data, password);
	msg.size = strlen(msg.data) + 1;
	send_message(sockfd, &msg);
}

void register_account(int sockfd, unsigned char* client_id, unsigned char* password) {
	struct message msg;
	msg.type = REGISTER;
	strcpy(msg.source, client_id);
	strcpy(msg.data, password);
	msg.size = strlen(msg.data) + 1;
	send_message(sockfd, &msg);
}

void logout(int sockfd, unsigned char* client_id, int* fd_count){
	struct message msg;
	msg.type = EXIT;
	strcpy(msg.source, client_id);
	msg.size = 0;
	send_message(sockfd, &msg);

	client_id[0] = '\0';
	close(sockfd);
	(*fd_count)--;
	printf("Logged out.\n");
}

void join_session(int sockfd, unsigned char* session_id, unsigned char* cur_client_id) {
	struct message msg;
	msg.type = JOIN;
	strcpy(msg.source, cur_client_id);
	strcpy(msg.data, session_id);
	msg.size = strlen(msg.data) + 1;
	send_message(sockfd, &msg);
}

void leave_session(int sockfd, unsigned char* client_id) {
	struct message msg;
	msg.type = LEAVE_SESS;
	strcpy(msg.source, client_id);
	msg.size = 0;
	send_message(sockfd, &msg);
}

void create_session(int sockfd, unsigned char* session_id, unsigned char* cur_client_id) {
	struct message msg;
	msg.type = NEW_SESS;
	strcpy(msg.source, cur_client_id);
	strcpy(msg.data, session_id);
	msg.size = strlen(msg.data) + 1;
	send_message(sockfd, &msg);
}

void message_session(int sockfd, unsigned char* message_data, unsigned char* cur_client_id) {
	struct message msg;
	msg.type = MESSAGE;
	strcpy(msg.source, cur_client_id);
	strcpy(msg.data, message_data);
	msg.size = strlen(msg.data) + 1;
	send_message(sockfd, &msg);
}

void list(int sockfd, unsigned char* client_id){
	struct message msg;
	msg.type = QUERY;
	strcpy(msg.source, client_id);
	msg.size = 0;
	send_message(sockfd, &msg);
}

void send_message(int sockfd, struct message* msg) {
	unsigned char buf[MAX_BUF];
	unsigned int len = convert_from_message(msg, buf + 4);
	((unsigned int*)buf)[0] = len;
	if (send(sockfd, buf, len + 4, 0) == -1) {
		perror("send");
	}
}

void handle_message(unsigned char* msg_buf, struct pollfd pfds[], int* fd_count, int* session) {
	struct message msg;
	convert_to_message(msg_buf + 4, &msg);
	switch (msg.type) {
		case LO_ACK:
			printf("Logged in\n");
			break;
		case LO_NAK:
			printf("Unsuccessful login: %s\n", msg.data);
			close(pfds[1].fd);
			(*fd_count)--;
			break;
		case REG_ACK:
			printf("Successfully registered and logged in.\n");
			break;
		case REG_NAK:
			printf("Unsuccessful registration: %s\n", msg.data);
			close(pfds[1].fd);
			(*fd_count)--;
			break;
		case JN_ACK:
			printf("Joined session %s\n", msg.data);
			*session = 1;
			break;
		case JN_NAK:
			printf("Unable to join: %s\n", msg.data);
			*session = 0;
			break;
		case NS_ACK:
			printf("Joined session %s\n", msg.data);
			*session = 1;
			break;
		case MESSAGE:
			printf("%s: %s\n", msg.source, msg.data);
			break;
		case QU_ACK:
			printf("%s", msg.data);
			break;
		case LOGOUT:
			printf("Logged out: %s", msg.data);
			break;
		default:
			perror("unkown message type");
			break;
	}
}

int num_spaces(char *buf) {
	int count = 0;
	for (int i = 0; buf[i] != '\0'; i++) {
		count += (buf[i] == ' ') ? 1 : 0;
	}
	return count;
}

int get_sockfd(char *node, char *server_port, struct addrinfo* dst)
{
	int sockfd;
	struct addrinfo hints, *servinfo, *p;
	int rv;

	memset(&hints, 0, sizeof hints);
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;

	if ((rv = getaddrinfo(node, server_port, &hints, &servinfo)) != 0) {
		fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(rv));
		return -1;
	}

	// loop through all the results and make a socket
	for(p = servinfo; p != NULL; p = p->ai_next) {
		if ((sockfd = socket(p->ai_family, p->ai_socktype,
			p->ai_protocol)) == -1) {
			perror("socket");
			continue;
		}
		if (connect(sockfd, p->ai_addr, p->ai_addrlen) == -1) {
			close(sockfd);
			perror("connect");
			continue;
		}
		break;
	}

	if (p == NULL) {
		fprintf(stderr, "failed to create socket\n");
		return -1;
	}

	freeaddrinfo(servinfo);
	return sockfd;
}
