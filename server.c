/*
 * ECE361 Text Conference Lab - server.c
 * Authors: Anthony Duong & Uttkarsh Mishra
 * Parts inspired by "Beej's Guide to Network Programming" Ch. 7.2
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <poll.h>
#include "main.h"
#include <time.h>

#define MAX_CLIENTS 5
#define INACTIVITY_TO 60

struct client {
	int sockfd;
	unsigned char id[MAX_NAME];
	unsigned int bytes_read;
	unsigned int msg_size;
	unsigned char msg_buf[MAX_BUF + 4];
	struct session* curr_session;
	time_t last_active_time;
};

struct session {
	unsigned char id[MAX_NAME];
	struct client** clients;
	int num_clients;
};

struct userpwd {
	unsigned char username[MAX_NAME];
	unsigned char password[MAX_NAME];
};

struct client* init_client_list();
struct session* init_session_list();
int get_socket_file_descriptor(char* port_num);
struct client* get_client_by_fd(int sockfd, struct client client_list[], int num_clients);

void *get_in_addr(struct sockaddr *sa);
void print_ip_and_port(int sockfd);
void send_message(int sockfd, struct message* msg);

void handle_message(struct client* client, struct client* client_list, struct session* session_list, struct pollfd pfds[], int* fd_count);
void handle_login(struct message* msg, struct client* client, struct client* client_list, int num_clients);
void handle_registration(struct message* msg, struct client* client);
void logout(struct client* client, struct client* client_list, struct pollfd pfds[], int* fd_count, char* reason);
void add_session(struct message* msg, struct client* client, struct session* session_list);
void join_session(struct message* msg, struct client* client, struct session* session_list); 
void leave_session(struct client* client);
void forward_message(struct message* msg, struct client* client);
void query(struct client* client, struct client* client_list, int num_clients, struct session* session_list);

struct userpwd* get_all_username_passwords(int* len);

#define BYTE_TO_BINARY_PATTERN "%c%c%c%c%c%c%c%c"
#define BYTE_TO_BINARY(byte)  \
	  ((byte) & 0x80 ? '1' : '0'), \
  ((byte) & 0x40 ? '1' : '0'), \
  ((byte) & 0x20 ? '1' : '0'), \
  ((byte) & 0x10 ? '1' : '0'), \
  ((byte) & 0x08 ? '1' : '0'), \
  ((byte) & 0x04 ? '1' : '0'), \
  ((byte) & 0x02 ? '1' : '0'), \
  ((byte) & 0x01 ? '1' : '0') 

int main(int argc, char* argv[])
{
	if (argc != 2) {
		fprintf(stderr, "usage %s <port number>\n", argv[0]);
		exit(1);
	}
	int listenerfd = get_socket_file_descriptor(argv[1]);

	struct client* client_list = init_client_list();
	struct session* session_list = init_session_list();
	int fd_count = 0;
	struct pollfd *pfds = malloc(sizeof *pfds * MAX_CLIENTS);

	pfds[0].fd = listenerfd;
	pfds[0].events = POLLIN;
	fd_count = 1;
	double highest_time = 0;
	int newfd;
	struct sockaddr_storage remoteaddr;
	socklen_t addrlen;
	for(;;) {
		int poll_count = poll(pfds, fd_count, (INACTIVITY_TO - highest_time) * 1000);
		if (poll_count == -1) {
			perror("poll");
			exit(1);
		}
		//getting current time
		time_t now;
		time(&now);

		for (int i = 0; i < fd_count; i++) {
			if (pfds[i].revents & POLLIN) {
				if (pfds[i].fd == listenerfd) {
					addrlen = sizeof remoteaddr;
					newfd = accept(listenerfd, 
							(struct sockaddr *)&remoteaddr,
							&addrlen);
					if (newfd == -1) {
						perror("accept");
					} else {
						client_list[fd_count - 1].sockfd = newfd;
						client_list[fd_count - 1].id[0] = '\0';
						client_list[fd_count - 1].last_active_time = now;
						pfds[fd_count].fd = newfd;
						pfds[fd_count].events = POLLIN;
						fd_count++;
					}
				} else { // regular client
					int sockfd = pfds[i].fd;
					// print_ip_and_port(sockfd);
					struct client* client = get_client_by_fd(sockfd, client_list, fd_count - 1);
					//updating last active time
					client->last_active_time = now;
					if (client->bytes_read < 4) {
						int nbytes = recv(sockfd, client->msg_buf + client->bytes_read, 4, 0);
						if (nbytes == -1) {
							perror("recv");
						} else if (nbytes == 0) {
							logout(client, client_list, pfds, &fd_count, "\n");
						} else {
							client->bytes_read += nbytes;
						}
					}
					if (client->bytes_read >= 4) {
						client->msg_size = *(unsigned int *)client->msg_buf;
						int nbytes = recv(sockfd, client->msg_buf + client->bytes_read, 
								client->msg_size - (client->bytes_read - 4), 0);
						if (nbytes == -1) {
							perror("recv");
						} else if (nbytes == 0) {
							logout(client, client_list, pfds, &fd_count, "\n");
						} else {
							client->bytes_read += nbytes;
							if (client->msg_size == client->bytes_read - 4) {
								handle_message(client, client_list, session_list, pfds, &fd_count);
							}
						}
					}
				}
			}
		}
		
		highest_time = 0;
		for (int i = 0; i < fd_count; i++) {
			//checking if client is active or not
			if(pfds[i].fd != listenerfd){
				int sockfd = pfds[i].fd;
				struct client* client = get_client_by_fd(sockfd, client_list, fd_count - 1);
				if (difftime(now, client->last_active_time) >= INACTIVITY_TO){
					char* reason = "Disconnected due to inactivity.\n";
					logout(client, client_list, pfds, &fd_count, reason);
					i--; // adjust the loop counter to avoid skipping clients
				} else if (difftime(now, client->last_active_time) > highest_time) {
					highest_time = difftime(now, client->last_active_time);
				}
			}
		}
	}
	return 0;
}


int get_socket_file_descriptor(char* port_num)
{
	int sockfd;
	int rv;
	struct addrinfo hints, *servinfo, *p;
	int yes = 1;

	memset(&hints, 0, sizeof hints);
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = AI_PASSIVE; // use my IP

	if ((rv = getaddrinfo(NULL, port_num, &hints, &servinfo)) != 0) {
		fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(rv));
		exit(1);
	}

	// loop through all the results and bind to the first we can
 	for (p = servinfo; p != NULL; p = p->ai_next) {
 		if ((sockfd = socket(p->ai_family, p->ai_socktype,
 				p->ai_protocol)) == -1) {
 				perror("socket");
 				continue;
 		}
		setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int));
		if (bind(sockfd, p->ai_addr, p->ai_addrlen) == -1) {
 			close(sockfd);
 			perror("bind");
 			continue;
 		}
 		break;
 	}
	freeaddrinfo(servinfo);
 	if (p == NULL) {
 		fprintf(stderr, "failed to bind socket\n");
 		exit(2);
 	}
	if (listen(sockfd, 10) == -1) {
		perror("listen");
		exit(1);
	}

 	return sockfd;
}

void handle_message(struct client* client, struct client* client_list, struct session* session_list,
	       	struct pollfd pfds[], int* fd_count) {
	struct message msg;
	convert_to_message(client->msg_buf + 4, &msg);
	switch (msg.type) {
		case LOGIN:
			handle_login(&msg, client, client_list, *fd_count - 1);
			break;
		case REGISTER:
			handle_registration(&msg, client);
			break;
		case EXIT:
			logout(client, client_list, pfds, fd_count, "\n");
			break;
		case JOIN:
			join_session(&msg, client, session_list);
			break;
		case LEAVE_SESS:
			leave_session(client);
			break;
		case NEW_SESS:
			add_session(&msg, client, session_list);
			break;
		case MESSAGE:
			forward_message(&msg, client);
			break;
		case QUERY:
			query(client, client_list, *fd_count - 1, session_list);
			break;
		default:
			perror("unkown message type");
			break;
	}
	// reset client message
	memset(client->msg_buf, 0, client->bytes_read);
	client->msg_size = 0;
	client->bytes_read = 0;

}

void handle_login(struct message* msg, struct client* client, struct client* client_list, int num_clients) {
	
	int num_reg_users = 0;
	struct userpwd* userpwds = get_all_username_passwords(&num_reg_users);
	struct message ret_msg;
	ret_msg.source[0] = '\0';
	bool ret_msg_set = false;

	// Check if user is already logged in
	for (int i = 0; i < num_clients; i++) {
		if (strcmp(msg->source, client_list[i].id) == 0) {
			ret_msg.type = LO_NAK;
			sprintf(ret_msg.data, "User %s is already logged in.\n", msg->source);
			ret_msg_set = true;
			break;
		}
	}
	
	// Go through all username and password pairs to find a match
	for (int i = 0; !ret_msg_set && i < num_reg_users; i++) {
		if (strcmp(msg->source, userpwds[i].username) == 0) {
			if (strcmp(msg->data, userpwds[i].password) == 0) {
				printf("Logged in %s\n", msg->source);
				// login success
				strcpy(client->id, msg->source);
				ret_msg.type = LO_ACK;
				strcpy(ret_msg.data, "");
			} else {
				// wrong password
				ret_msg.type = LO_NAK;
				sprintf(ret_msg.data, "Incorrect password.");
			}
			ret_msg_set = true;
		}

	}
	free(userpwds);

	// user not found
	if (!ret_msg_set) {
		ret_msg.type = LO_NAK;
		sprintf(ret_msg.data, "User %s not found.", msg->source);
		ret_msg_set = true;
	}

	ret_msg.size = strlen(ret_msg.data) + 1;
	send_message(client->sockfd, &ret_msg);
}

void handle_registration(struct message* msg, struct client* client) {
	struct message ret_msg;
	ret_msg.source[0] = '\0';
	bool ret_msg_set = false;
	
	// Check if username is valid
	if (strlen(msg->source) > MAX_NAME) {
		ret_msg.type = REG_NAK;
		sprintf(ret_msg.data, "Username must be %s or less characters long.", MAX_NAME);
		ret_msg_set = true;
	}
	int num_reg_users = 0;
	struct userpwd* userpwds = get_all_username_passwords(&num_reg_users);
	// Go through all usernames to see if username is taken
	for (int i = 0; !ret_msg_set && i < num_reg_users; i++) {
		if (strcmp(msg->source, userpwds[i].username) == 0) {
			ret_msg.type = REG_NAK;
			sprintf(ret_msg.data, "Username %s is already taken.", msg->source);
			ret_msg_set = true;
		}

	}
	free(userpwds);

	// Check if password is valid
	if (!ret_msg_set && strlen(msg->data) > MAX_NAME) {
		ret_msg.type = REG_NAK;
		sprintf(ret_msg.data, "Password must be %s or less characters long.", MAX_NAME);
		ret_msg_set = true;
	}
	for (int i = 0; !ret_msg_set && i < strlen(msg->data); i++) {
		if (msg->data[i] == ',') {
			ret_msg.type = REG_NAK;
			sprintf(ret_msg.data, "Password must not contain commas.");
			ret_msg_set = true;
		}
	}

	// Valid username and password
	if (!ret_msg_set) {
	       	strcpy(client->id, msg->source); // populating the id field means the user is logged in
		// Save username and password to file
		FILE* file = fopen("users.txt", "a");
		fprintf(file, "%s,%s\n", msg->source, msg->data);
		fclose(file);

		ret_msg.type = REG_ACK;
		strcpy(ret_msg.data, "");
		ret_msg_set = true;
	}

	ret_msg.size = strlen(ret_msg.data) + 1;
	send_message(client->sockfd, &ret_msg);
}

void logout(struct client* client, struct client* client_list, struct pollfd pfds[], int* fd_count, char* reason) {
	printf("Logging out %s.\n", client->id);
	leave_session(client);

	struct message ret_msg;
	ret_msg.type = LOGOUT;
	ret_msg.source[0] = '\0';
	strcpy(ret_msg.data, reason);
	ret_msg.size = strlen(reason);
	send_message(client->sockfd, &ret_msg);

	int old_fd_count = *fd_count;
	close(client->sockfd);
	for (int i = 0; i < old_fd_count; i++) {
		if (pfds[i].fd == client->sockfd) {
			pfds[i] = pfds[old_fd_count - 1];
			(*fd_count)--;
			break;
		}
	}
	for (int i = 0; i < old_fd_count - 1; i++) {
		if (client_list[i].sockfd == client->sockfd) {
			client_list[i] = client_list[old_fd_count - 2];
			break;
		}
	}
}

void add_session(struct message* msg, struct client* client, struct session* session_list) {
	struct message ret_msg;
	ret_msg.type = NS_ACK;
	ret_msg.source[0] = '\0';
	strcpy(ret_msg.data, msg->data);
	ret_msg.size = strlen(ret_msg.data) + 1;

	for (int i = 0; i < MAX_CLIENTS; i++) {
		if (session_list[i].id[0] == '\0') {
			struct session* session = session_list + i;
			strcpy(session->id, msg->data);
			session->clients = malloc(sizeof (struct client*) * MAX_CLIENTS);

			if (client->curr_session) {
				leave_session(client);
			}
			session->clients[0] = client;
			session->num_clients = 1;
			client->curr_session = session;
			
			send_message(client->sockfd, &ret_msg);
			break;
		}
	}
}

void join_session(struct message* msg, struct client* client, struct session* session_list) { 
	struct message ret_msg;
	ret_msg.source[0] = '\0';
	bool added = false;
	for (int i = 0; i < MAX_CLIENTS; i++) {
		if (strcmp(session_list[i].id, msg->data) == 0) {
			struct session* session = session_list + i;
			session->clients[session->num_clients] = client;
			session->num_clients++;

			if (client->curr_session) {
				leave_session(client);
			}
			client->curr_session = session;
			added = true;

			ret_msg.type = JN_ACK;
			strcpy(ret_msg.data, msg->data);
			ret_msg.size = strlen(ret_msg.data) + 1;
			break;
		}
	}
	if (!added) {
		ret_msg.type = JN_NAK;
		sprintf(ret_msg.data, "No session with id %s.", msg->data);
		ret_msg.size = strlen(ret_msg.data) + 1;
	}
	send_message(client->sockfd, &ret_msg);
}

void leave_session(struct client* client) {
	if (client->curr_session == NULL) {
		return;
	}
	struct session* session = client->curr_session;
	for (int i = 0; i < session->num_clients; i++) {
		if (strcmp(session->clients[i]->id, client->id) == 0) {
			session->clients[i] = session->clients[session->num_clients - 1];
			session->num_clients--;
			break;
		}
	}
	
	client->curr_session = NULL;

	if (session->num_clients == 0) {
		free(session->clients);
		session->id[0] = '\0';
	}
}

void forward_message(struct message* msg, struct client* client) {
	struct message fwd;
	fwd.type = MESSAGE;
	strcpy(fwd.source, msg->source); // source is original sender, not server
	strcpy(fwd.data, msg->data);
	fwd.size = strlen(fwd.data) + 1;

	struct session* session = client->curr_session;
	if (session) {
		for (int i = 0; i < session->num_clients; i++) {
			if (client->sockfd != session->clients[i]->sockfd) {
				send_message(session->clients[i]->sockfd, &fwd);
			}
		}
	}
}

void query(struct client* client, struct client* client_list, int num_clients, struct session* session_list) {
	struct message ret_msg;
	ret_msg.type = QU_ACK;
	ret_msg.source[0] = '\0';
	int nbytes = 0;
	nbytes = sprintf(ret_msg.data, "Client List: \n");
	if (nbytes < 0) {
		perror("sprintf");
	} else {
		ret_msg.size = nbytes;
	}
	for (int i = 0; i < num_clients; i++) {
		nbytes = sprintf(ret_msg.data + ret_msg.size, "\t %s\n", client_list[i].id);
		if (nbytes < 0) {
			perror("sprintf");
		} else {
			ret_msg.size += nbytes;
		}
	}
	nbytes = sprintf(ret_msg.data + ret_msg.size, "Session List: \n");
	if (nbytes < 0) {
		perror("sprintf");
	} else {
		ret_msg.size += nbytes;
	}
	for (int i = 0; i < MAX_CLIENTS; i++) {
		if (session_list[i].id[0] != '\0') {
			nbytes = sprintf(ret_msg.data + ret_msg.size, "\t %s\n", session_list[i].id);
			if (nbytes < 0) {
				perror("sprintf");
			} else {
				ret_msg.size += nbytes;
			}
			for (int j = 0; j < session_list[i].num_clients; j++) {
				nbytes = sprintf(ret_msg.data + ret_msg.size, "\t\t %s\n", session_list[i].clients[j]->id);
				if (nbytes < 0) {
					perror("sprintf");
				} else {
					ret_msg.size += nbytes;
				}

			}
		}
	}

	ret_msg.size += 1;
	send_message(client->sockfd, &ret_msg);
}

void send_message(int sockfd, struct message* msg) {
	unsigned char buf[MAX_BUF];
	unsigned int len = convert_from_message(msg, buf + 4);
	((unsigned int*)buf)[0] = len;
	if (send(sockfd, buf, len + 4, 0) == -1) {
		perror("send");
	}
}

int get_num_lines_in_file(char* filename) {
	FILE* file;
	if ((file = fopen(filename, "r")) == NULL) {
		perror("fopen");
		exit(1);
	}
	char c;
	int count = 0;
	for (c = getc(file); c != EOF; c = getc(file)) {
		count += (c == '\n' ? 1 : 0);
	}
	fclose(file);
	return count;
}

struct userpwd* get_all_username_passwords(int* num_users) {
	char *filename = "users.txt";
	int num_lines = get_num_lines_in_file(filename);
	*num_users = num_lines;
	struct userpwd* userpwds = malloc(sizeof(struct userpwd) * num_lines);
	FILE* file;
	if ((file = fopen(filename, "r")) == NULL) {
		perror("fopen");
		exit(1);
	}

	int buf_len = 2 * MAX_NAME + 2;
	char buf[buf_len];
	for (int i = 0; i < num_lines; i++) {
		fgets(buf, buf_len, file); 
		char* username = strtok(buf, ",");
		char* password = strtok(NULL, "\n");
		strcpy(userpwds[i].username, username);
		strcpy(userpwds[i].password, password);
	}

	return userpwds;
}

struct client* init_client_list() {
	struct client* client_list = malloc(sizeof (struct client) * MAX_CLIENTS);
	memset(client_list, 0, sizeof (struct client) * MAX_CLIENTS);
	for (int i = 0; i < MAX_CLIENTS; i++) {
		client_list[i].id[0] = '\0';
		client_list[i].curr_session = NULL;
	}
	return client_list;
}

struct session* init_session_list() {
	struct session* session_list = malloc(sizeof (struct session) * MAX_CLIENTS);
	memset(session_list, 0, sizeof (struct session) * MAX_CLIENTS);
	for (int i = 0; i < MAX_CLIENTS; i++) {
		session_list[i].id[0] = '\0';
		session_list[i].clients = NULL;
	}
	return session_list;
}

struct client* get_client_by_fd(int sockfd, struct client client_list[], int num_clients) {
	for (int i = 0; i < num_clients; i++) {
		if (client_list[i].sockfd == sockfd) {
			return client_list + i;
		}
	}
	perror("no client with fd");
	return NULL;
}

void *get_in_addr(struct sockaddr *sa) {
	if (sa->sa_family == AF_INET) {
		return &(((struct sockaddr_in*)sa)->sin_addr);
	}
	return &(((struct sockaddr_in6*)sa)->sin6_addr);
}

void print_ip_and_port(int sockfd) {
	struct sockaddr_in addr;
	socklen_t addr_size = sizeof(struct sockaddr_in);
	int res = getpeername(sockfd, (struct sockaddr *)&addr, &addr_size);
	printf("%s %d\n", inet_ntoa(addr.sin_addr), ntohs(addr.sin_port));
}

