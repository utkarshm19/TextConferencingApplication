#define MAX_DATA 1000
#define MAX_NAME 19
#define MAX_BUF 1028

struct message {
	unsigned int type;
	unsigned int size;
	unsigned char source[MAX_NAME];
	unsigned char data[MAX_DATA];
};

#define LOGIN 1
#define LO_ACK 2
#define LO_NAK 3
#define EXIT 4
#define JOIN 5
#define JN_ACK 6
#define JN_NAK 7
#define LEAVE_SESS 8
#define NEW_SESS 9
#define NS_ACK 10
#define MESSAGE 11
#define QUERY 12
#define QU_ACK 13
#define LOGOUT 14
#define REGISTER 29
#define REG_ACK 30
#define REG_NAK 31

void convert_to_message(unsigned char *buf, struct message* msg) {
	msg->type = buf[0] + (buf[1] << 8) + (buf[2] << 16) + (buf[3] << 24);
	msg->size = buf[4] + (buf[5] << 8) + (buf[6] << 16) + (buf[7] << 24);
	strcpy(msg->source, buf + 8);
	memcpy(msg->data, buf + 8 + strlen(msg->source) + 1, msg->size);
}

unsigned int convert_from_message(struct message* msg, unsigned char *buf) {
	((unsigned int*) buf)[0] = msg->type;
	((unsigned int*) buf)[1] = msg->size;
	strcpy(buf + 8, msg->source);
	unsigned int id_len = strlen(msg->source);
	memcpy(buf + 8 + id_len + 1, msg->data, msg->size);
	return 8 + id_len + 1 + msg->size; 
}

