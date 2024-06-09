/* Chat Application: 
Build a simple chat application using TCP sockets, supporting multiple clients and a server. */

#include <arpa/inet.h>
#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <openssl/sha.h>
#include <pthread.h>
#include <regex.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#define PORT 8080
#define BUFFER_SIZE 104857600
#define MAX_CLIENT_COUNT 10
#define USR_MAX_CHAR 30

uint8_t client_list[MAX_CLIENT_COUNT];
uint8_t client_count = 0;
uint32_t encoding_codes[MAX_CLIENT_COUNT];
char client_names[MAX_CLIENT_COUNT][USR_MAX_CHAR];

static char encoding_table[] = {'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H',
                                'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P',
                                'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X',
                                'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f',
                                'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n',
                                'o', 'p', 'q', 'r', 's', 't', 'u', 'v',
                                'w', 'x', 'y', 'z', '0', '1', '2', '3',
                                '4', '5', '6', '7', '8', '9', '+', '/'};
static char *decoding_table = NULL;
static int mod_table[] = {0, 2, 1};

const char *get_file_extension(const char *file_name) {
    const char *dot = strrchr(file_name, '.');
    if (!dot || dot == file_name) {
        return "";
    }
    return dot + 1;
}

const char *get_mime_type(const char *file_ext) {
    if (strcasecmp(file_ext, "html") == 0 || strcasecmp(file_ext, "htm") == 0) {
        return "text/html";
    } else if (strcasecmp(file_ext, "txt") == 0) {
        return "text/plain";
    } else if (strcasecmp(file_ext, "jpg") == 0 || strcasecmp(file_ext, "jpeg") == 0) {
        return "image/jpeg";
    } else if (strcasecmp(file_ext, "png") == 0) {
        return "image/png";
    } else {
        return "application/octet-stream";
    }
}

bool case_insensitive_compare(const char *s1, const char *s2) {
    while (*s1 && *s2) {
        if (tolower((unsigned char)*s1) != tolower((unsigned char)*s2)) {
            return false;
        }
        s1++;
        s2++;
    }
    return *s1 == *s2;
}

char *get_file_case_insensitive(const char *file_name) {
    DIR *dir = opendir(".");
    if (dir == NULL) {
        perror("opendir");
        return NULL;
    }

    struct dirent *entry;
    char *found_file_name = NULL;
    while ((entry = readdir(dir)) != NULL) {
        if (case_insensitive_compare(entry->d_name, file_name)) {
            found_file_name = entry->d_name;
            break;
        }
    }

    closedir(dir);
    return found_file_name;
}

char *url_decode(const char *src) {
    size_t src_len = strlen(src);
    char *decoded = malloc(src_len + 1);
    size_t decoded_len = 0;

    // decode %2x to hex
    for (size_t i = 0; i < src_len; i++) {
        if (src[i] == '%' && i + 2 < src_len) {
            int hex_val;
            sscanf(src + i + 1, "%2x", &hex_val);
            decoded[decoded_len++] = hex_val;
            i += 2;
        } else {
            decoded[decoded_len++] = src[i];
        }
    }

    // add null terminator
    decoded[decoded_len] = '\0';
    return decoded;
}

void build_http_response(const char *file_name, 
                        const char *file_ext, 
                        char *response, 
                        size_t *response_len) {
    // build HTTP header
    const char *mime_type = get_mime_type(file_ext);
    char *header = (char *)malloc(BUFFER_SIZE * sizeof(char));
    snprintf(header, BUFFER_SIZE,
             "HTTP/1.1 200 OK\r\n"
             "Content-Type: %s\r\n"
             "\r\n",
             mime_type);

    // if file not exist, response is 404 Not Found
    int file_fd = open(file_name, O_RDONLY);
    if (file_fd == -1) {
        snprintf(response, BUFFER_SIZE,
                 "HTTP/1.1 404 Not Found\r\n"
                 "Content-Type: text/plain\r\n"
                 "\r\n"
                 "404 Not Found");
        *response_len = strlen(response);
        return;
    }

    // get file size for Content-Length
    struct stat file_stat;
    fstat(file_fd, &file_stat);
    off_t file_size = file_stat.st_size;

    // copy header to response buffer
    *response_len = 0;
    memcpy(response, header, strlen(header));
    *response_len += strlen(header);

    // copy file to response buffer
    ssize_t bytes_read;
    while ((bytes_read = read(file_fd, 
                            response + *response_len, 
                            BUFFER_SIZE - *response_len)) > 0) {
        *response_len += bytes_read;
    }
    free(header);
    close(file_fd);
}

void build_websocket_response(char *response, size_t *response_len, const char *key) {
    snprintf(response, BUFFER_SIZE,
                "HTTP/1.1 101 Switching Protocolsr\n"
                "Upgrade: websocket\r\n"
                "Connection: Upgrade\r\n"
                "Sec-WebSocket-Accept: %s\r\n"
                "\r\n",
                key);
    *response_len = strlen(response);
}

char *base64_encode(const unsigned char *data,
                    size_t input_length,
                    size_t *output_length) {

    *output_length = 4 * ((input_length + 2) / 3);

    char *encoded_data = malloc(*output_length);
    if (encoded_data == NULL) return NULL;

    for (int i = 0, j = 0; i < input_length;) {

        uint32_t octet_a = i < input_length ? (unsigned char)data[i++] : 0;
        uint32_t octet_b = i < input_length ? (unsigned char)data[i++] : 0;
        uint32_t octet_c = i < input_length ? (unsigned char)data[i++] : 0;

        uint32_t triple = (octet_a << 0x10) + (octet_b << 0x08) + octet_c;

        encoded_data[j++] = encoding_table[(triple >> 3 * 6) & 0x3F];
        encoded_data[j++] = encoding_table[(triple >> 2 * 6) & 0x3F];
        encoded_data[j++] = encoding_table[(triple >> 1 * 6) & 0x3F];
        encoded_data[j++] = encoding_table[(triple >> 0 * 6) & 0x3F];
    }

    for (int i = 0; i < mod_table[input_length % 3]; i++)
        encoded_data[*output_length - 1 - i] = '=';

    return encoded_data;
}

unsigned char* calc_websocket_accept(char* key){
    char* str_to_concat = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

    char* complete_key = (char*)malloc(strlen(key) + strlen(str_to_concat) + 1);
    strcpy(complete_key, key);
    strcat(complete_key, str_to_concat);

    size_t length = strlen(complete_key);
    size_t out_length = 0;
    unsigned char hash[SHA_DIGEST_LENGTH];

    char* sha1_hash = SHA1(complete_key, length, hash);
    unsigned char* base64_encoded = base64_encode(sha1_hash, strlen(sha1_hash), &out_length);
    
    base64_encoded[out_length] = '\0';
    return base64_encoded;
}

void encode_message(char* payload, uint32_t* encoding_code, uint8_t* ptr){
    for(int i = 0; i < strlen(payload); i++){
        payload[i] = (char)(payload[i] ^ *((uint8_t*)&(*encoding_code) + *ptr) & 0xff);
        if(*ptr == 3) 
            *ptr = 0;
        else 
            *ptr = *ptr + 1;
    }
}

void send_websocket_frame(uint32_t* encoding_code, char* payload, char* msg_type, int client_fd){
    char message_header[2];
    char message_key[4];
    message_header[0] = (char)0x81;
    uint8_t type = 0;

    for(uint8_t i = 0; i < sizeof(message_key); i++){
        message_key[i] = (char)(*((uint8_t*)&(*encoding_code) + i) & 0xff);
    }

    uint8_t ptr = 0;
    uint8_t decode_ptr = 0;
    uint8_t sender_index = 0;

    if (strcmp(msg_type, "MSG:") == 0){
        type = 2;
        for(uint8_t i = 0; i < client_count; i++){
            if(client_list[i] == client_fd){
                sender_index = i;
                break;
            }
        }
    }

    if (strcmp(msg_type, "LOGOUT:") == 0) type = 1;
    else encode_message(payload, encoding_code, &decode_ptr); //TODO: not decoding MSG okay
    if (strcmp(msg_type, "USERNAME:") == 0) memcpy(&client_names[client_count], payload, strlen(payload));

    encode_message(msg_type, encoding_code, &ptr);    

    if(type == 0){
        client_list[client_count] = client_fd;
        client_count++;
    }

    uint8_t ptr_last_pos = ptr;
    
    switch(type){
        case 0: // Login
        case 1: // Logout
            for(uint8_t i = 0; i < client_count + type; i++){ // Loop through all registered client names
                char frame[6 + strlen(msg_type) + strlen(client_names[i])];
                char name_storage[strlen(client_names[i])];

                strcpy(name_storage, client_names[i]);
                message_header[1] = (char)((1 << 7) + (strlen(client_names[i]) + strlen(msg_type)));
                ptr = ptr_last_pos;

                encode_message(name_storage, encoding_code, &ptr);
                memcpy(frame, message_header, 2);
                memcpy(frame + 2, message_key, 4);
                memcpy(frame + 6, msg_type, strlen(msg_type));
                memcpy(frame + 6 + strlen(msg_type), name_storage, strlen(name_storage));

                for(uint8_t j = 0; j < client_count; j++){ // Loop through all registered client FDs
                    if(((i == client_count - 1 || j == client_count - 1) && type == 0)
                    || (strcmp(payload, client_names[i]) == 0 && type == 1))
                        send(client_list[j], frame, 6 + strlen(msg_type) + strlen(client_names[i]), 0);
                }
            }
            break;

        case 2: // Message
            decode_ptr = 0;
            ptr = ptr_last_pos;

            uint8_t payload_length = strlen(payload);
            char usr_msg_separator = ':';

            char frame[6 + strlen(msg_type) + strlen(client_names[sender_index]) + payload_length + 1];
            char name_storage[strlen(client_names[sender_index]) + 1];

            strcpy(name_storage, client_names[sender_index]);
            message_header[1] = (char)((1 << 7) + (strlen(client_names[sender_index]) + strlen(msg_type) + payload_length) + 1);

            strcat(name_storage, &usr_msg_separator);
            encode_message(name_storage, encoding_code, &ptr);
            encode_message(payload, encoding_code, &ptr);

            memcpy(frame, message_header, 2);
            memcpy(frame + 2, message_key, 4);
            memcpy(frame + 6, msg_type, strlen(msg_type));
            memcpy(frame + 6 + strlen(msg_type), name_storage, strlen(name_storage));
            memcpy(frame + 6 + strlen(msg_type) + strlen(name_storage), payload, payload_length);

            for(uint8_t i = 0; i < client_count; i++){
                send(client_list[i], frame, 6 + strlen(msg_type) + strlen(name_storage) + payload_length, 0);
            }
            break;
    }
}

void handle_rx_data(int client_fd, char *buffer, ssize_t bytes_received){
    bool login = false;

    while ((bytes_received = recv(client_fd, buffer, 128, 0)) > 0) { // Listen to client websocket
        if(!login){
            encoding_codes[client_count] = ((uint32_t)(buffer[5] & 0xFF) << 24) | ((uint32_t)(buffer[4] & 0xFF) << 16)
            | ((uint32_t)(buffer[3] & 0xFF) << 8) | (uint32_t)(buffer[2] & 0xFF);
            
            char msg_type[] = "USERNAME:";

            send_websocket_frame(&encoding_codes[client_count], buffer + 6, msg_type, client_fd);
            memset(buffer, 0, BUFFER_SIZE);

            login = true; 
        }else{
            char msg_type[] = "MSG:";

            for(uint8_t i = 0; i < client_count; i++){
                if(client_list[i] == client_fd){
                    encoding_codes[i] = ((uint32_t)(buffer[5] & 0xFF) << 24) | ((uint32_t)(buffer[4] & 0xFF) << 16)
                    | ((uint32_t)(buffer[3] & 0xFF) << 8) | (uint32_t)(buffer[2] & 0xFF);

                    send_websocket_frame(&encoding_codes[i], buffer + 6, msg_type, client_fd);
                    memset(buffer, 0, BUFFER_SIZE);
                    break;
                }
            }
            
        }
    }
}

void close_client_fd(int client_fd, char* buffer){
    //close(client_fd);
    free(buffer);

    bool found = false;
    for(uint8_t i = 0; i < client_count; i++){
        if(found)
            client_list[i - 1] = client_list[i];

        if(client_list[i] == (uint8_t)client_fd)
            found = true;        
    }
    if(client_count > 0)
        client_count--;
    client_list[client_count] = 0;

    char msg_type[] = "LOGOUT:";

    send_websocket_frame(&encoding_codes[client_count], client_names[client_count], msg_type, client_fd);

    found = false;
    for(uint8_t i = 0; i < client_count + 1; i++){
        if(found){
            memcpy(client_names[i - 1], client_names[i], 30);
        }

        if(strcmp(client_names[client_count], client_names[i]) == 0)
            found = true;        
    }

    memset(client_names[client_count], 0, 30);
}

void handle_http_request(int client_fd, char *buffer_aux){
    regex_t regex;
    regcomp(&regex, "^GET /([^ ]*) HTTP/1", REG_EXTENDED);
    regmatch_t matches[2];

    char *buffer = (char *)malloc(BUFFER_SIZE * sizeof(char));
    memcpy(buffer, buffer_aux, BUFFER_SIZE * sizeof(char));

    if (regexec(&regex, buffer, 2, matches, 0) == 0) {
        // extract filename from request and decode URL
        buffer[matches[1].rm_eo] = '\0';

        if(strcmp(buffer, "GET /") == 0) return;

        const char *url_encoded_file_name = buffer + matches[1].rm_so;
        char *file_name = url_decode(url_encoded_file_name);

        // get file extension
        char file_ext[32];
        strcpy(file_ext, get_file_extension(file_name));

        // build HTTP response
        char *response = (char *)malloc(BUFFER_SIZE * 2 * sizeof(char));
        size_t response_len;
        build_http_response(file_name, file_ext, response, &response_len);

        // send HTTP response to client
        send(client_fd, response, response_len, 0);

        free(response);
        free(file_name);

        close(client_fd);
    }
    free(buffer);
    regfree(&regex);
}

void handle_websocket_request(int client_fd, char *buffer, ssize_t bytes_received){
    regex_t regex;
    regcomp(&regex, "Sec-WebSocket-Key: ([^\r\n]+)\r\n", REG_EXTENDED);
    regmatch_t matches[2];

    if (regexec(&regex, buffer, 2, matches, 0) == 0) {
        buffer[matches[1].rm_eo] = '\0';
        char *key = buffer + matches[1].rm_so;

        unsigned char* accept_key = calc_websocket_accept(key);
        // build HTTP response
        char *response = (char *)malloc(BUFFER_SIZE * 2 * sizeof(char));
        size_t response_len;
        build_websocket_response(response, &response_len, accept_key);

        // send HTTP response to client
        send(client_fd, response, response_len, 0);

        free(response);

        memset(buffer, 0, BUFFER_SIZE);

        handle_rx_data(client_fd, buffer, bytes_received);
        close_client_fd(client_fd, buffer);
    }
    regfree(&regex);
}

void *handle_client(void *arg) {
    int client_fd = *((int *)arg);
    free(arg);
    char *buffer = (char *)malloc(BUFFER_SIZE * sizeof(char));

    // receive request data from client and store into buffer
    ssize_t bytes_received = recv(client_fd, buffer, BUFFER_SIZE, 0);
    if (bytes_received > 0) {
        // check if request is GET
        handle_http_request(client_fd, buffer);
        handle_websocket_request(client_fd, buffer, bytes_received);
    }
    return NULL;
}

int main(int argc, char *argv[]) {
    int server_fd;
    struct sockaddr_in server_addr;

    // create server socket
    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        perror("socket failed");
        exit(EXIT_FAILURE);
    }
    int option = 1;
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &option, sizeof(option));

    // config socket
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(PORT);

    // bind socket to port
    if (bind(server_fd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("bind failed");
        exit(EXIT_FAILURE);
    }

    // listen for connections
    if (listen(server_fd, 10) < 0) {
        perror("listen failed");
        exit(EXIT_FAILURE);
    }

    printf("Server listening on port %d\n", PORT);
    while (1) {
        // client info
        struct sockaddr_in client_addr;
        socklen_t client_addr_len = sizeof(client_addr);
        int *client_fd = malloc(sizeof(int));

        // accept client connection
        if ((*client_fd = accept(server_fd, (struct sockaddr *)&client_addr, &client_addr_len)) < 0) {
            perror("accept failed");
            continue;
        }

        // create a new thread to handle client request
        pthread_t thread_id;
        pthread_create(&thread_id, NULL, handle_client, (void *)client_fd);
        pthread_detach(thread_id);
    }

    close(server_fd);
    return 0;
}
