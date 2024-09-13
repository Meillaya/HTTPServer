#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>



#define BUFFER_SIZE 1024

char* handle_request(char* buffer);
char* extract_first_line(char* buffer);


int main() {
	// Disable output buffering
	setbuf(stdout, NULL);
 	setbuf(stderr, NULL);

	// You can use print statements as follows for debugging, they'll be visible when running tests.
	printf("Logs from your program will appear here!\n");



	int server_fd, client_addr_len, client_fd;
	struct sockaddr_in client_addr;
	char buffer [BUFFER_SIZE] = {0};

	server_fd = socket(AF_INET, SOCK_STREAM, 0);
	if (server_fd == -1) {
		printf("Socket creation failed: %s...\n", strerror(errno));
		return 1;
	}
	
	// Since the tester restarts your program quite often, setting SO_REUSEADDR
	// ensures that we don't run into 'Address already in use' errors
	int reuse = 1;
	if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse)) < 0) {
		printf("SO_REUSEADDR failed: %s \n", strerror(errno));
		return 1;
	}
	
	struct sockaddr_in serv_addr = { .sin_family = AF_INET ,
									 .sin_port = htons(4221),
									 .sin_addr = { htonl(INADDR_ANY) },
									};
	
	if (bind(server_fd, (struct sockaddr *) &serv_addr, sizeof(serv_addr)) != 0) {
		printf("Bind failed: %s \n", strerror(errno));
		return 1;
	}
	
	int connection_backlog = 5;
	if (listen(server_fd, connection_backlog) != 0) {
		printf("Listen failed: %s \n", strerror(errno));
		return 1;
	}
	
	printf("Waiting for a client to connect...\n");
	client_addr_len = sizeof(client_addr);

	while(1) {
		client_fd = accept(server_fd, (struct sockaddr *) &client_addr, &client_addr_len);
		if (client_fd < 0) {

			printf("Accept failed: %s \n", strerror(errno));
			continue;
		}
		
		printf("Client connected\n");

		int valread = read(client_fd, buffer, BUFFER_SIZE);

		if (valread < 0){
			printf("Failed to read from client: %s\n", strerror(errno));
			close(client_fd);
			continue;
		}

		const char *response = handle_request(buffer);

		if (send(client_fd, response, strlen(response), 0) < 0) {
			printf("Failed to send response: %s\n", strerror(errno));
		}

		if (response[0] == 'H' && response[1] == 'T' && response[2] == 'T' && response[3] == 'P') {
			
		} else {
			free((void*)response);
		}

		

		close(client_fd);
	}
	
	close(server_fd);

	return 0;
}


char* handle_request(char* buffer){

		char *end_of_request_line = strstr(buffer, "\r\n");
		char* first_line = extract_first_line(buffer);

		if (end_of_request_line != NULL && first_line != NULL) {

			int request_line_length = end_of_request_line - buffer;
			char request_line[request_line_length + 1];
			strncpy(request_line, buffer, request_line_length);
			request_line[request_line_length] = '\0';

			char *method = strtok(request_line, " ");
			char *path = strtok(NULL, " ");
			char *version = strtok(NULL, " ");

			if ( method != NULL && path != NULL) {

				if (strncmp(path, "/echo/", 6) == 0){

					char* echo_string = path + 6;
					int content_length = strlen(echo_string);
					char *response = malloc(256 + content_length);

					if (response == NULL){
						free(first_line);
						return "HTTP/1.1 500 Internal Server Error\r\n\r\n";
					}

					sprintf(response,
						"HTTP/1.1 200 OK\r\n"
						"Content-Type: text/plain\r\n"
						"Content-Length: %d\r\n"
						"\r\n"
						"%s", content_length, echo_string);

					free(first_line);
					return response;
				} else if (strcmp(path, "/") == 0){
					free(first_line);
					return "HTTP/1.1 200 OK\r\n\r\n";
				} else {
					free(first_line);
					return "HTTP/1.1 404 Not Found\r\n\r\n";
				}

			}

		}

		if (first_line != NULL) {
			free(first_line);
		}
	
	return "HTTP/1.1 400 Bad Request\r\n\r\n";
	}
		

/**
 * @brief Extracts the first line from a given buffer
 *
 * This function searches for the first occurrence of "\r\n" in the input buffer,
 * extracts the content before it (the first line), and returns it as a new string.
 *
 * @param buffer Pointer to the input buffer containing the text
 * @return char* Pointer to a newly allocated string containing the first line,
 *               or NULL if no line ending is found or if memory allocation fails
 */
char* extract_first_line(char* buffer) {
    // Find the end of the first line (marked by "\r\n")
    char* end_of_line = strstr(buffer, "\r\n");
    if (end_of_line != NULL) {
        // Calculate the length of the first line
        int line_length = end_of_line - buffer;

        // Allocate memory for the new string (line_length + 1 for null terminator)
        char* first_line = malloc(line_length + 1);

        // Check if memory allocation was successful
        if (first_line == NULL) {
            // Return NULL if memory allocation failed
            return NULL;
        }

        // Copy the first line into the newly allocated memory
        strncpy(first_line, buffer, line_length);
        // Null-terminate the new string
        first_line[line_length] = '\0';

        // Return the pointer to the new string containing the first line
        return first_line;
    }

    // Return NULL if no line ending ("\r\n") was found
    return NULL;
}