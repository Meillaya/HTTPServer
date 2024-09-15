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
#include <sys/wait.h>
#include <pthread.h>
#include <time.h>


#define BUFFER_SIZE 1024

void *handle_client(void *arg);
char* handle_request(char* buffer);
char* extract_first_line(char* buffer);


struct client_info{
	int client_fd;               // Client file descriptor
    struct sockaddr_in address;  // Client address information
    char buffer[BUFFER_SIZE];    // Buffer to store incoming data
    // size_t buffer_used;          // Amount of data currently in the buffer
    // time_t last_activity;   // Timestamp of last activity (for timeout handling) 
	// is_header_complete;    //A boolean flag to indicate whether the full HTTP header has been received.
	// content_length;        //integer to store the content length of the request, if present.
	// request_method;        //enum or string to store the HTTP method
	// request_path; 		   //string to store the requested path

};

struct sockaddr_in client_addr;

int server_fd, client_addr_len, client_fd;


int main() {

	char buffer [BUFFER_SIZE] = {0};
	// Disable output buffering
	setbuf(stdout, NULL);
 	setbuf(stderr, NULL);

	// You can use print statements as follows for debugging, they'll be visible when running tests.
	printf("Logs from your program will appear here!\n");

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
	
	
	while(1) {

		struct client_info *client = malloc(sizeof(struct client_info));
		client_addr_len = sizeof(client->address);
		
		
		if ((client->client_fd = accept(server_fd, (struct sockaddr *)&client->address, &client_addr_len)) < 0) {

			printf("Accept failed: %s \n", strerror(errno));
			free(client);
			continue;
		}
		
		printf("Client connected\n");

		
		pthread_t thread_id;

		if (pthread_create(&thread_id, NULL, handle_client,(void *)client) < 0) {

			printf("Error creating thread: %\n");
			free(client);
			close(client->client_fd);
			continue;
		}

		pthread_detach(thread_id);
	
	}

	close(server_fd);

	return 0;
}



void *handle_client(void *arg) {

	struct client_info *client = (struct client_info *)arg;	
	char buffer [BUFFER_SIZE] = {0};

	int valread = read(client->client_fd, buffer, BUFFER_SIZE);

	if (valread < 0){
		printf("Failed to read from client: %s\n", strerror(errno));
	} else {

		const char *response = handle_request(buffer);

		if (send(client->client_fd, response, strlen(response), 0) < 0) {
			printf("Failed to send response: %s\n", strerror(errno));
		}

		if (response[0] == 'H' && response[1] == 'T' && response[2] == 'T' && response[3] == 'P') {
		
			free((void*)response);
		}

}
	
	
	close(client->client_fd);
	free(client);
	return NULL;

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

			if (method != NULL && path != NULL) {
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
				}
				else if (strcmp(path, "/user-agent") == 0) {
					char *user_agent = strstr(buffer, "User-Agent: ");
					if (user_agent) {
						user_agent += 12;  // Skip "User-Agent: "
						char *end_of_user_agent = strstr(user_agent, "\r\n");
						if (end_of_user_agent) {
							int content_length = end_of_user_agent - user_agent;
							char *response = malloc(256 + content_length);
							if (response == NULL) {
								free(first_line);
								return "HTTP/1.1 500 Internal Server Error\r\n\r\n";
							}
							sprintf(response,
								"HTTP/1.1 200 OK\r\n"
								"Content-Type: text/plain\r\n"
								"Content-Length: %d\r\n"
								"\r\n"
								"%.*s", content_length, content_length, user_agent);
							free(first_line);
							return response;
						}
					}
					// If we get here, we couldn't find the User-Agent
					free(first_line);
					return "HTTP/1.1 400 Bad Request\r\n\r\n";
				} else if (strcmp(path, "/") == 0) {
					free(first_line);
					return "HTTP/1.1 200 OK\r\n\r\n";
				} else {
					free(first_line);
					return "HTTP/1.1 404 Not Found\r\n\r\n";
				}
			}
			// If we get here, either method or path was NULL
			if (first_line != NULL) {
				free(first_line);
			}
			return "HTTP/1.1 400 Bad Request\r\n\r\n";

	}

	return "HTTP/1.1 500 Internal Server Error\r\n\r\n";

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