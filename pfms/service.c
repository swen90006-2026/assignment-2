#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <errno.h>
#include <ctype.h>
#include "common.h"

int client_sock;      /* accepted client socket */

/**
  * main function
  * It expects to take two arguments
  * arg_1: an IP address of the service provider (e.g., 127.0.0.1)
  * arg_2: a port to which the service is listening (e.g., 9999)
  * Example command: ./service 127.0.0.1 9999
  *
  */

int main(int argc , char *argv[]) {
  int service_sock, addrlen, read_size;
  struct sockaddr_in server, client;
  char rcvbuf[CLIENT_REQUEST_MAX_SIZE];
  int exit_code = 0;

  //Check the number of arguments
  if (argc < 3) {
    fprintf(stderr, "[ERROR] This service requires two arguments: an IP address and a port number\n");
    fprintf(stderr, "[ERROR] Sample command: ./service 127.0.0.1 9999\n");
    exit_code = 1;
    goto exit;
  }

  //Create a TCP socket
  service_sock = socket(AF_INET , SOCK_STREAM , 0);
  if (service_sock == -1) {
    fprintf(stderr, "[ERROR] Cannot create a socket\n");
    exit_code = 1;
    goto exit;
  }

  //Enable reusing of local addresses
  const int trueFlag = 1;
  if (setsockopt(service_sock, SOL_SOCKET, SO_REUSEADDR, &trueFlag, sizeof(int)) < 0) {
    fprintf(stderr, "[ERROR] Cannot set a socket option\n");
    exit_code = 1;
    goto exit;
  }

  //Prepare a sockaddr_in structure for the server
  server.sin_family = AF_INET;
  server.sin_addr.s_addr = inet_addr(argv[1]);
  server.sin_port = htons(atoi(argv[2]));

  //Bind a socket to the server
  if(bind(service_sock, (struct sockaddr *)&server, sizeof(server)) < 0) {
    fprintf(stderr, "[ERROR] Bind failed. error code is %d\n", errno);
    exit_code = 1;
    goto exit;
  }

  //Listen to incoming connection request
  fprintf(stdout, "Waiting for incoming connections from client services...\n");

  //For simplicity, this server accepts only one connection
  listen(service_sock, 1);
  addrlen = sizeof(struct sockaddr_in);

  client_sock = accept(service_sock, (struct sockaddr *)&client, (socklen_t*)&addrlen);
  if (client_sock < 0) {
    fprintf(stderr, "[ERROR] Fails to accept an incoming connection\n");
    exit_code = 1;
    goto exit;
  }

  fprintf(stdout, "A client service is connected\n");

  int i, j, cmdlen, cmdno, rv;
  char *cmd = NULL, *params = NULL;

  //Receive requests from client
  while (service_sock != INVALID_SOCKET) {
    read_size = recvcmd(client_sock, rcvbuf, CLIENT_REQUEST_MAX_SIZE);
    if (read_size <= 0) break;

    fprintf(stdout,"[INFO] Client request: %s\n", rcvbuf);

    //For simplicity, we do not implement the connection between the service
    //provider and the devices
    fprintf(stdout,"[INFO] A message has been sent to the selected device.\n");
  }

  if(read_size == 0) {
    fprintf(stdout, "Client service is disconnected\n");
  } else if(read_size == -1) {
    fprintf(stderr, "[ERROR] Fails to receive messages from the client service\n");
    exit_code = 1;
    goto exit;
  }
exit:
  return exit_code;
}
