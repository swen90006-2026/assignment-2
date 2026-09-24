#ifndef COMMON_H_
#define COMMON_H_

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <errno.h>
#include <ctype.h>

#define INVALID_SOCKET         -1
#define CLIENT_REQUEST_MAX_SIZE 2000

/**
  * Read a command sent from the client.
  * Each command ends with two special characters "\r\n"
  *
  * @in     sockfd        socket from which command is read
  * @in-out buffer        a buffer storing the command
  * @in     buffer size   buffer size
  */
int recvcmd(int sockfd, char *buffer, size_t buffer_size) {
  ssize_t	bytes_received, pointer = 0;

  memset(buffer, 0, buffer_size);
  --buffer_size;

  while (buffer_size > 0) {
    bytes_received = recv(sockfd, buffer + pointer, buffer_size, 0);

    if (bytes_received <= 0)
      return bytes_received;

    buffer_size -= bytes_received;
    pointer += bytes_received;

    //Check for the command terminator ("\r\n")
    if (pointer >= 2) {
      if ((buffer[pointer-2] == '\r') && (buffer[pointer-1] == '\n')) {
        buffer[pointer-2] = 0;
        return 1;
      }
    }
  }
  return 0;
}

/**
  * Send a response to the client
  *
  * @in sockfd        socket to which response is sent
  * @in response      response to be sent
  */
ssize_t sendResponse(const int sockfd, const char *response)
{
  size_t len = strlen(response);
  return (send(sockfd, response, len, MSG_NOSIGNAL) >= 0);
}

/**
  * Split a string using a delimiter
  *
  * @in str       socket to which response is sent
  * @in delim     a delimiter (e.g., a comma)
  * @in count     number of tokens after splitting
  */
char** strSplit(char* str, const char* delim, int *count)
{
  char** tokens = NULL;
  char *token;
  *count = 0;

  /* get the first token */
  char* tmp = strdup(str);
  token = strtok(tmp, delim);

  /* walk through other tokens */
  while (token != NULL)
  {
    tokens = (char**) realloc(tokens, sizeof(char*) * (*count + 1));
    tokens[*count] = strdup(token);
    *count = *count + 1;
    token = strtok(NULL, delim);
  }

  free(token);
  free(tmp);
  return tokens;
}

#endif /* COMMON_H_ */
