/**
 *
 * ACKNOWLEDGEMENT:
 * The server code is written based on this C socket server example
 * https://www.binarytides.com/server-client-example-c-sockets-linux/
 *
 * We also use code from the LightFTP project (https://github.com/hfiref0x/LightFTP)
 * with some modifications
 *
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <errno.h>
#include <ctype.h>
#include <assert.h>
#include <time.h>
#include "pfms.h"
#include "common.h"

#define INVALID_SOCKET  -1
#define MSG_BUF_SIZE    100
#define CMD_QUIT        10
#define MFA_TRIAL_MAX   3
#define MAX_ACCOUNTS    64
#define MAX_TICKETS     256

static const double FINE_AMOUNTS[] = { 65.00, 90.00, 55.00, 300.00 };

//Define a "lookup" table for all command-handling functions
static const FUNCTION_ENTRY pfmsprocs[MAX_CMDS] = {
  {"USER", pfmsUSER}, {"PASS", pfmsPASS}, {"UPDP", pfmsUPDP}, {"DPIN", pfmsDPIN},
  {"REGU", pfmsREGU}, {"AMFA", pfmsAMFA}, {"CHKT", pfmsCHKT}, {"ISST", pfmsISST},
  {"PAYT", pfmsPAYT}, {"LOGO", pfmsLOGO}, {"QUIT", pfmsQUIT}
};

//Global variables
int client_sock;       /* accepted client socket */
int service_sock;      /* service provider socket */

static account_info_t *accounts[MAX_ACCOUNTS];
static char *account_names[MAX_ACCOUNTS];
static int account_count = 0;

static ticket_info_t tickets[MAX_TICKETS];
static int ticket_count = 0;
static unsigned int ticket_seq = 1;

int pfms_state = INIT, discard;
char *active_user_name = NULL;
int mfa_pin;
int mfa_trial_count = 0;

/**
  * Create a new account_info_t object
  */
account_info_t *newAccount() {
  account_info_t *a = (account_info_t *) malloc(sizeof(account_info_t));
  a->password[0] = '\0';
  a->device_id = NULL;
  a->role = ROLE_OWNER;
  return a;
}

/**
  * Check if an account with the given username exists
  */
int isAccount(const char *name) {
  for (int i = 0; i < account_count; i++) {
    if (account_names[i] != NULL && strcmp(account_names[i], name) == 0) return 1;
  }
  return 0;
}

/**
  * Get the account object for a given username, or NULL
  */
account_info_t *getAccount(const char *name) {
  if (name == NULL) return NULL;
  for (int i = 0; i < account_count; i++) {
    if (account_names[i] != NULL && strcmp(account_names[i], name) == 0) return accounts[i];
  }
  return NULL;
}

/**
  * Check if the given password is correct for the active user
  */
int isPasswordCorrect(const char *password) {
  account_info_t *a = getAccount(active_user_name);
  return (a != NULL && strcmp(a->password, password) == 0);
}

/**
  * Check if the current user has MFA enabled
  */
int isMFAEnabled() {
  account_info_t *a = getAccount(active_user_name);
  return (a != NULL && a->device_id != NULL);
}

/**
  * Check if a given device id is valid: a numeric string of a fixed size
  */
int isDeviceIDValid(char *device) {
  if (strlen(device) != DEVICE_ID_LENGTH) return 0;
  for (size_t i = 0; i < strlen(device); i++) {
    if (!isdigit((unsigned char)device[i])) return 0;
  }
  return 1;
}

/**
  * Check if a given string is a numeric string
  */
int isNumber(char *str) {
  if (str == NULL || str[0] == '\0') return 0;
  for (size_t i = 0; i < strlen(str); i++) {
    if (!isdigit((unsigned char)str[i])) return 0;
  }
  return 1;
}

/**
  * Check plate number format: 6-8 chars, A-Z and 0-9, at least one of each
  */
int isValidPlateFormat(const char *s) {
  int len = strlen(s);
  if (len < MIN_PLATE_LENGTH || len > MAX_PLATE_LENGTH) return 0;
  int has_letter = 0, has_digit = 0;
  for (int i = 0; i < len; i++) {
    char c = s[i];
    if (c >= 'A' && c <= 'Z') has_letter = 1;
    else if (c >= '0' && c <= '9') has_digit = 1;
    else return 0;
  }
  return has_letter && has_digit;
}

/**
  * Check admin username format: 4-12 letters
  */
int isValidAdminFormat(const char *s) {
  int len = strlen(s);
  if (len < MIN_ADMIN_NAME_LENGTH || len > MAX_ADMIN_NAME_LENGTH) return 0;
  for (int i = 0; i < len; i++) {
    if (!isalpha((unsigned char)s[i])) return 0;
  }
  return 1;
}

/**
  * Check password format: 10-16 chars, at least one letter, one digit,
  * one special character
  */
int isValidPasswordFormat(const char *s) {
  int len = strlen(s);
  if (len < MIN_PASSWORD_LENGTH || len > MAX_PASSWORD_LENGTH) return 0;
  int has_letter = 0, has_digit = 0, has_special = 0;
  for (int i = 0; i < len; i++) {
    char c = s[i];
    if (isalpha((unsigned char)c)) has_letter = 1;
    else if (isdigit((unsigned char)c)) has_digit = 1;
    else has_special = 1;
  }
  return has_letter && has_digit && has_special;
}

/**
  * Generate a random N-digit PIN
  */
int generatePIN(int N) {       
  int i, result = 0;
  time_t t;

  // Intialize the random number generator
  srand((unsigned) time(&t));
  
  for (i = 0; i < N; i++) {
    result = (result * 10) + (rand() % 10);
  } 

  if (result < 1000) {
    int num = rand() % 10;
    while (num == 0) {
      num = rand() % 10; 
    }
    result = result + num * 1000;
  }
  return result;
}

/**
  * Send a PIN to the service provider (telco), which "delivers" it to
  * the user's device. PFMS generates the PIN
  * itself; the telco service is only asked to deliver it, and does not
  * send anything back.
  */
void sendPIN(int PIN) {
  char message[MSG_BUF_SIZE];
  account_info_t *a = getAccount(active_user_name);
  sprintf(message, "Device-%s, PIN-%d\r\n", a->device_id, PIN);
  if (send(service_sock, message, strlen(message), 0) < 0) {
    fprintf(stderr, "[ERROR] PFMS cannot communicate with the service provider");
  }
}

/**
  * Find a ticket by plate number and ticket ID
  */
ticket_info_t *findTicket(const char *plateNumber, const char *ticketID) {
  for (int i = 0; i < ticket_count; i++) {
    if (tickets[i].used &&
        strcmp(tickets[i].plateNumber, plateNumber) == 0 &&
        strcmp(tickets[i].ticketID, ticketID) == 0) {
      return &tickets[i];
    }
  }
  return NULL;
}

/**
  * Free up memory used to store all accounts
  */
void freeAccounts() {
  for (int i = 0; i < account_count; i++) {
    if (accounts[i]) {
      if (accounts[i]->device_id) free(accounts[i]->device_id);
      free(accounts[i]);
    }
    if (account_names[i]) free(account_names[i]);
  }
  free(active_user_name);
}

/**
  * Free up a string array
  */
void freeTokens(char **tokens, int count) {
  for (int i = 0; i < count; i++) free(tokens[i]);
  free(tokens);
}

/*** Command-handling functions ***/

/**
  * Handle USER
  * E.g. USER ABC1234
  */
PFMS_COMMAND(pfmsUSER) {
  if (pfms_state == INIT) {
    if (params == NULL) return sendResponse(client_sock, error520);

    if (!isAccount(params)) {
      return sendResponse(client_sock, error400);
    } else {
      sendResponse(client_sock, success210);
      free(active_user_name);
      active_user_name = strdup(params);
      pfms_state = USER_OK;
    }
  } else {
    return sendResponse(client_sock, error530);
  }
  return 0;
}

/**
  * Handle PASS
  * E.g. PASS hunter2!23
  */
PFMS_COMMAND(pfmsPASS) {
  if (pfms_state == USER_OK) {
    if (params == NULL) return sendResponse(client_sock, error520);

    if (!isPasswordCorrect(params)) {
      return sendResponse(client_sock, error410);
    } else {
      if (!isMFAEnabled()) {
        sendResponse(client_sock, success220);
        pfms_state = LOGIN_SUCCESS;
      } else {
        sendResponse(client_sock, success290);
        pfms_state = PASS_OK;
        mfa_pin = generatePIN(MFA_PIN_LENGTH);
        mfa_trial_count = MFA_TRIAL_MAX;   /* fresh budget for this login */
        sendPIN(mfa_pin);
      }
    }
  } else {
    return sendResponse(client_sock, error530);
  }
  return 0;
}

/**
  * Handle DPIN
  * E.g. DPIN 4456
  */
PFMS_COMMAND(pfmsDPIN) {
  if (pfms_state == PASS_OK) {
    if (params == NULL) return sendResponse(client_sock, error520);

    int PIN = atoi(params);

    if (PIN != mfa_pin) {
      mfa_trial_count--;
      if (mfa_trial_count == 0) {
        pfms_state = INIT;
      }
      return sendResponse(client_sock, error440);
    } else {
      sendResponse(client_sock, success220);
      pfms_state = LOGIN_SUCCESS;
    }
  } else {
    sendResponse(client_sock, error530);
  }
  return 0;
}

/**
  * Handle UPDP -- Update password
  * E.g. UPDP newpass!23,newpass!23
  */
PFMS_COMMAND(pfmsUPDP) {
  if (pfms_state == LOGIN_SUCCESS) {
    if (params == NULL) return sendResponse(client_sock, error520);

    //This command expects two arguments/parameters
    //e.g. UPDP newpassword,newpassword
    char **tokens = NULL;
    int count = 0;
    tokens = strSplit(params, ",", &count);

    if (count == 2) {
      if (strcmp(tokens[0], tokens[1]) != 0) {
        freeTokens(tokens, count);
        return sendResponse(client_sock, error450);
      }

      if (!isValidPasswordFormat(tokens[0])) {
        freeTokens(tokens, count);
        return sendResponse(client_sock, error451);
      }

      account_info_t *a = getAccount(active_user_name);
      strncpy(a->password, tokens[0], MAX_PASSWORD_LENGTH);
      a->password[MAX_PASSWORD_LENGTH] = '\0';
      sendResponse(client_sock, success300);
    } else {
      sendResponse(client_sock, error520);
    }

    freeTokens(tokens, count);
  } else {
    return sendResponse(client_sock, error530);
  }
  return 0;
}

/**
  * Handle REGU -- Register new account
  * E.g. REGU ABC1234,hunter2!23,OWNER
  * E.g. REGU staffbob,hunter2!23,ADMIN,0412345678
  */
PFMS_COMMAND(pfmsREGU) {
  if (params == NULL) return sendResponse(client_sock, error520);

  //This command expects three or four arguments/parameters
  //(username, password, role, [deviceId]) separated by commas
  char **tokens = NULL;
  int count = 0;
  tokens = strSplit(params, ",", &count);

  if (count != 3 && count != 4) {
    freeTokens(tokens, count);
    return sendResponse(client_sock, error520);
  }

  char buf[MAX_PLATE_LENGTH + 1];
  strcpy(buf, tokens[0]);

  int role;
  if (strcmp(tokens[2], "ADMIN") == 0) role = ROLE_ADMIN;
  else if (strcmp(tokens[2], "OWNER") == 0) role = ROLE_OWNER;
  else { freeTokens(tokens, count); return sendResponse(client_sock, error490); }

  if (isAccount(buf)) {
    freeTokens(tokens, count);
    return sendResponse(client_sock, error460);
  }

  int username_ok = (role == ROLE_ADMIN) ? isValidAdminFormat(buf) : isValidPlateFormat(buf);
  if (!username_ok) { freeTokens(tokens, count); return sendResponse(client_sock, error520); }
  if (!isValidPasswordFormat(tokens[1])) { freeTokens(tokens, count); return sendResponse(client_sock, error451); }

  /* MFA enrolment: compulsory for ADMIN, opt-in for OWNER. */
  char *device_id = NULL;
  if (role == ROLE_ADMIN) {
    if (count != 4 || !isDeviceIDValid(tokens[3])) {
      freeTokens(tokens, count);
      return sendResponse(client_sock, error540);
    }
    device_id = strdup(tokens[3]);
  } else if (count == 4) {
    if (!isDeviceIDValid(tokens[3])) { freeTokens(tokens, count); return sendResponse(client_sock, error540); }
    device_id = strdup(tokens[3]);
  }

  if (account_count >= MAX_ACCOUNTS) { freeTokens(tokens, count); return sendResponse(client_sock, error530); }

  account_info_t *a = newAccount();
  strncpy(a->password, tokens[1], MAX_PASSWORD_LENGTH);
  a->role = role;
  a->device_id = device_id;

  account_names[account_count] = strdup(buf);
  accounts[account_count] = a;
  account_count++;

  freeTokens(tokens, count);
  return sendResponse(client_sock, success230);
}

/**
  * Handle AMFA -- Add/replace a MFA device (owner opt-in, or replace)
  * E.g. AMFA 0412345678
  */
PFMS_COMMAND(pfmsAMFA) {
  if (pfms_state == LOGIN_SUCCESS) {
    if (params == NULL) return sendResponse(client_sock, error520);

    if (!isDeviceIDValid(params)) return sendResponse(client_sock, error540);

    account_info_t *a = getAccount(active_user_name);
    if (a->device_id != NULL) free(a->device_id);
    a->device_id = strdup(params);

    sendResponse(client_sock, success280);
  } else {
    sendResponse(client_sock, error530);
  }
  return 0;
}

/**
  * Handle CHKT -- Check outstanding tickets for a plate number
  * E.g. CHKT ABC1234
  */
PFMS_COMMAND(pfmsCHKT) {
  if (pfms_state == LOGIN_SUCCESS) {
    if (params == NULL) return sendResponse(client_sock, error520);

    char *plateNumber = params;
    account_info_t *target = getAccount(plateNumber);
    if (target == NULL) return sendResponse(client_sock, error470);
    if (target->role != ROLE_OWNER) return sendResponse(client_sock, error480);

    account_info_t *caller = getAccount(active_user_name);
    int is_admin_caller = (caller != NULL && caller->role == ROLE_ADMIN);
    int is_owner_caller = (strcmp(active_user_name, plateNumber) == 0);

    if (!is_admin_caller && !is_owner_caller) return sendResponse(client_sock, error430);

    int any = 0;
    for (int i = 0; i < ticket_count; i++) {
      ticket_info_t *t = &tickets[i];
      if (t->used &&
          strncmp(t->plateNumber, plateNumber, strlen(plateNumber)) == 0 && 
          t->fineAmount > t->amountPaid) {
        sendResponse(client_sock, successcode);
        char line[MSG_BUF_SIZE];
        sprintf(line, " %s: %s/$%.2f/$%.2f\r\n", t->ticketID, t->plateNumber, t->amountPaid, t->fineAmount);
        sendResponse(client_sock, line);
        any = 1;
      }
    }
    if (!any) sendResponse(client_sock, error420);
  } else {
    sendResponse(client_sock, error530);
  }
  return 0;
}

/**
  * Handle ISST -- Issue a ticket (admin only)
  * E.g. ISST ABC1234,1
  */
PFMS_COMMAND(pfmsISST) {
  if (pfms_state == LOGIN_SUCCESS) {
    if (params == NULL) return sendResponse(client_sock, error520);

    account_info_t *caller = getAccount(active_user_name);
    if (caller == NULL || caller->role != ROLE_ADMIN) return sendResponse(client_sock, error430);

    char **tokens = NULL;
    int count = 0;
    tokens = strSplit(params, ",", &count);
    if (count != 2) { freeTokens(tokens, count); return sendResponse(client_sock, error520); }

    account_info_t *target = getAccount(tokens[0]);
    if (target == NULL) { freeTokens(tokens, count); return sendResponse(client_sock, error470); }
    if (target->role != ROLE_OWNER) { freeTokens(tokens, count); return sendResponse(client_sock, error480); }

    if (!isNumber(tokens[1])) { freeTokens(tokens, count); return sendResponse(client_sock, error520); }
    int fine_idx = atoi(tokens[1]);
    if (fine_idx < 0 || fine_idx > 3) { freeTokens(tokens, count); return sendResponse(client_sock, error520); }

    if (ticket_count >= MAX_TICKETS) { freeTokens(tokens, count); return sendResponse(client_sock, error530); }

    ticket_info_t *t = &tickets[ticket_count++];
    t->used = 1;
    snprintf(t->ticketID, sizeof(t->ticketID), "T%u", ticket_seq++);
    strncpy(t->plateNumber, tokens[0], sizeof(t->plateNumber) - 1);
    t->fineType = fine_idx;
    t->fineAmount = FINE_AMOUNTS[fine_idx];
    t->amountPaid = 0.0;

    char msg[64];
    snprintf(msg, sizeof(msg), " Ticket %s issued.\r\n", t->ticketID);
    sendResponse(client_sock, success240);
    sendResponse(client_sock, msg);

    freeTokens(tokens, count);
  } else {
    sendResponse(client_sock, error530);
  }
  return 0;
}

/**
  * Handle PAYT -- Pay a ticket
  * E.g. PAYT ABC1234,T1,65.00
  *
  * Note: unlike most other commands, PAYT does not require login (this
  * matches Assignment 1's spec: paying a fine is intentionally open to
  * anyone who knows the plate number and ticket ID).
  */
PFMS_COMMAND(pfmsPAYT) {
  if (params == NULL) return sendResponse(client_sock, error520);

  char **tokens = NULL;
  int count = 0;
  tokens = strSplit(params, ",", &count);
  if (count != 3) { freeTokens(tokens, count); return sendResponse(client_sock, error520); }

  account_info_t *target = getAccount(tokens[0]);
  if (target == NULL) { freeTokens(tokens, count); return sendResponse(client_sock, error470); }
  if (target->role != ROLE_OWNER) { freeTokens(tokens, count); return sendResponse(client_sock, error480); }

  ticket_info_t *t = findTicket(tokens[0], tokens[1]);
  if (t == NULL) { freeTokens(tokens, count); return sendResponse(client_sock, error471); }

  double amount = atof(tokens[2]);

  if (amount <= 0) {
    freeTokens(tokens, count);
    return sendResponse(client_sock, error550);
  }
  double outstanding = t->fineAmount - t->amountPaid;
  if (outstanding <= 0) {
    freeTokens(tokens, count);
    return sendResponse(client_sock, error570);
  }
  if (amount > outstanding) {
    freeTokens(tokens, count);
    return sendResponse(client_sock, error560);
  }

  t->amountPaid += amount;
  sendResponse(client_sock, success250);

  freeTokens(tokens, count);
  return 0;
}

/**
  * Handle LOGO -- Log out
  * E.g. LOGO
  */
PFMS_COMMAND(pfmsLOGO) {
  if (pfms_state == LOGIN_SUCCESS) {
    //This command expects no arguments
    sendResponse(client_sock, success260);

    free(active_user_name);
    active_user_name = NULL;

    pfms_state = INIT;
  } else {
    sendResponse(client_sock, error530);
  }
  return 0;
}

/**
  * Handle QUIT -- Terminate the connection
  * E.g. QUIT
  */
PFMS_COMMAND(pfmsQUIT) {
  //This command expects no arguments
  sendResponse(client_sock, success270);
  return 0;
}

/**
  * main function
  * It expects to take four arguments
  * arg_1: an IP address on which the server is running (e.g., 127.0.0.1)
  * arg_2: a port to which the server is listening (e.g., 8888)
  * arg_3: an IP address of the selected MFA service provider (e.g., 127.0.0.1)
  * arg_4: a port opened by the MFA service provider (e.g., 9999)
  * Example command: ./pfms 127.0.0.1 8888 127.0.0.1 9999
  */
int main(int argc, char *argv[]) {
  int pfms_sock, addrlen, read_size;
  struct sockaddr_in server, client;
  char rcvbuf[CLIENT_REQUEST_MAX_SIZE];
  int exit_code = 0;

  if (argc < 5) {
    fprintf(stderr, "[ERROR] PFMS requires four arguments: IPs and port numbers of PFMS and a MFA service provider\n");
    fprintf(stderr, "[ERROR] Sample command: ./pfms 127.0.0.1 8888 127.0.0.1 9999\n");
    exit_code = 1;
    goto exit;
  }

  //Add a default admin account
  account_info_t *admin = newAccount();
  strcpy(admin->password, "admin1234!");            /* initial account */
  admin->device_id = strdup("0123456789");
  admin->role = ROLE_ADMIN;
  account_names[account_count] = strdup("admin");
  accounts[account_count] = admin;
  account_count++;

  /**
    * Set up the connection to the service provider (e.g., a telco)
    */
  struct sockaddr_in service_server;

  service_sock = socket(AF_INET, SOCK_STREAM, 0);
  if (service_sock == -1) {
    fprintf(stderr, "[ERROR] PFMS: cannot create a socket connecting to the service provider\n");
    exit_code = 1;
    goto exit;
  }

  const int trueFlag = 1;
  if (setsockopt(service_sock, SOL_SOCKET, SO_REUSEADDR, &trueFlag, sizeof(int)) < 0) {
    fprintf(stderr, "[ERROR] PFMS: cannot set a socket option for the service provider\n");
    exit_code = 1;
    goto exit;
  }

  service_server.sin_addr.s_addr = inet_addr(argv[3]);
  service_server.sin_family = AF_INET;
  service_server.sin_port = htons(atoi(argv[4]));

  if (connect(service_sock, (struct sockaddr *)&service_server, sizeof(service_server)) < 0) {
    fprintf(stderr, "[ERROR] PFMS: cannot connect to the service provider server\n");
    exit_code = 1;
    goto exit;
  } else {
    fprintf(stdout, "PFMS: successfully connect to the service provider\n");
  }

  /**
    * Create a TCP socket for PFMS to accept client requests
    */
  pfms_sock = socket(AF_INET, SOCK_STREAM, 0);
  if (pfms_sock == -1) {
    fprintf(stderr, "[ERROR] PFMS: cannot create a socket\n");
    exit_code = 1;
    goto exit;
  }

  if (setsockopt(pfms_sock, SOL_SOCKET, SO_REUSEADDR, &trueFlag, sizeof(int)) < 0) {
    fprintf(stderr, "[ERROR] PFMS: cannot set a socket option for the server\n");
    exit_code = 1;
    goto exit;
  }

  server.sin_family = AF_INET;
  server.sin_addr.s_addr = inet_addr(argv[1]);
  server.sin_port = htons(atoi(argv[2]));

  if (bind(pfms_sock, (struct sockaddr *)&server, sizeof(server)) < 0) {
    fprintf(stderr, "[ERROR] PFMS: bind failed. error code is %d\n", errno);
    exit_code = 1;
    goto exit;
  }

  fprintf(stdout, "PFMS: waiting for an incoming connection ...\n");

  //For simplicity, this server accepts only one connection
  listen(pfms_sock, 1);
  addrlen = sizeof(struct sockaddr_in);

  client_sock = accept(pfms_sock, (struct sockaddr *)&client, (socklen_t*)&addrlen);
  if (client_sock < 0) {
    fprintf(stderr, "[ERROR] PFMS fails to accept an incoming connection\n");
    exit_code = 1;
    goto exit;
  }

  fprintf(stdout, "PFMS: connection accepted\n");

  int i, j, cmdlen, cmdno, rv;
  char *cmd = NULL, *params = NULL;
  while (pfms_sock != INVALID_SOCKET) {
    read_size = recvcmd(client_sock, rcvbuf, CLIENT_REQUEST_MAX_SIZE);
    if (read_size <= 0) break;
    fprintf(stdout, "PFMS: receiving %s\n", rcvbuf);

    i = 0;
    while ((rcvbuf[i] != 0) && (isalpha((unsigned char)rcvbuf[i]) == 0)) ++i;

    cmd = &rcvbuf[i];
    while ((rcvbuf[i] != 0) && (rcvbuf[i] != ' ')) ++i;

    cmdlen = &rcvbuf[i] - cmd;
    while (rcvbuf[i] == ' ') ++i;

    if (rcvbuf[i] == 0) params = NULL;
    else params = &rcvbuf[i];

    cmdno = -1;
    rv = 1;

    for (j = 0; j < MAX_CMDS; j++) {
      if (cmdlen != (int)strlen(pfmsprocs[j].name)) break;
      if (strncasecmp(cmd, pfmsprocs[j].name, strlen(pfmsprocs[j].name)) == 0) {
        cmdno = j;
        rv = pfmsprocs[j].proc(params);
        break;
      }
    }

    if (cmdno == -1) {
      sendResponse(client_sock, error500);
    }

    if (cmdno == CMD_QUIT) {
      goto exit;
    }
  }

  if (read_size == 0) {
    fprintf(stdout, "PFMS: client disconnected\n");
  } else if (read_size == -1) {
    fprintf(stderr, "[ERROR] PFMS fails to receive client requests\n");
    exit_code = 1;
    goto exit;
  }

exit:
  freeAccounts();
  return exit_code;
}
