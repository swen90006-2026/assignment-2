#ifndef PFMS_H_
#define PFMS_H_

typedef int (*PFMSROUTINE) (char* params);

typedef struct {
    const char* name;
    PFMSROUTINE proc;
} FUNCTION_ENTRY;

#define PFMS_COMMAND(cmdname)  int cmdname(char* params)
#define MAX_CMDS               11
#define MFA_PIN_LENGTH         4
#define DEVICE_ID_LENGTH       10
#define MAX_PASSWORD_LENGTH    16
#define MIN_PASSWORD_LENGTH    10
#define MAX_PLATE_LENGTH       8
#define MIN_PLATE_LENGTH       6
#define MAX_ADMIN_NAME_LENGTH  12
#define MIN_ADMIN_NAME_LENGTH  4

PFMS_COMMAND(pfmsUSER); //provide username
PFMS_COMMAND(pfmsPASS); //provide password
PFMS_COMMAND(pfmsUPDP); //update password
PFMS_COMMAND(pfmsDPIN); //provide pin number - mfa
PFMS_COMMAND(pfmsREGU); //register new account
PFMS_COMMAND(pfmsAMFA); //add/replace mfa device (owner opt-in / admin replace)
PFMS_COMMAND(pfmsCHKT); //check outstanding tickets
PFMS_COMMAND(pfmsISST); //issue a ticket (admin only)
PFMS_COMMAND(pfmsPAYT); //pay a ticket
PFMS_COMMAND(pfmsLOGO); //log out of an account
PFMS_COMMAND(pfmsQUIT); //terminate the server

#define successcode    "200"

#define success200     "200 Command okay.\r\n"
#define success210     "210 USER okay.\r\n"
#define success220     "220 User logged in, proceed.\r\n"
#define success230     "230 New account registered.\r\n"
#define success240     "240 Ticket issued.\r\n"
#define success250     "250 Payment accepted.\r\n"
#define success260     "260 Log out successfully.\r\n"
#define success270     "270 Goodbye!\r\n"
#define success280     "280 New MFA device added.\r\n"
#define success290     "290 PASS okay. Please enter your PIN.\r\n"
#define success300     "300 Password updated.\r\n"

#define error400       "400 USER does not exist.\r\n"
#define error410       "410 PASS incorrect.\r\n"
#define error420       "420 No outstanding tickets.\r\n"
#define error430       "430 Permission denied.\r\n"
#define error440       "440 MFA PIN is incorrect.\r\n"
#define error450       "450 The two given passwords do not match.\r\n"
#define error451       "451 The given password is invalid.\r\n"
#define error460       "460 Account already exists.\r\n"
#define error470       "470 No such account.\r\n"
#define error471       "471 No such ticket.\r\n"
#define error480       "480 Not a vehicle owner account.\r\n"
#define error490       "490 Invalid role.\r\n"

#define error500       "500 Syntax error, command unrecognized.\r\n"
#define error510       "510 Please login with USER and PASS (and MFA).\r\n"
#define error520       "520 Syntax error, parameters in wrong format.\r\n"
#define error530       "530 This command is not allowed in the current state.\r\n"
#define error540       "540 Device ID is invalid. It must be a 10-digit numeric string.\r\n"
#define error550       "550 Invalid payment amount.\r\n"
#define error560       "560 Overpayment.\r\n"
#define error570       "570 No outstanding balance on this ticket.\r\n"

typedef struct {
  char* device_id;                          /* NULL => MFA not enabled */
  char password[MAX_PASSWORD_LENGTH + 1];
  int  role;                                 /* ROLE_OWNER or ROLE_ADMIN */
} account_info_t;

typedef struct {
  int    used;
  char   ticketID[8];
  char   plateNumber[MAX_PLATE_LENGTH + 1];
  int    fineType;
  double fineAmount;
  double amountPaid;
} ticket_info_t;

enum {
  /* 00 */ INIT,
  /* 01 */ USER_OK,
  /* 02 */ PASS_OK,
  /* 03 */ LOGIN_SUCCESS
};

enum {
  /* 00 */ ROLE_OWNER,
  /* 01 */ ROLE_ADMIN
};

enum {
  /* 00 */ FINE_OVERSTAYED_PARKING,      /* $65.00 */
  /* 01 */ FINE_NO_STANDING_ZONE,        /* $90.00 */
  /* 02 */ FINE_EXPIRED_METER,           /* $55.00 */
  /* 03 */ FINE_DISABLED_PARKING_MISUSE  /* $300.00 */
};

#endif /* PFMS_H_ */
