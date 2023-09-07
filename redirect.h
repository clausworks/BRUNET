#ifndef REDIRECT_H
#define REDIRECT_H

typedef enum { ROLE_CLIENT, ROLE_SERVER } ConnectionRole;
typedef enum { OOB_ENABLE, OOB_DISABLE } OutOfBandStatus;

int rdr_redirect(Connection *, ConnectionRole);

#endif
