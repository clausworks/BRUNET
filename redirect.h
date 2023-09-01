#ifndef REDIRECT_H
#define REDIRECT_H

typedef enum { ROLE_CLIENT, ROLE_SERVER } ConnectionRole;

int rdr_redirect(Connection *, ConnectionRole);

#endif
