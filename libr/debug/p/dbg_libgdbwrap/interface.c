#include "gdbwrapper.h"

int             gdbwrap_simpleconnect(char *host, int port)
{
  int           rval;
  int           sd;
  struct        sockaddr_in   socketaddr;
  struct        hostent       *hostaddr;
  struct        protoent      *protocol;

  PROFILER_IN(__FILE__, __FUNCTION__, __LINE__);
  
  hostaddr = gethostbyname(host);
  protocol = getprotobyname("tcp");

  if (!hostaddr)
    PROFILER_ERR(__FILE__, __FUNCTION__, __LINE__, "invalid gethostbyname", -1);

  if (!port)
    PROFILER_ERR(__FILE__, __FUNCTION__, __LINE__, "invalid port", -1);
  
   if (!protocol)
    PROFILER_ERR(__FILE__, __FUNCTION__, __LINE__, "invalid getprotobyname()",
		 -1);
  
  sd = socket(PF_INET, SOCK_STREAM, protocol->p_proto);
  
  if (sd == -1)
    PROFILER_ERR(__FILE__, __FUNCTION__, __LINE__, "invalid socket", -1);
  
  memset(&socketaddr, 0, sizeof(socketaddr));
  socketaddr.sin_family = AF_INET;
  socketaddr.sin_port = htons(port);

  memcpy(&socketaddr.sin_addr, hostaddr->h_addr, hostaddr->h_length);
  rval = connect(sd, (struct sockaddr *)&socketaddr, sizeof(socketaddr));

  if (rval == -1)
    PROFILER_ERR(__FILE__, __FUNCTION__, __LINE__, "Problem when connecting",
		 -1);

  PROFILER_ROUT(__FILE__, __FUNCTION__, __LINE__, sd);
}
