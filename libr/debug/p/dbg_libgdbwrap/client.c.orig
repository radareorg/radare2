/* Basic TCP client aimed to develop of fully modular gdb wrapper. Not
   part of eresi project.  Took code from:
   http://neworder.box.sk/newsread.php?newsid=2844.
*/


#include "revm.h"
#include "gdbwrapper.h"


extern int errno;
extern int h_errno;

static void dumpreg(gdbwrap_t *desc)
{
  unsigned i;

  for (i = 0; i < sizeof(gdbwrap_gdbreg32) / sizeof(ureg32); i++)
    printf("Reg %d - %#x\n", i, *(&desc->reg32.eax + i));
}

int main( int argc, char **argv )
{
  char                 buffer[4096];
  int                  port;
  int                  rval;
  int                  sd;
  struct sockaddr_in   socketaddr;
  struct hostent       *hostaddr;
  struct protoent      *protocol;
  gdbwrap_t            *desc = NULL;
 
  if ( argc < 3 )
    {
      printf( "usage:  client  server port \n" );
      return (EINVAL); /* Invalid argument */
    }
  
  /* quick sanity check */
  
  port = atoi( argv[2] );
  
  if ( port < 1 || port > 65535 )
    {
      printf( "client: invalid port number\n" );
      return (EINVAL);
    }
  
  /*
   * Build our socket
   */
  
  protocol = getprotobyname( "tcp" );
  if ( !protocol )
    {
      perror( "getprotobyname()" );
      return (errno);
    }
  
  sd = socket( PF_INET, SOCK_STREAM, protocol->p_proto );
  if ( sd == -1 )
    {
      perror( "socket()" );
      return (errno);
    }
   /*
   * Setup info about the remote host
   */
  
  memset( &socketaddr, 0, sizeof(socketaddr) );
  
  socketaddr.sin_family = AF_INET;
  socketaddr.sin_port = htons( port );
  
  hostaddr = gethostbyname( argv[1] );
  if ( !hostaddr )
    {
      fprintf( stderr, "gethostbyname(): %s\n", hstrerror(h_errno) );
      return (h_errno);
    }
  
  /* copy address from hostaddr to socketaddr */
  
  memcpy( &socketaddr.sin_addr, hostaddr->h_addr, hostaddr->h_length );
  
  /*
   * Connect to the host
   */
  
  rval = connect( sd, (struct sockaddr *) &socketaddr, sizeof(socketaddr) );
  if ( rval == -1 )
    {
      perror( "connect()" );
      return (errno);
    }
  
  /* Now that we're connected, we can send and receive all we want.
   * I've decided to use this example as a means of simply grabbing
   * whatever banner the server sends us and sending it to stdout.
   */

  desc = gdbwrap_init(sd);
  do
    {
      char * ret;

      ret = fgets(buffer, sizeof(buffer) - 1, stdin);
      assert(ret != NULL);
      
      if(!strncmp("hello", buffer,  5))
	  gdbwrap_hello(desc);
      else if(!strncmp("disconnect", buffer,  5))
	{
	  gdbwrap_bye(desc);
	  exit(0);
	}
      else if(!strncmp("why", buffer,  3))
	gdbwrap_reason_halted(desc);
/*       else if(!strncmp("test", buffer,  4)) */
/* 	gdbwrap_test(desc); */
      else if(!strncmp("gpr", buffer,  3))
	gdbwrap_readgenreg(desc);
      else if(!strncmp("cont", buffer,  4))
	gdbwrap_continue(desc);
      else if(!strncmp("dump", buffer,  4))
	dumpreg(desc);
      else if(!strncmp("stepi", buffer, 5))
	gdbwrap_stepi(desc);
      else if(!strncmp("signal", buffer, 5))
	gdbwrap_signal(0x1, desc);
      else if(!strncmp("muuu", buffer, 4))
	gdbwrap_writereg2(6, 0x12345678, desc);
      else if(!strncmp("ship", buffer, 4))
	gdbwrap_shipallreg(desc);
      else if(!strncmp("cr0", buffer, 4))
	printf("Value: %s\n", gdbwrap_remotecmd("r cr0", desc));
      else if(!strncmp("mem", buffer, 3))
	{
	  char *c;
	  char u = 0xff;
	  c = gdbwrap_writememory(0xb7fe49a0, &u, 0x1, desc);
	  printf("Returned from memorycontent: %s\n", c);
	  fflush(stdout);
	}
/*       else if(!strncmp("own", buffer,  3)) */
/* 	{ */
/* 	  while (strncmp("quitown", buffer, 7)) */
/* 	    { */
/* 	      printf("\nCommand: "); */
/* 	      ret = gdbwrap_own_command(fgets(buffer, sizeof(buffer) - 1, stdin), */
/* 					desc); */
/* 	      printf("\n%s - size: %d", ret, strlen(ret)); */
/* 	    } */
/* 	} */
      else printf("not supported yet\n");
      
    } while (strncmp("bye", buffer, 3));
  
  
  close(sd);
  return (0);
}
