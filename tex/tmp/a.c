/* RPC client for simple addition example */

#include <stdio.h>
#include "simp.h" 

int main( int argc, char *argv[]) {
  CLIENT *clnt;
  operands ops;

  if (argc!=4) {
    fprintf(stderr,"Usage: %s hostname num1 num\n",argv[0]);
    exit(0);
  }

  clnt = clnt_create(argv[1], SIMP_PROG, SIMP_VERSION, "udp");

  if (clnt == (CLIENT *) NULL) {
    clnt_pcreateerror(argv[1]);
    exit(1);
  }
  ops.x = atoi(argv[2]);
  ops.y = atoi(argv[3]);

  printf("%d + %d = %d\n",ops.x,ops.y, *add_1(&ops,clnt));
  printf("%d - %d = %d\n",ops.x,ops.y, *sub_1(&ops,clnt));
  return(0);
}



