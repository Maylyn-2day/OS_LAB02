#include "kernel/types.h"
#include "kernel/stat.h"
#include "kernel/sysinfo.h"
#include "user/user.h"

int
main(void)
{
  struct sysinfo info;

  if (sysinfo(&info) < 0) {
    printf("sysinfotest: FAIL\n");
    exit(1);
  }

  printf("Free memory: %ld bytes\n", info.freemem);
  printf("Processes: %ld\n", info.nproc);

  if (info.freemem == 0 || info.nproc == 0) {
    printf("sysinfotest: FAIL\n");
    exit(1);
  }

  printf("sysinfotest: OK\n");
  exit(0);
}