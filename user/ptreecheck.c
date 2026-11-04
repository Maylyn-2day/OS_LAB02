#include "kernel/types.h"
#include "kernel/param.h"
#include "kernel/riscv.h"
#include "kernel/ptree.h"
#include "user/user.h"

static struct ptreeinfo records[NPROC];
static const struct ptreeinfo readonly_info = { .pid = -1 };

static void
fail(const char *message)
{
  fprintf(2, "ptreecheck: %s FAILED\n", message);
  exit(1);
}

static void
check_record(struct ptreeinfo *info)
{
  if(info->pid <= 0 || info->ppid < 0 || info->pid == info->ppid)
    fail("PID/PPID");
  // enum procstate in this repository: USED=1 through ZOMBIE=5.
  if(info->state < 1 || info->state > 5)
    fail("state range");
  if(info->memsize > MAXVA)
    fail("memsize range");
  for(int i = 0; i < sizeof(info->name); i++){
    if(info->name[i] == 0)
      return;
  }
  fail("name is not NUL-terminated");
}

static void
check_full(int n, int pid, uint64 size)
{
  int found = 0;

  if(n < 1 || n > NPROC)
    fail("snapshot count");
  for(int i = 0; i < n; i++){
    check_record(&records[i]);
    for(int j = 0; j < i; j++){
      if(records[j].pid == records[i].pid)
        fail("duplicate PID");
    }
    if(records[i].pid == pid){
      found = 1;
      if(records[i].ppid == 0 || records[i].name[0] == 0)
        fail("caller metadata");
      if(records[i].memsize != size)
        fail("caller memsize differs from sbrk(0)");
    }
  }
  if(!found)
    fail("caller missing from full snapshot");
}

int
main(void)
{
  struct {
    uint64 before;
    struct ptreeinfo info;
    uint64 after;
  } one;
  const uint64 canary = 0x1122334455667788UL;
  int n, pid = getpid();
  uint64 size = (uint64)sbrk(0);

  printf("ptreecheck: sizeof=%d align=%d\n",
         (int)sizeof(struct ptreeinfo), (int)_Alignof(struct ptreeinfo));
  n = ptree(records, NPROC);
  check_full(n, pid, size);
  printf("ptreecheck: full snapshot and caller metadata OK (%d records)\n", n);

  if(ptree(0, NPROC) != -1)
    fail("NULL buffer");
  if(ptree(records, 0) != -1 || ptree(records, -1) != -1)
    fail("non-positive max");
  printf("ptreecheck: NULL/zero/negative arguments OK\n");

  memset(&one, 0, sizeof(one));
  one.before = one.after = canary;
  n = ptree(&one.info, 1);
  if(n != 1 || one.before != canary || one.after != canary)
    fail("max=1 count or buffer bounds");
  check_record(&one.info);
  printf("ptreecheck: max=1 canaries OK\n");

  check_full(ptree(records, NPROC + 1), pid, size);
  check_full(ptree(records, 0x7fffffff), pid, size);
  printf("ptreecheck: max>NPROC and INT_MAX OK\n");

  if(ptree((struct ptreeinfo *)MAXVA, 1) != -1 ||
     ptree((struct ptreeinfo *)~(uint64)0, 1) != -1)
    fail("out-of-range address");
  if(ptree((struct ptreeinfo *)(size - sizeof(struct ptreeinfo) + 1), 1) != -1)
    fail("buffer crosses process size");
  if(ptree((struct ptreeinfo *)&readonly_info, 1) != -1)
    fail("read-only buffer");
  check_full(ptree(records, NPROC), pid, size);
  printf("ptreecheck: memory errors and recovery OK\n");
  printf("ptreecheck: all checks passed\n");
  exit(0);
}
