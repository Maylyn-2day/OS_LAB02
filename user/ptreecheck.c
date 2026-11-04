#include "kernel/types.h"
#include "kernel/ptree.h"
#include "user/user.h"

// Milestone 3A smoke check. A -1 return alone does not prove handler entry;
// use a debugger breakpoint at sys_ptree to verify the dispatch path.
int
main(void)
{
  struct ptreeinfo info = {0};
  int result;

  printf("ptreecheck: sizeof=%d align=%d\n",
         (int)sizeof(info), (int)_Alignof(struct ptreeinfo));
  printf("ptreecheck: offsets=%d,%d,%d,%d,%d\n",
         (int)__builtin_offsetof(struct ptreeinfo, pid),
         (int)__builtin_offsetof(struct ptreeinfo, ppid),
         (int)__builtin_offsetof(struct ptreeinfo, state),
         (int)__builtin_offsetof(struct ptreeinfo, memsize),
         (int)__builtin_offsetof(struct ptreeinfo, name));

  result = ptree(&info, 1);
  if(result != -1){
    fprintf(2, "ptreecheck: expected stub return -1, got %d\n", result);
    exit(1);
  }
  printf("ptreecheck: stub returned -1; snapshot not implemented\n");
  exit(0);
}
