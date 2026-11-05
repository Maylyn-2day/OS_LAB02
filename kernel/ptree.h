#ifndef XV6_PTREE_H
#define XV6_PTREE_H

// Include types.h before this shared kernel/user ABI header.
struct ptreeinfo {
  int pid;
  int ppid;
  int state;
  uint64 memsize;
  char name[16];
};

_Static_assert(sizeof(struct ptreeinfo) == 40, "ptreeinfo size");
_Static_assert(_Alignof(struct ptreeinfo) == 8, "ptreeinfo alignment");

#endif
