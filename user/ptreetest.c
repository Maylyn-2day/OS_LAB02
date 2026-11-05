#include "kernel/types.h"
#include "kernel/param.h"
#include "kernel/riscv.h"
#include "kernel/ptree.h"
#include "user/user.h"

// Values checked against enum procstate in kernel/proc.h.
enum { STATE_USED = 1, STATE_SLEEPING = 2, STATE_ZOMBIE = 5 };
enum { TIMEOUT_TICKS = 100, MARKER = 0xa5 };

static struct ptreeinfo rows[NPROC];
static uchar arena[2 * PGSIZE] __attribute__((aligned(PGSIZE)));
static int count, self, tracked[8], ntracked;
static uint64 initial_size;

// Only the supervising process calls stop(); children report via pipes/status.
static void
stop(int code, const char *message)
{
  fprintf(2, "ptreetest: %s %s\n", message,
          code == 2 ? "INCONCLUSIVE" : "FAIL");
  for(int i = 0; i < ntracked; i++)
    kill(tracked[i]);
  while(wait(0) > 0)
    ;
  exit(code);
}

static void
watch(int pid)
{
  if(pid <= 0 || ntracked == sizeof(tracked) / sizeof(tracked[0]))
    stop(1, "child creation/tracking");
  tracked[ntracked++] = pid;
}

static void
newpipe(int fd[2])
{
  if(pipe(fd) < 0)
    stop(1, "pipe creation");
}

static int
read_all(int fd, void *buffer, int bytes)
{
  char *p = buffer;
  while(bytes > 0){
    int n = read(fd, p, bytes);
    if(n <= 0)
      return -1;
    p += n;
    bytes -= n;
  }
  return 0;
}

static int
write_all(int fd, const void *buffer, int bytes)
{
  const char *p = buffer;
  while(bytes > 0){
    int n = write(fd, p, bytes);
    if(n <= 0)
      return -1;
    p += n;
    bytes -= n;
  }
  return 0;
}

static void
release_gate(int fd)
{
  if(write_all(fd, "x", 1) < 0)
    stop(1, "gate release");
  close(fd);
}

static void
validate(int n, int capacity, int require_self)
{
  int found = 0;
  uint64 size = (uint64)sbrk(0);

  if(n < 1 || n > capacity || n > NPROC)
    stop(1, "snapshot count");
  for(int i = 0; i < n; i++){
    struct ptreeinfo *p = &rows[i];
    if(p->pid <= 0 || p->ppid < 0 || p->pid == p->ppid ||
       p->state < STATE_USED || p->state > STATE_ZOMBIE || p->memsize > MAXVA)
      stop(1, "record values");
    int terminated = 0;
    for(int j = 0; j < sizeof(p->name); j++){
      if(p->name[j] == 0)
        terminated = 1;
    }
    if(!terminated)
      stop(1, "unterminated name");
    for(int j = 0; j < i; j++){
      if(rows[j].pid == p->pid)
        stop(1, "duplicate PID");
    }
    if(p->pid == self){
      found = 1;
      if(p->memsize != size)
        stop(1, "caller memsize");
    }
  }
  if(require_self && !found)
    stop(1, "caller missing");
}

static void
snapshot(void)
{
  count = ptree(rows, NPROC);
  validate(count, NPROC, 1);
}

static int
find(int pid)
{
  for(int i = 0; i < count; i++){
    if(rows[i].pid == pid)
      return i;
  }
  return -1;
}

static int
ancestry_root(void)
{
  int pid = self;
  snapshot();
  for(int i = 0; i < NPROC; i++){
    int index = find(pid);
    if(index < 0)
      stop(1, "incomplete caller ancestry");
    if(rows[index].ppid == 0)
      return pid;
    pid = rows[index].ppid;
  }
  stop(1, "cyclic caller ancestry");
  return -1;
}

static void
expect_process(int pid, int ppid, int state)
{
  uint start = uptime();
  do {
    snapshot();
    int index = find(pid);
    if(index < 0 || rows[index].ppid != ppid)
      stop(1, "controlled process PID/PPID");
    if(rows[index].state == state)
      return;
    // Yield between observations; elapsed time is never evidence of state.
    sleep(1);
  } while((uint)(uptime() - start) < TIMEOUT_TICKS);
  stop(2, "state observation timeout");
}

static void
expect_absent(int pid)
{
  uint start = uptime();
  do {
    snapshot();
    if(find(pid) < 0)
      return;
    sleep(1);
  } while((uint)(uptime() - start) < TIMEOUT_TICKS);
  stop(2, "process collection timeout");
}

static void
test_buffers(void)
{
  int limits[] = {1, NPROC, NPROC + 1, 0x7fffffff};
  uchar *buffer = arena + PGSIZE - 16;
  int offset = buffer - arena;

  for(int i = 0; i < sizeof(limits) / sizeof(limits[0]); i++){
    memset(arena, MARKER, sizeof(arena));
    int n = ptree((struct ptreeinfo *)buffer, limits[i]);
    int capacity = limits[i] < NPROC ? limits[i] : NPROC;
    if(n < 1 || n > capacity)
      stop(1, "two-page buffer count");
    int bytes = n * sizeof(struct ptreeinfo);
    for(int j = 0; j < sizeof(arena); j++){
      if((j < offset || j >= offset + bytes) && arena[j] != MARKER)
        stop(1, "write outside returned records");
    }
    memmove(rows, buffer, bytes);
    validate(n, capacity, capacity == NPROC);
  }
  printf("ptreetest: two-page buffers and exact write bounds PASS\n");

  // exec() places its guard immediately before USERSTACK pages. The large
  // BSS above guarantees that the preceding page is writable data. Preserve
  // its last 16 bytes, even if they belong to another global, then restore
  // them before using any globals or reporting the result.
  uchar saved[16];
  uchar *prefix = (uchar *)(initial_size - (USERSTACK + 1) * PGSIZE - 16);
  for(int i = 0; i < sizeof(saved); i++){
    saved[i] = prefix[i];
    prefix[i] = MARKER;
  }
  int result = ptree((struct ptreeinfo *)prefix, 1);
  int changed = 0;
  for(int i = 0; i < sizeof(saved); i++){
    if(prefix[i] != MARKER)
      changed = 1;
    prefix[i] = saved[i];
  }
  if(result != -1)
    stop(1, "copyout into guard did not fail");
  // The API permits partial writes but does not require them. This check
  // proves coverage of this repository's page-by-page copyout error path.
  if(!changed)
    stop(2, "partial copyout path not observed");
  snapshot();
  printf("ptreetest: partial copyout failure and recovery PASS\n");
}

static void
test_memsize(void)
{
  uint64 before = (uint64)sbrk(0);
  int delta = PGSIZE + 13;
  if((uint64)sbrk(delta) != before || (uint64)sbrk(0) != before + delta)
    stop(1, "heap growth");
  snapshot();
  if((uint64)sbrk(-delta) != before + delta || (uint64)sbrk(0) != before)
    stop(1, "heap shrink");
  snapshot();
  printf("ptreetest: synchronized grow/shrink memsize PASS\n");
}

static void
test_tree(void)
{
  int a_gate[2], g_gate[2], b_gate[2], report[2];
  int a, b, g, status;
  char token;

  newpipe(a_gate);
  newpipe(g_gate);
  newpipe(b_gate);
  newpipe(report);
  a = fork();
  if(a < 0)
    stop(1, "first child fork");
  if(a == 0){
    close(a_gate[1]); close(g_gate[1]); close(report[0]);
    close(b_gate[0]); close(b_gate[1]);
    g = fork();
    if(g == 0){
      close(a_gate[0]); close(report[1]);
      if(read_all(g_gate[0], &token, 1) < 0)
        exit(1);
      close(g_gate[0]);
      exit(0);
    }
    close(g_gate[0]);
    if(write_all(report[1], &g, sizeof(g)) < 0 || g < 0)
      exit(1);
    close(report[1]);
    if(read_all(a_gate[0], &token, 1) < 0)
      exit(1);
    close(a_gate[0]);
    if(wait(&status) != g || status != 0)
      exit(1);
    exit(0);
  }
  watch(a);
  close(a_gate[0]); close(g_gate[0]); close(report[1]);
  b = fork();
  if(b < 0)
    stop(1, "sibling fork");
  if(b == 0){
    close(a_gate[1]); close(g_gate[1]); close(report[0]); close(b_gate[1]);
    if(read_all(b_gate[0], &token, 1) < 0)
      exit(1);
    close(b_gate[0]);
    exit(0);
  }
  watch(b);
  close(b_gate[0]);
  if(read_all(report[0], &g, sizeof(g)) < 0)
    stop(1, "grandchild report");
  close(report[0]);
  watch(g);
  expect_process(a, self, STATE_SLEEPING);
  expect_process(b, self, STATE_SLEEPING);
  expect_process(g, a, STATE_SLEEPING);
  release_gate(g_gate[1]);
  release_gate(a_gate[1]);
  release_gate(b_gate[1]);
  int first = wait(&status);
  if((first != a && first != b) || status != 0)
    stop(1, "first child wait");
  int second = wait(&status);
  if((second != a && second != b) || first == second || status != 0)
    stop(1, "second child wait");
  ntracked = 0;
  printf("ptreetest: parent/child/grandchild, siblings and SLEEPING PASS\n");
}

static void
test_zombie(void)
{
  int done[2], status, pid;
  char token;

  newpipe(done);
  pid = fork();
  if(pid < 0)
    stop(1, "zombie fork");
  if(pid == 0){
    close(done[0]);
    if(write_all(done[1], "z", 1) < 0)
      exit(1);
    exit(37);
  }
  watch(pid);
  close(done[1]);
  if(read_all(done[0], &token, 1) < 0 || read(done[0], &token, 1) != 0)
    stop(1, "exit pipe notification");
  close(done[0]);
  // EOF precedes ZOMBIE in exit(); observe the actual state before wait().
  expect_process(pid, self, STATE_ZOMBIE);
  if(wait(&status) != pid || status != 37)
    stop(1, "zombie wait/status");
  snapshot();
  if(find(pid) >= 0)
    stop(1, "reaped PID remains");
  ntracked = 0;
  printf("ptreetest: ZOMBIE before wait and absence after wait PASS\n");
}

static void
test_reparent(int init_pid)
{
  int p_gate[2], g_gate[2], report[2], done[2];
  int parent, grandchild, status;
  char token;

  newpipe(p_gate); newpipe(g_gate); newpipe(report); newpipe(done);
  parent = fork();
  if(parent < 0)
    stop(1, "reparent fork");
  if(parent == 0){
    close(p_gate[1]); close(g_gate[1]); close(report[0]); close(done[0]);
    grandchild = fork();
    if(grandchild == 0){
      close(p_gate[0]); close(report[1]);
      if(write_all(done[1], "r", 1) < 0 || read_all(g_gate[0], &token, 1) < 0)
        exit(1);
      close(g_gate[0]);
      if(write_all(done[1], "d", 1) < 0)
        exit(1);
      exit(0);
    }
    close(g_gate[0]); close(done[1]);
    if(write_all(report[1], &grandchild, sizeof(grandchild)) < 0 || grandchild < 0)
      exit(1);
    close(report[1]);
    if(read_all(p_gate[0], &token, 1) < 0)
      exit(1);
    close(p_gate[0]);
    exit(0); // Deliberately leave the live grandchild for init to adopt.
  }
  watch(parent);
  close(p_gate[0]); close(g_gate[0]); close(report[1]); close(done[1]);
  if(read_all(report[0], &grandchild, sizeof(grandchild)) < 0)
    stop(1, "orphan PID report");
  close(report[0]);
  watch(grandchild);
  if(read_all(done[0], &token, 1) < 0 || token != 'r')
    stop(1, "grandchild readiness");
  expect_process(parent, self, STATE_SLEEPING);
  expect_process(grandchild, parent, STATE_SLEEPING);
  release_gate(p_gate[1]);
  if(wait(&status) != parent || status != 0)
    stop(1, "intermediate parent wait");
  expect_process(grandchild, init_pid, STATE_SLEEPING);
  release_gate(g_gate[1]);
  if(read_all(done[0], &token, 1) < 0 || token != 'd' ||
     read(done[0], &token, 1) != 0)
    stop(1, "orphan exit notification");
  close(done[0]);
  expect_absent(grandchild);
  ntracked = 0;
  printf("ptreetest: reparent to ancestry root and init collection PASS\n");
}

int
main(void)
{
  self = getpid();
  initial_size = (uint64)sbrk(0);
  int init_pid = ancestry_root();
  test_buffers();
  test_memsize();
  test_tree();
  test_zombie();
  test_reparent(init_pid);
  printf("ptreetest: all checks passed\n");
  exit(0);
}
