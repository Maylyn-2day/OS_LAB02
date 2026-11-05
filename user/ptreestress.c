#include "kernel/types.h"
#include "kernel/param.h"
#include "kernel/riscv.h"
#include "kernel/ptree.h"
#include "user/user.h"

enum {
  ROUNDS = 3, CALLERS = 4, CALLS = 512, OBSERVERS = 3,
  EPOCHS = 8, OBS_CALLS = 96, OPS = 4, EXEC_STEPS = 4,
  REUSE = 64, NEAR_CALLS = 64, ERROR_LOOPS = 128,
  PROBE_LIMIT = 32768, MARKER = 0xa5,
  OBSERVE = 0, FORKER = 1, EXECUTOR = 2, GROWER = 3,
  SEEN_EXEC = 1, SEEN_GROW = 2, SEEN_FORK = 4
};

struct report {
  int pid, epoch, status, calls, seen, ops;
  uint64 size;
};

// kernel/pipe.c uses a 512-byte pipe buffer; one epoch never fills it.
_Static_assert((OBSERVERS + 3) * sizeof(struct report) <= 512,
               "epoch reports must fit in the result pipe");

struct config {
  int root, exec_pid, grow_pid, fork_pid;
  uint64 base;
};

static struct {
  uint64 before[2];
  struct ptreeinfo rows[NPROC];
  uchar after[16];
} buffer;
static const struct ptreeinfo readonly_info = { .pid = -1 };
static struct config cfg;
static int supervisor, reply_fd = -1, current_epoch = -1;
static int children[NPROC], nchildren, alias_created, seen;
static uint64 local_calls, remote_calls, expected_errors;
static uint64 fork_ops, exec_ops, grow_ops;
static int peak;

static int
read_all(int fd, void *data, int bytes)
{
  char *p = data;
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
write_all(int fd, const void *data, int bytes)
{
  const char *p = data;
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
stop(int status, const char *message)
{
  fprintf(2, "ptreestress: pid=%d %s %s\n", getpid(), message,
          status == 2 ? "INCONCLUSIVE" : "FAIL");
  if(getpid() != supervisor){
    struct report r = { .pid = getpid(), .epoch = current_epoch, .status = status };
    if(reply_fd >= 0)
      write_all(reply_fd, &r, sizeof(r));
    exit(status);
  }
  for(int i = 0; i < nchildren; i++){
    if(children[i] > 0)
      kill(children[i]);
  }
  while(wait(0) > 0)
    ;
  if(alias_created)
    unlink("ptreeflip");
  exit(status);
}

static void
newpipe(int fd[2])
{
  if(pipe(fd) < 0)
    stop(1, "pipe allocation");
}

static void
track(int pid)
{
  if(pid <= 0 || nchildren == NPROC)
    stop(1, "fork/child limit");
  children[nchildren++] = pid;
  fork_ops++;
}

static void
reap_all(void)
{
  for(int i = 0; i < nchildren; i++){
    int status, pid = wait(&status), found = -1;
    for(int j = 0; j < nchildren; j++){
      if(children[j] == pid)
        found = j;
    }
    if(found < 0 || status != 0)
      stop(1, "wait PID/status");
    children[found] = 0;
  }
  nchildren = 0;
  if(wait(0) != -1)
    stop(1, "uncollected direct child");
}

static void
metadata(struct ptreeinfo *p)
{
  if(p->pid <= 0 || p->ppid < 0 || p->pid == p->ppid ||
     p->state < 1 || p->state > 5 || p->memsize > MAXVA)
    stop(1, "invalid record values");
  int nul = 0;
  for(int i = 0; i < sizeof(p->name); i++){
    if(p->name[i] == 0)
      nul = 1;
  }
  if(!nul)
    stop(1, "unterminated name");
  if(p->pid == getpid() && p->memsize != (uint64)sbrk(0))
    stop(1, "caller size");

  // Registry entries stay alive throughout each mixed phase. USED records
  // without a published parent and all unrelated processes remain generic.
  if(p->pid == cfg.exec_pid){
    if(p->ppid != cfg.root)
      stop(1, "exec worker parent");
    if(strcmp(p->name, "ptreeflip") == 0){
      if(p->memsize != cfg.base)
        stop(1, "mixed exec name/size");
      seen |= SEEN_EXEC;
    } else if(strcmp(p->name, "ptreestress") != 0 ||
              (p->memsize != cfg.base && p->memsize != cfg.base + PGSIZE)){
      stop(1, "exec worker metadata");
    }
  }
  if(p->pid == cfg.grow_pid){
    if(p->ppid != cfg.root || strcmp(p->name, "ptreestress") != 0 ||
       (p->memsize != cfg.base && p->memsize != cfg.base + PGSIZE + 17))
      stop(1, "sbrk worker metadata");
    if(p->memsize != cfg.base)
      seen |= SEEN_GROW;
  }
  if(cfg.fork_pid && p->ppid == cfg.fork_pid){
    if(strcmp(p->name, "ptreestress") != 0 || p->memsize != cfg.base)
      stop(1, "fork generation metadata");
    seen |= SEEN_FORK;
  }
}

static int
checked(int max)
{
  memset(&buffer, MARKER, sizeof(buffer));
  int n = ptree(buffer.rows, max);
  int cap = max < NPROC ? max : NPROC;
  if(n < 0 || n > cap)
    stop(1, "snapshot return count");
  uchar *raw = (uchar *)&buffer;
  int offset = (uchar *)buffer.rows - raw;
  int bytes = n * sizeof(struct ptreeinfo);
  for(int i = 0; i < sizeof(buffer); i++){
    if((i < offset || i >= offset + bytes) && raw[i] != MARKER)
      stop(1, "snapshot buffer overwrite");
  }
  for(int i = 0; i < n; i++){
    metadata(&buffer.rows[i]);
    for(int j = 0; j < i; j++){
      if(buffer.rows[j].pid == buffer.rows[i].pid)
        stop(1, "duplicate PID");
    }
  }
  local_calls++;
  return n;
}

static struct ptreeinfo *
lookup(int n, int pid)
{
  for(int i = 0; i < n; i++){
    if(buffer.rows[i].pid == pid)
      return &buffer.rows[i];
  }
  return 0;
}

static void
number(char *out, int value)
{
  char tmp[16];
  int n = 0, negative = value < 0;
  uint x = negative ? -value : value;
  do {
    tmp[n++] = '0' + x % 10;
    x /= 10;
  } while(x);
  if(negative)
    *out++ = '-';
  while(n)
    *out++ = tmp[--n];
  *out = 0;
}

static void
exec_worker(int gate, int output, int epoch, int left, const char *image)
{
  char token;
  reply_fd = output;
  if(epoch < -1 || epoch >= EPOCHS || left < 0 || left > EXEC_STEPS)
    stop(1, "invalid exec continuation");
  for(;;){
    if(left == 0){
      if(epoch >= 0){
        struct report r = { .pid = getpid(), .epoch = epoch, .ops = EXEC_STEPS };
        if(write_all(output, &r, sizeof(r)) < 0)
          stop(1, "exec acknowledgement");
      }
      epoch++;
      current_epoch = epoch;
      if(read_all(gate, &token, 1) < 0)
        stop(1, "exec command");
      if(token == 'q')
        exit(0);
      if(token != 'g' || epoch >= EPOCHS)
        stop(1, "exec epoch bound");
      left = EXEC_STEPS;
    }
    current_epoch = epoch;
    int flip = strcmp(image, "ptreeflip") == 0;
    if(!flip && sbrk(PGSIZE) == (char *)-1)
      stop(1, "pre-exec growth");
    sleep(1); // Widen observation windows, never used as a state oracle.
    char a[16], b[16], c[16], d[16];
    number(a, gate); number(b, output); number(c, epoch); number(d, left - 1);
    char *target = flip ? "ptreestress" : "ptreeflip";
    char *argv[] = {target, "execworker", a, b, c, d, 0};
    exec(target, argv);
    stop(1, "exec transition");
  }
}

static void
leaf(int gate, int output)
{
  struct report r = { .pid = getpid(), .epoch = -2, .size = (uint64)sbrk(0) };
  char token;
  if(write_all(output, &r, sizeof(r)) < 0 || read(gate, &token, 1) < 0)
    exit(1);
  exit(0);
}

static void
worker(int role, int gate, int output)
{
  reply_fd = output;
  local_calls = 0;
  if(read_all(gate, &cfg, sizeof(cfg)) < 0)
    stop(1, "worker configuration");
  if(role == EXECUTOR)
    exec_worker(gate, output, -1, 0, "ptreestress");
  for(int epoch = 0;; epoch++){
    char token;
    current_epoch = epoch;
    if(read_all(gate, &token, 1) < 0)
      stop(1, "worker command");
    if(token == 'q')
      exit(0);
    if(token != 'g' || epoch >= EPOCHS)
      stop(1, "worker epoch bound");
    uint64 start = local_calls;
    seen = 0;
    if(role == OBSERVE){
      int limits[] = {1, NPROC, NPROC + 1, 0x7fffffff};
      int calls = cfg.exec_pid ? OBS_CALLS : CALLS;
      for(int i = 0; i < calls; i++){
        checked(limits[i % 4]);
        if(i % 8 == 7)
          sleep(1);
      }
    } else if(role == FORKER){
      for(int i = 0; i < OPS; i++){
        int pid = fork(), status;
        if(pid < 0)
          stop(1, "churn fork");
        if(pid == 0){
          sleep(1);
          exit(i);
        }
        checked(NPROC);
        if(wait(&status) != pid || status != i)
          stop(1, "churn wait");
      }
    } else if(role == GROWER){
      for(int i = 0; i < OPS; i++){
        if((uint64)sbrk(PGSIZE + 17) != cfg.base)
          stop(1, "concurrent sbrk growth");
        sleep(1);
        checked(NPROC);
        if((uint64)sbrk(-(PGSIZE + 17)) != cfg.base + PGSIZE + 17)
          stop(1, "concurrent sbrk shrink");
        sleep(1);
        checked(NPROC);
      }
    }
    struct report r = { .pid = getpid(), .epoch = epoch,
      .calls = local_calls - start, .seen = seen, .ops = role == OBSERVE ? 0 : OPS };
    if(write_all(output, &r, sizeof(r)) < 0)
      stop(1, "worker acknowledgement");
  }
}

static void
run_workers(int mixed)
{
  int result[2], gates[OBSERVERS + 3], pids[OBSERVERS + 3], roles[OBSERVERS + 3];
  int workers = mixed ? OBSERVERS + 3 : CALLERS;
  int epochs = mixed ? EPOCHS : 1, coverage = 0;
  uint64 before = remote_calls;
  newpipe(result);
  for(int i = 0; i < workers; i++){
    int gate[2];
    newpipe(gate);
    roles[i] = !mixed || i < OBSERVERS ? OBSERVE : i - OBSERVERS + 1;
    int pid = fork();
    if(pid == 0){
      close(result[0]); close(gate[1]);
      for(int j = 0; j < i; j++)
        close(gates[j]);
      worker(roles[i], gate[0], result[1]);
      exit(1);
    }
    track(pid);
    pids[i] = pid;
    gates[i] = gate[1];
    close(gate[0]);
  }
  close(result[1]);
  cfg.exec_pid = mixed ? pids[OBSERVERS + 1] : 0;
  cfg.grow_pid = mixed ? pids[OBSERVERS + 2] : 0;
  cfg.fork_pid = mixed ? pids[OBSERVERS] : 0;
  for(int i = 0; i < workers; i++){
    if(write_all(gates[i], &cfg, sizeof(cfg)) < 0)
      stop(1, "send worker configuration");
  }
  for(int epoch = 0; epoch < epochs; epoch++){
    int received[OBSERVERS + 3] = {0};
    for(int i = 0; i < workers; i++){
      if(write_all(gates[i], "g", 1) < 0)
        stop(1, "start epoch");
    }
    for(int i = 0; i < workers; i++){
      struct report r;
      if(read_all(result[0], &r, sizeof(r)) < 0)
        stop(1, "missing worker report");
      int index = -1;
      for(int j = 0; j < workers; j++){
        if(pids[j] == r.pid)
          index = j;
      }
      if(index < 0 || received[index] || r.epoch != epoch || r.status)
        stop(r.status == 2 ? 2 : 1, "worker report/status");
      received[index] = 1;
      remote_calls += r.calls;
      if(roles[index] == OBSERVE)
        coverage |= r.seen;
      else if(roles[index] == FORKER)
        fork_ops += r.ops;
      else if(roles[index] == EXECUTOR)
        exec_ops += r.ops;
      else if(roles[index] == GROWER)
        grow_ops += r.ops;
    }
  }
  for(int i = 0; i < workers; i++){
    if(write_all(gates[i], "q", 1) < 0)
      stop(1, "stop worker");
    close(gates[i]);
  }
  close(result[0]);
  reap_all();
  cfg.exec_pid = cfg.grow_pid = cfg.fork_pid = 0;
  if(mixed && coverage != (SEEN_EXEC | SEEN_GROW | SEEN_FORK))
    stop(2, "mixed activity not observed by snapshot callers");
  printf("ptreestress: %s calls=%lu coverage=%d PASS\n",
         mixed ? "mixed" : "callers", remote_calls - before, coverage);
}

static void
test_reuse(void)
{
  for(int i = 0; i < REUSE; i++){
    int gate[2], result[2];
    newpipe(gate); newpipe(result);
    int pid = fork();
    if(pid == 0){
      close(gate[1]); close(result[0]);
      if(i % 2){
        char a[16], b[16];
        number(a, gate[0]); number(b, result[1]);
        char *argv[] = {"ptreeflip", "leaf", a, b, 0};
        exec(argv[0], argv);
        exit(1);
      }
      leaf(gate[0], result[1]);
    }
    track(pid);
    close(gate[0]); close(result[1]);
    struct report r;
    if(read_all(result[0], &r, sizeof(r)) < 0 || r.pid != pid || r.size != cfg.base)
      stop(1, "reuse readiness");
    int n = checked(NPROC);
    struct ptreeinfo *p = lookup(n, pid);
    if(!p || p->ppid != supervisor || p->memsize != cfg.base ||
       strcmp(p->name, i % 2 ? "ptreeflip" : "ptreestress") != 0)
      stop(1, "reused generation identity");
    if(write_all(gate[1], "x", 1) < 0)
      stop(1, "release generation");
    close(gate[1]); close(result[0]);
    reap_all();
    if(lookup(checked(NPROC), pid))
      stop(1, "reaped generation remains");
  }
  exec_ops += REUSE / 2;
  printf("ptreestress: slot reuse generations=%d PASS\n", REUSE);
}

static void
test_near_full(void)
{
  int initial = checked(NPROC);
  int holders = NPROC - initial - 3;
  if(holders < 1)
    stop(2, "insufficient spare slots for near-full test");
  int gate[2], result[2];
  newpipe(gate); newpipe(result);
  for(int i = 0; i < holders; i++){
    int pid = fork();
    if(pid == 0){
      close(gate[1]); close(result[0]);
      leaf(gate[0], result[1]);
    }
    track(pid);
    struct report r;
    if(read_all(result[0], &r, sizeof(r)) < 0 || r.pid != pid)
      stop(1, "near-full readiness");
  }
  close(gate[0]); close(result[0]); close(result[1]);
  // Unlike the mixed phase, all these known holders are stable behind a
  // pipe gate and the buffer covers NPROC, so each must be represented.
  for(int i = 0; i < NEAR_CALLS; i++){
    int n = checked(NPROC);
    if(n > peak)
      peak = n;
    for(int j = 0; j < nchildren; j++){
      struct ptreeinfo *p = lookup(n, children[j]);
      if(!p || p->ppid != supervisor || p->memsize != cfg.base ||
         strcmp(p->name, "ptreestress") != 0)
        stop(1, "near-full held process metadata");
    }
  }
  close(gate[1]); // EOF releases every holder; no per-child descriptor needed.
  reap_all();
  checked(NPROC);
  printf("ptreestress: near-full holders=%d peak=%d/%d PASS\n", holders, peak, NPROC);
}

static void
test_errors(void)
{
  for(int i = 0; i < ERROR_LOOPS; i++){
    uint64 end = (uint64)sbrk(0);
    if(ptree((struct ptreeinfo *)&readonly_info, 1) != -1 ||
       ptree((struct ptreeinfo *)(end - sizeof(struct ptreeinfo) + 1), 1) != -1)
      stop(1, "snapshot error cleanup return");
    expected_errors += 2;
  }
  printf("ptreestress: post-allocation error calls=%d PASS\n", ERROR_LOOPS * 2);
}

// A user-page allocation capacity probe, not an exact free-kernel-page count.
// Each probe uses the same child image, break and single result pipe.
static int
probe(int pressure)
{
  int result[2];
  newpipe(result);
  int pid = fork();
  if(pid == 0){
    close(result[0]);
    reply_fd = result[1];
    local_calls = 0;
    if(pressure)
      checked(NPROC); // Establish the buffer's mapping before exhausting RAM.
    uint64 old = (uint64)sbrk(0);
    int pages;
    for(pages = 0; pages < PROBE_LIMIT; pages++){
      char *p = sbrk(PGSIZE);
      if(p == (char *)-1)
        break;
      *p = 1;
    }
    if(pages == PROBE_LIMIT)
      stop(2, "allocation probe bound reached");
    int held[4][2], pipes = 0, forced = 0;
    if(pressure){
      // A page-table boundary can leave a residual page after sbrk fails.
      // Each successful pipe consumes one page; at most eight extra FDs.
      while(pipes < 4 && pipe(held[pipes]) == 0)
        pipes++;
      int value = ptree(buffer.rows, NPROC);
      forced = value == -1;
      if(value < -1 || value > NPROC)
        stop(1, "pressure return count");
    }
    for(int i = 0; i < pipes; i++){
      close(held[i][0]); close(held[i][1]);
    }
    if((uint64)sbrk(-pages * PGSIZE) != old + (uint64)pages * PGSIZE)
      stop(1, "probe heap restoration");
    if(pressure)
      checked(NPROC);
    struct report r = { .pid = getpid(), .epoch = pipes,
      .status = pressure && !forced ? 3 : 0,
      .calls = local_calls, .ops = forced, .size = pages };
    if(write_all(result[1], &r, sizeof(r)) < 0)
      exit(1);
    exit(0);
  }
  track(pid);
  close(result[1]);
  struct report r;
  if(read_all(result[0], &r, sizeof(r)) < 0 || r.pid != pid)
    stop(1, "resource probe report");
  if(r.status != 0 && r.status != 3)
    stop(r.status == 2 ? 2 : 1, "resource probe status");
  close(result[0]);
  reap_all();
  remote_calls += r.calls;
  if(pressure){
    if(r.status == 3)
      printf("ptreestress: procptree kalloc failure NOT TESTED (bounded pressure insufficient)\n");
    else
      printf("ptreestress: procptree kalloc failure pages=%lu residual_pipes=%d recovery PASS\n",
             r.size, r.epoch);
    expected_errors += r.ops;
  }
  return r.size;
}

int
main(int argc, char **argv)
{
  if(argc == 6 && strcmp(argv[1], "execworker") == 0)
    exec_worker(atoi(argv[2]), atoi(argv[3]), atoi(argv[4]), atoi(argv[5]), argv[0]);
  if(argc == 4 && strcmp(argv[1], "leaf") == 0)
    leaf(atoi(argv[2]), atoi(argv[3]));
  if(argc != 1)
    exit(1);
  supervisor = getpid();
  cfg.root = supervisor;
  cfg.base = (uint64)sbrk(0);
  if(link("ptreestress", "ptreeflip") < 0)
    stop(2, "cannot create reserved exec alias");
  alias_created = 1;
  int baseline = probe(0);
  if(probe(0) != baseline)
    stop(2, "unstable baseline allocation capacity");
  printf("ptreestress: allocation capacity baseline=%d user pages\n", baseline);
  for(int round = 0; round < ROUNDS; round++){
    run_workers(0);
    run_workers(1);
    test_reuse();
    test_near_full();
    test_errors();
    int after = probe(0);
    if(after < baseline)
      stop(1, "allocation capacity decreased after stress");
    if(after > baseline)
      stop(2, "allocation capacity changed after stress");
    printf("ptreestress: round=%d capacity=%d all children reaped PASS\n", round + 1, after);
  }
  probe(1);
  if(probe(0) != baseline)
    stop(1, "allocation capacity changed after pressure recovery");
  if(unlink("ptreeflip") < 0)
    stop(1, "exec alias cleanup");
  alias_created = 0;
  printf("ptreestress: rounds=%d successful_calls=%lu expected_error_calls=%lu forks=%lu execs=%lu grow_shrink_pairs=%lu peak=%d PASS\n",
         ROUNDS, local_calls + remote_calls, expected_errors, fork_ops, exec_ops, grow_ops, peak);
  printf("ptreestress: all checks passed\n");
  exit(0);
}
