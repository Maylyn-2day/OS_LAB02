#include "kernel/types.h"
#include "kernel/param.h"
#include "kernel/ptree.h"
#include "user/user.h"

// Integration test only: hold a known family alive while a child execs pstree.
static struct ptreeinfo baseline[NPROC];
static int tracked[4], ntracked;

static void
fail(const char *message)
{
  fprintf(2, "pstreeprobe: %s FAIL\n", message);
  for(int i = 0; i < ntracked; i++){
    if(tracked[i] > 0)
      kill(tracked[i]);
  }
  while(wait(0) > 0)
    ;
  exit(1);
}

int
main(void)
{
  int gate[2], report[2], start[2], status, a, b, g, printer;
  char token;

  if(pipe(gate) < 0 || pipe(report) < 0)
    fail("pipe creation");
  a = fork();
  if(a < 0)
    fail("child fork");
  if(a == 0){
    close(gate[1]); close(report[0]);
    g = fork();
    if(g == 0){
      close(report[1]);
      if(read(gate[0], &token, 1) != 0)
        exit(1);
      exit(0);
    }
    if(write(report[1], &g, sizeof(g)) != sizeof(g) || g < 0)
      exit(1);
    close(report[1]);
    if(read(gate[0], &token, 1) != 0 || wait(&status) != g || status != 0)
      exit(1);
    exit(0);
  }
  tracked[ntracked++] = a;
  b = fork();
  if(b < 0)
    fail("sibling fork");
  if(b == 0){
    close(gate[1]); close(report[0]); close(report[1]);
    if(read(gate[0], &token, 1) != 0)
      exit(1);
    exit(0);
  }
  tracked[ntracked++] = b;
  close(gate[0]); close(report[1]);
  if(read(report[0], &g, sizeof(g)) != sizeof(g) || g <= 0)
    fail("grandchild report");
  close(report[0]);
  tracked[ntracked++] = g;

  int n = ptree(baseline, NPROC);
  if(n < 1 || n >= NPROC)
    fail("baseline count");
  printf("pstreeprobe: ids root=%d child=%d grandchild=%d sibling=%d\n",
         getpid(), a, g, b);
  for(int i = 0; i < n; i++)
    printf("pstreeprobe: record pid=%d ppid=%d\n", baseline[i].pid, baseline[i].ppid);

  if(pipe(start) < 0)
    fail("printer barrier");
  printer = fork();
  if(printer < 0)
    fail("printer fork");
  if(printer == 0){
    close(gate[1]); close(start[1]);
    if(read(start[0], &token, 1) != 1)
      exit(1);
    close(start[0]);
    char *argv[] = {"pstree", 0};
    exec(argv[0], argv);
    exit(1);
  }
  tracked[ntracked++] = printer;
  close(start[0]);
  printf("pstreeprobe: printer=%d\n", printer);
  printf("pstreeprobe: BEGIN\n");
  if(write(start[1], "x", 1) != 1)
    fail("printer release");
  close(start[1]);
  if(wait(&status) != printer || status != 0)
    fail("pstree exit status");
  tracked[ntracked - 1] = 0;
  printf("pstreeprobe: END\n");

  close(gate[1]); // EOF releases the family only after pstree has exited.
  int first = wait(&status);
  if((first != a && first != b) || status != 0)
    fail("first family wait");
  int second = wait(&status);
  if((second != a && second != b) || second == first || status != 0)
    fail("second family wait");
  ntracked = 0;
  if(wait(0) != -1)
    fail("uncollected child");
  printf("pstreeprobe: all children reaped PASS\n");
  exit(0);
}
