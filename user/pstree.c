#include "kernel/types.h"
#include "kernel/param.h"
#include "kernel/ptree.h"
#include "user/user.h"

static struct ptreeinfo records[NPROC];
static int parent_index[NPROC], order[NPROC];
static uchar visited[NPROC];
static struct {
  int index;
  int depth;
} stack[NPROC];

static void
build_tree(int n)
{
  for(int i = 0; i < n; i++){
    order[i] = i;
    visited[i] = 0;
    parent_index[i] = -1;
    if(records[i].pid <= 0 || records[i].ppid <= 0 ||
       records[i].pid == records[i].ppid)
      continue;
    int own_matches = 0, parent_matches = 0, candidate = -1;
    for(int j = 0; j < n; j++){
      if(records[j].pid == records[i].pid)
        own_matches++;
      if(records[j].pid == records[i].ppid){
        parent_matches++;
        candidate = j;
      }
    }
    // Duplicate/non-positive PIDs must not create ambiguous tree edges.
    if(own_matches == 1 && parent_matches == 1)
      parent_index[i] = candidate;
  }

  // Sort indices only: PID is an identifier, never an array subscript.
  for(int i = 1; i < n; i++){
    int index = order[i], j = i;
    while(j > 0 && records[order[j - 1]].pid > records[index].pid){
      order[j] = order[j - 1];
      j--;
    }
    order[j] = index;
  }
}

static void
print_node(int index, int depth)
{
  char name[sizeof(records[index].name) + 1];
  for(int i = 0; i < sizeof(records[index].name); i++)
    name[i] = records[index].name[i];
  name[sizeof(records[index].name)] = 0;
  for(int i = 0; i < depth; i++)
    printf("  ");
  printf("%s (pid=%d, ppid=%d, state=%d, mem=%lu bytes)\n",
         name[0] ? name : "(unnamed)", records[index].pid,
         records[index].ppid, records[index].state, records[index].memsize);
}

static void
walk(int root, int n)
{
  int top = 0;
  stack[top].index = root;
  stack[top++].depth = 0;
  visited[root] = 1;
  while(top > 0){
    top--;
    int index = stack[top].index, depth = stack[top].depth;
    print_node(index, depth);
    // Reverse insertion makes the next sibling visited the lowest PID.
    for(int i = n - 1; i >= 0; i--){
      int child = order[i];
      if(parent_index[child] == index && !visited[child]){
        // Mark on push: each index enters the stack once, so top <= n.
        visited[child] = 1;
        stack[top].index = child;
        stack[top++].depth = depth + 1;
      }
    }
  }
}

static void
print_tree(int n)
{
  build_tree(n);
  for(int i = 0; i < n; i++){
    int index = order[i];
    if(parent_index[index] == -1 && !visited[index])
      walk(index, n);
  }
  // A component with a cycle has no natural root. Keep its original PPIDs
  // and start from one remaining node; visited prevents duplicate output.
  for(int i = 0; i < n; i++){
    int index = order[i];
    if(!visited[index])
      walk(index, n);
  }
}

int
main(void)
{
  int n = ptree(records, NPROC);
  if(n == -1){
    fprintf(2, "pstree: ptree failed\n");
    exit(1);
  }
  if(n < 0 || n > NPROC){
    fprintf(2, "pstree: invalid record count %d\n", n);
    exit(1);
  }
  print_tree(n);
  exit(0);
}
