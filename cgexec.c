#include <errno.h>
#include <stdio.h>
#include <unistd.h>

int main(int argc, char *argv[], char *envp[]) {
  const char program[9] = "/bin/bash";
  // throws a SEGFAULT when not accessible (either due to non-existence or permission problems)
  FILE *tasksFile = fopen("/sys/fs/cgroup/memory/tcg1/tasks", "w");
  fprintf(tasksFile, "%d\n", (int)getpid());
  fclose(tasksFile);

  // completely ignoring argv here
  int result = execve(program, NULL, envp);
  if (result == -1) {
    printf("%s\n", errno);
  } else {
    printf("%d\n", result);
  }

  return result;
}
