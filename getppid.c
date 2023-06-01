#include <stdio.h>
#include <unistd.h>

int main() {
  printf("%d -> %d\n", (int)getppid(), (int)getpid());

  return 0;
}
