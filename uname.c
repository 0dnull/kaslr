
#include <sys/utsname.h>

int main() {
  char buff[1024];
  volatile unsigned long long x;

  while (1) {
    uname((struct utsname *) &buff);
    // x = 0; // uncomment this to introduce a local variable x
  }

  return 0;
}
