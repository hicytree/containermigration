#include <stdio.h>
#include <unistd.h>

int main() {
	int count = 0;
	while(1) {
		printf("Counter: %d\n", count);
		sleep(1);
		count += 1;
	}
	
	return 0;
}