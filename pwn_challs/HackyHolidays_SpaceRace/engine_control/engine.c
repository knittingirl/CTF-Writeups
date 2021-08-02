#include <stdlib.h>
#include <stdio.h>
#include <string.h>


int main(void) {

 char i[200] = {0};
 setbuf(stdout, 0);

 printf("\033[1mCommand: \033[0m");

 while(fgets(i, 200, stdin)!=NULL) {
    i[strcspn(i,"\n")] = 0;

    if (strlen(i) > 0) {
	    printf("Running command (");
	    printf(i);
	    printf(") now on engine.\n");
    }

    printf("\033[1mCommand: \033[0m");
 }
}
