#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define TAILLE 20

int main(int argc, char **argv){

	char *ptr[TAILLE];
	int i;

	for(i=0; i<TAILLE; i++){
		ptr[i] = malloc(0x10);
		printf("malloc %p\n",ptr[i]);	
	}
	i-=1;
	for(; i>=0; i-=1){
		free(ptr[i]);
		printf("free %p\n",ptr[i]);
	}
}
