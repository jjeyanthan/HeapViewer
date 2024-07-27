#include <stdio.h>
#include <stdlib.h>
#include <sys/ptrace.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <fcntl.h>
#include <string.h>

#define MAX_PATH_SIZE 100
#define MAX_PRINT 100
#define CHUNK_SZ_10 10
#define GREEN "\033[0;32m"
#define RED_HIGH  "\033[7;31m"
#define RED "\033[0;31m"
#define BLUE "\033[0;34m"
#define CYAN "\033[0;36m"
#define PURPLE "\033[0;35m"
#define NEUTRAL "\033[0m"
#define YELLOW "\033[0;33m"
#define MAGENTA "\033[0;95m"


#define GREEN_IT "\033[3;32m"
#define RED_IT "\033[3;31m"
#define BLUE_IT "\033[3;34m"
#define CYAN_IT "\033[3;36m"
#define PURPLE_IT "\033[3;35m"
#define YELLOW_IT "\033[3;33m"
#define MAGENTA_IT "\033[3;95m"

#define RED_HIGH "\033[7;31m"
#define BLUE_HIGH "\033[7;34m"
#define CYAN_HIGH "\033[7;36m"
#define PURPLE_HIGH "\033[7;35m"
#define YELLOW_HIGH "\033[7;33m"
#define MAGENTA_HIGH "\033[7;95m"

#define BLUE_COOL "\033[0;96m"
#define RED_COOL "\033[0;91m"
#define GREEN_COOL "\033[0;92m"
#define ORANGE_COOL "\033[0;93m"


#define WHITE_BOLD "\033[1m"
#define USER_PTRACE_SINGLESTEP 0
#define USER_PTRACE_SYSCALL 0
#define MAX_ARG 10


// retrieve heap start and end address via /proc/pid/maps
int checkProcMaps(int child_pid, unsigned long *heap_start_address, unsigned long *heap_end_address , int *heap_found_){
	char path_proc[MAX_PATH_SIZE];  // 
	char *proc_mp = "/proc/";
	char *mps = "/maps";
	snprintf(path_proc, sizeof(path_proc), "%s%d%s", proc_mp, child_pid, mps);
	FILE *f = fopen(path_proc,"r");
	 if ( f == NULL ) {
        printf( "Cannot open file %s\n", path_proc );
        exit(0);
    }

	char *proc_maps_info = malloc(3000);
	fread(proc_maps_info,2000,1,f);	

	// DBG read line by line
	//printf("%s\n",proc_maps_info);
	char *nl_line = strtok(proc_maps_info,"\n");
	char *look_heap;
	while(nl_line){
		if(strstr(nl_line,"[heap]")!=NULL){
			//printf("--%s\n",nl_line);
			*heap_found_ = 1;
			*heap_start_address = strtol(strtok(nl_line, "-"),NULL ,16);
			*heap_end_address =  strtol(strtok(NULL," "), NULL,16);
			return 0;
		}
		nl_line = strtok(NULL,"\n");
	}

	fclose(f);
	free(proc_maps_info);
	return 0;
}

// retrieve .text section of the binary 
int find_binary_txt_section(int child_pid, char *binary_path_name , unsigned long *start_binary, unsigned long *end_binary){
	char path_proc[MAX_PATH_SIZE];  
	char *proc_mp = "/proc/";
	char *mps = "/maps";
	snprintf(path_proc, sizeof(path_proc), "%s%d%s", proc_mp, child_pid, mps);
	FILE *f = fopen(path_proc,"r");
	
	char *proc_maps_info = malloc(3000);
	fread(proc_maps_info,2000,1,f);	

	// DBG lire ligne par ligne
	//printf("%s\n",proc_maps_info);
	char *nl_line = strtok(proc_maps_info,"\n");
	while(nl_line){
		if(strstr(nl_line,binary_path_name)!=NULL){

			char *contentstrstr = strstr(nl_line,"r-x");
			if(contentstrstr != NULL){ // we found r-x section
				*start_binary = strtol(strtok(nl_line, "-"),NULL ,16);
				*end_binary =  strtol(strtok(NULL," "), NULL,16);
				return 0;
			}
	
		}
		nl_line = strtok(NULL,"\n");
	}
	*start_binary = 0;
	*end_binary=0;
	fclose(f);
	free(proc_maps_info);
	return 0;
}

// iterate until my expected top chunk is met, print heap chunks in color
void print_heap(int pid,long heap_st, long heap_ed){
	long curr_pos = 0;
	long full_heap_sz =  heap_ed - heap_st;
	char *full_heap = malloc(full_heap_sz*10);
	long chunk_end;
	long chunk_start;
	long fs_byte;
	long sd_byte;
	long chunk_sz=0;
	int isChunkEmpty = 0;
	long content=0;
	long first_eight_bt=0;
	long snd_eight_bt =0;
	char *chunk_color;
	
	fs_byte = ptrace(PTRACE_PEEKTEXT,pid,heap_st,0);
	sd_byte = ptrace(PTRACE_PEEKTEXT,pid,heap_st+8,0);
	if(sd_byte !=0){  
		printf("------------------------\n");
		curr_pos=0;
		for(long addr  = heap_st; addr<heap_ed; addr+=chunk_sz){

			isChunkEmpty=1;
			fs_byte = ptrace(PTRACE_PEEKTEXT,pid,addr,0);
			sd_byte = ptrace(PTRACE_PEEKTEXT,pid,addr+8,0);
			chunk_start= addr+8;
			if(sd_byte > 0x411){ // probably the topchunk and we stop iterating here
				if(strncmp(&full_heap[curr_pos-8],"......",6)==0){ 
					curr_pos+=snprintf(&full_heap[curr_pos],MAX_PRINT,"%s%016lx 0000000000000000 %016lx\n%s" ,RED_HIGH,addr ,sd_byte,NEUTRAL);
				}else{
					curr_pos+=snprintf(&full_heap[curr_pos],MAX_PRINT,"%s%016lx\n%s" ,RED_HIGH, sd_byte,NEUTRAL);
				}	
				break;	
			} 
			if (sd_byte == 0){
				chunk_end=addr;  //
				break;
			}
			if((sd_byte & 0x1) == 1){ // if bit prev in use
				chunk_end = (addr+8) + (sd_byte-1);
				chunk_sz = sd_byte-1;
			}else{
				chunk_end = (addr+8) + sd_byte;
				chunk_sz = sd_byte;
			}
			
			// iteration sur un chunk
			for(long chunk_start= addr+16; chunk_start<chunk_end;chunk_start+=8){
			
				content+=ptrace(PTRACE_PEEKTEXT,pid,chunk_start);
				if(content!=0){
					
					isChunkEmpty=0;
					content=0;
					break; // on va devoir afficher
				}
			}
			if(isChunkEmpty == 1){
			// if the chunk contained only 0, print a minify version of it rather than printing all 
				long chunksz = addr+8;
				long chunk_ct = ptrace(PTRACE_PEEKTEXT,pid,chunksz);
			
				
				curr_pos+=snprintf(&full_heap[curr_pos],MAX_PRINT,"\n%016lx 0000000000000000 %016lx\n\t\t................ \n" ,addr, chunk_ct);

			}else{
				// if chunk none empty set colors per size
				if(chunk_sz==0x20){
					chunk_color = PURPLE;
				}
				else if(chunk_sz==0x10){
					chunk_color = GREEN;
				}
				else if(chunk_sz==0x30){
					chunk_color = GREEN_COOL;
				}
				else if(chunk_sz==0x40){
					chunk_color = RED_COOL;
				}
				else if(chunk_sz==0x50){
					chunk_color = PURPLE_IT;
				}
				else if(chunk_sz==0x60){
					chunk_color = GREEN_IT;
				}
				else if(chunk_sz==0x70){
					chunk_color = WHITE_BOLD;
				}
				else if(chunk_sz==0x80){
					chunk_color = GREEN_COOL;
				}
				else if(chunk_sz==0x90){
					chunk_color = ORANGE_COOL;
				}
				else if(chunk_sz==0x100){
					chunk_color = YELLOW_IT;
				}
				else if(chunk_sz==0x110){
					chunk_color = BLUE_COOL;
				}
				else if(chunk_sz==0x290){
					chunk_color = CYAN_IT;
				}
				else if(chunk_sz==0x410){
					chunk_color = BLUE_COOL;
				}else{
					chunk_color=NEUTRAL;
				}

				if(addr ==heap_st){
					// first chunk
					curr_pos+=snprintf(&full_heap[curr_pos],MAX_PRINT,"%016lx 0000000000000000 %s%016lx\n",addr,chunk_color,sd_byte);
				}else if(strncmp(&full_heap[curr_pos-8],"......",6)==0){
					// if the previous chunk is null
					curr_pos+=snprintf(&full_heap[curr_pos],MAX_PRINT,"%016lx 0000000000000000%s %016lx\n",addr,chunk_color,sd_byte);
				}else{
					
					curr_pos+=snprintf(&full_heap[curr_pos],MAX_PRINT,"%s%016lx\n",chunk_color,sd_byte);
				}
				
				// print content of the chunk if none empty
				for(long chunk_start= addr+16; chunk_start<=chunk_end;chunk_start+=16){
					first_eight_bt = ptrace(PTRACE_PEEKTEXT,pid,chunk_start);
					snd_eight_bt = ptrace(PTRACE_PEEKTEXT,pid,chunk_start+8);
		
					if(chunk_start+8 ==chunk_end){
						curr_pos+=snprintf(&full_heap[curr_pos],MAX_PRINT,"%s%016lx %016lx %s",chunk_color,chunk_start,first_eight_bt,NEUTRAL);
					}else{
						curr_pos+=snprintf(&full_heap[curr_pos],MAX_PRINT,"%s%016lx %016lx %016lx\n%s",chunk_color,chunk_start,first_eight_bt,snd_eight_bt,NEUTRAL);
					}
				}
			

			}
		
		
		}
		puts("HEAP\n");
		printf("%s\n",full_heap);
		free(full_heap); 
	}else{  //
		printf("intial chunk don't have size!!!\n");
		
		exit(0);
	}
}


// launch the given process as a child process and trace it  
void traceMyBinary(char *myBinary, char *binaryArguments[], int isPTRACE_SYSCALL,unsigned int  USER_PTRACE_OPERATION){
	long pc =0;
	int binary_main=0;
	long cpt_print_heap=0;
	long pos=0;
	int heap_found = 0;
	unsigned long heap_st_addr= 0;
	unsigned long heap_end_addr= 0;
	unsigned long binary_st_addr= 0;
	unsigned long binary_end_addr= 0;
	
	struct user_regs_struct uregs;
	
	int pid;
	printf("[+] fork %s\n",myBinary);
	if((pid =fork())==0){
	
		// CHILD
		ptrace(PTRACE_TRACEME, 0, NULL, NULL); // we are waiting to be trace by the parent
		if (execve(myBinary,binaryArguments ,NULL) == -1){
			printf("%s[-] Give the absolut path or check if the name is valid: %s%s \n",RED,myBinary,NEUTRAL);
			exit(0);	
		}
		printf("PID du parent:%d\n",pid);
	}else{
		//Child PID is returned we are in the PARENT process
		int status;
		waitpid(pid, &status, 0);
		while(status!=-1){ 

			if(ptrace(PTRACE_GETREGS, pid, 0, &uregs)!=0){
				printf("\n[+] Exit... PC=%llx\n",uregs.rip);
				exit(0);
			}
			else{
				if(binary_st_addr == 0 && binary_end_addr ==0){
					find_binary_txt_section(pid,myBinary,&binary_st_addr,&binary_end_addr);
				}else{
													
					if(isPTRACE_SYSCALL || (uregs.rip >= binary_st_addr && uregs.rip <= binary_end_addr)){ // print only when pc point inside binary
						
						if(heap_found){
							printf("PRINTED HEAP %ld\n", cpt_print_heap);
							print_heap(pid,heap_st_addr,  heap_end_addr);
							sleep(0.4);
							if(cpt_print_heap % 1000 == 0){
								heap_found=0;
							}
							cpt_print_heap+=1;
							
						
						}else{

							checkProcMaps(pid,&heap_st_addr,&heap_end_addr, &heap_found);	
						}
					}
					
				}
				ptrace(USER_PTRACE_OPERATION,pid, 0, 0); 
				waitpid(pid,&status,0);
			}

		}
								
	}

}

// attach to an existing process given its PID and print the heap
void attachBinary(char *binary_path, int pid_to_attach,int isPTRACE_SYSCALL ,unsigned int USER_PTRACE_OPERATION){
	unsigned long cpt_print_heap=0;
	int heap_found = 0;
	int status;
	int cpt=0;
	unsigned long binary_st_addr= 0;
	unsigned long binary_end_addr= 0;
	unsigned long heap_st_addr= 0;
	unsigned long heap_end_addr= 0;
	struct user_regs_struct uregs;
	if(ptrace(PTRACE_ATTACH, pid_to_attach, NULL, NULL) == -1)
	{
		fprintf(stderr, "ptrace(PTRACE_ATTACH) failed\n");
		exit(1);
	}

	waitpid(pid_to_attach, &status, WUNTRACED);	
	while(status!=-1){
		if(ptrace(PTRACE_GETREGS, pid_to_attach, 0, &uregs)!=0){
				printf("\n[+] Exit.. PC=%llx\n",uregs.rip);
				exit(0);
		}else{
			if(binary_st_addr ==0 && binary_end_addr == 0){
				find_binary_txt_section(pid_to_attach,binary_path,&binary_st_addr,&binary_end_addr);
			}
			else{
				if(isPTRACE_SYSCALL || (uregs.rip >= binary_st_addr && uregs.rip <= binary_end_addr)){ // print only when pc point inside binary
							
					if(heap_found){
						printf("PRINTED HEAP %ld\n", cpt_print_heap);
						print_heap(pid_to_attach,heap_st_addr, heap_end_addr);
					
						sleep(0.7);
						if(cpt_print_heap % 1000 == 0){
							heap_found=0;
						}
						cpt_print_heap+=1;
					}else{
						checkProcMaps(pid_to_attach,&heap_st_addr,&heap_end_addr, &heap_found);	
					}
				}
			}
			ptrace(USER_PTRACE_OPERATION,pid_to_attach, 0, 0);
			waitpid(pid_to_attach,&status,0);
		}
	}
}	

// menu
void help(){
		puts("usage: ./heapView MODE PRINT_MODE BINARY_NAME \n");
		puts("MODE:\n");
		puts(GREEN);
		puts("NORMAL:  [SSTEP|SYSCALL] BINARY_NAME\n");
		puts("\tex: ./heapView NORMAL SSTEP PATH_TO_BINARY_NAME\n");
		puts("\tex: ./heapView NORMAL SYSCALL PATH_TO_BINARY_NAME\n\n");
		puts(NEUTRAL);
		puts(BLUE);
		puts("ATTACH:  [SSTEP|SYSCALL] BINARY_NAME PID\n");
		puts("\tex: ./heapView ATTACH SSTEP PATH_TO_BINARY_NAME PID\n");
		puts("\tex: ./heapView ATTACH SYSCALL PATH_TO_BINARY_NAME PID\n");
		puts(NEUTRAL);
		puts("SSTEP for single step : print heap at each instruction inside .text (of the binary)");
		puts("SYSCALL : print heap whenever a SYSCALL happen");
}

// check if given PID is valid
int check_pid_is_num(char *argv_){
	int res = atoll(argv_);
	if(res !=0 ){
		return 1;
	}
	return 0;
}

// retrieve user supply argument (max 10)
void parse_argument(char *binary_path_arg, char *arr[]){

	char *delim_check = strtok(binary_path_arg," ");

	for(int i=0; i<MAX_ARG; i++){
		
		if(delim_check == NULL){
			break;
		}else{
			printf("[+] arg %d %s\n",i, delim_check);
			arr[i]=delim_check;
		}
		delim_check = strtok(NULL," ");
	}
	
}

int main(int argc, char **argv){
	setvbuf(stdout, NULL, _IONBF, 0);

	if(argc < 4 ){
		help();
		exit(0);
	}
	char *binary_arg[MAX_ARG] = {0}; 
	parse_argument(argv[3], binary_arg);
	if(argc == 4){
		if(!strncmp("NORMAL",argv[1],6)){
		
			if(!strncmp("SSTEP",argv[2],5)){
				printf("[+] HEAP will be printed at each instruction \n");
				char *binary_name = argv[3];
				traceMyBinary(binary_name,binary_arg,0, PTRACE_SINGLESTEP);
			
				return 0;
			}
			if(!strncmp("SYSCALL",argv[2],7)){
				printf("[+] HEAP will be printed at each SYSCALL \n");
				char *binary_name = argv[3];
				traceMyBinary(binary_name,binary_arg,1, PTRACE_SYSCALL);
			
				return 0;
			}

			help();
			exit(0);

		}
	}

	// ATTACH 
	if(argc == 5){
		if(!strncmp("ATTACH",argv[1],6)){
		
			if(!strncmp("SSTEP",argv[2],5)){

				if(check_pid_is_num(argv[4])){
					printf("[+] ATTACH pid %s\n",argv[4]);
					printf("[+] HEAP will be printed at each instruction \n");
					char *binary_name = argv[3];
					unsigned int pid_to_attach = atoi(argv[4]);
					attachBinary(binary_name, pid_to_attach, 0, PTRACE_SINGLESTEP);
					return 0;
				}
				help();
				exit(0);
			}
			if(!strncmp("SYSCALL",argv[2],7)){
				printf("SYSCALL\n");
				if(check_pid_is_num(argv[4])){
					printf("[+] ATTACH pid %s\n",argv[4]);
					printf("[+] HEAP will be printed at each SYSCALL \n");
					char *binary_name = argv[3];
					unsigned int pid_to_attach = atoi(argv[4]);
					attachBinary(binary_name, pid_to_attach, 1, PTRACE_SYSCALL);
					return 0;
					
				}
				
				help();
				exit(0);
			}

			help();
			exit(0);

		}
	}
	help();
	exit(0);
}
