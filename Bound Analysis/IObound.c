
#define _GNU_SOURCE

#include <stdlib.h>
#include <stdio.h>
#include <sched.h>
#include <unistd.h>
#include <errno.h>
#include <math.h>
#include <fcntl.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>

#define MAXFILENAMELENGTH 80
#define DEFAULT_INPUTFILENAME "rwinput"
#define DEFAULT_OUTPUTFILENAMEBASE "rwoutput"
#define DEFAULT_BLOCKSIZE 1024
#define DEFAULT_TRANSFERSIZE 1024*100

#define USAGE "./cpu-bound ITERATIONS SCHED_POLICY PROC_COUNT\n"
#define DEFAULT_PROCESSES 10

int main(int argc, char* argv[]){

    int rv;
    int inputFD;
    int outputFD;
    char inputFilename[MAXFILENAMELENGTH];
    char outputFilename[MAXFILENAMELENGTH];
    char outputFilenameBase[MAXFILENAMELENGTH];
    
    struct sched_param param;
    int policy;
    int numprocess;
    int child_status;

    ssize_t transfersize = 0;
    ssize_t blocksize = 0; 
    char* transferBuffer = NULL;
    ssize_t buffersize;

    ssize_t bytesRead = 0;
    ssize_t totalBytesRead = 0;
    int totalReads = 0;
    ssize_t bytesWritten = 0;
    ssize_t totalBytesWritten = 0;
    int totalWrites = 0;
    int inputFileResets = 0;
    
    
    if(argc < 2){
		numprocess = DEFAULT_PROCESSES;
    }
    else{
	numprocess = atol(argv[1]);
		if( numprocess < 1 || numprocess > 5000 ){
            fprintf(stderr, "There will be %d children.", numprocess);
            fprintf(stderr, USAGE);
            exit(EXIT_FAILURE);
        }
	}

    if(argc > 2){
	if(!strcmp(argv[2], "SCHED_OTHER")){
	    policy = SCHED_OTHER;
	}
	else if(!strcmp(argv[2], "SCHED_FIFO")){
	    policy = SCHED_FIFO;
	}
	else if(!strcmp(argv[2], "SCHED_RR")){
	    policy = SCHED_RR;
	}
	else{
	    fprintf(stderr, "Unhandeled scheduling policy\n");
	    exit(EXIT_FAILURE);
	}
    }   
    
    param.sched_priority = sched_get_priority_max(policy);
    fprintf(stdout, "Current Scheduling Policy: %d\n", sched_getscheduler(0));
    fprintf(stdout, "Setting Scheduling Policy to: %d\n", policy);
    if(sched_setscheduler(0, policy, &param)){
	perror("Error setting scheduler policy");
	exit(EXIT_FAILURE);
    }
    fprintf(stdout, "New Scheduling Policy: %d\n", sched_getscheduler(0));
    
    if(argc < 4){
	transfersize = DEFAULT_TRANSFERSIZE;
    }
    else{
	transfersize = atol(argv[3]);
	if(transfersize < 1){
	    fprintf(stderr, "Bad transfersize value\n");
	    exit(EXIT_FAILURE);
	}
    }
    if(argc < 5){
	blocksize = DEFAULT_BLOCKSIZE;
    }
    else{
	blocksize = atol(argv[4]);
	if(blocksize < 1){
	    fprintf(stderr, "Bad blocksize value\n");
	    exit(EXIT_FAILURE);
	}
    }
    if(argc < 6){
	if(strnlen(DEFAULT_INPUTFILENAME, MAXFILENAMELENGTH) >= MAXFILENAMELENGTH){
	    fprintf(stderr, "Default input filename too long\n");
	    exit(EXIT_FAILURE);
	}
	strncpy(inputFilename, DEFAULT_INPUTFILENAME, MAXFILENAMELENGTH);
    }
    else{
	if(strnlen(argv[5], MAXFILENAMELENGTH) >= MAXFILENAMELENGTH){
	    fprintf(stderr, "Input filename too long\n");
	    exit(EXIT_FAILURE);
	}
	strncpy(inputFilename, argv[5], MAXFILENAMELENGTH);
    }
    if(argc < 7){
	if(strnlen(DEFAULT_OUTPUTFILENAMEBASE, MAXFILENAMELENGTH) >= MAXFILENAMELENGTH){
	    fprintf(stderr, "Default output filename base too long\n");
	    exit(EXIT_FAILURE);
	}
	strncpy(outputFilenameBase, DEFAULT_OUTPUTFILENAMEBASE, MAXFILENAMELENGTH);
    }
    else{
	if(strnlen(argv[6], MAXFILENAMELENGTH) >= MAXFILENAMELENGTH){
	    fprintf(stderr, "Output filename base is too long\n");
	    exit(EXIT_FAILURE);
	}
	strncpy(outputFilenameBase, argv[6], MAXFILENAMELENGTH);
    }
	
  
    if(blocksize > transfersize){
	fprintf(stderr, "blocksize can not exceed transfersize\n");
	exit(EXIT_FAILURE);
    }
    if(transfersize % blocksize){
	fprintf(stderr, "blocksize must be multiple of transfersize\n");
	exit(EXIT_FAILURE);
    }

    buffersize = blocksize;
    if(!(transferBuffer = malloc(buffersize*sizeof(*transferBuffer)))){
	perror("Failed to allocate transfer buffer");
	exit(EXIT_FAILURE);
    }
		
    if((inputFD = open(inputFilename, O_RDONLY | O_SYNC)) < 0){
	perror("Failed to open input file");
	exit(EXIT_FAILURE);
    }
    
	int k = 0; 
	for (k = 0; k < numprocess; k++){
		if (fork() == 0){
			rv = snprintf(outputFilename, MAXFILENAMELENGTH, "%s-%d",
				  outputFilenameBase, getpid());    
			if(rv > MAXFILENAMELENGTH){
			fprintf(stderr, "Output filenmae length exceeds limit of %d characters.\n",
				MAXFILENAMELENGTH);
			exit(EXIT_FAILURE);
			}
			else if(rv < 0){
			perror("Failed to generate output filename");
			exit(EXIT_FAILURE);
			}
			if((outputFD =
			open(outputFilename,
				 O_WRONLY | O_CREAT | O_TRUNC | O_SYNC,
				 S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH)) < 0){
			perror("Failed to open output file");
			exit(EXIT_FAILURE);
			}

			/* Print Status */
			fprintf(stdout, "Reading from %s and writing to %s\n",
				inputFilename, outputFilename);

			do{
			bytesRead = read(inputFD, transferBuffer, buffersize);
			if(bytesRead < 0){
				perror("Error reading input file");
				exit(EXIT_FAILURE);
			}
			else{
				totalBytesRead += bytesRead;
				totalReads++;
			}

			if(bytesRead == blocksize){
				bytesWritten = write(outputFD, transferBuffer, bytesRead);
				if(bytesWritten < 0){
				perror("Error writing output file");
				exit(EXIT_FAILURE);
				}
				else{
				totalBytesWritten += bytesWritten;
				totalWrites++;
				}
			}
			else{
				if(lseek(inputFD, 0, SEEK_SET)){
				perror("Error resetting to beginning of file");
				exit(EXIT_FAILURE);
				}
				inputFileResets++;
			}

			}while(totalBytesWritten < transfersize);

			fprintf(stdout, "Read:    %zd bytes in %d reads\n",
				totalBytesRead, totalReads);
			fprintf(stdout, "Written: %zd bytes in %d writes\n",
				totalBytesWritten, totalWrites);
			fprintf(stdout, "Read input file in %d pass%s\n",
				(inputFileResets + 1), (inputFileResets ? "es" : ""));
			fprintf(stdout, "Processed %zd bytes in blocks of %zd bytes\n",
				transfersize, blocksize);

			free(transferBuffer);

			if(close(outputFD)){
			perror("Failed to close output file");
			exit(EXIT_FAILURE);
			}
			
			if(close(inputFD)){
			perror("Failed to close input file");
			exit(EXIT_FAILURE);
			}
			return 0;
		}
	}
	
	int j;  
	for (j = 0; j < numprocess; j++) {
	pid_t wpid = wait(&child_status);

		if (!WIFEXITED(child_status)){
			printf("Child %d terminated abnormally\n", wpid);
		}
	}

    

    return EXIT_SUCCESS;
}
