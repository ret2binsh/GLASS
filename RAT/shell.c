#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <unistd.h>

# define BUFF 1024
# define TOK_SIZE 64
# define TOK_DELIM " \t\r\n\a"

int lsh_cd(char **args);
int lsh_help(char **args);
int lsh_exit(char **args);
int unrestrict_exec(char **args);

char *builtins[]={
	"cd",
	"help",
	"exit"
};

int (*builtin_funcs[]) (char**) = {
	&lsh_cd,
	&lsh_help,
	&lsh_exit
};

int num_builtins(){
	return sizeof(builtins)/sizeof(char *);
}

int lsh_cd(char **args){
	if (args[1] == NULL){
		fprintf(stderr,"\"cd\" expects an argument\n");
	} else {
		if (chdir(args[1])!=0){
			perror("Error changing directories\n");
		}
	}
	return 1;
}

int lsh_exit(char **args){
	return 0;
}

int lsh_help(char **args){
	int i;
	printf("Welcome to TArp Shell\n");
	printf("The following are are builtin, the rest will run on box:\n");

	for (i=0;i<num_builtins();i++){
		printf("  %s\n",builtins[i]);
	}
	printf("Use man pages for other functions\n");
	return 1;
}

char* lsh_readline(void){
	int buffsize = BUFF;
	int i = 0;
	char *buffer = malloc(sizeof(char)*buffsize);
	int c;
	
	if (!buffer){
		fprintf(stderr, "Command allocation failure\n");
		exit(EXIT_FAILURE);
	}

	while (1) {
		c = getchar();
		if (c == EOF || c=='\n'){
			buffer[i] = '\0';
			return buffer;
		} else {
			buffer[i] = c;
		}
		i++;

		if (i >= buffsize){
			buffsize += BUFF;
			buffer = realloc(buffer,buffsize);
			if (!buffer){
				fprintf(stderr, "Command reallocation failure\n");
				exit(EXIT_FAILURE);
			}
		}	

	}
}

char ** lsh_splitline(char *line){
	int buffsize = TOK_SIZE;
	int i = 0;
	char **tokens = malloc(buffsize * sizeof(char*));
	char *token;

	if (!token){
		fprintf(stderr,"Token allocation error\n");
		exit(EXIT_FAILURE);
		}
	token = strtok(line,TOK_DELIM);
	while (token!= NULL){
		tokens[i] = token;
		i++;
	
		if (i >= buffsize){
			buffsize += TOK_SIZE;
			tokens = realloc(tokens, buffsize * sizeof(char*));
			if (!token){
				fprintf(stderr,"Token allocation error\n");
				exit(EXIT_FAILURE);
			}
		}

		token = strtok(NULL,TOK_DELIM);
		}
		tokens[i]=NULL;
		return tokens;
	}


int unrestrict_exec(char **args){
	pid_t pid,wpid;
	int status;

	pid = fork();
	if (pid == 0){
		if (execvp(args[0],args)==-1){
			perror("exec");
		}
		exit(EXIT_FAILURE);
	} else if (pid < 0) {
		perror("Negative pid");
	} else {
		do {
			wpid = waitpid(pid, &status, WUNTRACED);
		} while (!WIFEXITED(status) && !WIFSIGNALED(status));
	}
	return 1;
}

int launch(char **args){
	int i;

	if (args[0]==NULL){
		return 1;
	}

	for (i = 0; i<num_builtins();i++){
		if (strcmp(args[0],builtins[i])==0){
			return (*builtin_funcs[i])(args);
		}
	}
	return unrestrict_exec(args);
}
		

int main(){
	char *line;
	char **args;
	int status;

	do{
		printf("> ");
		line = lsh_readline();
		args = lsh_splitline(line);
		status = launch(args);


		line = NULL;
		args = NULL;
		free(line);
		free(args);

	}while (status);
	return 0;
}
