#define _GNU_SOURCE
#include <unistd.h>
#include <string.h>
#include <ctype.h>
#include <stdbool.h>
#include <signal.h>
#include <regex.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <pthread.h>
#define TRUE 1

/* Structure contains information required of each process
 * executed through RUN command
 * pid contains Process ID of process
 * name contains the name of process
 * status contains whether process is running or terminated
 * startTime contains time at which process was executed
 * endTime contains time at which process was terminated
 * elapsed time contains time process was active
*/

struct processStruct
{
    int pid;
    char *name;
    char *status;
    time_t startTime;
    time_t endTime;
    time_t elapsedTime;
};

typedef struct processStruct ProcessObject;

ProcessObject *processObject_new(int pid, char *name, char *status)
{
    ProcessObject *p = malloc(sizeof(ProcessObject));
    p->name = malloc(sizeof(name));
    strcpy(p->name, name);

    p->status = malloc(sizeof(status));
    strcpy(p->status, status);

    p->pid = pid;

    p->startTime = time(NULL);
    p->endTime = 0;
    p->elapsedTime = 0;

    return p;
}

void changeProcessStatus(ProcessObject *p, char *status)
{
    p->status = realloc(p->status, sizeof(status));
    strcpy(p->status, status);
}

void processObject_free(ProcessObject *p)
{
    free(p->name);
    free(p->status);
    free(p);
}


/* Structure which contains all the information of clients required
 * pid is client's PID
 * fd contains pipe FD on which connection handler will write
 * syncFD is used to sync clients
 * status contains whether clients is running or disconnected
*/

struct clientHandlerInfoStruct
{
    int pid;
    int fd;
    int syncFd;
    char *status;
};

typedef struct clientHandlerInfoStruct clientHandlerInfo;

clientHandlerInfo *clientHandlerInfo_new(int pid, int fd, int syncFd, char *status)
{
    clientHandlerInfo *p = malloc(sizeof(clientHandlerInfo));

    p->pid = pid;
    p->fd = fd;
    p->syncFd = syncFd;

    p->status = malloc(sizeof(status));
    strcpy(p->status, status);

    return p;
}

/* Global Declaration of variables
 * processLst contains processes executed through run program
 * processCount contains number of processes executed
 * clientList contains all the clients ever connected
 * clientCount contains number of clients which have ever connected
*/

ProcessObject *processLst;
int processCount;

clientHandlerInfo *clientList;
int clientCount;

/* Method to check the string provided in variable token is a number or not
 * It used regex to check if it is a number
 * Also supports negative numbers with negative (-) symbol in start
*/

bool checkIfNumber(char *token, int socket)
{

    regex_t regex;
    int return_val;
    return_val = regcomp(&regex, "^[-]*[0-9]+$", REG_EXTENDED);

    if (return_val != 0)
    {
        char invalidInput[] = {"Failed.\n;"};
        write(socket, invalidInput, sizeof(invalidInput) - 1);
        return false;
    }

    return_val = regexec(&regex, token, 0, NULL, 0);

    if (return_val == REG_NOMATCH)
    {
        char invalidInput[] = {"Enter correct numbers.\n;"};
        write(socket, invalidInput, sizeof(invalidInput) - 1);
        return false;
    }

    return true;
}

/* Checks if string provided in variable str is valid operator
 * validOps contains list of all valid operations
 * size contains size of validOps list
 * The method loops through validOps and compares str to it
 * If it finds a match then returns true as it is a valid operation
 * else if returns false
*/

bool validOpCheck(char *str, char *validOps[], int size)
{
    for (int i = 0; i < size; ++i)
    {
        if (strcmp(validOps[i], str) == 0)
        {
            return true;
        }
    }
    return false;
}

/*  Performs Add/Sub/Mult/Div opeartions.
    Takes 4 inputs, input[] which contains numbers,
    opeartor[] which contains operations (ADD,SUB etc),
    socked which contains socket's Fd
    resultPrompt which contains orginal input as a whole to know answer corresponds to which input
*/

void calcOperation(char input[], char operator[], int socket, char resultPrompt[])
{
    int ans = 0;
    char *token;
    char test[100];

    token = strtok(input, " ");
    token = strtok(NULL, " ");
    strcpy(test, token);

    if (token == NULL || !checkIfNumber(test, socket))
    {

        return;
    }

    ans = atoi(token);

    token = strtok(NULL, " ");

    while (token != NULL)
    {
        strcpy(test, token);
        if (!checkIfNumber(test, socket))
        {
            return;
        }

        int num;
        num = atoi(token);
        if (strcmp(operator, "add") == 0)
            ans += num;
        if (strcmp(operator, "sub") == 0)
            ans -= num;
        if (strcmp(operator, "mult") == 0)
            ans *= num;
        if (strcmp(operator, "div") == 0)
        {
            if (num == 0)
            {
                char res[100];

                char divByZeroPrompt[50];
                int written = sprintf(divByZeroPrompt, "%s:  Can not divide by zero.\n;", resultPrompt);
                write(socket, divByZeroPrompt, written);
                return;
            }
            ans /= num;
        }
        token = strtok(NULL, " ");
    }

    char res[100];
    int written = sprintf(res, "%s: %d\n;", resultPrompt, ans);

    write(socket, res, written);
}

/* Lists all processes
 * Takes socket file descriptor as input to write to socket
 * Boolean isServerThread identifies if method is called by ClientHandler Thread
 * If isServerThread is true, then result is displayed on server
 * If isServerThread is false, then result is written on socked
*/

void listMethod(int socket, bool isServerThread)
{
    int bwritten = 0;
    char details[1500];

    if (isServerThread)
    {
        char listBuf[100];
        int listB = sprintf(listBuf, "LIST OF %d\n\n\n", getpid());
        write(STDOUT_FILENO, listBuf, listB);
    }

    bwritten += sprintf(&details[bwritten], "LIST:\n\n%5s %20s %25s %15s %15s %15s\n",
                        "Pid", "Name", "Status", "StartTime", "EndTime", "ElapsedTime");

    for (int i = 0; i < processCount; i++)
    {
        int pid = processLst[i].pid;
        char *name = processLst[i].name;
        char *status = processLst[i].status;
        time_t stTime = processLst[i].startTime;
        time_t endTime = processLst[i].endTime;
        time_t elapsedTime = processLst[i].elapsedTime;

        struct tm *timeinfo;
        timeinfo = localtime(&stTime);
        char startTime[10];
        sprintf(startTime, "%d:%d:%d", timeinfo->tm_hour, timeinfo->tm_min, timeinfo->tm_sec);

        if (endTime == 0)
        {

            elapsedTime = difftime(time(NULL), stTime);

            char elapsedTimeString[10];
            sprintf(elapsedTimeString, "%ld:%ld:%ld", (elapsedTime / 3600) % 24, (elapsedTime / 60) % 60, (elapsedTime % 60));

            bwritten += sprintf(&details[bwritten], "%5d %20s %25s %15s %15s %15s\n",
                                pid, name, status, startTime, "{none}", elapsedTimeString);
        }
        else
        {

            elapsedTime = difftime(endTime, stTime);
            char elapsedTimeString[10];
            sprintf(elapsedTimeString, "%ld:%ld:%ld", (elapsedTime / 3600) % 24, (elapsedTime / 60) % 60, (elapsedTime % 60));

            char endTimeString[10];
            timeinfo = localtime(&endTime);
            sprintf(endTimeString, "%d:%d:%d", timeinfo->tm_hour, timeinfo->tm_min, timeinfo->tm_sec);

            bwritten += sprintf(&details[bwritten], "%5d %20s %25s %15s %15s %15s\n",
                                pid, name, status, startTime, endTimeString, elapsedTimeString);
        }

        if (bwritten >= 800)
        {
            if (!isServerThread)
            {
                if (write(socket, details, bwritten) < 0)
                {
                    perror("List write");
                }
                bwritten = 0;
            }
            else
            {
                write(STDOUT_FILENO, details, bwritten);
                bwritten = 0;
            }
        }
    }
    if (!isServerThread)
    {
        write(socket, details, bwritten);
        write(socket, "\n;", 2);
    }
    else
    {
        write(STDOUT_FILENO, details, bwritten);
        write(STDOUT_FILENO, "\n\n\n", 3);

    }
}

/* Runs a program on system path
 * cpyInput contains the program to run along with its arguments
 * socket has socket's fd to write to
 * The method breaks cpyInput into arguments and calls execvp to execute the process
*/

void runMethod(char *token, char *cpyInput, int socket)
{
    char *args[100];
    int argsCount = 0;

    token = strtok(cpyInput, " ");
    token = strtok(NULL, " ");

    if (token == NULL)  //If user passed no arguments display error
    {
        char invalidPrompt[] = {"RUN: Enter valid arguments\n;"};
        write(socket, invalidPrompt, sizeof(invalidPrompt) - 1);
        return;
    }

    while (token != NULL)  //Break command into arguments
    {
        args[argsCount] = token;
        token = strtok(NULL, " ");
        argsCount++;
    }
    args[argsCount] = NULL;

    int pipeRun[2];
    pipe2(pipeRun, O_CLOEXEC); //close pipe if exec successful
    int runPid = fork();

    bool errFound = false;

    if (runPid == 0)
    {
        close(pipeRun[0]);
        execvp(args[0], args);

        //Will reach here if exec fails
        char temp[100];
        sprintf(temp, "%s\n", strerror(errno));
        write(pipeRun[1], temp, strlen(temp));
        exit(0);
    }
    else
    {
        close(pipeRun[1]);

        processLst[processCount] = *processObject_new(runPid, args[0], "Running");

        char temp[100];

        //Check if anything is written on pipe, if yes that means exec failed
        while (read(pipeRun[0], temp, 1) > 0)
        {
            if (!errFound)
                errFound = true;
            write(socket, temp, 1);
        }

        //If no error is found update process list and realloc list
        if (!errFound)
        {
            int pid = processLst[processCount].pid;
            char *name = processLst[processCount].name;
            char *status = processLst[processCount].status;

            char details[100];
            int bwritten = sprintf(details, "RUN:  Pid: %d, Name: %s, Status: %s", pid, name, status);

            write(socket, details, bwritten);
            write(socket, "\n;", 2);
            processCount++;

            processLst = realloc(processLst, (processCount + 1) * sizeof(struct processStruct));
        }
        else
        {
            write(socket, ";", 1);
        }

        close(pipeRun[0]);
    }
}

/* Kills a process executed by run command
 * cpyInput contains pid or name of program to be killed
 * socket contain socket file descriptor
 * Method first checks if arguments are valid
 * Then uses regex to identify if pid is passed or name
 * It then checks if process is not already running then sigterms it
*/

void killMethod(char *cpyInput, int socket)
{
    regex_t regex;
    int return_val;
    return_val = regcomp(&regex, "^[0-9]+$", REG_EXTENDED);

    char *token = strtok(cpyInput, " ");
    token = strtok(NULL, " ");
    if (token == NULL)
    {
        char invalidPrompt[] = {"KILL:  Enter valid arguments\n;"};
        write(socket, invalidPrompt, sizeof(invalidPrompt) - 1);
        return;
    }
    return_val = regexec(&regex, token, 0, NULL, 0);

    int bwritten = 0;
    char details[1000];
    bool found = false;

    if (return_val == REG_NOMATCH)
    {
        //process name provided
        for (int i = 0; i < processCount; i++)
        {

            if (strcmp(processLst[i].name, token) == 0)
            {
                found = true;
                int pid = processLst[i].pid;
                char *name = processLst[i].name;

                if (strcmp(processLst[i].status, "Running") != 0)
                {
                    bwritten = sprintf(details, "KILL:  Already Terminated\n;");
                    continue;
                    // break;
                }
                bwritten = 0;

                int stat;
                kill(pid, SIGTERM);
                waitpid(pid, &stat, 0);
                if (WIFSIGNALED(stat))
                {
                    changeProcessStatus(&processLst[i], "Succesful termination");
                    processLst[i].endTime = time(NULL);
                }

                char *status = processLst[i].status;
                bwritten = sprintf(&details[bwritten], "KILL:  Pid: %d, Name: %s, Status: %s\n;", pid, name, status);
                break;
            }
        }
    }
    else
    {
        //process pid
        for (int i = 0; i < processCount; i++)
        {

            if (processLst[i].pid == atoi(token))
            {
                found = true;

                if (strcmp(processLst[i].status, "Running") != 0)
                {
                    bwritten += sprintf(details, "Already Terminated\n;");

                    break;
                }

                int pid = processLst[i].pid;
                char *name = processLst[i].name;

                int stat;
                kill(pid, SIGTERM);
                waitpid(pid, &stat, 0);
                if (WIFSIGNALED(stat))
                {
                    processLst[i].status = "Succesful termination";
                    processLst[i].endTime = time(NULL);
                }

                char *status = processLst[i].status;
                bwritten += sprintf(&details[bwritten], "KILL:  Pid: %d, Name: %s, Status: %s\n;", pid, name, status);
                break;
            }
        }
    }

    if (!found)
    {
        bwritten = sprintf(details, "KILL:  Process not found\n;");
    }

    write(socket, details, bwritten);
}

/* Signal handler to handle when a process executed through run command terminates
 * It first display the pid through which SIGCHLD was generated
 * After that it keeps reading childPids then traverses the processList
 * When it finds the corresponding process in processList it checks if process was terminated through signal
 * If it was not signalled (not terminated through kill command) then it changed status to External Termination
*/

void childTerminationHandler(int signo, siginfo_t *siginfo, void *context)
{

    int childPid;
    int stat;

    char sigPrompt[100];
    int bwritten = sprintf(sigPrompt, "Signal sent by pid %d\n", siginfo->si_pid);
    write(STDOUT_FILENO, sigPrompt, bwritten);

    while ((childPid = waitpid(0, &stat, WNOHANG)) > 0)
    {
        for (int i = 0; i < processCount; i++)
        {
            if (processLst[i].pid == childPid)
            {
                if (!WIFSIGNALED(stat))
                {
                    processLst[i].status = "Externally Terminated";
                    processLst[i].endTime = time(NULL);
                    break;
                }
            }
        }
    }

    if (childPid == 0)
    {
        write(STDOUT_FILENO, "No child left\n", 14);
        return;
    }
}

/* Structure which stores Fds required by Client Handler Thread 
    The structure can be passed as void* while creating the thread */

struct threadFileDescriptorsStruct
{
    int pipeFd;
    int sockFd;
    int syncFd;
};

typedef struct threadFileDescriptorsStruct threadFileDescriptors;

threadFileDescriptors *threadFDs_new(int pipeFd, int sockFd, int syncFd)
{
    threadFileDescriptors *p = malloc(sizeof(threadFileDescriptors));

    p->pipeFd = pipeFd;
    p->sockFd = sockFd;
    p->syncFd = syncFd;
}


/* CONNECTION HANDLER THREAD
 * Responsible for taking input on server
 * Supported commands print, printid <pid>, clear, list
 * Uses clientList to send commands to clients
 * Checks status of each client before sending command
 * If status is terminated, it doesn't send command
*/
void *interactiveServer(void *ptr)
{
    char inputBuff[1024];
    int inputRead;

    char supportedCommandsPrompt[] = "Supported commands:\n1)print\n2)printid <pid>\n3)list\n4)clear\n\n";
    write(STDOUT_FILENO, supportedCommandsPrompt, strlen(supportedCommandsPrompt));

    while (true)
    {
        inputRead = read(STDIN_FILENO, inputBuff, 1024);
        if(inputRead <2){
            continue;
        }
        inputBuff[inputRead-1] = 0;


         if(strcasecmp(inputBuff, "clear") == 0){
            system("clear");
            write(STDOUT_FILENO, supportedCommandsPrompt, strlen(supportedCommandsPrompt));
            inputRead = 0;
            continue;
        }

        char inputcpy[1024];
        strcpy(inputcpy, inputBuff);

        char *operator;
        operator= strtok(inputcpy, " ");
        int pid = -1;

        if (strcasecmp(operator, "printid") == 0)
        {
            char *temp = strtok(NULL, " ");
            pid = atoi(temp);
            
        }else if(strcasecmp(operator, "print") !=0
                && strcasecmp(operator,"list") != 0){
            inputRead = 0;

            write(STDOUT_FILENO, "Incorrect Operation\n", sizeof("Incorrect Operation\n"));
            continue;
        }

        inputBuff[inputRead - 1] = 0;

        

        for (int i = 0; i < clientCount; ++i)
        {

            clientHandlerInfo p = clientList[i];

            if (pid == -1 || pid == p.pid)
            {
                
                if (strcasecmp(p.status, "terminated") != 0)
                {

                    if( write(p.fd, inputBuff, inputRead) < 0){
                        perror("thread pipe write");
                    }

                    char syncBuf[2];
                    while(read(p.syncFd, syncBuf, 1) < 1){

                    }
                }
            }
        }



        inputRead = 0;
    }
}

/* CLIENT HANDLER THREAD
 * Responsible for listening to command sent from CONNECTION HANDLER THREAD
 * ptr variable contains threadFileDescriptor object which contains required FDs
*/
void *threadedServer(void *ptr)
{
    threadFileDescriptors fdObject = *(threadFileDescriptors *)ptr;

    int socketFd = fdObject.sockFd;
    int pipeFd = fdObject.pipeFd;
    int syncFd = fdObject.syncFd;

    char buff[1024];

    int bwritten = 0;
    while ( (bwritten = read(pipeFd, buff, 1024) ) > 0)
    {
        buff[bwritten] = 0;


        char *operator= strtok(buff, " ");
        char *token;
       
        if (strcasecmp(operator, "print") == 0 || strcasecmp(operator, "printid")==0)
        {
            /* If command is printid then use strtok to remove next argument which is pid
             * We dont't have to print pid so we discard it
            */

            if(strcasecmp(operator,"printid") == 0){
                strtok(NULL, " ");
            }
            
            
            bwritten = 0;
            token = strtok(NULL, " ");
            char resBuff[1024];
            while (token != NULL)
            {
                
                bwritten += sprintf(&resBuff[bwritten], "%s ", token);

                token = strtok(NULL, " ");
            }


            // Add newline to result and delimit with semicolon before writing to socket
            resBuff[bwritten] = '\n';
            resBuff[bwritten+1] = ';';
            
            write(socketFd, resBuff, bwritten+2);

            /* Write to syncFd to indicate command has executed fully so that
             * command can be sent to next client without any sync issues
            */
            write(syncFd, ";", 1);
        }
        else if (strcasecmp(operator, "list") == 0)
        {

            listMethod(-1, true);
            write(syncFd, ";", 1);
        }

        bwritten = 0;
    }

    if (bwritten < 0) {
        perror("pipeRead");
    }else if(bwritten == 0){
        exit(0);
    }
}

/* Client Handler method
 * Contains socket Fd to communicate with client
 * pipeFd to communicate with Connection Handler
 * syncFD to keep Client Handlers in sync
*/

void server(int socket, int pipeFd, int syncFd)
{

    /* Setup advanced signal handler to handle
     * termination of procceses executed through run command
     * SA_SIGINFO flag used so that sa_sigaction is used instead of sa_handler
     * SA_RESTART flag used to that read api can continue taking input after signal is handled
    */

    struct sigaction new_action, old_action;
    sigemptyset(&new_action.sa_mask);
    new_action.sa_sigaction = &childTerminationHandler;
    new_action.sa_flags = SA_SIGINFO | SA_RESTART;

    if (sigaction(SIGCHLD, &new_action, NULL) < 0)
    {
        perror("sigaction");
    }

    /* Create a thread to handle incoming commands from connection handler */

    pthread_t threadServer;

    threadFileDescriptors fdObject = *threadFDs_new(pipeFd, socket, syncFd);
    pthread_create(&threadServer, NULL, threadedServer, (void *)&fdObject);

    /* Declare variables and initialize valid operations list */

    char *token, *operator;
    char input[4096];
    char *validOps[] = {"print", "exit", "add", "sub", "mult", "div", "run", "list", "kill"};
    int opsSize = 9;

    /* Initialize process list which contains process executed through RUN command */

    processLst = malloc(1 * sizeof(ProcessObject));
    processCount = 0;

    int totalRead = 0;
    int checkB = 1;

    /* Read input from socket 1 byte at a time
     * Convert it to lowercase to standardize
     * As input is delimited by semicolon (;) which indetifies end of a command
     * It checks for semicolon and then checks if command has a valid operation
     * If it is a print or exit command it's handled there only
     * Every other command is passed to its respective method
    */
    while ((checkB = read(socket, &input[totalRead], 1)) > 0)
    {
        if(input[totalRead] == '\n'){
            input[totalRead] = ' ';
        }

        input[totalRead] = tolower(input[totalRead]);
        totalRead += 1;
        if (input[totalRead - 1] == ';' )
        {
            if (totalRead <= 2)
            {
                char incorrectInp[] = {"Incorrect input.\n;"};
                write(socket, incorrectInp, sizeof(incorrectInp) - 1);

                totalRead = 0;
                continue;
            }

            input[totalRead - 1] = 0;


            char cpyInput[4096];
            char resultPrompt[4096];
            strcpy(resultPrompt, input);
            strcpy(cpyInput, input);


            token = strtok(input, " ");
            operator = token;


            if (!validOpCheck(operator, validOps, opsSize))
            {
                char incorrectOpPrompt[] = {"Incorrect operation.\n;"};
                write(socket, incorrectOpPrompt, sizeof(incorrectOpPrompt) - 1);
                totalRead = 0;
                continue;
            }
            else
            {
                if (strcmp(operator, "exit") == 0)
                {
                    break;
                }
                else if (strcmp(operator, "print") == 0)
                {
                    char promptBuff[100];
                    int bytes = sprintf(promptBuff, "Message from clientId %d: ", getpid());
                    write(STDOUT_FILENO, promptBuff, bytes);

                    token = strtok(cpyInput, " ");
                    token = strtok(NULL, " ");

                    while (token != NULL)
                    {

                        write(STDOUT_FILENO, token, strlen(token));
                        write(STDOUT_FILENO, " ", 1);
                        token = strtok(NULL, " ");
                    }

                    write(STDOUT_FILENO, "\n", 1);
                    write(socket, "Message Written\n;", 18);
                }
                else if (strcmp(operator, "run") == 0)
                {

                    runMethod(token, cpyInput, socket);
                }
                else if (strcmp(operator, "list") == 0)
                {

                    listMethod(socket, false);
                }
                else if (strcmp(operator, "kill") == 0)
                {
                    killMethod(cpyInput, socket);
                }
                else
                {
                    calcOperation(cpyInput, operator, socket, resultPrompt);
                }

                totalRead = 0;
            }
        }
    }

    if (checkB < 0)
    {
        perror("read failed");
    }

    /* When socket is closed it terminates all process in process list and exits */

    for (int i = 0; i < processCount; i++)
    {
        kill(processLst[i].pid, SIGTERM);
    }
    char prompt[] = "Client Disconnected\n";
    write(STDOUT_FILENO, prompt, sizeof(prompt) - 1);
    write(socket, "exited\n;", 8);

    exit(0);
}

/* Signal handler to handle when a client terminates
 * It goes through the connected client list
 * And updates the status of terminated client
 * so that no command is sent to that pid
*/
void clientHandlerTermination(int signo, siginfo_t *siginfo, void *context)
{
    int childPid;

    while ((childPid = waitpid(0, NULL, WNOHANG)) > 0)
    {
        for (int i = 0; i < clientCount; i++)
        {
            if (clientList[i].pid == childPid)
            {
                
                clientList[i].status = "Terminated";
                break;
                
            }
        }
    }
}

int main(void)
{
    /* Initialize variables required for socket connection */
    int sock, length;
    struct sockaddr_in serverInfo;
    int msgsock;
    char buf[1024];
    int rval;
    int i;

    /* Allocate memory to client list to initialize it */
    clientList = malloc(1 * sizeof(clientList));
    clientCount = 0;

    /* Setup signal handler to handle when a client terminates */
    struct sigaction new_action;
    sigemptyset(&new_action.sa_mask);
    new_action.sa_sigaction = &clientHandlerTermination;
    new_action.sa_flags = SA_SIGINFO | SA_RESTART;

    if (sigaction(SIGCHLD, &new_action, NULL) < 0)
    {
        perror("sigaction");
    }

    /* Create CONNECTION HANDLER THREAD
     * Which sends commands to client handlers
    */

    pthread_t interactiveThread;

    pthread_create(&interactiveThread, NULL, interactiveServer, NULL);

    /* Create socket
     * AF_INET tells that ipv4 is being used
     * Sock_Stream defines that its a connection based stream (TCP)
    */
    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0)
    {
        perror("opening stream socket");
        exit(1);
    }
    /* Name socket using wildcards */
    serverInfo.sin_family = AF_INET;
    serverInfo.sin_addr.s_addr = INADDR_ANY;
    serverInfo.sin_port = htons(32768);

    int option = 1;
    setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &option, sizeof(option));

    if (bind(sock, (struct sockaddr *)&serverInfo, sizeof(serverInfo)))
    {
        perror("binding stream socket");
        exit(1);
    }
    /* Find out assigned port number and print it out */
    length = sizeof(serverInfo);
    if (getsockname(sock, (struct sockaddr *)&serverInfo, (socklen_t *)&length))
    {
        perror("getting socket name");
        exit(1);
    }

    /*  printf("Socket has port #%d\n", ntohs(serverInfo.sin_port));
        fflush(stdout);
    */

    /* Start accepting connections */
    listen(sock, 5);
    do
    {

        msgsock = accept(sock, 0, 0);
        if (msgsock == -1)
            perror("accept");
        else
        {

            bzero(buf, sizeof(buf));
            int socketFd;
            socketFd = msgsock;

            /* Create and fill variables for pipe */

            int pipeFds[2];
            int syncFd[2];

            pipe(pipeFds);
            pipe(syncFd);

            int pid = fork();

            if (pid == 0)
            {
                /* If child process then call server method */
                close(pipeFds[1]);
                close(syncFd[0]);
                server(socketFd, pipeFds[0], syncFd[1]);
            }
            else
            {
                /* If client handler then update client list with new clients pid and relevant pipeFds */
                close(pipeFds[0]);
                close(syncFd[1]);

                clientList[clientCount] = *clientHandlerInfo_new(pid, pipeFds[1], syncFd[0], "Running");

                clientCount++;
                clientList = realloc(clientList, (clientCount + 1) * sizeof(clientHandlerInfo));
            }
        }

    } while (TRUE);
}
