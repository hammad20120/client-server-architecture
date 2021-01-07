#define _GNU_SOURCE
#include <unistd.h>
#include <string.h>
#include <ctype.h>
#include <stdbool.h>
#include <signal.h>
#include <regex.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <fcntl.h>

pthread_t result_thread;
int pid_xterm = -2;

/* Signal handler to close external xterm window when socket closes */

void sockClosed(int signo)
{
    if (signo == SIGPIPE)
    {
        if(pid_xterm > 0){
            kill(pid_xterm, SIGTERM);
        }
        write(STDOUT_FILENO, "SOCKET CLOSED\n", 14);
        exit(0);
    }
}

/* Thread responsible for displaying output that comes in socked
 * It first creates a pseudo-terminal to redirect that output to
 * Then attaches it to xterm which displays the output
 */

void *result_printer(void *ptr)
{

    /* Code for preparing xterm window start */

    int pt = posix_openpt(O_RDWR);
    if (pt == -1)
    {
        perror("posix_openpt");
    }
    char* ptname = ptsname(pt);
    if (!ptname)
    {
        perror("ptsname");
    }

    if (unlockpt(pt) == -1)
    {
        perror("unlockpt");
    }

    pid_xterm = fork();
    char xterm_argument[40];

    int bWritten = sprintf(xterm_argument,"-S%s/%d", ptname,pt);
    xterm_argument[bWritten]=0;

    if(pid_xterm == 0){
        execlp("xterm","xterm",xterm_argument,"-geometry", "110x65",
        "-fa", "<truetype font>" ,"-fs" ,"10","-fg","green", NULL);
    }

    int xterm_fd1 = open(ptname,O_RDWR);

    /* Code for preparing xterm window end */

    int socketFd;
    socketFd = *(int *)ptr;

    char resBuff[1500];
    int resRead = 0;

    while (read(socketFd, &resBuff[resRead], 1) > 0)
    {

        if (resBuff[resRead] == ';')
        {

            if(write(xterm_fd1, resBuff, resRead) < 0){
                perror("Xterm");
            }
            write(xterm_fd1, "\n", 1);


            resBuff[resRead] = 0;
            if (strcmp(resBuff, "exited\n") == 0)
            {
                kill(pid_xterm, SIGTERM);
                close(xterm_fd1);
                exit(0);    
            }
            resRead = 0;
            continue;
        }

        resRead++;

        if (resRead >= 800)
        {
            write(xterm_fd1, resBuff, resRead);
            resRead = 0;
        }
    }
    if (resRead == 0 && resBuff[resRead] != ';')
    {
        sockClosed(SIGPIPE);
    }
}

/* client method which is responsible for taking input from user
 * and sending it to server
*/

int client(int socketFd)
{
    signal(SIGPIPE, sockClosed);
    char input[4096], operator[6];
    char *token;
    

    pthread_create(&result_thread, NULL, result_printer, (void *)&socketFd);

    char supportedCommandsPrompt[] = "Supported commands:\n1)Add/Sub/Mult/Div\n2)Run\n3)List\n4)Kill\n5)Print\n6)Clear\n7)Exit\n\n";
    write(STDOUT_FILENO, supportedCommandsPrompt, strlen(supportedCommandsPrompt));

    char prompt[] = {"\nEnter your command:-\n"};

    char inputcpy[4096];

    while (true)
    {
        write(STDOUT_FILENO, prompt, sizeof(prompt) - 1);
        int strReadSize = read(STDIN_FILENO, input, 4096);

        if (strReadSize > 1)
        {
            input[strReadSize - 1] = 0;
            strcpy(inputcpy, input);
            inputcpy[strReadSize - 1] = ';';
            inputcpy[strReadSize] = 0;

            token = strtok(input, " ");
            if (strcmp(token, "clear") == 0)
            {
                system("clear");
                write(STDOUT_FILENO, supportedCommandsPrompt, strlen(supportedCommandsPrompt));
            }
            else
            {

                write(socketFd, inputcpy, strReadSize);
                if (strcasecmp(token, "exit") == 0)
                {
                    break;
                }
                else
                    continue;
            }
        }
        else
        {
            token = "";
            char incorrectInp[] = {"Incorrect input.\n"};
            write(STDOUT_FILENO, incorrectInp, sizeof(incorrectInp) - 1);
            continue;
        }
    }

    pthread_join(result_thread, NULL);
    return 0;
}

/* Sets up socket, connects to server and calls client method */

int main(int argc, char *argv[])
{
    int sock;
    struct sockaddr_in server;
    struct hostent *hp;
    char buf[1024];

    int defaulPort = 32768;
    char ipPrompt[] = "Enter server ip: ";
    write(STDOUT_FILENO, ipPrompt, sizeof(ipPrompt) - 1);

    char ipAdd[15];
    int bread = read(STDIN_FILENO, ipAdd, 15);
    ipAdd[bread - 1] = 0;

    /* Create socket */
    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0)
    {
        perror("opening stream socket");
        exit(1);
    }
    /* Connect socket using name specified by command line. */
    server.sin_family = AF_INET;
    hp = gethostbyname(ipAdd);
    if (hp == 0)
    {
        fprintf(stderr, "%s: unknown host\n", ipAdd);
        exit(2);
    }
    bcopy(hp->h_addr, &server.sin_addr, hp->h_length);
    server.sin_port = htons(defaulPort);

    if (connect(sock, (struct sockaddr *)&server, sizeof(server)) < 0)
    {
        perror("connecting stream socket");
        exit(1);
    }

    int socketFd;
    socketFd = sock;
    client(socketFd);

    close(sock);
}