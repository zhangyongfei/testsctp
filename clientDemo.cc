/*
 * Usage: client remote_addr remote_port [local_port] [local_encaps_port] [remote_encaps_port]
 */
#include "SctpWrapper.h"
#include <stdio.h>
#include <string.h>


int ToNetwork(const char* const data, int dataLen, void *context){
    CSctpWrapper *pthis = (CSctpWrapper *)context;

	pthis->InputData(data, dataLen);

	return dataLen;
}

int RecvDataCB(const char* const data, int dataLen, void *context){
    CSctpWrapper *pthis = (CSctpWrapper *)context;

	printf("Recv Data:%s\n", data);

	return 0;
}

int main(int argc, char *argv[])
{
	CSctpWrapper sctp;

    sctp.setRecvCB(RecvDataCB, &sctp);
	sctp.setOutputCB(ToNetwork, &sctp);

	sctp.Connect();

	char buffer[1024] = {0};

	while ((fgets(buffer, sizeof(buffer), stdin) != NULL)) {
		if(strcmp(buffer, "exit") == 0){
			break;
		}
        sctp.sendData(buffer, strlen(buffer));
		//usrsctp_sendv(sock, buffer, strlen(buffer), NULL, 0, NULL, 0, SCTP_SENDV_NOINFO, 0);
	}

	return 0;
}
