#pragma once
#include <usrsctp.h>

enum PreservedErrno {
	SCTP_EINPROGRESS = EINPROGRESS,
	SCTP_EWOULDBLOCK = EWOULDBLOCK
};

typedef int (*OutputNetwork)(const char* const data, int dataLen, void *context);
typedef int (*RecvCB)(const char* const data, int dataLen, void *context);

class CSctpWrapper
{
public:
	CSctpWrapper(void);
	~CSctpWrapper(void);

    bool Connect();

	void Disconnect();

	void InputData(const char * const data, int dataLen);

	void setOutputCB(OutputNetwork output, void *context);

	void setRecvCB(RecvCB recv, void *context);

	int sendData(char *data, int dataLen);

protected:
    bool OpenSctpSocket();

    void CloseSctpSocket();

	sockaddr_conn GetSctpSockAddr(int port);

	static int OnSctpOutboundPacket(void* addr, void* data, size_t length,
		uint8_t tos, uint8_t set_df);

	static int OnSctpInboundPacket(struct socket* sock, union sctp_sockstore addr,
		void* data, size_t length,
	    struct sctp_rcvinfo rcv, 
		int flags,
		void* ulp_info);

private:
	struct socket* sock_;
	bool sending_;

	int local_port_;
	int remote_port_;

    OutputNetwork m_output;
    void* m_outContext;

	RecvCB m_recv;
	void* m_recvContext;
};
