#include "SctpWrapper.h"
#include <stdio.h>
#include <iostream>
#include <stdarg.h>
#include <malloc.h>

#define ARRAY_SIZE(x) (static_cast<int>(sizeof(x) / sizeof(x[0])))

// Helper for logging SCTP messages.
static void debug_sctp_printf(const char *format, ...) {
	char s[255];
	va_list ap;
	va_start(ap, format);
	vsnprintf(s, sizeof(s), format, ap);
	std::cout << "SCTP: " << s;
	va_end(ap);
}

CSctpWrapper::CSctpWrapper(void)
{
	m_output = NULL;
	m_recv = NULL;

	/// TODO ³õÊ¼»¯
	// First argument is udp_encapsulation_port, which is not releveant for our
	// AF_CONN use of sctp.
	usrsctp_init(0, OnSctpOutboundPacket, debug_sctp_printf);

	// To turn on/off detailed SCTP debugging. You will also need to have the
	// SCTP_DEBUG cpp defines flag.
	usrsctp_sysctl_set_sctp_debug_on(SCTP_DEBUG_ALL);

	// TODO(ldixon): Consider turning this on/off.
	usrsctp_sysctl_set_sctp_ecn_enable(0);

	// TODO(ldixon): Consider turning this on/off.
	// This is not needed right now (we don't do dynamic address changes):
	// If SCTP Auto-ASCONF is enabled, the peer is informed automatically
	// when a new address is added or removed. This feature is enabled by
	// default.
	// usrsctp_sysctl_set_sctp_auto_asconf(0);

	// TODO(ldixon): Consider turning this on/off.
	// Add a blackhole sysctl. Setting it to 1 results in no ABORTs
	// being sent in response to INITs, setting it to 2 results
	// in no ABORTs being sent for received OOTB packets.
	// This is similar to the TCP sysctl.
	//
	// See: http://lakerest.net/pipermail/sctp-coders/2012-January/009438.html
	// See: http://svnweb.freebsd.org/base?view=revision&revision=229805
	// usrsctp_sysctl_set_sctp_blackhole(2);

	// Set the number of default outgoing streams.  This is the number we'll
	// send in the SCTP INIT message.  The 'appropriate default' in the
	// second paragraph of
	// http://tools.ietf.org/html/draft-ietf-rtcweb-data-channel-05#section-6.2
	// is cricket::kMaxSctpSid.
	usrsctp_sysctl_set_sctp_nr_outgoing_streams_default(
		1023);

	local_port_ = 5000;
	remote_port_ = 5000;
}

CSctpWrapper::~CSctpWrapper(void)
{
}

// This is the callback usrsctp uses when there's data to send on the network
// that has been wrapped appropriatly for the SCTP protocol.
int CSctpWrapper::OnSctpOutboundPacket(void* addr, void* data, size_t length, uint8_t tos, uint8_t set_df){
	
    CSctpWrapper* pthis = (CSctpWrapper*)addr;

	int res = 0;

	if (pthis->m_output != NULL)
	{
        res = pthis->m_output((char *)data, length, pthis->m_outContext);
	}

	return res;
}

// This is the callback called from usrsctp when data has been received, after
// a packet has been interpreted and parsed by usrsctp and found to contain
// payload data. It is called by a usrsctp thread. It is assumed this function
// will free the memory used by 'data'.
int CSctpWrapper::OnSctpInboundPacket(struct socket* sock, union sctp_sockstore addr,
	void* data, size_t length,
    struct sctp_rcvinfo rcv, int flags,
	void* ulp_info) {

	CSctpWrapper* pthis = static_cast<CSctpWrapper*>(ulp_info);

    if (pthis->m_recv != NULL)
    {
		pthis->m_recv((char *)data, length, pthis->m_recvContext);
    }    
    
	free(data);
	return 1;
}

void CSctpWrapper::InputData(const char * const data, int data_len){
	// Only give receiving packets to usrsctp after if connected. This enables two
	// peers to each make a connect call, but for them not to receive an INIT
	// packet before they have called connect; least the last receiver of the INIT
	// packet will have called connect, and a connection will be established.
	if (sending_) {
		// Pass received packet to SCTP stack. Once processed by usrsctp, the data
		// will be will be given to the global OnSctpInboundData, and then,
		// marshalled by a Post and handled with OnMessage.
		usrsctp_conninput(this, data, data_len, 0);
	} else {
		// TODO(ldixon): Consider caching the packet for very slightly better
		// reliability.
	}
}

bool CSctpWrapper::OpenSctpSocket() {
	if (sock_) {		
		return false;
	}
	sock_ = usrsctp_socket(AF_CONN, SOCK_STREAM, IPPROTO_SCTP,
		OnSctpInboundPacket, NULL, 0, this);
	if (!sock_) {
		return false;
	}

	// Make the socket non-blocking. Connect, close, shutdown etc will not block
	// the thread waiting for the socket operation to complete.
	if (usrsctp_set_non_blocking(sock_, 1) < 0) {
		return false;
	}

	// This ensures that the usrsctp close call deletes the association. This
	// prevents usrsctp from calling OnSctpOutboundPacket with references to
	// this class as the address.
	linger linger_opt;
	linger_opt.l_onoff = 1;
	linger_opt.l_linger = 0;
	if (usrsctp_setsockopt(sock_, SOL_SOCKET, SO_LINGER, &linger_opt,
		sizeof(linger_opt))) {
			return false;
	}

	// Enable stream ID resets.
	struct sctp_assoc_value stream_rst;
	stream_rst.assoc_id = SCTP_ALL_ASSOC;
	stream_rst.assoc_value = 1;
	if (usrsctp_setsockopt(sock_, IPPROTO_SCTP, SCTP_ENABLE_STREAM_RESET,
		&stream_rst, sizeof(stream_rst))) {
			return false;
	}

	// Nagle.
	uint32_t nodelay = 1;
	if (usrsctp_setsockopt(sock_, IPPROTO_SCTP, SCTP_NODELAY, &nodelay,
		sizeof(nodelay))) {
			return false;
	}

	// Subscribe to SCTP event notifications.
	int event_types[] = {
		SCTP_ASSOC_CHANGE,
		SCTP_PEER_ADDR_CHANGE,
		SCTP_SEND_FAILED_EVENT,
		SCTP_SENDER_DRY_EVENT,
		SCTP_STREAM_RESET_EVENT};
	struct sctp_event event = {0};
	event.se_assoc_id = SCTP_ALL_ASSOC;
	event.se_on = 1;
	for (size_t i = 0; i < ARRAY_SIZE(event_types); i++) {
		event.se_type = event_types[i];
		if (usrsctp_setsockopt(sock_, IPPROTO_SCTP, SCTP_EVENT, &event,
			sizeof(event)) < 0) {
				return false;
		}
	}

	// Register this class as an address for usrsctp. This is used by SCTP to
	// direct the packets received (by the created socket) to this class.
	usrsctp_register_address(this);
	sending_ = true;
	return true;
}

void CSctpWrapper::CloseSctpSocket() {
	if (sock_) {
		// We assume that SO_LINGER option is set to close the association when
		// close is called. This means that any pending packets in usrsctp will be
		// discarded instead of being sent.
		usrsctp_close(sock_);
		sock_ = NULL;
		usrsctp_deregister_address(this);
	}
}

sockaddr_conn CSctpWrapper::GetSctpSockAddr(int port) {
	sockaddr_conn sconn = {0};
	sconn.sconn_family = AF_CONN;
#ifdef HAVE_SCONN_LEN
	sconn.sconn_len = sizeof(sockaddr_conn);
#endif
	// Note: conversion from int to uint16_t happens here.
	sconn.sconn_port = htons(port);
	sconn.sconn_addr = this;
	return sconn;
}

bool CSctpWrapper::Connect() {
	// If we already have a socket connection, just return.
	if (sock_) {
		return true;
	}

	// If no socket (it was closed) try to start it again. This can happen when
	// the socket we are connecting to closes, does an sctp shutdown handshake,
	// or behaves unexpectedly causing us to perform a CloseSctpSocket.
	if (!sock_ && !OpenSctpSocket()) {
		return false;
	}

	// Note: conversion from int to uint16_t happens on assignment.
	sockaddr_conn local_sconn = GetSctpSockAddr(local_port_);
	if (usrsctp_bind(sock_, reinterpret_cast<sockaddr *>(&local_sconn),
		sizeof(local_sconn)) < 0) {
			CloseSctpSocket();
			return false;
	}

	// Note: conversion from int to uint16_t happens on assignment.
	sockaddr_conn remote_sconn = GetSctpSockAddr(remote_port_);
	int connect_result = usrsctp_connect(
		sock_, reinterpret_cast<sockaddr *>(&remote_sconn), sizeof(remote_sconn));
	if (connect_result < 0 && errno != SCTP_EINPROGRESS) {
		CloseSctpSocket();
		return false;
	}
	return true;
}

void CSctpWrapper::Disconnect() {
	// TODO(ldixon): Consider calling |usrsctp_shutdown(sock_, ...)| to do a
	// shutdown handshake and remove the association.
	CloseSctpSocket();
}

int CSctpWrapper::sendData(char *data, int dataLen){
    return (int)usrsctp_sendv(sock_, data, dataLen, NULL, 0, NULL, 0, SCTP_SENDV_NOINFO, 0);
}

void CSctpWrapper::setOutputCB(OutputNetwork output, void *context){
    m_output = output;
	m_outContext = context;
}

void CSctpWrapper::setRecvCB(RecvCB recv, void *context){
    m_recv = recv;
	m_recvContext = context;
}

