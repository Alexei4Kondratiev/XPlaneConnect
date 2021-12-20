// Copyright (c) 2013-2018 United States Government as represented by the Administrator of the
// National Aeronautics and Space Administration. All Rights Reserved.
//
// DISCLAIMERS
//     No Warranty: THE SUBJECT SOFTWARE IS PROVIDED "AS IS" WITHOUT ANY WARRANTY OF ANY KIND,
//     EITHER EXPRESSED, IMPLIED, OR STATUTORY, INCLUDING, BUT NOT LIMITED TO, ANY WARRANTY THAT
//     THE SUBJECT SOFTWARE WILL CONFORM TO SPECIFICATIONS, ANY IMPLIED WARRANTIES OF
//     MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE, OR FREEDOM FROM INFRINGEMENT, ANY WARRANTY
//     THAT THE SUBJECT SOFTWARE WILL BE ERROR FREE, OR ANY WARRANTY THAT DOCUMENTATION, IF PROVIDED,
//     WILL CONFORM TO THE SUBJECT SOFTWARE. THIS AGREEMENT DOES NOT, IN ANY MANNER, CONSTITUTE AN
//     ENDORSEMENT BY GOVERNMENT AGENCY OR ANY PRIOR RECIPIENT OF ANY RESULTS, RESULTING DESIGNS,
//     HARDWARE, SOFTWARE PRODUCTS OR ANY OTHER APPLICATIONS RESULTING FROM USE OF THE SUBJECT
//     SOFTWARE.  FURTHER, GOVERNMENT AGENCY DISCLAIMS ALL WARRANTIES AND LIABILITIES REGARDING
//     THIRD-PARTY SOFTWARE, IF PRESENT IN THE ORIGINAL SOFTWARE, AND DISTRIBUTES IT "AS IS."
//
//     Waiver and Indemnity: RECIPIENT AGREES TO WAIVE ANY AND ALL CLAIMS AGAINST THE UNITED STATES
//     GOVERNMENT, ITS CONTRACTORS AND SUBCONTRACTORS, AS WELL AS ANY PRIOR RECIPIENT.  IF
//     RECIPIENT'S USE OF THE SUBJECT SOFTWARE RESULTS IN ANY LIABILITIES, DEMANDS, DAMAGES, EXPENSES
//     OR LOSSES ARISING FROM SUCH USE, INCLUDING ANY DAMAGES FROM PRODUCTS BASED ON, OR RESULTING
//     FROM, RECIPIENT'S USE OF THE SUBJECT SOFTWARE, RECIPIENT SHALL INDEMNIFY AND HOLD HARMLESS THE
//     UNITED STATES GOVERNMENT, ITS CONTRACTORS AND SUBCONTRACTORS, AS WELL AS ANY PRIOR RECIPIENT,
//     TO THE EXTENT PERMITTED BY LAW.  RECIPIENT'S SOLE REMEDY FOR ANY SUCH MATTER SHALL BE THE
//     IMMEDIATE, UNILATERAL TERMINATION OF THIS AGREEMENT.

//  X-Plane Connect Client
//
//  DESCRIPTION
//      Communicates with the XPC plugin to facilitate controling and gathering data from X-Plane.
//
//  INSTRUCTIONS
//      See Readme.md in the root of this repository or the wiki hosted on GitHub at
//      https://github.com/nasa/XPlaneConnect/wiki for requirements, installation instructions,
//      and detailed documentation.

#include "xplane-connect-cpp/xplane_connect.h"

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "ws2_32.lib") // Need to link with Ws2_32.lib

#undef min
#undef max

#else //  _WIN32
/* Assume that any non-Windows platform uses POSIX-style sockets instead. */
#include <arpa/inet.h>
#include <netdb.h> // Needed for getaddrinfo() and freeaddrinfo()
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h> // Needed for close()

#endif //  _WIN32

#include <cstdarg>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>

#include <algorithm>
#include <iterator>
#include <limits>
#include <memory>
#include <string>
#include <utility>

#include "helper.h"
#include "xplane-connect-cpp/xplane_exceptions.h"

namespace xpc {

// Default X-Plane Port
constexpr std::uint16_t kXPCDefaultXplanePort{49009};

struct XPlaneConnect::XPCSocket {
    // X-Plane IP and Port
    std::string xplane_ipv4_addr;
    std::uint16_t xplane_port{0};
    std::uint16_t local_port{0};

#ifdef _WIN32
    SOCKET datagramSocket{INVALID_SOCKET};
#else  //  _WIN32
    int datagramSocket{-1};
#endif //  _WIN32
};

void winSockInit() {
#ifdef _WIN32
    /* Use the MAKEWORD(lowbyte, highbyte) macro declared in Windef.h */
    WORD wVersionRequested = MAKEWORD(2, 2);
    WSADATA wsaData{};
    int err = WSAStartup(wVersionRequested, &wsaData);
    if (err != 0) {
        throw WinSockInitError{
            ComposeErrorMessage(__FILE__, __func__, __LINE__, "WSAStartup failed with error: " + std::to_string(err))};
    }
    /* Confirm that the WinSock DLL supports 2.2.*/
    if (LOBYTE(wsaData.wVersion) != 2 || HIBYTE(wsaData.wVersion) != 2) {
        WSACleanup();
        throw WinSockInitError{
            ComposeErrorMessage(__FILE__, __func__, __LINE__, "Could not find a usable version of Winsock.dll")};
    }
/* The Winsock DLL is acceptable. Proceed to use it. */
/* Call WSACleanup when done using the Winsock dll */
#endif //  _WIN32
}

int winSockQuit() {
#ifdef _WIN32
    return WSACleanup();
#else  //  _WIN32
    return 0;
#endif //  _WIN32
}

void printError(const char *functionName, const char *format, ...) {
    va_list args;
    va_start(args, format);

    printf("[%s] ERROR: ", functionName);
    vprintf(format, args);
    printf("\n");

    va_end(args);
}

/*****************************************************************************/
/****                       Low Level UDP functions                       ****/
/*****************************************************************************/

/// Opens a new connection to XPC on the specified local_port.
///
/// \param xplaneIPv4Addr   A string representing the IP address of the host running X-Plane.
/// \param xplanePort The local_port of the X-Plane Connect plugin is listening on. Usually 49009.
/// \param localPort   The local local_port to use when sending and receiving data from XPC.
/// \returns      An XPCSocket struct representing the newly created connection.
std::unique_ptr<XPlaneConnect::XPCSocket> XPlaneConnect::openUDP(std::string xplaneIPv4Addr, unsigned short xplanePort,
                                                                 unsigned short localPort) {
    // Set X-Plane Port and IP
    if (xplaneIPv4Addr.empty() || xplaneIPv4Addr == "localhost") {
        xplaneIPv4Addr = "127.0.0.1";
    }
    auto pXPCSocket = std::make_unique<XPCSocket>();
    pXPCSocket->xplane_ipv4_addr = std::move(xplaneIPv4Addr);
    pXPCSocket->xplane_port = xplanePort == 0 ? 49009 : xplanePort;

    try {
        winSockInit();
    } catch (const WinSockInitError &ex) {
        throw OpenUDPError{
            ComposeErrorMessage(__FILE__, __func__, __LINE__, "WSAStartup failed: " + std::string{ex.what()})};
    }

    pXPCSocket->datagramSocket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
#ifdef _WIN32
    if (pXPCSocket->datagramSocket == INVALID_SOCKET) {
        throw OpenUDPError{ComposeErrorMessage(__FILE__, __func__, __LINE__, "Socket creation failed")};
    }
#else  //  _WIN32
    if (pXPCSocket->datagramSocket == -1) {
        throw OpenUDPError{ComposeErrorMessage(__FILE__, __func__, __LINE__, "Socket creation failed")};
    }
#endif //  _WIN32

    // Setup Port
    sockaddr_in recvaddr{};
    recvaddr.sin_family = AF_INET;
    recvaddr.sin_addr.s_addr = INADDR_ANY;
    recvaddr.sin_port = htons(localPort);
    if (bind(pXPCSocket->datagramSocket, reinterpret_cast<sockaddr *>(&recvaddr), sizeof(recvaddr)) == -1) {
        throw OpenUDPError{ComposeErrorMessage(__FILE__, __func__, __LINE__, "Socket bind failed")};
    }

    // Set socket timeout period for sendUDP to 1 millisecond
    // Without this, playback may become choppy due to process blocking
#ifdef _WIN32
    // Minimum socket timeout in Windows is 1 millisecond (0 makes it blocking)
    DWORD timeout = 1;
#else  //  _WIN32
    // Set socket timeout to 1 millisecond = 1,000 microseconds to make it the same as Windows (0 makes it blocking)
    struct timeval timeout;
    timeout.tv_sec = 0;
    timeout.tv_usec = 1000;
#endif //  _WIN32
    if (setsockopt(pXPCSocket->datagramSocket, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<char *>(&timeout),
                   sizeof(timeout)) < 0) {
        throw OpenUDPError{ComposeErrorMessage(__FILE__, __func__, __LINE__, "Failed to set timeout")};
    }
    return pXPCSocket;
}

/// Closes the specified connection and releases resources associated with it.
///
/// \param sock The socket to close.
int XPlaneConnect::closeUDP() {
#ifdef _WIN32
    int status = shutdown(pImpl_->datagramSocket, SD_BOTH);
    if (status == 0) {
        status = closesocket(pImpl_->datagramSocket);
    }
    pImpl_->datagramSocket = INVALID_SOCKET;
#else  //  _WIN32
    int status = shutdown(pImpl_->datagramSocket, SHUT_RDWR);
    if (status == 0) {
        status = close(pImpl_->datagramSocket);
    }
    pImpl_->datagramSocket = -1;
#endif //  _WIN32
    return status;
}

/// Initializes a new instance of the {\code XPlaneConnect} class using default ports and assuming X-Plane is
/// running on the local machine.
///
/// \throws SocketException If this instance is unable to bind to the default receive port.
XPlaneConnect::XPlaneConnect() : XPlaneConnect("") {}

/// Initializes a new instance of the {\code XPlaneConnect} class using the specified X-Plane host.
///
/// \param xplaneIPv4Addr The network host on which X-Plane is running.
/// \throws java.net.SocketException      If this instance is unable to bind to the specified port.
/// \throws java.net.UnknownHostException If the specified hostname can not be resolved.
XPlaneConnect::XPlaneConnect(std::string xplaneIPv4Addr)
    : XPlaneConnect(std::move(xplaneIPv4Addr), kXPCDefaultXplanePort, 0) {}

/// Initializes a new instance of the {\code XPlaneConnect} class using the specified ports and X-Plane host.
///
/// \param xplaneIPv4Addr The network host on which X-Plane is running.
/// \param xplanePort The port on which the X-Plane Connect plugin is listening.
/// \param localPort  The local port to use when sending and receiving data from XPC.
/// \throws java.net.SocketException      If this instance is unable to bind to the specified port.
/// \throws java.net.UnknownHostException If the specified hostname can not be resolved.
XPlaneConnect::XPlaneConnect(std::string xplaneIPv4Addr, std::uint16_t xplanePort, std::uint16_t localPort)
    : pImpl_{openUDP(std::move(xplaneIPv4Addr), xplanePort, localPort)} {}

/// Closes the specified connection and releases resources associated with it.
XPlaneConnect::~XPlaneConnect() {
    closeUDP();
    winSockQuit();
}

/// Gets the hostname of the X-Plane host.
///
/// @return The hostname of the X-Plane host.
const std::string &XPlaneConnect::getXPlaneAddr() const noexcept { return pImpl_->xplane_ipv4_addr; }

/// Sets the hostname of the X-Plane host.
///
/// @param host The new hostname of the X-Plane host machine.
/// @throws UnknownHostException {@code host} is not valid.
void XPlaneConnect::setXplaneAddr(std::string xplaneAddr) noexcept { pImpl_->xplane_ipv4_addr = std::move(xplaneAddr); }

/// Gets the port on which the client sends data to X-Plane.
///
/// @return The outgoing port number.
std::uint16_t XPlaneConnect::getXPlanePort() const noexcept { return pImpl_->xplane_port; }

/// Sets the port on which the client sends data to X-Plane
///
/// @param port The new outgoing port number.
/// @throws IllegalArgumentException If {@code port} is not a valid port number.
void XPlaneConnect::setXPlanePort(std::uint16_t xplanePort) noexcept { pImpl_->xplane_port = xplanePort; }

/// Gets the port on which the client receives data from the plugin.
///
/// @return The incoming port number.
std::uint16_t XPlaneConnect::getRecvPort() const noexcept { return pImpl_->local_port; }

/// Sends the given data to the X-Plane plugin.
///
/// \param sock   The socket to use to send the data.
/// \param buffer A pointer to the data to send.
/// \param len    The number of bytes to send.
/// \returns      If an error occurs, a negative number. Otehrwise, the number of bytes sent.
int XPlaneConnect::sendUDP(const std::vector<char> &buffer) {
    if (buffer.empty()) {
        return 0;
    }

    // Set up destination address
    sockaddr_in dst{};
    dst.sin_family = AF_INET;
    dst.sin_port = htons(pImpl_->xplane_port);
    inet_pton(AF_INET, pImpl_->xplane_ipv4_addr.c_str(), &dst.sin_addr.s_addr);

    int result = sendto(pImpl_->datagramSocket, buffer.data(), static_cast<int>(buffer.size()), 0,
                        (const struct sockaddr *)&dst, sizeof(dst));
    if (result < 0) {
        throw SendUDPError{
            ComposeErrorMessage(__FILE__, __func__, __LINE__, "Send operation failed: " + std::to_string(result))};
    }
    if (result != buffer.size()) {
        throw SendUDPError{ComposeErrorMessage(__FILE__, __func__, __LINE__,
                                               "Unexpected number of bytes sent: " + std::to_string(result) + " from " +
                                                   std::to_string(buffer.size()))};
    }
    return result;
}

/// Reads a datagram from the specified socket.
///
/// \param sock   The socket to read from.
/// \param buffer A pointer to the location to store the data.
/// \param len    The number of bytes to read.
/// \returns      If an error occurs, a negative number. Otherwise, the number of bytes read.
std::vector<char> XPlaneConnect::readUDP(std::size_t size) {
    // For readUDP, use the select command - minimum timeout of 0 makes it polling.
    // Without this, playback may become choppy due to process blocking

    // Definitions
    fd_set stReadFDS;
    fd_set stExceptFDS;
    timeval timeout{};

    // Setup for Select
    FD_ZERO(&stReadFDS);
    FD_SET(pImpl_->datagramSocket, &stReadFDS);
    FD_ZERO(&stExceptFDS);
    FD_SET(pImpl_->datagramSocket, &stExceptFDS);

    // Set timeout period for select to 0.05 sec = 50 milliseconds = 50,000 microseconds (0 makes it polling)
    // TO DO - This could be set to 0 if a message handling system were implemented, like in the plugin.
    timeout.tv_sec = 0;
    timeout.tv_usec = 50000;

    // Select Command
    int status = select(static_cast<int>(pImpl_->datagramSocket + 1), &stReadFDS, nullptr, &stExceptFDS, &timeout);
    if (status < 0) {
        throw ReadUDPError{
            ComposeErrorMessage(__FILE__, __func__, __LINE__, "Select command error: " + std::to_string(status))};
    }
    if (status == 0) {
        // No data
        return {};
    }

    std::vector<char> buffer(size);
    // If no error: Read Data
    status = recv(pImpl_->datagramSocket, buffer.data(), static_cast<int>(size), 0);
    if (status < 0) {
        throw ReadUDPError{
            ComposeErrorMessage(__FILE__, __func__, __LINE__, "Error reading socket: " + std::to_string(status))};
    }
    buffer.resize(status);
    return buffer;
}

/*****************************************************************************/
/****                    End Low Level UDP functions                      ****/
/*****************************************************************************/

/*****************************************************************************/
/****                      Configuration functions                        ****/
/*****************************************************************************/

void XPlaneConnect::setCONN(std::uint16_t port) {
    static const std::size_t command_size{7U};
    static const std::string command_tag{"CONN"};
    static const std::string response_tag{"CONF"};

    // Set up command
    std::vector<char> buffer{command_tag.begin(), command_tag.end()};
    buffer.resize(command_size);
    std::memcpy(&buffer[5], &port, sizeof(port));

    // Send command
    try {
        sendUDP(buffer);
    } catch (const SendUDPError &ex) {
        throw SetCONNError{
            ComposeErrorMessage(__FILE__, __func__, __LINE__, "Failed to send command: " + std::string{ex.what()})};
    }

    // Switch socket
    closeUDP();
    pImpl_ = openUDP(pImpl_->xplane_ipv4_addr, pImpl_->xplane_port, port);

    // Read response
    try {
        buffer = readUDP(32);
    } catch (const ReadUDPError &ex) {
        throw SetCONNError{
            ComposeErrorMessage(__FILE__, __func__, __LINE__, "Failed to read response: " + std::string{ex.what()})};
    }

    // Response incorrect
    if (buffer.size() < response_tag.size() ||
        std::string{buffer.begin(), std::next(buffer.begin(), static_cast<std::int64_t>(response_tag.size()))} !=
            response_tag) {

        throw SetCONNError{ComposeErrorMessage(__FILE__, __func__, __LINE__, "Response incorrect")};
    }
}

void XPlaneConnect::pauseSim(std::uint8_t pause) {
    static const std::size_t command_size{6U};
    static const std::string command_tag{"SIMU"};

    // Validate input
    if ((pause > 2 && pause < 100) || (pause > 119 && pause < 200) || pause > 219) {
        throw PauseSimError{
            ComposeErrorMessage(__FILE__, __func__, __LINE__, "Invalid argument: " + std::to_string(pause))};
    }

    // Setup command
    std::vector<char> buffer{command_tag.begin(), command_tag.end()};
    buffer.resize(command_size);
    buffer[5] = static_cast<char>(pause);

    // Send command
    try {
        sendUDP(buffer);
    } catch (const SendUDPError &ex) {
        throw PauseSimError{
            ComposeErrorMessage(__FILE__, __func__, __LINE__, "Failed to send command: " + std::string{ex.what()})};
    }
}

/*****************************************************************************/
/****                    End Configuration functions                      ****/
/*****************************************************************************/

/*****************************************************************************/
/****                    X-Plane UDP Data functions                       ****/
/*****************************************************************************/

void XPlaneConnect::sendDATA(const std::vector<DataRowType> &data) {
    static const std::size_t max_data_row_size{134U};
    static const std::string command_tag{"DATA"};

    // Preconditions
    if (data.empty()) {
        return;
    }
    // There are only 134 DATA rows in X-Plane. Realistically, clients probably
    // shouldn't be trying to set nearly this much data at once anyway.
    if (data.size() > max_data_row_size) {
        printError("sendDATA", "Too many rows.");
        throw SendDATAError{
            ComposeErrorMessage(__FILE__, __func__, __LINE__, "Too many rows: " + std::to_string(data.size()))};
    }

    // Setup command
    // 5 byte header + 134 rows * 9 values * 4 bytes per value => 4829 byte max length.
    std::vector<char> buffer{command_tag.begin(), command_tag.end()};
    const std::size_t size = 5U + data.size() * std::tuple_size<DataRowType>::value * sizeof(float);
    buffer.resize(size);
    auto step = std::tuple_size<DataRowType>::value * sizeof(float);
    for (std::size_t i = 0; i < size; ++i) {
        std::memcpy(&buffer[5 + i * step], &data[i][0], std::tuple_size<DataRowType>::value * sizeof(float));
    }

    // Send command
    try {
        sendUDP(buffer);
    } catch (const SendUDPError &ex) {
        throw SendDATAError{
            ComposeErrorMessage(__FILE__, __func__, __LINE__, "Failed to send command: " + std::string{ex.what()})};
    }
}

std::vector<XPlaneConnect::DataRowType> XPlaneConnect::readDATA(std::size_t rows) {
    static const std::size_t max_data_row_size{134U};

    // 5 byte header + 134 rows * 9 values * 4 bytes per value => 4829 byte max length.
    static const std::size_t max_data_buffer_size{5U + max_data_row_size * std::tuple_size<DataRowType>::value *
                                                           sizeof(float)};
    static const std::size_t data_read_row_size{36U};

    // Preconditions
    if (rows == 0) {
        return {};
    }
    // There are only 134 DATA rows in X-Plane. Realistically, clients probably
    // shouldn't be trying to read nearly this much data at once anyway.
    rows = std::min(rows, max_data_row_size);

    // Read data
    std::vector<char> buffer;
    try {
        buffer = readUDP(max_data_buffer_size);
    } catch (const ReadUDPError &ex) {
        throw ReadDATAError{
            ComposeErrorMessage(__FILE__, __func__, __LINE__, "Failed to read from socket: " + std::string{ex.what()})};
    }

    // Validate data
    const std::size_t readRows = (buffer.size() <= 5) ? 0 : (buffer.size() - 5) / data_read_row_size;
    // Copy as much data as we read anyway
    rows = std::min(rows, readRows);

    std::vector<XPlaneConnect::DataRowType> data(rows);
    // Parse data
    for (std::size_t i = 0; i < rows; ++i) {
        std::memcpy(&data[i][0], &buffer[5 + i * data_read_row_size],
                    std::tuple_size<DataRowType>::value * sizeof(float));
    }
    return data;
}

/*****************************************************************************/
/****                  End X-Plane UDP Data functions                     ****/
/*****************************************************************************/

/*****************************************************************************/
/****                          DREF functions                             ****/
/*****************************************************************************/

void XPlaneConnect::sendDREF(const std::string &dref, const std::vector<float> &values) {
    if (dref.empty() || values.empty()) {
        return;
    }
    return sendDREFs({dref}, {values});
}

void XPlaneConnect::sendDREFs(const std::vector<std::string> &drefs, const std::vector<std::vector<float>> &values) {
    static const std::size_t command_size{65536U};
    static const std::string command_tag{"DREF"};
    static const std::size_t command_pos{5U};

    if (drefs.empty() || values.empty()) {
        return;
    }

    // Setup command
    // Max size is technically unlimited.
    std::vector<char> buffer{command_tag.begin(), command_tag.end()};
    buffer.resize(command_size);
    std::size_t pos = command_pos;
    for (std::size_t i = 0; i < drefs.size(); ++i) {
        const std::size_t drefLen = drefs[i].length();
        if (drefLen > std::numeric_limits<unsigned char>::max()) {
            throw SendDREFError{ComposeErrorMessage(__FILE__, __func__, __LINE__,
                                                    "dref " + std::to_string(drefLen) +
                                                        " is too long. Must be less than 256 characters")};
        }
        const std::size_t size = values[i].size();
        if (values[i].size() > std::numeric_limits<unsigned char>::max()) {
            throw SendDREFError{ComposeErrorMessage(
                __FILE__, __func__, __LINE__, "size " + std::to_string(size) + " is too big. Must be less than 256")};
        }
        if (pos + drefLen + size * sizeof(float) + 2 * sizeof(unsigned char) > command_size) {
            throw SendDREFError{ComposeErrorMessage(__FILE__, __func__, __LINE__, "About to overrun the send buffer!")};
        }
        // Copy dref to buffer
        buffer[pos++] = static_cast<char>(drefLen);
        std::copy_n(drefs[i].begin(), drefLen, std::next(buffer.begin(), static_cast<std::int64_t>(pos)));
        pos += drefLen;

        // Copy values to buffer
        buffer[pos++] = static_cast<char>(size);
        std::memcpy(&buffer[pos], values[i].data(), size * sizeof(float));
        pos += size * sizeof(float);
    }
    buffer.resize(pos);

    // Send command
    try {
        sendUDP(buffer);
    } catch (const SendUDPError &ex) {
        throw SendDREFError{
            ComposeErrorMessage(__FILE__, __func__, __LINE__, "Failed to send command: " + std::string{ex.what()})};
    }
}

void XPlaneConnect::sendDREFRequest(const std::vector<std::string> &drefs) {
    static const std::size_t command_size{65536U};
    static const std::string command_tag{"GETD"};
    static const std::size_t command_pos{5U};

    if (drefs.empty()) {
        return;
    }
    if (drefs.size() > std::numeric_limits<unsigned char>::max()) {
        throw getDREFsError{
            ComposeErrorMessage(__FILE__, __func__, __LINE__,
                                "size " + std::to_string(drefs.size()) + " is too big. Must be less than 256")};
    }

    // Setup command
    // 6 byte header + potentially 255 drefs, each 256 chars long.
    // Easiest to just round to an even 2^16.
    std::vector<char> buffer{command_tag.begin(), command_tag.end()};
    buffer.resize(command_size);
    buffer[command_pos] = static_cast<char>(drefs.size());
    std::size_t len = command_pos + 1;
    for (const auto &dref : drefs) {
        std::size_t drefLen = dref.length();
        if (drefLen > std::numeric_limits<unsigned char>::max()) {
            throw getDREFsError{ComposeErrorMessage(__FILE__, __func__, __LINE__,
                                                    "dref " + std::to_string(drefLen) +
                                                        " is too long. Must be less than 256 characters")};
        }
        buffer[len++] = static_cast<char>(drefLen);
        std::copy_n(dref.begin(), drefLen, std::next(buffer.begin(), static_cast<std::int64_t>(len)));
        len += drefLen;
    }
    buffer.resize(len);

    // Send Command
    try {
        sendUDP(buffer);
    } catch (const SendUDPError &ex) {
        throw getDREFsError{
            ComposeErrorMessage(__FILE__, __func__, __LINE__, "Failed to send command: " + std::string{ex.what()})};
    }
}

std::vector<std::vector<float>> XPlaneConnect::getDREFResponse(std::uint8_t count) {
    static const std::size_t command_size{65536U};
    static const std::size_t command_pos{5U};

    std::vector<char> buffer;
    try {
        buffer = readUDP(command_size);
    } catch (const ReadUDPError &ex) {
        throw getDREFsError{
            ComposeErrorMessage(__FILE__, __func__, __LINE__, "Read operation failed: " + std::string{ex.what()})};
    }

    if (buffer.empty() || buffer.size() <= command_pos) {
        throw getDREFsError{ComposeErrorMessage(__FILE__, __func__, __LINE__,
                                                "Response was too short. Expected at least 6 bytes, but only got " +
                                                    std::to_string(buffer.size()))};
    }
    if (buffer[command_pos] != count) {
        throw getDREFsError{ComposeErrorMessage(__FILE__, __func__, __LINE__,
                                                "Unexpected response size. Expected " +
                                                    std::to_string(static_cast<std::size_t>(count)) + " rows, got " +
                                                    std::to_string(static_cast<std::size_t>(buffer[5])) + " instead")};
    }

    std::vector<std::vector<float>> values(count);
    std::size_t cur = command_pos + 1;
    for (std::size_t i = 0; i < count; ++i) {
        std::size_t len = static_cast<std::uint8_t>(buffer[cur++]);
        values[i].resize(len * sizeof(float));
        std::memcpy(values[i].data(), &buffer[cur], len * sizeof(float));
        cur += len * sizeof(float);
    }
    return values;
}

std::vector<std::vector<float>> XPlaneConnect::getDREF(const std::string &dref) { return getDREFs({dref}); }

std::vector<std::vector<float>> XPlaneConnect::getDREFs(const std::vector<std::string> &drefs) {
    // Send Command
    sendDREFRequest(drefs);
    // Read Response
    return getDREFResponse(drefs.size());
}

/*****************************************************************************/
/****                        End DREF functions                           ****/
/*****************************************************************************/

/*****************************************************************************/
/****                          POSI functions                             ****/
/*****************************************************************************/

std::vector<double> XPlaneConnect::getPOSI(std::uint8_t ac) {
    static const std::size_t command_size{6U};
    static const std::string command_tag{"GETP"};
    static const std::size_t command_pos{5U};
    static const std::size_t read_buffer_size{46U};
    static const std::size_t response_values_size{7U};

    // Setup send command
    std::vector<char> buffer{command_tag.begin(), command_tag.end()};
    buffer.resize(command_size);
    buffer[command_pos] = static_cast<char>(ac);

    // Send command
    try {
        sendUDP(buffer);
    } catch (const SendUDPError &ex) {
        throw getPOSIError{
            ComposeErrorMessage(__FILE__, __func__, __LINE__, "Failed to send command: " + std::string{ex.what()})};
    }

    // Get response
    std::vector<char> readBuffer;
    try {
        readBuffer = readUDP(read_buffer_size);
    } catch (const ReadUDPError &ex) {
        throw getPOSIError{
            ComposeErrorMessage(__FILE__, __func__, __LINE__, "Failed to read response: " + std::string{ex.what()})};
    }

    // Copy response into values
    std::vector<double> values(response_values_size);
    std::array<float, response_values_size> f_val{};
    if (readBuffer.size() == command_pos + 1 + response_values_size * sizeof(float)) {
        /* lat/lon/h as 32-bit float */
        std::memcpy(f_val.data(), &readBuffer[command_pos + 1], response_values_size * sizeof(float));
        values[0] = static_cast<double>(f_val[0]);
        values[1] = static_cast<double>(f_val[1]);
        values[2] = static_cast<double>(f_val[2]);
        values[3] = static_cast<double>(f_val[3]);
        values[4] = static_cast<double>(f_val[4]);
        values[5] = static_cast<double>(f_val[5]);
        values[6] = static_cast<double>(f_val[6]);
    } else if (readBuffer.size() == command_pos + 1 + 3 * sizeof(double) + 4 * sizeof(float)) {
        /* lat/lon/h as 64-bit double */
        std::memcpy(values.data(), &readBuffer[command_pos + 1], 3 * sizeof(double));
        std::memcpy(f_val.data(), &readBuffer[command_pos + 1 + 3 * sizeof(double)], 4 * sizeof(float));
        values[3] = static_cast<double>(f_val[0]);
        values[4] = static_cast<double>(f_val[1]);
        values[5] = static_cast<double>(f_val[2]);
        values[6] = static_cast<double>(f_val[3]);
    } else {
        throw getPOSIError{ComposeErrorMessage(__FILE__, __func__, __LINE__,
                                               "Unexpected response length: " + std::to_string(readBuffer.size()))};
    }
    return values;
}

void XPlaneConnect::sendPOSI(const std::vector<double> &values, std::uint8_t ac) {
    static const std::size_t command_size{46U};
    static const std::string command_tag{"POSI"};
    static const std::size_t command_pos{5U};
    static const std::size_t request_values_size{7U};

    // Validate input
    if (values.empty()) {
        return;
    }
    if (values.size() > request_values_size) {
        throw sendPOSIError{ComposeErrorMessage(
            __FILE__, __func__, __LINE__, "Size should be a value between 1 and 7: " + std::to_string(values.size()))};
    }
    if (ac > 20) {
        throw sendPOSIError{ComposeErrorMessage(__FILE__, __func__, __LINE__,
                                                "Aircraft should be a value between 0 and 20: " +
                                                    std::to_string(static_cast<std::size_t>(ac)))};
    }

    // Setup command
    std::vector<char> buffer{command_tag.begin(), command_tag.end()};
    buffer.resize(command_size);
    buffer[command_pos - 1] = static_cast<char>(0xFF); // Placeholder for message length
    buffer[command_pos] = static_cast<char>(ac);

    for (std::size_t i = 0; i < request_values_size; ++i) {
        // double for lat/lon/h
        double val = -998;

        if (i < values.size()) {
            val = values[i];
        }
        if (i < 3) {
            /* Lat, Lon, Alt */
            memcpy(&buffer[command_pos + 1 + i * sizeof(double)], &val, sizeof(double));
        } else {
            /* Pitch, Roll, Yaw, Gear */
            auto f_val = static_cast<float>(val);
            memcpy(&buffer[command_pos + 1 + 3 * sizeof(double) + i * sizeof(float)], &f_val, sizeof(float));
        }
    }

    // Send Command
    try {
        sendUDP(buffer);
    } catch (const SendUDPError &ex) {
        throw sendPOSIError{
            ComposeErrorMessage(__FILE__, __func__, __LINE__, "Failed to send command: " + std::string{ex.what()})};
    }
}

/*****************************************************************************/
/****                        End POSI functions                           ****/
/*****************************************************************************/

/*****************************************************************************/
/****                          TERR functions                             ****/
/*****************************************************************************/

void XPlaneConnect::sendTERRRequest(const std::vector<double> &posi, std::uint8_t ac) {
    static const std::size_t command_size{30U};
    static const std::string command_tag{"GETT"};
    static const std::size_t command_pos{5U};
    static const std::size_t request_values_size{3U};

    // Validate input
    if (posi.empty()) {
        return;
    }
    if (posi.size() != request_values_size) {
        throw getTERRError{ComposeErrorMessage(__FILE__, __func__, __LINE__,
                                               "Size should be a value 3: " + std::to_string(posi.size()))};
    }

    // Setup send command
    std::vector<char> buffer{command_tag.begin(), command_tag.end()};
    buffer.resize(command_size);
    buffer[command_pos] = static_cast<char>(ac);
    std::memcpy(&buffer[command_pos + 1], posi.data(), request_values_size * sizeof(double));

    // Send command
    try {
        sendUDP(buffer);
    } catch (const SendUDPError &ex) {
        throw getTERRError{
            ComposeErrorMessage(__FILE__, __func__, __LINE__, "Failed to send command: " + std::string{ex.what()})};
    }
}

std::vector<double> XPlaneConnect::getTERRResponse() {
    static const std::size_t read_buffer_size{62U};
    static const std::size_t command_pos{5U};
    static const std::size_t response_values_size{11U};
    static const std::size_t tmp_float_values_size{8U};

    // Get response
    std::vector<char> readBuffer;
    try {
        readBuffer = readUDP(read_buffer_size);
    } catch (const ReadUDPError &ex) {
        throw getTERRError{
            ComposeErrorMessage(__FILE__, __func__, __LINE__, "Failed to read response: " + std::string{ex.what()})};
    }
    if (readBuffer.size() != read_buffer_size) {
        throw getTERRError{ComposeErrorMessage(__FILE__, __func__, __LINE__,
                                               "Unexpected response length: " + std::to_string(readBuffer.size()))};
    }

    // Copy response into outputs
    std::vector<double> values(response_values_size);
    std::array<float, tmp_float_values_size> f_val{};
    std::memcpy(values.data(), &readBuffer[command_pos + 1], 3 * sizeof(double));
    std::memcpy(f_val.data(), &readBuffer[command_pos + 1 + 3 * sizeof(double)], 8 * sizeof(float));
    values[3] = static_cast<double>(f_val[0]);
    values[4] = static_cast<double>(f_val[1]);
    values[5] = static_cast<double>(f_val[2]);
    values[6] = static_cast<double>(f_val[3]);
    values[7] = static_cast<double>(f_val[4]);
    values[8] = static_cast<double>(f_val[5]);
    values[9] = static_cast<double>(f_val[6]);
    values[10] = static_cast<double>(f_val[7]);

    return values;
}

std::vector<double> XPlaneConnect::sendPOST(const std::vector<double> &posi, std::uint8_t ac) {
    static const std::size_t command_size{46U};
    static const std::string command_tag{"POST"};
    static const std::size_t command_pos{5U};
    static const std::size_t request_values_size{7U};

    // Validate input
    if (posi.empty()) {
        return {};
    }
    if (posi.size() > request_values_size) {
        throw sendPOSTError{ComposeErrorMessage(
            __FILE__, __func__, __LINE__, "Size should be a value between 1 and 7: " + std::to_string(posi.size()))};
    }
    if (ac > 20) {
        throw sendPOSTError{ComposeErrorMessage(__FILE__, __func__, __LINE__,
                                                "Aircraft should be a value between 0 and 20: " +
                                                    std::to_string(static_cast<std::size_t>(ac)))};
    }

    // Setup command
    std::vector<char> buffer{command_tag.begin(), command_tag.end()};
    buffer.resize(command_size);
    buffer[command_pos - 1] = static_cast<char>(0xFF); // Placeholder for message length
    buffer[command_pos] = static_cast<char>(ac);

    for (std::size_t i = 0; i < request_values_size; ++i) {
        // double for lat/lon/h
        double val = -998;

        if (i < posi.size()) {
            val = posi[i];
        }
        if (i < 3) {
            /* Lat, Lon, Alt */
            std::memcpy(&buffer[command_pos + 1 + i * sizeof(double)], &val, sizeof(double));
        } else {
            /* Pitch, Roll, Yaw, Gear */
            auto f_val = static_cast<float>(val);
            std::memcpy(&buffer[command_pos + 1 + 3 * sizeof(double) + i * sizeof(float)], &f_val, sizeof(float));
        }
    }

    // Send Command
    try {
        sendUDP(buffer);
    } catch (const SendUDPError &ex) {
        throw sendPOSTError{
            ComposeErrorMessage(__FILE__, __func__, __LINE__, "Failed to send command: " + std::string{ex.what()})};
    }

    // Read Response
    return getTERRResponse();
}

std::vector<double> XPlaneConnect::getTERR(const std::vector<double> &posi, std::uint8_t ac) {
    // Send Command
    sendTERRRequest(posi, ac);
    // Read Response
    return getTERRResponse();
}

/*****************************************************************************/
/****                        End TERR functions                           ****/
/*****************************************************************************/

/*****************************************************************************/
/****                          CTRL functions                             ****/
/*****************************************************************************/

std::vector<float> XPlaneConnect::getCTRL(std::uint8_t ac) {
    static const std::size_t command_size{6U};
    static const std::string command_tag{"GETC"};
    static const std::size_t command_pos{5U};
    static const std::size_t read_buffer_size{31U};
    static const std::size_t response_values_size{7U};

    // Setup send command
    std::vector<char> buffer{command_tag.begin(), command_tag.end()};
    buffer.resize(command_size);
    buffer[command_pos] = static_cast<char>(ac);

    // Send command
    try {
        sendUDP(buffer);
    } catch (const SendUDPError &ex) {
        throw getCTRLError{
            ComposeErrorMessage(__FILE__, __func__, __LINE__, "Failed to send command: " + std::string{ex.what()})};
    }

    // Get response
    std::vector<char> readBuffer;
    try {
        readBuffer = readUDP(read_buffer_size);
    } catch (const ReadUDPError &ex) {
        throw getCTRLError{
            ComposeErrorMessage(__FILE__, __func__, __LINE__, "Failed to read response: " + std::string{ex.what()})};
    }
    if (readBuffer.size() != read_buffer_size) {
        throw getCTRLError{ComposeErrorMessage(__FILE__, __func__, __LINE__,
                                               "Unexpected response length: " + std::to_string(readBuffer.size()))};
    }

    std::vector<float> values(response_values_size);
    // Copy response into values
    std::memcpy(values.data(), &readBuffer[command_pos], 4 * sizeof(float));
    values[4] = readBuffer[command_pos + 4 * sizeof(float)];
    values[5] = *reinterpret_cast<float *>(&readBuffer[command_pos + 4 * sizeof(float) + 1]);
    values[6] = *reinterpret_cast<float *>(&readBuffer[read_buffer_size - sizeof(float)]);
    return values;
}

void XPlaneConnect::sendCTRL(const std::vector<float> &values, std::uint8_t ac) {
    static const std::size_t command_size{31U};
    static const std::string command_tag{"CTRL"};
    static const std::size_t command_pos{5U};
    static const std::size_t request_values_size{7U};

    // Validate input
    if (values.empty()) {
        return;
    }
    if (values.size() > request_values_size) {
        throw sendCTRLError{ComposeErrorMessage(
            __FILE__, __func__, __LINE__, "Size should be a value between 1 and 7: " + std::to_string(values.size()))};
    }
    if (ac > 20) {
        throw sendCTRLError{ComposeErrorMessage(__FILE__, __func__, __LINE__,
                                                "Aircraft should be a value between 0 and 20: " +
                                                    std::to_string(static_cast<std::size_t>(ac)))};
    }

    // Setup Command
    // 5 byte header + 5 float values * 4 + 2 byte values
    std::vector<char> buffer{command_tag.begin(), command_tag.end()};
    buffer.resize(command_size);
    std::size_t cur = command_pos;
    for (std::size_t i = 0; i < request_values_size - 1; ++i) {
        float val = -998;

        if (i < values.size()) {
            val = values[i];
        }
        if (i == 4) {
            buffer[cur++] = (val == -998) ? static_cast<char>(-1) : static_cast<char>(val);
        } else {
            *reinterpret_cast<float *>(&buffer[cur]) = val;
            cur += sizeof(float);
        }
    }
    buffer[command_size - sizeof(float) - 1] = static_cast<char>(ac);
    *reinterpret_cast<float *>(&buffer[command_size - sizeof(float)]) = (values.size() == 7) ? values[6] : -998;

    // Send Command
    try {
        sendUDP(buffer);
    } catch (const SendUDPError &ex) {
        throw sendCTRLError{
            ComposeErrorMessage(__FILE__, __func__, __LINE__, "Failed to send command: " + std::string{ex.what()})};
    }
}

/*****************************************************************************/
/****                        End CTRL functions                           ****/
/*****************************************************************************/

/*****************************************************************************/
/****                        Drawing functions                            ****/
/*****************************************************************************/

void XPlaneConnect::sendTEXT(std::string_view msg, std::int32_t x, std::int32_t y) {
    static const std::size_t command_size{269U};
    static const std::string command_tag{"TEXT"};
    static const std::size_t command_pos{5U};
    static const std::size_t request_min_size{14U};

    // Input Validation
    if (msg.empty()) {
        return;
    }
    if (msg.length() > 255) {
        throw sendTEXTError{ComposeErrorMessage(
            __FILE__, __func__, __LINE__, "Message must be less than 255 bytes: " + std::to_string(msg.length()))};
    }
    if (x < -1) {
        // Technically, this should work, and may print something to the screen.
        throw sendTEXTError{ComposeErrorMessage(__FILE__, __func__, __LINE__,
                                                "X should be positive (or -1 for default): " + std::to_string(x))};
    }
    if (y < -1) {
        // Negative y will never result in text being displayed.
        throw sendTEXTError{ComposeErrorMessage(__FILE__, __func__, __LINE__,
                                                "Y should be positive (or -1 for default): " + std::to_string(y))};
    }

    // Setup command
    // 5 byte header + 8 byte position + up to 256 byte message
    std::vector<char> buffer{command_tag.begin(), command_tag.end()};
    buffer.resize(command_size);
    std::size_t len = request_min_size + msg.length();
    std::memcpy(&buffer[command_pos], &x, sizeof(std::int32_t));
    std::memcpy(&buffer[command_pos + sizeof(std::int32_t)], &y, sizeof(std::int32_t));
    buffer[request_min_size - 1] = static_cast<char>(msg.length());
    std::copy(msg.begin(), msg.end(), std::next(buffer.begin(), request_min_size));

    // Send Command
    try {
        sendUDP(buffer);
    } catch (const SendUDPError &ex) {
        throw sendTEXTError{
            ComposeErrorMessage(__FILE__, __func__, __LINE__, "Failed to send command: " + std::string{ex.what()})};
    }
}

void XPlaneConnect::sendWYPT(WYPT_OP op, const std::vector<float> &points) {
    static const std::size_t command_size{7U};
    static const std::string command_tag{"WYPT"};
    static const std::size_t command_pos{5U};

    // Input Validation
    if (points.empty()) {
        return;
    }
    if (points.size() > 255) {
        throw sendWYPTError{ComposeErrorMessage(
            __FILE__, __func__, __LINE__, "Too many points. Must be less than 256: " + std::to_string(points.size()))};
    }
    if (op < WYPT_OP::XPC_WYPT_ADD || op > WYPT_OP::XPC_WYPT_CLR) {
        throw sendWYPTError{ComposeErrorMessage(__FILE__, __func__, __LINE__, "Unrecognized operation")};
    }

    // Setup Command
    // 7 byte header + 12 bytes * count
    std::vector<char> buffer{command_tag.begin(), command_tag.end()};
    std::size_t ptLen = sizeof(float) * 3 * points.size();
    buffer.resize(command_size + ptLen);
    buffer[command_pos] = static_cast<char>(op);
    buffer[command_pos + 1] = static_cast<char>(points.size());
    std::memcpy(&buffer[command_size], points.data(), ptLen);

    // Send Command
    try {
        sendUDP(buffer);
    } catch (const SendUDPError &ex) {
        throw sendWYPTError{
            ComposeErrorMessage(__FILE__, __func__, __LINE__, "Failed to send command: " + std::string{ex.what()})};
    }
}

/*****************************************************************************/
/****                      End Drawing functions                          ****/
/*****************************************************************************/

/*****************************************************************************/
/****                          View functions                             ****/
/*****************************************************************************/

int XPlaneConnect::sendVIEW(VIEW_TYPE view) {
    // Validate Input
    if (view < VIEW_TYPE::XPC_VIEW_FORWARDS || view > VIEW_TYPE::XPC_VIEW_FULLSCREENNOHUD) {
        printError("sendVIEW", "Unrecognized view");
        return -1;
    }

    // Setup Command
    char buffer[9] = "VIEW";
    *((int *)(buffer + 5)) = static_cast<int>(view);

    // Send Command
    if (sendUDP(buffer, 9) < 0) {
        printError("sendVIEW", "Failed to send command");
        return -2;
    }
    return 0;
}
/*****************************************************************************/
/****                        End View functions                           ****/
/*****************************************************************************/

/*****************************************************************************/
/****                          Comm functions                             ****/
/*****************************************************************************/
int XPlaneConnect::sendCOMM(const char *comm) {
    // Setup command
    // Max size is technically unlimited.
    unsigned char buffer[65536] = "COMM";
    int pos = 5;

    int commLen = strnlen(comm, 256);
    if (pos + commLen + 2 > 65536) {
        printError("sendCOMM", "About to overrun the send buffer!");
        return -4;
    }
    if (commLen > 255) {
        printError("sendCOMM", "comm is too long. Must be less than 256 characters.");
        return -1;
    }
    // Copy comm to buffer
    buffer[pos++] = (unsigned char)commLen;
    memcpy(buffer + pos, comm, commLen);
    pos += commLen;

    // Send command
    if (sendUDP((char *)buffer, pos) < 0) {
        printError("setDREF", "Failed to send command");
        return -3;
    }
    return 0;
}
/*****************************************************************************/
/****                        End Comm functions                           ****/
/*****************************************************************************/

} // namespace xpc
