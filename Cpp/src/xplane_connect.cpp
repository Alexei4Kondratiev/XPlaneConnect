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
    std::string xplaneIPv4Addr;
    std::uint16_t xplanePort{0};
    std::uint16_t localPort{0};

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

/// Opens a new connection to XPC on the specified localPort.
///
/// \param xplaneIPv4Addr   A string representing the IP address of the host running X-Plane.
/// \param xplanePort The localPort of the X-Plane Connect plugin is listening on. Usually 49009.
/// \param localPort   The local localPort to use when sending and receiving data from XPC.
/// \returns      An XPCSocket struct representing the newly created connection.
std::unique_ptr<XPlaneConnect::XPCSocket> XPlaneConnect::openUDP(std::string xplaneIPv4Addr, unsigned short xplanePort,
                                                                 unsigned short localPort) {
    // Set X-Plane Port and IP
    if (xplaneIPv4Addr.empty() || xplaneIPv4Addr == "localhost") {
        xplaneIPv4Addr = "127.0.0.1";
    }
    auto pXPCSocket = std::make_unique<XPCSocket>();
    pXPCSocket->xplaneIPv4Addr = std::move(xplaneIPv4Addr);
    pXPCSocket->xplanePort = xplanePort == 0 ? 49009 : xplanePort;

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
    int status = shutdown(pXPCSocket_->datagramSocket, SD_BOTH);
    if (status == 0) {
        status = closesocket(pXPCSocket_->datagramSocket);
    }
    pXPCSocket_->datagramSocket = INVALID_SOCKET;
#else  //  _WIN32
    int status = shutdown(pXPCSocket_->datagramSocket, SHUT_RDWR);
    if (status == 0) {
        status = close(pXPCSocket_->datagramSocket);
    }
    pXPCSocket_->datagramSocket = -1;
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
    : pXPCSocket_{openUDP(std::move(xplaneIPv4Addr), xplanePort, localPort)} {}

/// Closes the specified connection and releases resources associated with it.
XPlaneConnect::~XPlaneConnect() {
    closeUDP();
    winSockQuit();
}

/// Gets the hostname of the X-Plane host.
///
/// @return The hostname of the X-Plane host.
const std::string &XPlaneConnect::getXPlaneAddr() const noexcept { return pXPCSocket_->xplaneIPv4Addr; }

/// Sets the hostname of the X-Plane host.
///
/// @param host The new hostname of the X-Plane host machine.
/// @throws UnknownHostException {@code host} is not valid.
void XPlaneConnect::setXplaneAddr(std::string xplaneAddr) noexcept {
    pXPCSocket_->xplaneIPv4Addr = std::move(xplaneAddr);
}

/// Gets the port on which the client sends data to X-Plane.
///
/// @return The outgoing port number.
std::uint16_t XPlaneConnect::getXPlanePort() const noexcept { return pXPCSocket_->xplanePort; }

/// Sets the port on which the client sends data to X-Plane
///
/// @param port The new outgoing port number.
/// @throws IllegalArgumentException If {@code port} is not a valid port number.
void XPlaneConnect::setXPlanePort(std::uint16_t xplanePort) noexcept { pXPCSocket_->xplanePort = xplanePort; }

/// Gets the port on which the client receives data from the plugin.
///
/// @return The incoming port number.
std::uint16_t XPlaneConnect::getRecvPort() const noexcept { return pXPCSocket_->localPort; }

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
    dst.sin_port = htons(pXPCSocket_->xplanePort);
    inet_pton(AF_INET, pXPCSocket_->xplaneIPv4Addr.c_str(), &dst.sin_addr.s_addr);

    int result = sendto(pXPCSocket_->datagramSocket, buffer.data(), static_cast<int>(buffer.size()), 0,
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
    FD_SET(pXPCSocket_->datagramSocket, &stReadFDS);
    FD_ZERO(&stExceptFDS);
    FD_SET(pXPCSocket_->datagramSocket, &stExceptFDS);

    // Set timeout period for select to 0.05 sec = 50 milliseconds = 50,000 microseconds (0 makes it polling)
    // TO DO - This could be set to 0 if a message handling system were implemented, like in the plugin.
    timeout.tv_sec = 0;
    timeout.tv_usec = 50000;

    // Select Command
    int status = select(static_cast<int>(pXPCSocket_->datagramSocket + 1), &stReadFDS, nullptr, &stExceptFDS, &timeout);
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
    status = recv(pXPCSocket_->datagramSocket, buffer.data(), static_cast<int>(size), 0);
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
    pXPCSocket_ = openUDP(pXPCSocket_->xplaneIPv4Addr, pXPCSocket_->xplanePort, port);

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

    // Preconditions
    if (rows == 0) {
        return {};
    }
    // There are only 134 DATA rows in X-Plane. Realistically, clients probably
    // shouldn't be trying to read nearly this much data at once anyway.
    rows = std::min<>(rows, max_data_row_size);

    // Read data
    std::vector<char> buffer;
    try {
        buffer = readUDP(max_data_buffer_size);
    } catch (const ReadUDPError &ex) {
        throw ReadDATAError{
            ComposeErrorMessage(__FILE__, __func__, __LINE__, "Failed to read from socket: " + std::string{ex.what()})};
    }

    // Validate data
    auto readRows = (buffer.size() - 5) / 36;
    if (readRows > rows) {
        printError("readDATA", "Read more rows than will fit in dataRef.");
    } else if (readRows < rows) {
        printError("readDATA", "Read fewer rows than expected.");
        // Copy as much data as we read anyway
        rows = readRows;
    }

    // Parse data
    int i; // iterator
    for (i = 0; i < rows; ++i) {
        data[i][0] = buffer[5 + i * 36];
        memcpy(&data[i][1], &buffer[9 + i * 36], 8 * sizeof(float));
    }
    return rows;
}

/*****************************************************************************/
/****                  End X-Plane UDP Data functions                     ****/
/*****************************************************************************/

/*****************************************************************************/
/****                          DREF functions                             ****/
/*****************************************************************************/
int XPlaneConnect::sendDREF(const char *dref, float values[], int size) { return sendDREFs(&dref, &values, &size, 1); }

int XPlaneConnect::sendDREFs(const char *drefs[], float *values[], int sizes[], int count) {
    // Setup command
    // Max size is technically unlimited.
    char buffer[65536] = "DREF";
    int pos = 5;
    int i; // Iterator
    for (i = 0; i < count; ++i) {
        int drefLen = strnlen(drefs[i], 256);
        if (pos + drefLen + sizes[i] * 4 + 2 > 65536) {
            printError("sendDREF", "About to overrun the send buffer!");
            return -4;
        }
        if (drefLen > 255) {
            printError("sendDREF", "dref %d is too long. Must be less than 256 characters.", i);
            return -1;
        }
        if (sizes[i] > 255) {
            printError("sendDREF", "size %d is too big. Must be less than 256.", i);
            return -2;
        }
        // Copy dref to buffer
        buffer[pos++] = (unsigned char)drefLen;
        memcpy(buffer + pos, drefs[i], drefLen);
        pos += drefLen;

        // Copy values to buffer
        buffer[pos++] = (unsigned char)sizes[i];
        memcpy(buffer + pos, values[i], sizes[i] * sizeof(float));
        pos += sizes[i] * sizeof(float);
    }

    // Send command
    if (sendUDP(buffer, pos) < 0) {
        printError("setDREF", "Failed to send command");
        return -3;
    }
    return 0;
}

int XPlaneConnect::sendDREFRequest(const char *drefs[], unsigned char count) {
    // Setup command
    // 6 byte header + potentially 255 drefs, each 256 chars long.
    // Easiest to just round to an even 2^16.
    char buffer[65536] = "GETD";
    buffer[5] = count;
    int len = 6;
    int i; // iterator
    for (i = 0; i < count; ++i) {
        std::size_t drefLen = strnlen(drefs[i], 256);
        if (drefLen > 255) {
            printError("getDREFs", "dref %d is too long.", i);
            return -1;
        }
        buffer[len++] = (unsigned char)drefLen;
        strncpy(buffer + len, drefs[i], drefLen);
        len += drefLen;
    }
    // Send Command
    if (sendUDP(buffer, len) < 0) {
        printError("getDREFs", "Failed to send command");
        return -2;
    }
    return 0;
}

int XPlaneConnect::getDREFResponse(float *values[], unsigned char count, int sizes[]) {
    char buffer[65536];
    int result = readUDP(buffer, 65536);

    if (result < 0) {
#ifdef _WIN32
        printError("getDREFs", "Read operation failed. (%d)", WSAGetLastError());
#else
        printError("getDREFs", "Read operation failed.");
#endif
        return -1;
    }

    if (result < 6) {
        printError("getDREFs", "Response was too short. Expected at least 6 bytes, but only got %d.", result);
        return -2;
    }
    if (buffer[5] != count) {
        printError("getDREFs", "Unexpected response size. Expected %d rows, got %d instead.", count, buffer[5]);
        return -3;
    }

    int cur = 6;
    int i; // Iterator
    for (i = 0; i < count; ++i) {
        int l = buffer[cur++];
        if (l > sizes[i]) {
            printError("getDREFs", "values is too small. Row had %d values, only room for %d.", l, sizes[i]);
            // Copy as many values as we can anyway
            memcpy(values[i], buffer + cur, sizes[i] * sizeof(float));
        } else {
            memcpy(values[i], buffer + cur, l * sizeof(float));
            sizes[i] = l;
        }
        cur += l * sizeof(float);
    }
    return 0;
}

int XPlaneConnect::getDREF(const char *dref, float values[], int *size) { return getDREFs(&dref, &values, 1, size); }

int XPlaneConnect::getDREFs(const char *drefs[], float *values[], unsigned char count, int sizes[]) {
    // Send Command
    int result = sendDREFRequest(drefs, count);
    if (result < 0) {
        // An error ocurred while sending.
        // sendDREFRequest will print an error message, so just return.
        return -1;
    }

    // Read Response
    if (getDREFResponse(values, count, sizes) < 0) {
        // An error ocurred while reading the response.
        // getDREFResponse will print an error message, so just return.
        return -2;
    }
    return 0;
}
/*****************************************************************************/
/****                        End DREF functions                           ****/
/*****************************************************************************/

/*****************************************************************************/
/****                          POSI functions                             ****/
/*****************************************************************************/
int XPlaneConnect::getPOSI(double values[7], char ac) {
    // Setup send command
    char buffer[6] = "GETP";
    buffer[5] = ac;

    // Send command
    if (sendUDP(buffer, 6) < 0) {
        printError("getPOSI", "Failed to send command.");
        return -1;
    }

    // Get response
    char readBuffer[46];
    float f[7];
    int readResult = readUDP(readBuffer, 46);

    // Copy response into values
    if (readResult < 0) {
        printError("getPOSI", "Failed to read response.");
        return -2;
    } else if (readResult == 34) /* lat/lon/h as 32-bit float */
    {
        memcpy(f, readBuffer + 6, 7 * sizeof(float));
        values[0] = (double)f[0];
        values[1] = (double)f[1];
        values[2] = (double)f[2];
        values[3] = (double)f[3];
        values[4] = (double)f[4];
        values[5] = (double)f[5];
        values[6] = (double)f[6];
    } else if (readResult == 46) /* lat/lon/h as 64-bit double */
    {
        memcpy(values, readBuffer + 6, 3 * sizeof(double));
        memcpy(f, readBuffer + 30, 4 * sizeof(float));
        values[3] = (double)f[0];
        values[4] = (double)f[1];
        values[5] = (double)f[2];
        values[6] = (double)f[3];
    } else {
        printError("getPOSI", "Unexpected response length.");
        return -3;
    }
    return 0;
}

int XPlaneConnect::sendPOSI(double values[], int size, char ac) {
    // Validate input
    if (ac < 0 || ac > 20) {
        printError("sendPOSI", "aircraft should be a value between 0 and 20.");
        return -1;
    }
    if (size < 1 || size > 7) {
        printError("sendPOSI", "size should be a value between 1 and 7.");
        return -2;
    }

    // Setup command
    char buffer[46] = "POSI";
    buffer[4] = 0xff; // Placeholder for message length
    buffer[5] = ac;
    int i; // iterator

    for (i = 0; i < 7; i++) // double for lat/lon/h
    {
        double val = -998;

        if (i < size) {
            val = values[i];
        }
        if (i < 3) /* lat/lon/h */
        {
            memcpy(&buffer[6 + i * 8], &val, sizeof(double));
        } else /* attitude and gear */
        {
            float f = (float)val;
            memcpy(&buffer[18 + i * 4], &f, sizeof(float));
        }
    }

    // Send Command
    if (sendUDP(buffer, 46) < 0) {
        printError("sendPOSI", "Failed to send command");
        return -3;
    }
    return 0;
}
/*****************************************************************************/
/****                        End POSI functions                           ****/
/*****************************************************************************/

/*****************************************************************************/
/****                          TERR functions                             ****/
/*****************************************************************************/
int XPlaneConnect::sendTERRRequest(double posi[3], char ac) {
    // Setup send command
    char buffer[30] = "GETT";
    buffer[5] = ac;
    memcpy(&buffer[6], posi, 3 * sizeof(double));

    // Send command
    if (sendUDP(buffer, 30) < 0) {
        printError("getTERR", "Failed to send command.");
        return -1;
    }
    return 0;
}

int XPlaneConnect::getTERRResponse(double values[11], char ac) {
    // Get response
    char readBuffer[62];
    int readResult = readUDP(readBuffer, 62);
    if (readResult < 0) {
        printError("getTERR", "Failed to read response.");
        return -2;
    }
    if (readResult != 62) {
        printError("getTERR", "Unexpected response length.");
        return -3;
    }

    // Copy response into outputs
    float f[8];
    ac = readBuffer[5];
    memcpy(values, readBuffer + 6, 3 * sizeof(double));
    memcpy(f, readBuffer + 30, 8 * sizeof(float));
    values[3] = (double)f[0];
    values[4] = (double)f[1];
    values[5] = (double)f[2];
    values[6] = (double)f[3];
    values[7] = (double)f[4];
    values[8] = (double)f[5];
    values[9] = (double)f[6];
    values[10] = (double)f[7];

    return 0;
}

int XPlaneConnect::sendPOST(double posi[], int size, double values[11], char ac) {
    // Validate input
    if (ac < 0 || ac > 20) {
        printError("sendPOST", "aircraft should be a value between 0 and 20.");
        return -1;
    }
    if (size < 1 || size > 7) {
        printError("sendPOST", "size should be a value between 1 and 7.");
        return -2;
    }

    // Setup command
    char buffer[46] = "POST";
    buffer[4] = 0xff; // Placeholder for message length
    buffer[5] = ac;
    int i; // iterator

    for (i = 0; i < 7; i++) // double for lat/lon/h
    {
        double val = -998;

        if (i < size) {
            val = posi[i];
        }
        if (i < 3) /* lat/lon/h */
        {
            memcpy(&buffer[6 + i * 8], &val, sizeof(double));
        } else /* attitude and gear */
        {
            float f = (float)val;
            memcpy(&buffer[18 + i * 4], &f, sizeof(float));
        }
    }

    // Send Command
    if (sendUDP(buffer, 46) < 0) {
        printError("sendPOST", "Failed to send command");
        return -3;
    }

    // Read Response
    int result = getTERRResponse(values, ac);
    if (result < 0) {
        // A error ocurred while reading the response.
        // getTERRResponse will print an error message, so just return.
        return result;
    }
    return 0;
}

int XPlaneConnect::getTERR(double posi[3], double values[11], char ac) {
    // Send Command
    int result = sendTERRRequest(posi, ac);
    if (result < 0) {
        // An error ocurred while sending.
        // sendTERRRequest will print an error message, so just return.
        return result;
    }

    // Read Response
    result = getTERRResponse(values, ac);
    if (result < 0) {
        // An error ocurred while reading the response.
        // getTERRResponse will print an error message, so just return.
        return result;
    }
    return 0;
}
/*****************************************************************************/
/****                        End TERR functions                           ****/
/*****************************************************************************/

/*****************************************************************************/
/****                          CTRL functions                             ****/
/*****************************************************************************/
int XPlaneConnect::getCTRL(float values[7], char ac) {
    // Setup send command
    char buffer[6] = "GETC";
    buffer[5] = ac;

    // Send command
    if (sendUDP(buffer, 6) < 0) {
        printError("getCTRL", "Failed to send command.");
        return -1;
    }

    // Get response
    char readBuffer[31];
    int readResult = readUDP(readBuffer, 31);
    if (readResult < 0) {
        printError("getCTRL", "Failed to read response.");
        return -2;
    }
    if (readResult != 31) {
        printError("getCTRL", "Unexpected response length.");
        return -3;
    }

    // Copy response into values
    memcpy(values, readBuffer + 5, 4 * sizeof(float));
    values[4] = readBuffer[21];
    values[5] = *((float *)(readBuffer + 22));
    values[6] = *((float *)(readBuffer + 27));
    return 0;
}

int XPlaneConnect::sendCTRL(float values[], int size, char ac) {
    // Validate input
    if (ac < 0 || ac > 20) {
        printError("sendCTRL", "aircraft should be a value between 0 and 20.");
        return -1;
    }
    if (size < 1 || size > 7) {
        printError("sendCTRL", "size should be a value between 1 and 7.");
        return -2;
    }

    // Setup Command
    // 5 byte header + 5 float values * 4 + 2 byte values
    char buffer[31] = "CTRL";
    int cur = 5;
    int i; // iterator
    for (i = 0; i < 6; i++) {
        float val = -998;

        if (i < size) {
            val = values[i];
        }
        if (i == 4) {
            buffer[cur++] = val == -998 ? -1 : (unsigned char)val;
        } else {
            *((float *)(buffer + cur)) = val;
            cur += sizeof(float);
        }
    }
    buffer[26] = ac;
    *((float *)(buffer + 27)) = size == 7 ? values[6] : -998;

    // Send Command
    if (sendUDP(buffer, 31) < 0) {
        printError("sendCTRL", "Failed to send command");
        return -3;
    }
    return 0;
}
/*****************************************************************************/
/****                        End CTRL functions                           ****/
/*****************************************************************************/

/*****************************************************************************/
/****                        Drawing functions                            ****/
/*****************************************************************************/
int XPlaneConnect::sendTEXT(char *msg, int x, int y) {
    if (msg == NULL) {
        msg = "";
    }
    std::size_t msgLen = strnlen(msg, 255);
    // Input Validation
    if (x < -1) {
        printError("sendTEXT", "x should be positive (or -1 for default).");
        // Technically, this should work, and may print something to the screen.
    }
    if (y < -1) {
        printError("sendTEXT", "y should be positive (or -1 for default).");
        // Negative y will never result in text being displayed.
        return -1;
    }
    if (msgLen > 255) {
        printError("sendTEXT", "msg must be less than 255 bytes.");
        return -2;
    }

    // Setup command
    // 5 byte header + 8 byte position + up to 256 byte message
    char buffer[269] = "TEXT";
    std::size_t len = 14 + msgLen;
    memcpy(buffer + 5, &x, sizeof(int));
    memcpy(buffer + 9, &y, sizeof(int));
    buffer[13] = (unsigned char)msgLen;
    strncpy(buffer + 14, msg, msgLen);

    // Send Command
    if (sendUDP(buffer, len) < 0) {
        printError("sendTEXT", "Failed to send command");
        return -3;
    }
    return 0;
}

int XPlaneConnect::sendWYPT(WYPT_OP op, float points[], int count) {
    // Input Validation
    if (op < WYPT_OP::XPC_WYPT_ADD || op > WYPT_OP::XPC_WYPT_CLR) {
        printError("sendWYPT", "Unrecognized operation.");
        return -1;
    }
    if (count > 255) {
        printError("sendWYPT", "Too many points. Must be less than 256.");
        return -2;
    }

    // Setup Command
    // 7 byte header + 12 bytes * count
    char buffer[3067] = "WYPT";
    buffer[5] = (unsigned char)op;
    buffer[6] = (unsigned char)count;
    std::size_t ptLen = sizeof(float) * 3 * count;
    memcpy(buffer + 7, points, ptLen);

    // Send Command
    if (sendUDP(buffer, 7 + 12 * count) < 0) {
        printError("sendWYPT", "Failed to send command");
        return -2;
    }
    return 0;
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
