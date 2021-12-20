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

#ifndef INCLUDE_XPLANE_CONNECT_CPP_XPLANE_EXCEPTIONS_H_
#define INCLUDE_XPLANE_CONNECT_CPP_XPLANE_EXCEPTIONS_H_

#include <stdexcept>

namespace xpc {

class XPlaneConnectError : public std::runtime_error {
  public:
    using std::runtime_error::runtime_error;
};

class WinSockInitError : public XPlaneConnectError {
  public:
    using XPlaneConnectError::XPlaneConnectError;
};

class OpenUDPError : public XPlaneConnectError {
  public:
    using XPlaneConnectError::XPlaneConnectError;
};

class SendUDPError : public XPlaneConnectError {
  public:
    using XPlaneConnectError::XPlaneConnectError;
};

class ReadUDPError : public XPlaneConnectError {
  public:
    using XPlaneConnectError::XPlaneConnectError;
};

class SetCONNError : public XPlaneConnectError {
  public:
    using XPlaneConnectError::XPlaneConnectError;
};

class PauseSimError : public XPlaneConnectError {
  public:
    using XPlaneConnectError::XPlaneConnectError;
};

class SendDATAError : public XPlaneConnectError {
  public:
    using XPlaneConnectError::XPlaneConnectError;
};

class ReadDATAError : public XPlaneConnectError {
  public:
    using XPlaneConnectError::XPlaneConnectError;
};

class SendDREFError : public XPlaneConnectError {
  public:
    using XPlaneConnectError::XPlaneConnectError;
};

class getDREFsError : public XPlaneConnectError {
  public:
    using XPlaneConnectError::XPlaneConnectError;
};

class getPOSIError : public XPlaneConnectError {
  public:
    using XPlaneConnectError::XPlaneConnectError;
};

class sendPOSIError : public XPlaneConnectError {
  public:
    using XPlaneConnectError::XPlaneConnectError;
};

class getTERRError : public XPlaneConnectError {
  public:
    using XPlaneConnectError::XPlaneConnectError;
};

class sendPOSTError : public XPlaneConnectError {
  public:
    using XPlaneConnectError::XPlaneConnectError;
};

class getCTRLError : public XPlaneConnectError {
  public:
    using XPlaneConnectError::XPlaneConnectError;
};

class sendCTRLError : public XPlaneConnectError {
  public:
    using XPlaneConnectError::XPlaneConnectError;
};

} // namespace xpc

#endif // INCLUDE_XPLANE_CONNECT_CPP_XPLANE_EXCEPTIONS_H_
