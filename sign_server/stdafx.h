#define SECURITY_WIN32
#define CRYPT_OID_INFO_HAS_EXTRA_FIELDS
#include "../inc/StdAfx.h"

#include <intrin.h>
#include <ws2spi.h>
#include <WinDNS.h>
#include <ws2ipdef.h>
#include <mstcpip.h>

#include "../tpm2.0/Tpm20.h"

_NT_BEGIN

#include <MSWSock.h>
#include <tdi.h>

_NT_END
