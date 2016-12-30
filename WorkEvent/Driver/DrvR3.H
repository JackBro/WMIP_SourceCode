// Driver Definitions Shared with User Mode Clients
// ================================================
//
// (c), 2003 by Enrico Martignetti - All rights reserved.

//----------------------------------------------------------------------
//
// Defines
// -------



// Name of the logical device managed by the driver
//#define DRV_DEVICE_NAME_ANSI    "SkelDrvDevice"
#define DRV_DEVICE_NAME			L"WrkEventDevice"

#define IOCTL_WRKEVENT_SIGNAL_EVENT		CTL_CODE(FILE_DEVICE_UNKNOWN, \
	0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IOCTL_WRKEVENT_CLEAR_EVENT		CTL_CODE(FILE_DEVICE_UNKNOWN, \
	0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)

// Caution!!! this IOCTL only works on Windows 7 x64 RTM. WILL CRASH
// any other version of Windows!
//
#define IOCTL_WRKEVENT_SIGNAL_GATE	CTL_CODE(FILE_DEVICE_UNKNOWN, \
	0x802, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IOCTL_WRKEVENT_PRINT_OBJ_ADDRS	CTL_CODE(FILE_DEVICE_UNKNOWN, \
	0x803, METHOD_BUFFERED, FILE_ANY_ACCESS)

// Number of elements of the events array
#define EVENT_COUNT		5

//----------------------------------------------------------------------
//
// Data Types
// ----------

