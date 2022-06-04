#include <stdint.h>

struct WIN_UNICODE_STRING
{
	uint16_t Length;
	uint16_t MaximumLength;
	uint16_t *Buffer;
} __attribute__((packed));

#define IRP_MJ_MAXIMUM_FUNCTION 0x1b

struct WIN_DRIVER_OBJECT
{
	int16_t Type;
	int16_t Size;
	void *DeviceObject;
	uint64_t Flags;
	void *DriverStart;
	uint64_t DriverSize;
	void *DriverSection;
	void *DriverExtension;
	struct WIN_UNICODE_STRING DriverName;
	struct WIN_UNICODE_STRING *HardwareDatabase;
	void *FastIoDispatch;
	void *DriverInit;
	void *DriverStartIo;
	void *DriverUnload;
	void *MajorFunction[IRP_MJ_MAXIMUM_FUNCTION + 1];
} __attribute__((packed));
