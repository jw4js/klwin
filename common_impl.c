#include "common_impl.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

uint32_t __attribute__((ms_abi)) ntoskrnl_exe_RtlDuplicateUnicodeString(int32_t add_nul,struct WIN_UNICODE_STRING *src,struct WIN_UNICODE_STRING *dst)
{
	printf("ntoskrnl_exe_RtlDuplicateUnicodeString %p %p\n",dst,src);
	fwrite(src->Buffer,1,src->Length,stdout);
	dst->MaximumLength = src->Length;
	if(add_nul)
		dst->MaximumLength += sizeof(uint16_t);
	dst->Buffer = malloc(dst->MaximumLength);
	dst->Length = src->Length;
	memcpy(dst->Buffer,src->Buffer,dst->Length);
	dst->Buffer[dst->Length >> 1] = 0;
}
