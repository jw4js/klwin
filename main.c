#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <stdint.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <dlfcn.h>

#include "common_impl.h"

struct peSectionHeader
{
	uint8_t Name[8];
	uint32_t VirtualSize;
	uint32_t VirtualAddress;
	uint32_t SizeOfRawData;
	uint32_t PointerToRawData;
	uint32_t PointerToRelocations;
	uint32_t PointerToLinenumbers;
	uint16_t NumberOfRelocations;
	uint16_t NumberOfLinenumbers;
	uint32_t Characteristics;
} __attribute__((packed));

static const uint32_t IMAGE_SCN_MEM_EXECUTE = 0x20000000u;
static const uint32_t IMAGE_SCN_MEM_READ = 0x40000000u;
static const uint32_t IMAGE_SCN_MEM_WRITE = 0x80000000u;

struct peDataDirectory
{
	uint32_t VirtualAddress;
	uint32_t Size;
} __attribute__((packed));

struct peImportDirectoryEntry
{
	uint32_t RVAImportLookupTable;
	uint32_t TimeDateStamp;
	uint32_t FowarderChain;
	uint32_t RVAName;
	uint32_t RVAImportAddressTable;
} __attribute__((packed));

union peImportLookupEntry
{
	struct
	{
		union
		{
			struct
			{
				uint16_t OrdinalNumber;
				uint16_t __pad0;
			};
			struct
			{
				uint32_t RVAHintName : 31;
				uint32_t __pad1 : 1;
			};
		};
		uint32_t __pad2 : 31;
		uint32_t FlagOrdinal : 1;
	};
	void *ResolvedAddr;
} __attribute__((packed));

struct mmap_entry
{
	void *base;
	void *end;
	uint32_t flags;
};

static size_t round_to_page(size_t size)
{
	return (size + (1 << 12) - 1) & (-(1 << 12));
}

static ssize_t get_mmap_entry(struct mmap_entry *mem_maps,size_t num_mem_maps,void *ptr)
{
	ssize_t res = -1;
	for(size_t i = 0;i < num_mem_maps;i++)
	{
		if(mem_maps[i].base <= ptr && ptr <= mem_maps[i].end)
		{
			res = i;
			break;
		}
	}
	return res;
}

static const uint8_t zero[64];
static ssize_t get_arr_max(struct mmap_entry *mem_maps,size_t num_mem_maps,void *base,size_t size)
{
	ssize_t res = -1;
	ssize_t i = get_mmap_entry(mem_maps,num_mem_maps,base);
	if(i == -1)
		goto out;
	if(base + size <= mem_maps[i].end)
		res = 0;
	while(base + size <= mem_maps[i].end && memcmp(zero,base,size) != 0)
	{
		base += size;
		res++;
	}
out:
	return res;
}

static ssize_t safe_strlen(struct mmap_entry *mem_maps,size_t num_mem_maps,void *str)
{
	ssize_t res = -1;
	ssize_t i = get_mmap_entry(mem_maps,num_mem_maps,str);
	if(i == -1)
		goto out;
	size_t rem = mem_maps[i].end - str;
	size_t sz = strnlen(str,rem);
	if(rem != sz)
		res = sz;
out:
	return res;
}

extern void win_call_stub();
extern uint64_t __attribute__((noreturn)) call_driver_entry(void *,void *,void *);

void win_call_stub_c(uint64_t regs[static 15])
{
	puts("call stub called");
	for(uint_fast32_t i = 0;i < 3;i++)
	{
		for(uint_fast32_t j = 0;j < 5;j++)
			printf("%016llx ",regs[i * 5 + j]);
		putchar('\n');
	}
}

static void *int_calloc(size_t size)
{
	void *buf = malloc(size);
	memset(buf,0,size);
	return buf;
}

int32_t main(int32_t argc,int8_t **argv)
{
	int32_t fd = open(argv[1],O_RDONLY);
	void *lib = dlopen(argv[2],RTLD_NOW);
	if(!lib)
	{
		fprintf(stderr,"loading external calls library object failed %s\n",dlerror());
		return EXIT_FAILURE;
	}
	struct stat statbuf;
	fstat(fd,&statbuf);
	FILE *pe_file = fdopen(fd,"rb");
	const off_t pe_file_size = statbuf.st_size;
	void *buf = malloc(pe_file_size),*buf_end = buf + pe_file_size;
	fread(buf,1,pe_file_size,pe_file);
	fclose(pe_file);
	if(pe_file_size < 0x40)
	{
		fprintf(stderr,"cannot access offset to PE header; file size too small\n");
		return EXIT_FAILURE;
	}
	void *pe_hdr = buf + *(uint32_t *)(buf + 0x3c);
	if(pe_hdr >= buf_end)
	{
		fprintf(stderr,"COFF header out of bounds\n");
		return EXIT_FAILURE;
	}
	uint16_t NumberOfSections = *(uint16_t *)(pe_hdr + 4 + 2);
	uint16_t SizeOfOptionalHeader = *(uint64_t *)(pe_hdr + 4 + 16);
	printf("found %hu sections\n",NumberOfSections);
	void *coff_hdr = pe_hdr + 4 + 20;
	struct peSectionHeader *sec_hdr = coff_hdr + SizeOfOptionalHeader;
	if((void *)&sec_hdr[NumberOfSections] > buf_end)
	{
		fprintf(stderr,"section header table out of bounds, section header table size %hu, SizeOfOptionalHeader %hu\n",NumberOfSections,SizeOfOptionalHeader);
		return EXIT_FAILURE;
	}
	if(SizeOfOptionalHeader < 0x20)
	{
		fprintf(stderr,"optional header too small, cannot read ImageBase, SizeOfOptionalHeader %hu\n",SizeOfOptionalHeader);
		return EXIT_FAILURE;
	}
	size_t tot_hdr_size = (void*)&sec_hdr[NumberOfSections] - pe_hdr;
	void *n_pe_hdr = malloc(tot_hdr_size);
	memcpy(n_pe_hdr,pe_hdr,tot_hdr_size);
	pe_hdr = n_pe_hdr;
	coff_hdr = pe_hdr + 4 + 20;
	sec_hdr = coff_hdr + SizeOfOptionalHeader;
	void *image_base = *(void **)(coff_hdr + 24);
	struct mmap_entry *mem_maps = malloc(sizeof(*mem_maps) * NumberOfSections);
	for(uint16_t i = 0;i < NumberOfSections;i++)
	{
		void *vma = image_base + sec_hdr[i].VirtualAddress;
		size_t size_pages = round_to_page(sec_hdr[i].VirtualSize);
		mem_maps[i].base = vma;
		mem_maps[i].end = vma + size_pages;
		if(mmap(vma,size_pages,PROT_READ | PROT_WRITE,MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE,-1,0) == MAP_FAILED)
		{
			fprintf(stderr,"mmap() failed: %d %s\n",errno,strerror(errno));
			return EXIT_FAILURE;
		}
		if(sec_hdr[i].PointerToRawData + sec_hdr[i].SizeOfRawData > pe_file_size)
		{
			fprintf(stderr,"invalid section %hu %.8s: section header data source out of bounds\n",i,sec_hdr[i].Name);
			return EXIT_FAILURE;
		}
		uint32_t prot_flags = 0,orig_flags = sec_hdr[i].Characteristics;
		if(orig_flags & IMAGE_SCN_MEM_EXECUTE)
			prot_flags ^= PROT_EXEC;
		if(orig_flags & IMAGE_SCN_MEM_READ)
			prot_flags ^= PROT_READ;
		if(orig_flags & IMAGE_SCN_MEM_WRITE)
			prot_flags ^= PROT_WRITE;
		mem_maps[i].flags = prot_flags;
		memcpy(vma,buf + sec_hdr[i].PointerToRawData,sec_hdr[i].VirtualSize);
		printf("loaded section %i %.8s at %p %u bytes\n",i,sec_hdr[i].Name,vma,sec_hdr[i].VirtualSize);
	}
	size_t num_mem_maps = NumberOfSections;
	free(buf);
	uint32_t NumberOfRvaAndSizes = *(uint32_t *)(coff_hdr + 108);
	struct peDataDirectory *data_dir = coff_hdr + 112;
	struct peImportDirectoryEntry *idt = image_base + data_dir[1].VirtualAddress;
	ssize_t num_idt = get_arr_max(mem_maps,num_mem_maps,idt,sizeof(*idt));
	if(num_idt == -1)
	{
		fprintf(stderr,"Import Directory Table out of bounds\n");
		return EXIT_FAILURE;
	}
	for(ssize_t i = 0;i < num_idt;i++)
	{
		uint8_t *dll_name = image_base + idt[i].RVAName;
		ssize_t dll_name_size = safe_strlen(mem_maps,num_mem_maps,dll_name);
		if(dll_name_size == -1)
		{
			fprintf(stderr,"IDT %ld: DLL name out of bounds\n",i);
			return EXIT_FAILURE;
		}
		uint8_t *sanitized_dll_name = malloc(dll_name_size + 2);
		memcpy(sanitized_dll_name,dll_name,dll_name_size);
		for(ssize_t j = 0;j < dll_name_size;j++)
			if(sanitized_dll_name[j] == '.')
				sanitized_dll_name[j] = '_';
		sanitized_dll_name[dll_name_size] = '_';
		sanitized_dll_name[dll_name_size + 1] = 0;
		union peImportLookupEntry *iat = image_base + idt[i].RVAImportAddressTable;
		ssize_t num_iat = get_arr_max(mem_maps,num_mem_maps,iat,sizeof(*iat));
		if(num_iat == -1)
		{
			fprintf(stderr,"IDT %ld: Import Address Table out of bounds\n",i);
			return EXIT_FAILURE;
		}
		printf("resolving %ld symbols in %.*s\n",num_iat,dll_name_size,dll_name);
		for(ssize_t j = 0;j < num_iat;j++)
		{
			if(iat[j].FlagOrdinal)
			{
				fprintf(stderr,"IDT %ld: Ordinal number linking not supported\n",i);
				return EXIT_FAILURE;
			}
			else
			{
				// Ignore "Hint"
				uint8_t *sym_name = image_base + iat[j].RVAHintName + 2;
				ssize_t sym_name_size = safe_strlen(mem_maps,num_mem_maps,sym_name);
				if(sym_name_size == -1)
				{
					fprintf(stderr,"IDT %ld sym %ld: Symbol name out of bounds\n",i,j);
					return EXIT_FAILURE;
				}
				size_t res_sym_name_size = dll_name_size + 1 + sym_name_size + 1;
				uint8_t *res_sym_name = malloc(res_sym_name_size);
				memcpy(res_sym_name,sanitized_dll_name,dll_name_size + 1);
				memcpy(res_sym_name + dll_name_size + 1,sym_name,sym_name_size + 1);
				void *sym = dlsym(lib,res_sym_name);
				void *dl_error = dlerror();
				if(dl_error)
					sym = &win_call_stub;
				printf("resolved %.*s to %p\n",res_sym_name_size,res_sym_name,sym);
				free(res_sym_name);
				iat[j].ResolvedAddr = sym;
			}
		}
		free(sanitized_dll_name);
	}
	for(uint16_t i = 0;i < num_mem_maps;i++)
		mprotect(mem_maps[i].base,mem_maps[i].end - mem_maps[i].base,mem_maps[i].flags);
	// NTSTATUS DriverEntry(DRIVER_OBJECT DriverObject,UNICODE_STRING RegistryPath)
	uint64_t (*entry_point)(void *,void *) = image_base + *(uint32_t *)(coff_hdr + 16);
	printf("found entry point at %p\n",entry_point);
	free(pe_hdr);
	free(mem_maps);
	struct WIN_DRIVER_OBJECT *driver_object = int_calloc(sizeof(*driver_object));
	uint8_t *str_registry_path = "\\blahblah";
	struct WIN_UNICODE_STRING *registry_path = malloc(sizeof(*registry_path));
	registry_path->Length = 2;
	registry_path->MaximumLength = 4;
	registry_path->Buffer = malloc(4);
	driver_object->DriverInit = entry_point;
	fflush(stdout);
	setbuf(stdout,NULL);
	uint64_t driver_res = call_driver_entry(entry_point,driver_object,registry_path);
}
