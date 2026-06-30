#include "pch.h"
#include "ElfHelper.h"
PRAGMA_WARNING(push, 0)
#include <platform/elf.h>
PRAGMA_WARNING(pop)
#include <algorithm>
#include <cstring>
#include <stdexcept>
#include <vector>
#if defined(_WIN32) || defined(WIN32)
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#else
#include <fcntl.h>
#include <sys/stat.h>
//#include <dlfcn.h>
#include <sys/mman.h>
#endif // #if defined(_WIN32) || defined(WIN32)

struct ElfIdent {
	uint8_t ei_magic[4];
	uint8_t ei_class;
	uint8_t ei_data;
	uint8_t ei_version;
	uint8_t ei_osabi;
	uint8_t ei_abiversion;
	uint8_t pad1[7];
};

using namespace dart::elf;

namespace {

struct MappedFile {
	void* data;
	size_t size;
};

constexpr uint32_t MH_MAGIC_64 = 0xfeedfacf;
constexpr uint32_t MH_CIGAM_64 = 0xcffaedfe;
constexpr uint32_t LC_SYMTAB = 0x2;
constexpr uint32_t LC_SEGMENT_64 = 0x19;

struct MachHeader64 {
	uint32_t magic;
	int32_t cputype;
	int32_t cpusubtype;
	uint32_t filetype;
	uint32_t ncmds;
	uint32_t sizeofcmds;
	uint32_t flags;
	uint32_t reserved;
};

struct MachLoadCommand {
	uint32_t cmd;
	uint32_t cmdsize;
};

struct MachSegmentCommand64 {
	uint32_t cmd;
	uint32_t cmdsize;
	char segname[16];
	uint64_t vmaddr;
	uint64_t vmsize;
	uint64_t fileoff;
	uint64_t filesize;
	int32_t maxprot;
	int32_t initprot;
	uint32_t nsects;
	uint32_t flags;
};

struct MachSymtabCommand {
	uint32_t cmd;
	uint32_t cmdsize;
	uint32_t symoff;
	uint32_t nsyms;
	uint32_t stroff;
	uint32_t strsize;
};

struct MachNlist64 {
	uint32_t n_strx;
	uint8_t n_type;
	uint8_t n_sect;
	uint16_t n_desc;
	uint64_t n_value;
};

struct MachSegmentMapping {
	uint64_t vmaddr;
	uint64_t vmsize;
	uint64_t fileoff;
	uint64_t filesize;
};

template<typename T>
const T* checked_ptr(const uint8_t* base, size_t size, size_t offset)
{
	if (offset > size || sizeof(T) > size - offset)
		throw std::invalid_argument("Mach-O: Invalid file structure");
	return reinterpret_cast<const T*>(base + offset);
}

const uint8_t* macho_addr_to_ptr(const uint8_t* macho, size_t size, const std::vector<MachSegmentMapping>& segments, uint64_t addr)
{
	for (const auto& segment : segments) {
		const uint64_t mapped_size = std::min(segment.vmsize, segment.filesize);
		if (mapped_size == 0)
			continue;
		if (addr >= segment.vmaddr && addr < segment.vmaddr + mapped_size) {
			const uint64_t fileoff = segment.fileoff + (addr - segment.vmaddr);
			if (fileoff >= size)
				throw std::invalid_argument("Mach-O: Symbol maps outside file");
			return macho + fileoff;
		}
	}

	// Many Flutter iOS App.framework binaries use __TEXT vmaddr=0 and fileoff=0,
	// so symbol values are already file offsets. Keep this fallback explicit.
	if (addr < size)
		return macho + addr;

	throw std::invalid_argument("Mach-O: Cannot map symbol address to file offset");
}

LibAppInfo findElfSnapshots(const uint8_t* elf)
{
	const auto* hdr = (const ElfHeader*)elf;
	if (hdr->section_table_entry_size != sizeof(SectionHeader))
		throw std::invalid_argument("ELF: Invalid section entry size");

	const auto* section = (SectionHeader*)(elf + hdr->section_table_offset);
	const auto sh_num = hdr->num_section_headers;

	// find .dynstr and .dynsym sections, so we can map the section names
	const char* dynstr = nullptr;
	const Symbol* dynsym = nullptr;
	const Symbol* dynsym_end = nullptr;
	for (uint16_t i = 0; i < sh_num; i++, section++) {
		if (section->type == SectionHeaderType::SHT_STRTAB && dynstr == nullptr) {
			// we want only .dynstr for .dynsym
			const char* strtab = (const char*)elf + section->file_offset;
			const char* last = strtab + section->file_size;
			const char* s_first = kVmSnapshotDataAsmSymbol;
			const char* s_last = s_first + strlen(kVmSnapshotDataAsmSymbol) + 1;
			//if (memmem(strtab, section->s_size, kVmSnapshotDataAsmSymbol, strlen(kVmSnapshotDataAsmSymbol))) {
			if (std::search(strtab, last, s_first, s_last) != last) {
				// found it
				dynstr = strtab;
			}
		}
		if (section->type == SectionHeaderType::SHT_DYNSYM) {
			if (section->entry_size != sizeof(Symbol))
				throw std::invalid_argument("ELF: Invalid DYNSYM entry size");
			dynsym = (Symbol*)(elf + section->file_offset);
			dynsym_end = (Symbol*)(elf + section->file_offset + section->file_size);
		}
		if (dynsym != nullptr && dynstr != nullptr)
			break;
	}

	// find the required symbol addresses
	const uint8_t* vm_snapshot_data = nullptr;
	const uint8_t* vm_snapshot_instructions = nullptr;
	const uint8_t* isolate_snapshot_data = nullptr;
	const uint8_t* isolate_snapshot_instructions = nullptr;
	for (; dynsym < dynsym_end; dynsym++) {
		if (dynsym->info == 0)
			continue;

		const char* name = dynstr + dynsym->name;
		// Note: sym_size is no needed for dart VM (its blob contains size)
		if (strcmp(name, kVmSnapshotDataAsmSymbol) == 0) {
			vm_snapshot_data = elf + dynsym->value;
		}
		else if (strcmp(name, kVmSnapshotInstructionsAsmSymbol) == 0) {
			vm_snapshot_instructions = elf + dynsym->value;
		}
		else if (strcmp(name, kIsolateSnapshotDataAsmSymbol) == 0) {
			isolate_snapshot_data = elf + dynsym->value;
		}
		else if (strcmp(name, kIsolateSnapshotInstructionsAsmSymbol) == 0) {
			isolate_snapshot_instructions = elf + dynsym->value;
		}
	}

	if (vm_snapshot_data == nullptr)
		throw std::invalid_argument("ELF: Cannot find Dart VM Snapshot Data");
	if (vm_snapshot_instructions == nullptr)
		throw std::invalid_argument("ELF: Cannot find Dart VM Snapshot Instructions");
	if (isolate_snapshot_data == nullptr)
		throw std::invalid_argument("ELF: Cannot find Dart Isolate Snapshot Data");
	if (isolate_snapshot_instructions == nullptr)
		throw std::invalid_argument("ELF: Cannot find Dart Isolate Snapshot Instructions");

	return LibAppInfo{
		.lib = elf,
		.vm_snapshot_data = vm_snapshot_data,
		.vm_snapshot_instructions = vm_snapshot_instructions,
		.isolate_snapshot_data = isolate_snapshot_data,
		.isolate_snapshot_instructions = isolate_snapshot_instructions,
	};
}

LibAppInfo findMachOSnapshots(const uint8_t* macho, size_t size)
{
	const auto* header = checked_ptr<MachHeader64>(macho, size, 0);
	if (header->magic == MH_CIGAM_64)
		throw std::invalid_argument("Mach-O: Expected a little-endian 64-bit header");
	if (header->magic != MH_MAGIC_64)
		throw std::invalid_argument("Mach-O: Invalid magic header");

	const MachSymtabCommand* symtab = nullptr;
	std::vector<MachSegmentMapping> segments;
	size_t command_offset = sizeof(MachHeader64);
	for (uint32_t i = 0; i < header->ncmds; i++) {
		const auto* command = checked_ptr<MachLoadCommand>(macho, size, command_offset);
		if (command->cmdsize < sizeof(MachLoadCommand) || command_offset + command->cmdsize > size)
			throw std::invalid_argument("Mach-O: Invalid load command size");

		if (command->cmd == LC_SEGMENT_64) {
			const auto* segment = checked_ptr<MachSegmentCommand64>(macho, size, command_offset);
			segments.push_back(MachSegmentMapping{
				.vmaddr = segment->vmaddr,
				.vmsize = segment->vmsize,
				.fileoff = segment->fileoff,
				.filesize = segment->filesize,
			});
		}
		else if (command->cmd == LC_SYMTAB) {
			symtab = checked_ptr<MachSymtabCommand>(macho, size, command_offset);
		}

		command_offset += command->cmdsize;
	}

	if (symtab == nullptr)
		throw std::invalid_argument("Mach-O: Cannot find LC_SYMTAB");
	if (symtab->symoff > size || symtab->stroff > size || symtab->strsize > size - symtab->stroff)
		throw std::invalid_argument("Mach-O: Invalid symbol table offsets");
	if (symtab->nsyms > (size - symtab->symoff) / sizeof(MachNlist64))
		throw std::invalid_argument("Mach-O: Invalid symbol count");

	const auto* symbols = reinterpret_cast<const MachNlist64*>(macho + symtab->symoff);
	const char* strings = reinterpret_cast<const char*>(macho + symtab->stroff);
	const char* strings_end = strings + symtab->strsize;

	const uint8_t* vm_snapshot_data = nullptr;
	const uint8_t* vm_snapshot_instructions = nullptr;
	const uint8_t* isolate_snapshot_data = nullptr;
	const uint8_t* isolate_snapshot_instructions = nullptr;
	for (uint32_t i = 0; i < symtab->nsyms; i++) {
		const auto& symbol = symbols[i];
		if (symbol.n_strx >= symtab->strsize || symbol.n_value == 0)
			continue;

		const char* name = strings + symbol.n_strx;
		if (std::find(name, strings_end, '\0') == strings_end)
			throw std::invalid_argument("Mach-O: Unterminated symbol name");

		if (strcmp(name, kVmSnapshotDataAsmSymbol) == 0) {
			vm_snapshot_data = macho_addr_to_ptr(macho, size, segments, symbol.n_value);
		}
		else if (strcmp(name, kVmSnapshotInstructionsAsmSymbol) == 0) {
			vm_snapshot_instructions = macho_addr_to_ptr(macho, size, segments, symbol.n_value);
		}
		else if (strcmp(name, kIsolateSnapshotDataAsmSymbol) == 0) {
			isolate_snapshot_data = macho_addr_to_ptr(macho, size, segments, symbol.n_value);
		}
		else if (strcmp(name, kIsolateSnapshotInstructionsAsmSymbol) == 0) {
			isolate_snapshot_instructions = macho_addr_to_ptr(macho, size, segments, symbol.n_value);
		}
	}

	if (vm_snapshot_data == nullptr)
		throw std::invalid_argument("Mach-O: Cannot find Dart VM Snapshot Data");
	if (vm_snapshot_instructions == nullptr)
		throw std::invalid_argument("Mach-O: Cannot find Dart VM Snapshot Instructions");
	if (isolate_snapshot_data == nullptr)
		throw std::invalid_argument("Mach-O: Cannot find Dart Isolate Snapshot Data");
	if (isolate_snapshot_instructions == nullptr)
		throw std::invalid_argument("Mach-O: Cannot find Dart Isolate Snapshot Instructions");

	return LibAppInfo{
		.lib = macho,
		.vm_snapshot_data = vm_snapshot_data,
		.vm_snapshot_instructions = vm_snapshot_instructions,
		.isolate_snapshot_data = isolate_snapshot_data,
		.isolate_snapshot_instructions = isolate_snapshot_instructions,
	};
}

} // namespace

#ifdef _WIN32
static MappedFile load_map_file(const char* path)
{
	HANDLE hFile = CreateFileA(path, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile == INVALID_HANDLE_VALUE) {
		printf("\nCannot find %s\n", path);
		return MappedFile{ .data = NULL, .size = 0 };
	}

	LARGE_INTEGER fileSize;
	if (!GetFileSizeEx(hFile, &fileSize)) {
		CloseHandle(hFile);
		return MappedFile{ .data = NULL, .size = 0 };
	}
	// because Dart API requires only snapshot buffer addresses (no relative access across snapshot),
	//   so we can just mapping a whole file and find address of snapshots
	HANDLE hMapFile = CreateFileMapping(hFile, NULL, PAGE_READONLY, 0, 0, NULL);
	if (hMapFile == INVALID_HANDLE_VALUE)
		return MappedFile{ .data = NULL, .size = 0 };

	// need RW because dart initialization need writing data in BSS
	void* mem = MapViewOfFile(hMapFile, FILE_MAP_COPY, 0, 0, 0);
	CloseHandle(hMapFile);

	CloseHandle(hFile);
	return MappedFile{ .data = mem, .size = static_cast<size_t>(fileSize.QuadPart) };
}
#else
static MappedFile load_map_file(const char* path)
{
	// need RW because dart initialization need writing data in BSS
	int fd = open(path, O_RDONLY);
	struct stat st;

	fstat(fd, &st);
	void* mem = mmap(NULL, st.st_size, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);

	close(fd);
	return MappedFile{ .data = mem, .size = static_cast<size_t>(st.st_size) };
}
#endif

LibAppInfo ElfHelper::findSnapshots(const uint8_t* lib, size_t size)
{
	if (size < 4)
		throw std::invalid_argument("Invalid libapp file");

	if (memcmp(lib, "\x7f" "ELF", 4) == 0) {
		const auto* hdr = (ElfHeader*)lib;
		const auto* ident = (ElfIdent*)hdr->ident;
		if (ident->ei_data != 1)
			throw std::invalid_argument("ELF: Support only little endian");
		if (ident->ei_class != ELFCLASS64)
			throw std::invalid_argument("ELF: Support only 64 bits");
		return findElfSnapshots(lib);
	}

	const uint32_t magic = *reinterpret_cast<const uint32_t*>(lib);
	if (magic == MH_MAGIC_64 || magic == MH_CIGAM_64)
		return findMachOSnapshots(lib, size);

	throw std::invalid_argument("Invalid libapp magic header");
}

LibAppInfo ElfHelper::MapLibAppSo(const char* path)
{
	auto mapped = load_map_file(path);
	if (mapped.data == nullptr)
		throw std::invalid_argument("Cannot map libapp file");
	return findSnapshots(reinterpret_cast<const uint8_t*>(mapped.data), mapped.size);
}
