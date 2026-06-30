import io
import os
import re
import requests
import sys
import zipfile
import zlib
from dataclasses import dataclass
from struct import unpack, unpack_from

from elftools.elf.elffile import ELFFile
from elftools.elf.enums import ENUM_E_MACHINE
from elftools.elf.sections import SymbolTableSection

MACHO_MAGIC_64 = 0xfeedfacf
MACHO_CIGAM_64 = 0xcffaedfe
LC_SYMTAB = 0x2
LC_SEGMENT_64 = 0x19
CPU_TYPE_X86_64 = 0x01000007
CPU_TYPE_ARM64 = 0x0100000c


@dataclass
class MachOSegment:
    vmaddr: int
    vmsize: int
    fileoff: int
    filesize: int


@dataclass
class MachOInfo:
    cputype: int
    segments: list[MachOSegment]
    symoff: int | None
    nsyms: int
    stroff: int | None
    strsize: int


def _read_c_string(data: bytes, offset: int, end: int | None = None) -> str:
    if end is None:
        end = len(data)
    zero = data.find(b'\0', offset, end)
    if zero == -1:
        raise ValueError("unterminated C string")
    return data[offset:zero].decode()


def _parse_macho(data: bytes) -> MachOInfo:
    if len(data) < 32:
        raise ValueError("Mach-O file is too small")
    magic, cputype, _, _, ncmds, _, _, _ = unpack_from('<IiiIIIII', data, 0)
    if magic == MACHO_CIGAM_64:
        raise ValueError("big-endian Mach-O is not supported")
    if magic != MACHO_MAGIC_64:
        raise ValueError("not a 64-bit Mach-O file")

    segments: list[MachOSegment] = []
    symoff = None
    nsyms = 0
    stroff = None
    strsize = 0
    offset = 32
    for _ in range(ncmds):
        if offset + 8 > len(data):
            raise ValueError("invalid Mach-O load command offset")
        cmd, cmdsize = unpack_from('<II', data, offset)
        if cmdsize < 8 or offset + cmdsize > len(data):
            raise ValueError("invalid Mach-O load command size")
        if cmd == LC_SEGMENT_64:
            _, _, _, vmaddr, vmsize, fileoff, filesize, _, _, _, _ = unpack_from('<II16sQQQQiiII', data, offset)
            segments.append(MachOSegment(vmaddr, vmsize, fileoff, filesize))
        elif cmd == LC_SYMTAB:
            _, _, symoff, nsyms, stroff, strsize = unpack_from('<IIIIII', data, offset)
        offset += cmdsize

    return MachOInfo(cputype, segments, symoff, nsyms, stroff, strsize)


def _macho_addr_to_offset(info: MachOInfo, file_size: int, addr: int) -> int:
    for segment in info.segments:
        mapped_size = min(segment.vmsize, segment.filesize)
        if mapped_size and segment.vmaddr <= addr < segment.vmaddr + mapped_size:
            offset = segment.fileoff + (addr - segment.vmaddr)
            if offset >= file_size:
                raise ValueError("Mach-O symbol points outside file")
            return offset

    # Flutter iOS App.framework often uses __TEXT vmaddr=0/fileoff=0.
    if addr < file_size:
        return addr
    raise ValueError(f"cannot map Mach-O address 0x{addr:x} to file offset")


def _macho_symbols(data: bytes):
    info = _parse_macho(data)
    if info.symoff is None or info.stroff is None:
        raise ValueError("Mach-O LC_SYMTAB not found")
    if info.symoff > len(data) or info.stroff > len(data) or info.stroff + info.strsize > len(data):
        raise ValueError("invalid Mach-O symbol table")
    if info.symoff + info.nsyms * 16 > len(data):
        raise ValueError("invalid Mach-O symbol count")

    symbols = {}
    strings_end = info.stroff + info.strsize
    for i in range(info.nsyms):
        n_strx, _, _, _, n_value = unpack_from('<IBBHQ', data, info.symoff + i * 16)
        if n_strx == 0 or n_strx >= info.strsize or n_value == 0:
            continue
        name = _read_c_string(data, info.stroff + n_strx, strings_end)
        symbols[name] = _macho_addr_to_offset(info, len(data), n_value)
    return symbols


def _extract_snapshot_hash_flags_elf(libapp_file):
    with open(libapp_file, 'rb') as f:
        elf = ELFFile(f)
        # find "_kDartVmSnapshotData" symbol
        dynsym = elf.get_section_by_name('.dynsym')
        sym = dynsym.get_symbol_by_name('_kDartVmSnapshotData')[0]
        #section = elf.get_section(sym['st_shndx'])
        assert sym['st_size'] > 128
        f.seek(sym['st_value']+20)
        snapshot_hash = f.read(32).decode()
        data = f.read(256) # should be enough
        flags = data[:data.index(b'\0')].decode().strip().split(' ')
    
    return snapshot_hash, flags


def _extract_snapshot_hash_flags_macho(libapp_file):
    with open(libapp_file, 'rb') as f:
        data = f.read()

    symbols = _macho_symbols(data)
    try:
        snapshot_offset = symbols['_kDartVmSnapshotData']
    except KeyError as exc:
        raise ValueError("Mach-O: cannot find _kDartVmSnapshotData") from exc

    if snapshot_offset + 20 + 32 >= len(data):
        raise ValueError("Mach-O: snapshot data is outside file")
    snapshot_hash = data[snapshot_offset + 20:snapshot_offset + 52].decode()
    flag_data = data[snapshot_offset + 52:snapshot_offset + 52 + 256]
    flags = flag_data[:flag_data.index(b'\0')].decode().strip().split(' ')
    return snapshot_hash, flags


def extract_snapshot_hash_flags(libapp_file):
    with open(libapp_file, 'rb') as f:
        magic = f.read(4)
    if magic == b'\x7fELF':
        return _extract_snapshot_hash_flags_elf(libapp_file)
    if unpack('<I', magic)[0] in (MACHO_MAGIC_64, MACHO_CIGAM_64):
        return _extract_snapshot_hash_flags_macho(libapp_file)
    raise ValueError(f"Unsupported libapp format: {libapp_file}")


def _extract_libflutter_info_elf(libflutter_file):
    with open(libflutter_file, 'rb') as f:
        elf = ELFFile(f)
        if elf.header.e_machine == 'EM_AARCH64': # 183
            arch = 'arm64'
        elif elf.header.e_machine == 'EM_IA_64': # 50
            arch = 'x64'
        else:
            assert False, f"Unsupport architecture: {elf.header.e_machine}"

        section = elf.get_section_by_name('.rodata')
        data = section.data()
        
        sha_hashes = re.findall(b'\x00([a-f\\d]{40})(?=\x00)', data)
        #print(sha_hashes)
        # all possible engine ids
        engine_ids = [ h.decode() for h in sha_hashes ]
        assert len(engine_ids) == 2, f'found hashes {", ".join(engine_ids)}'
        
        # beta/dev version of flutter might not use stable dart version (we can get dart version from sdk with found engine_id)
        # support stable, beta and dev channels
        m = re.search(br'\x00([\d\w\.-]+) \((stable|beta|dev)\)', data)
        if m is None:
            dart_version = None
        else:
            dart_version = m.group(1).decode()
        
    return engine_ids, dart_version, arch, 'android'


def _extract_libflutter_info_macho(libflutter_file):
    with open(libflutter_file, 'rb') as f:
        data = f.read()

    info = _parse_macho(data)
    if info.cputype == CPU_TYPE_ARM64:
        arch = 'arm64'
    elif info.cputype == CPU_TYPE_X86_64:
        arch = 'x64'
    else:
        raise AssertionError(f"Unsupported Mach-O architecture: {info.cputype}")

    sha_hashes = re.findall(b'\x00([a-f\\d]{40})(?=\x00)', data)
    engine_ids = [h.decode() for h in sha_hashes]

    m = re.search(br'\x00([\d\w\.-]+) \((stable|beta|dev)\)', data)
    dart_version = None if m is None else m.group(1).decode()
    if dart_version is None and not engine_ids:
        raise AssertionError('cannot find Flutter engine hash or Dart version in Mach-O Flutter binary')

    return engine_ids, dart_version, arch, 'ios'


def extract_libflutter_info(libflutter_file):
    with open(libflutter_file, 'rb') as f:
        magic = f.read(4)
    if magic == b'\x7fELF':
        return _extract_libflutter_info_elf(libflutter_file)
    if unpack('<I', magic)[0] in (MACHO_MAGIC_64, MACHO_CIGAM_64):
        return _extract_libflutter_info_macho(libflutter_file)
    raise ValueError(f"Unsupported Flutter binary format: {libflutter_file}")


def get_dart_sdk_url_size(engine_ids):
    #url = f'https://storage.googleapis.com/dart-archive/channels/stable/release/3.0.3/sdk/dartsdk-windows-x64-release.zip'
    for engine_id in engine_ids:
        url = f'https://storage.googleapis.com/flutter_infra_release/flutter/{engine_id}/dart-sdk-windows-x64.zip'
        resp = requests.head(url)
        if resp.status_code == 200:
           sdk_size = int(resp.headers['Content-Length'])
           return engine_id, url, sdk_size
    
    return None, None, None

def get_dart_commit(url):
    # in downloaded zip
    # * dart-sdk/revision - the dart commit id of https://github.com/dart-lang/sdk/
    # * dart-sdk/version  - the dart version
    # revision and version zip file records should be in first 4096 bytes
    # using stream in case a server does not support range
    commit_id = None
    dart_version = None
    fp = None
    with requests.get(url, headers={"Range": "bytes=0-4096"}, stream=True) as r:
        if r.status_code // 10 == 20:
            x = next(r.iter_content(chunk_size=4096))
            fp = io.BytesIO(x)
    
    if fp is not None:
        while fp.tell() < 4096-30 and (commit_id is None or dart_version is None):
            #sig, ver, flags, compression, filetime, filedate, crc, compressSize, uncompressSize, filenameLen, extraLen = unpack(fp, '<IHHHHHIIIHH')
            _, _, _, compMethod, _, _, _, compressSize, _, filenameLen, extraLen = unpack('<IHHHHHIIIHH', fp.read(30))
            filename = fp.read(filenameLen)
            #print(filename)
            if extraLen > 0:
                fp.seek(extraLen, io.SEEK_CUR)
            data = fp.read(compressSize)
            
            # expect compression method to be zipfile.ZIP_DEFLATED
            assert compMethod == zipfile.ZIP_DEFLATED, 'Unexpected compression method'
            if filename == b'dart-sdk/revision':
                commit_id = zlib.decompress(data, wbits=-zlib.MAX_WBITS).decode().strip()
            elif filename == b'dart-sdk/version':
                dart_version = zlib.decompress(data, wbits=-zlib.MAX_WBITS).decode().strip()
    
    # TODO: if no revision and version in first 4096 bytes, get the file location from the first zip dir entries at the end of file (less than 256KB)
    return commit_id, dart_version

def extract_dart_info(libapp_file: str, libflutter_file: str):
    snapshot_hash, flags = extract_snapshot_hash_flags(libapp_file)
    #print('snapshot hash', snapshot_hash)
    #print(flags)

    engine_ids, dart_version, arch, os_name = extract_libflutter_info(libflutter_file)
    # print('possible engine ids', engine_ids)
    # print('dart version', dart_version)

    if dart_version is None:
        engine_id, sdk_url, sdk_size = get_dart_sdk_url_size(engine_ids)
        # print(engine_id)
        # print(sdk_url)
        # print(sdk_size)

        commit_id, dart_version = get_dart_commit(sdk_url)
        # print(commit_id)
        # print(dart_version)
        #assert dart_version == dart_version_sdk
    
    # TODO: os (android or ios) and architecture (arm64 or x64)
    return dart_version, snapshot_hash, flags, arch, os_name


if __name__ == "__main__":
    libdir = sys.argv[1]
    libapp_file = os.path.join(libdir, 'libapp.so')
    libflutter_file = os.path.join(libdir, 'libflutter.so')

    print(extract_dart_info(libapp_file, libflutter_file))
