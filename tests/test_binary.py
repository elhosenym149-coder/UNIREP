import struct

from unirep.core.models import AnalysisTarget
from unirep.engines.binary import BinaryMetadataEngine, inspect_elf, inspect_macho, inspect_pe


def test_reads_minimal_32_bit_elf_header(tmp_path):
    data = bytearray(52)
    data[:4] = b"\x7fELF"
    data[4:6] = bytes([1, 1])
    struct.pack_into("<HHI", data, 16, 2, 3, 1)
    struct.pack_into("<III", data, 24, 0x08048000, 52, 0)
    struct.pack_into("<I", data, 36, 0)
    struct.pack_into("<HH", data, 44, 0, 0)
    path = tmp_path / "sample.elf"
    path.write_bytes(data)
    result = inspect_elf(path)
    assert result["class"] == "32-bit"
    assert result["machine"] == "x86"
    assert result["entry_point"] == 0x08048000


def test_reads_minimal_32_bit_macho_header(tmp_path):
    data = bytearray(28)
    data[:4] = b"\xce\xfa\xed\xfe"
    struct.pack_into("<IIIIII", data, 4, 7, 3, 2, 4, 64, 0)
    path = tmp_path / "sample.macho"
    path.write_bytes(data)
    result = inspect_macho(path)
    assert result["format"] == "Mach-O"
    assert result["class"] == "32-bit"
    assert result["cpu_type"] == 7


def test_reads_pe_header(tmp_path):
    data = bytearray(0x80 + 24 + 70 + 40)
    data[:2] = b"MZ"
    struct.pack_into("<I", data, 0x3C, 0x80)
    offset = 0x80
    data[offset:offset + 4] = b"PE\0\0"
    struct.pack_into("<HHIIIHH", data, offset + 4, 0x8664, 1, 123, 0, 0, 70, 0x2000)
    optional = offset + 24
    struct.pack_into("<H", data, optional, 0x20B)
    struct.pack_into("<I", data, optional + 16, 0x1000)
    struct.pack_into("<Q", data, optional + 24, 0x140000000)
    struct.pack_into("<H", data, optional + 68, 3)
    data[optional + 70:optional + 78] = b".text\0\0\0"
    path = tmp_path / "sample.exe"
    path.write_bytes(data)
    result = inspect_pe(path)
    assert result["machine"] == "x86_64"
    assert result["is_dll"] is True
    assert result["entry_point_rva"] == 0x1000


def test_unknown_file_is_reported_as_unsupported(tmp_path):
    path = tmp_path / "plain.txt"
    path.write_text("not a binary")
    result = BinaryMetadataEngine().analyze(AnalysisTarget(str(path), "file"))
    assert result.status == "unsupported"
