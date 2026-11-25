"""Read-only metadata inspection for common native executable formats."""
from __future__ import annotations

from pathlib import Path
import struct
from typing import Any

from unirep.core.engine import AnalysisEngine
from unirep.core.models import AnalysisTarget, EngineResult, Evidence


def _read_exact(path: Path, offset: int, size: int) -> bytes:
    with path.open("rb") as stream:
        stream.seek(offset)
        data = stream.read(size)
    if len(data) != size:
        raise ValueError("Truncated executable header")
    return data


def inspect_pe(path: Path) -> dict[str, Any]:
    dos = _read_exact(path, 0, 64)
    if dos[:2] != b"MZ":
        raise ValueError("Not a PE executable")
    pe_offset = struct.unpack_from("<I", dos, 0x3C)[0]
    if pe_offset > path.stat().st_size - 24 or pe_offset > (1 << 20):
        raise ValueError("Invalid PE header offset")
    coff = _read_exact(path, pe_offset, 24)
    if coff[:4] != b"PE\0\0":
        raise ValueError("Missing PE signature")
    machine, sections, timestamp, _, _, optional_size, characteristics = struct.unpack_from("<HHIIIHH", coff, 4)
    optional = _read_exact(path, pe_offset + 24, optional_size) if optional_size else b""
    magic = struct.unpack_from("<H", optional, 0)[0] if len(optional) >= 2 else 0
    if magic not in (0x10B, 0x20B):
        raise ValueError("Unsupported PE optional header")
    entry = struct.unpack_from("<I", optional, 16)[0] if len(optional) >= 20 else 0
    image_base = (struct.unpack_from("<Q", optional, 24)[0] if magic == 0x20B
                  else struct.unpack_from("<I", optional, 28)[0]) if len(optional) >= (32 if magic == 0x20B else 32) else 0
    subsystem = struct.unpack_from("<H", optional, 68)[0] if len(optional) >= 70 else None
    section_data = _read_exact(path, pe_offset + 24 + optional_size, min(sections, 96) * 40)
    names = [section_data[i:i + 8].rstrip(b"\0").decode("ascii", "replace")
             for i in range(0, len(section_data), 40)]
    return {
        "format": "PE", "machine": {0x14C: "x86", 0x8664: "x86_64", 0xAA64: "ARM64"}.get(machine, hex(machine)),
        "section_count": sections, "sections": names, "timestamp": timestamp,
        "entry_point_rva": entry, "image_base": image_base,
        "subsystem": subsystem, "is_dll": bool(characteristics & 0x2000),
        "pe32_plus": magic == 0x20B
    }


def inspect_elf(path: Path) -> dict[str, Any]:
    ident = _read_exact(path, 0, 16)
    if ident[:4] != b"\x7fELF":
        raise ValueError("Not an ELF executable")
    elf_class, encoding = ident[4], ident[5]
    if elf_class not in (1, 2) or encoding not in (1, 2):
        raise ValueError("Unsupported ELF class or byte order")
    header = _read_exact(path, 0, 64 if elf_class == 2 else 52)
    endian = "<" if encoding == 1 else ">"
    is_64 = elf_class == 2
    e_type, machine = struct.unpack_from(endian + "HH", header, 16)
    if is_64:
        entry, phoff, shoff = struct.unpack_from(endian + "QQQ", header, 24)
        flags = struct.unpack_from(endian + "I", header, 48)[0]
        phnum, shnum = struct.unpack_from(endian + "HH", header, 56)
    else:
        entry, phoff, shoff = struct.unpack_from(endian + "III", header, 24)
        flags = struct.unpack_from(endian + "I", header, 36)[0]
        phnum, shnum = struct.unpack_from(endian + "HH", header, 44)
    return {
        "format": "ELF", "class": "64-bit" if is_64 else "32-bit",
        "endianness": "little" if encoding == 1 else "big",
        "type": {1: "relocatable", 2: "executable", 3: "shared_object", 4: "core"}.get(e_type, e_type),
        "machine": {3: "x86", 40: "ARM", 62: "x86_64", 183: "AArch64", 243: "RISC-V"}.get(machine, machine),
        "entry_point": entry, "program_header_offset": phoff,
        "section_header_offset": shoff, "program_header_count": phnum,
        "section_header_count": shnum, "flags": flags
    }


def inspect_macho(path: Path) -> dict[str, Any]:
    magic = _read_exact(path, 0, 4)
    formats = {
        b"\xfe\xed\xfa\xce": (">", False), b"\xce\xfa\xed\xfe": ("<", False),
        b"\xfe\xed\xfa\xcf": (">", True), b"\xcf\xfa\xed\xfe": ("<", True)
    }
    if magic in (b"\xca\xfe\xba\xbe", b"\xbe\xba\xfe\xca", b"\xca\xfe\xba\xbf", b"\xbf\xba\xfe\xca"):
        fat = _read_exact(path, 0, 8)
        return {"format": "Mach-O universal/fat", "fat_header": fat.hex(),
                "note": "Fat binary header detected; slice parsing not yet implemented."}
    if magic not in formats:
        raise ValueError("Not a Mach-O executable")
    endian, is_64 = formats[magic]
    header = _read_exact(path, 0, 32 if is_64 else 28)
    cpu, subtype, filetype, ncmds, sizeofcmds, flags = struct.unpack_from(endian + "IIIIII", header, 4)
    return {"format": "Mach-O", "class": "64-bit" if is_64 else "32-bit",
            "cpu_type": cpu, "cpu_subtype": subtype, "file_type": filetype,
            "load_command_count": ncmds, "load_commands_size": sizeofcmds, "flags": flags}


class BinaryMetadataEngine(AnalysisEngine):
    name = "binary_metadata"
    description = "Reads PE, ELF and Mach-O executable headers without executing the target."
    supported_kinds = {"file"}

    def analyze(self, target: AnalysisTarget, options: dict[str, Any] | None = None) -> EngineResult:
        path = target.path.resolve(strict=True)
        if not path.is_file():
            raise ValueError("Binary metadata engine requires a file")
        with path.open("rb") as stream:
            magic = stream.read(4)
        if magic[:2] == b"MZ":
            facts = inspect_pe(path)
        elif magic == b"\x7fELF":
            facts = inspect_elf(path)
        elif magic in {b"\xfe\xed\xfa\xce", b"\xce\xfa\xed\xfe",
                       b"\xfe\xed\xfa\xcf", b"\xcf\xfa\xed\xfe",
                       b"\xca\xfe\xba\xbe", b"\xbe\xba\xfe\xca",
                       b"\xca\xfe\xba\xbf", b"\xbf\xba\xfe\xca"}:
            facts = inspect_macho(path)
        else:
            return EngineResult(engine=self.name, status="unsupported",
                                summary="File signature is not a supported native executable format.",
                                findings={"format": "unknown"}, confidence=0.0)
        return EngineResult(
            engine=self.name, status="ok",
            summary=f"Read {facts['format']} executable metadata.",
            findings=facts,
            evidence=[Evidence(claim=f"Executable header identifies {facts['format']}",
                              source=str(path), confidence=1.0)],
            confidence=0.99
        )
