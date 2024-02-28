"""BinaryView for UEFI Terse Executables"""

import glob
import os
import struct
from binaryninja import (
    BinaryView,
    platform,
    SegmentFlag,
    SectionSemantics,
    Symbol,
    SymbolType,
    Type,
)

TERSE_IMAGE_HEADER_SIZE = 40
SECTION_HEADER_SIZE = 40


class TerseExecutableView(BinaryView):
    """Class that implements the BinaryView for Terse Executables"""

    name = "TE"
    long_name = "Terse Executable"

    def __init__(self, data: bytes):
        BinaryView.__init__(self, parent_view=data, file_metadata=data.file)
        self.raw = data
        self.platform = None

    @classmethod
    def is_valid_for_data(cls, data: bytes) -> bool:
        """Determine if the loaded binary is a Terse Executable"""

        if data.length < TERSE_IMAGE_HEADER_SIZE:
            return False

        if data[0:2].decode("utf-8", "replace") != "VZ":
            return False

        return True

    def _set_platform(self, machine_type: int):
        if machine_type == 332:
            self.platform = platform.Platform["efi-x86"]
        elif machine_type == -31132:
            self.platform = platform.Platform["efi-x86_64"]
        elif machine_type == -21916:
            self.platform = platform.Platform["efi-aarch64"]

    def _create_segments(self, image_base: int, num_of_sections: int):
        headers_size = TERSE_IMAGE_HEADER_SIZE + num_of_sections * SECTION_HEADER_SIZE
        self.add_auto_segment(
            image_base, headers_size, 0, headers_size, SegmentFlag.SegmentReadable
        )
        code_region_size = self.raw.length - headers_size
        self.add_auto_segment(
            image_base + headers_size,
            code_region_size,
            headers_size,
            code_region_size,
            SegmentFlag.SegmentReadable
            | SegmentFlag.SegmentWritable
            | SegmentFlag.SegmentExecutable,
        )

    def _create_sections(self, image_base: int, num_of_sections: int):
        base = TERSE_IMAGE_HEADER_SIZE
        for _ in range(0, num_of_sections):
            name = self.raw[base : base + 8].decode("utf-8")
            virtual_size = struct.unpack("<I", self.raw[base + 8 : base + 12])[0]
            virtual_addr = struct.unpack("<I", self.raw[base + 12 : base + 16])[0]

            self.add_auto_section(
                name,
                image_base + virtual_addr,
                virtual_size,
                SectionSemantics.ReadOnlyCodeSectionSemantics,
            )
            base += SECTION_HEADER_SIZE

    def _apply_header_types(self, image_base: int, num_of_sections: int):
        t, name = self.parse_type_string(
            """struct {
             uint32_t VirtualAddress;
             uint32_t Size;
            } EFI_IMAGE_DATA_DIRECTORY;"""
        )
        self.define_type(Type.generate_auto_type_id("efi", name), name, t)

        # TODO: last 4 members should be an EFI_IMAGE_DATA_DIRECTORY[2], but something changed with
        # BN and it is preventing me from using types I've previously defined as part of this BV
        header, name = self.parse_type_string(
            """struct {
             char Signature[2];
             uint16_t Machine;
             uint8_t NumberOfSections;
             uint8_t Subsystem;
             uint16_t StrippedSize;
             uint32_t AddressOfEntryPoint;
             uint32_t BaseOfCode;
             uint64_t ImageBase;
             uint32_t DataDirectory1VirtualAddress;
             uint32_t DataDirectory1Size;
             uint32_t DataDirectory2VirtualAddress;
             uint32_t DataDirectory2Size;
            } EFI_TE_IMAGE_HEADER;"""
        )
        self.define_type(Type.generate_auto_type_id("efi", name), name, header)

        section_header, name = self.parse_type_string(
            """struct {
                char Name[8];
                union {
                    uint32_t  PhysicalAddress;
                    uint32_t  VirtualSize;
                } Misc;
                uint32_t  VirtualAddress;
                uint32_t  SizeOfRawData;
                uint32_t  PointerToRawData;
                uint32_t  PointerToRelocations;
                uint32_t  PointerToLinenumbers;
                uint16_t  NumberOfRelocations;
                uint16_t  NumberOfLinenumbers;
                uint32_t  Characteristics;
            } EFI_IMAGE_SECTION_HEADER;"""
        )

        self.define_type(Type.generate_auto_type_id("efi", name), name, section_header)
        self.define_data_var(image_base, header)
        self.define_auto_symbol(
            Symbol(SymbolType.DataSymbol, image_base, "TEImageHeader")
        )

        for i in range(
            TERSE_IMAGE_HEADER_SIZE,
            num_of_sections * (SECTION_HEADER_SIZE + 1),
            SECTION_HEADER_SIZE,
        ):
            self.define_data_var(image_base + i, section_header)
            self.define_auto_symbol(
                Symbol(
                    SymbolType.DataSymbol,
                    image_base + i,
                    f"TESectionHeader{i-40}",
                )
            )

    def init(self):
        """Load the Terse Executable"""

        machine = struct.unpack("<H", self.raw[2:4])[0]
        self._set_platform(machine)

        stripped_size = struct.unpack("<H", self.raw[6:8])[0]
        header_ofs = stripped_size - TERSE_IMAGE_HEADER_SIZE
        image_base = struct.unpack("<Q", self.raw[16:24])[0]
        num_of_sections = ord(self.raw[4])

        self._create_segments(image_base + header_ofs, num_of_sections)
        self._create_sections(image_base, num_of_sections)
        self._apply_header_types(image_base + header_ofs, num_of_sections)

        entry_addr = struct.unpack("<I", self.raw[8:12])[0] + image_base
        self.add_entry_point(entry_addr)
        _start = self.get_function_at(entry_addr)
        _start.type = (
            "EFI_STATUS ModuleEntryPoint(void * FileHandle, void **PeiServices);"
        )
        return True

    def perform_is_executable(self) -> bool:
        """Terse Executables are executable"""

        return True

    def perform_get_entry_point(self) -> int:
        """Determine the address of the entry point function"""

        image_base = struct.unpack("<Q", self.raw[16:24])[0]
        entry = struct.unpack("<I", self.raw[8:12])[0]
        return image_base + entry

    def perform_get_address_size(self) -> int:
        """Return the address width based on the platform"""

        if self.platform == platform.Platform["efi-x86"]:
            return 4

        return 8  # x86-64 and AArch64


TerseExecutableView.register()
