from pathlib import Path
import os
import struct
import subprocess
import sys
import tempfile

from test_guest_intel_trampolines import elf_loads, main_fixture
from test_guest_module_directories import module_with_symbol


TEXT = (5, 0x1000, 0x1000, 0x100, 0x100, 0x1000)
DATA = (6, 0x2000, 0x2000, 0x800, 0x800, 0x1000)


def reads(*addresses):
    code = bytearray()
    for address in addresses:
        code += b"\x03\x05" if code else b"\x8b\x05"
        code += struct.pack("<i", address - (0x1000 + len(code) + 4))
    return bytes(code) + b"\xc3"


def module(loads, code, size=0x4000):
    image = bytearray(size)
    image[:16] = b"\x7fELF\x02\x01\x01" + bytes(9)
    tags = [(5, 0x2600), (10, 8), (6, 0x2400), (11, 24), (4, 0x2500), (0, 0)]
    headers = [(1, *load) for load in loads] + [(2, 6, 0x2000, 0x2000, len(tags) * 16, len(tags) * 16, 8)]
    struct.pack_into("<HHIQQQIHHHHHH", image, 16, 3, 62, 1, 0, 64, 0, 0, 64, 56, len(headers), 0, 0, 0)
    for index, (kind, flags, offset, address, file_size, memory_size, alignment) in enumerate(headers):
        struct.pack_into("<IIQQQQQQ", image, 64 + index * 56,
                         kind, flags, offset, address, address, file_size, memory_size, alignment)
    for index, tag in enumerate(tags):
        struct.pack_into("<qQ", image, 0x2000 + index * 16, *tag)
    image[0x2600:0x2608] = b"\0Answer\0"
    struct.pack_into("<IBBHQQ", image, 0x2418, 1, 0x12, 0, 1, 0x1000, len(code))
    struct.pack_into("<II", image, 0x2500, 1, 2)
    image[0x1000:0x1000 + len(code)] = code
    struct.pack_into("<I", image, 0x2700, 42)
    return image


def incongruent_offsets():
    image = module_with_symbol(True)
    image[0x400:0x406] = bytes.fromhex("b8 2a 00 00 00 c3")
    return image, "shared#guest"


def shared_page():
    data = (6, 0x2000, 0x2000, 0x780, 0x800, 0x1000)
    image = module([TEXT, data, (4, 0x5800, 0x2800, 0x100, 0x100, 0x1000)], reads(0x2700, 0x27C0), 0x6000)
    image[0x5000:0x5800] = b"\xee" * 0x800
    return image, "Answer#guest"


def zero_fill_at_page_start():
    return module([TEXT, DATA, (6, 0x700, 0x3000, 0, 0x100, 0x100)], reads(0x2700, 0x3080)), "Answer#guest"


def empty_load():
    image = module([TEXT, DATA, (5, 0x3080, 0x1080, 0, 0, 0x1000)], reads(0x2700))
    image[0x3000:0x4000] = b"\xcc" * 0x1000
    return image, "Answer#guest"


def check(relinker, directory, build, native):
    image, symbol = build()
    case = Path(directory) / build.__name__
    modules = case / "sce_module"
    modules.mkdir(parents=True)
    (modules / "provider.prx").write_bytes(image)
    source = case / "input.elf"
    source.write_bytes(main_fixture())
    result = subprocess.run([str(relinker), str(source), str(case / "output.elf")],
                            capture_output=True, text=True, timeout=30)
    assert result.returncode == 0, (build.__name__, result.stdout, result.stderr)
    converted = case / "app0" / "sce_module" / "provider.prx.guest.prx"
    if native:
        run = subprocess.run([sys.executable, __file__, "--load", str(converted), symbol],
                             capture_output=True, text=True, timeout=30)
        assert run.returncode == 0 and run.stdout.strip() == "0x2a", (build.__name__, run.returncode, run.stdout, run.stderr)
    data = converted.read_bytes()
    loads = elf_loads(data)
    assert all((address - offset) % 0x1000 == 0 and memory_size and alignment and alignment % 0x1000 == 0
               for _, _, offset, address, _, _, memory_size, alignment in loads), (build.__name__, loads)
    for index, (_, _, offset, address, *_) in enumerate(loads):
        for _, _, below_offset, below, _, below_file, below_memory, _ in loads[:index]:
            for at in range(max(address - address % 0x1000, below), min(address, below + below_memory)):
                expected = data[below_offset + at - below] if at < below + below_file else 0
                assert data[offset - address + at] == expected, (build.__name__, hex(address), hex(at))


def main():
    if sys.argv[1] == "--load":
        import ctypes
        function = getattr(ctypes.CDLL(sys.argv[2]), sys.argv[3])
        function.restype = ctypes.c_uint32
        print(hex(function()))
        return
    relinker = Path(sys.argv[1]).resolve()
    native = sys.platform == "linux" and os.uname().machine == "x86_64"
    with tempfile.TemporaryDirectory(prefix="anyps5-guest-load-pages-") as directory:
        for build in (incongruent_offsets, shared_page, zero_fill_at_page_start, empty_load):
            check(relinker, directory, build, native)
    print("Linux guest load page tests passed")
    if not native:
        print("Native dlopen execution skipped: Linux x86-64 required")


if __name__ == "__main__":
    main()
