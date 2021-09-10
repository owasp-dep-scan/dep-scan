import lief
from lief import ELF, MachO


def parse_desc(e):
    return "{:02x}".format(e)


def is_shared_library(parsed_obj):
    if parsed_obj.format == lief.EXE_FORMATS.ELF:
        return parsed_obj.header.file_type == lief.ELF.E_TYPE.DYNAMIC
    elif parsed_obj.format == lief.EXE_FORMATS.PE:
        return parsed_obj.header.has_characteristic(lief.PE.HEADER_CHARACTERISTICS.DLL)
    elif parsed_obj.format == lief.EXE_FORMATS.MACHO:
        return parsed_obj.header.file_type == lief.MachO.FILE_TYPES.DYLIB
    return False


def parse_notes(parsed_obj):
    metadata = {"notes": []}
    notes = parsed_obj.notes
    if len(notes):
        for idx, note in enumerate(notes):
            description = note.description
            description_str = " ".join(map(parse_desc, description[:16]))
            if len(description) > 16:
                description_str += " ..."
            type_str = note.type_core if note.is_core else note.type
            type_str = str(type_str).split(".")[-1]
            note_details = note.details
            note_details_str = ""
            sdk_version = ""
            ndk_version = ""
            ndk_build_number = ""
            abi = ""
            version_str = ""
            if type(note_details) == lief.ELF.AndroidNote:
                sdk_version = note_details.sdk_version
                ndk_version = note_details.ndk_version
                ndk_build_number = note_details.ndk_build_number
            if type(note_details) == lief.ELF.NoteAbi:
                version = note_details.version
                abi = str(note_details.abi)
                version_str = "{:d}.{:d}.{:d}".format(
                    version[0], version[1], version[2]
                )
            if note.is_core:
                note_details_str = note.details
            metadata["notes"].append(
                {
                    "description": str(description_str),
                    "type": type_str,
                    "details": note_details_str,
                    "sdk_version": sdk_version,
                    "ndk_version": ndk_version,
                    "ndk_build_number": ndk_build_number,
                    "abi": abi,
                    "version": version_str,
                }
            )
    return metadata["notes"]


def parse_uuid(e):
    return "{:02x}".format(e)


def parse_relro(parsed_obj):
    bind_now = False
    now = False
    try:
        parsed_obj.get(lief.ELF.SEGMENT_TYPES.GNU_RELRO)
    except lief.not_found:
        return "no"
    try:
        bind_now = lief.ELF.DYNAMIC_FLAGS.BIND_NOW in parsed_obj.get(
            lief.ELF.DYNAMIC_TAGS.FLAGS
        )
    except lief.not_found:
        pass
    try:
        now = lief.ELF.DYNAMIC_FLAGS_1.NOW in parsed_obj.get(
            lief.ELF.DYNAMIC_TAGS.FLAGS_1
        )
    except lief.not_found:
        pass
    if bind_now or now:
        return "full"
    else:
        return "partial"


def parse(exe_file):
    """
    Parse the executable using lief and capture the metadata

    :param: exe_file Binary file
    :return Metadata dict
    """
    metadata = {}
    try:
        parsed_obj = lief.parse(exe_file)
        metadata["is_shared_library"] = is_shared_library(parsed_obj)
        # ELF Binary
        if isinstance(parsed_obj, ELF.Binary):
            header = parsed_obj.header
            identity = header.identity
            eflags_str = ""
            if header.machine_type == lief.ELF.ARCH.ARM:
                eflags_str = " - ".join(
                    [str(s).split(".")[-1] for s in header.arm_flags_list]
                )
            if header.machine_type in [
                lief.ELF.ARCH.MIPS,
                lief.ELF.ARCH.MIPS_RS3_LE,
                lief.ELF.ARCH.MIPS_X,
            ]:
                eflags_str = " - ".join(
                    [str(s).split(".")[-1] for s in header.mips_flags_list]
                )
            if header.machine_type == lief.ELF.ARCH.PPC64:
                eflags_str = " - ".join(
                    [str(s).split(".")[-1] for s in header.ppc64_flags_list]
                )
            if header.machine_type == lief.ELF.ARCH.HEXAGON:
                eflags_str = " - ".join(
                    [str(s).split(".")[-1] for s in header.hexagon_flags_list]
                )
            metadata["magic"] = "{:<02x} {:<02x} {:<02x} {:<02x}".format(
                identity[0], identity[1], identity[2], identity[3]
            )
            metadata["class"] = str(header.identity_class).split(".")[-1]
            metadata["endianness"] = str(header.identity_data).split(".")[-1]
            metadata["identity_version"] = str(header.identity_version).split(".")[-1]
            metadata["identity_os_abi"] = str(header.identity_os_abi).split(".")[-1]
            metadata["identity_abi_version"] = header.identity_abi_version
            metadata["file_type"] = str(header.file_type).split(".")[-1]
            metadata["machine_type"] = str(header.machine_type).split(".")[-1]
            metadata["object_file_version"] = str(header.object_file_version).split(
                "."
            )[-1]
            metadata["entrypoint"] = header.entrypoint
            metadata["processor_flag"] = str(header.processor_flag) + eflags_str
            metadata["name"] = parsed_obj.name
            metadata["imagebase"] = parsed_obj.imagebase
            metadata["interpreter"] = parsed_obj.interpreter
            metadata["is_pie"] = parsed_obj.is_pie
            metadata["virtual_size"] = parsed_obj.virtual_size
            metadata["has_nx"] = parsed_obj.has_nx
            metadata["relro"] = parse_relro(parsed_obj)
            # Canary check
            canary_sections = ["__stack_chk_fail", "__intel_security_cookie"]
            for section in canary_sections:
                try:
                    if parsed_obj.get_symbol(section):
                        metadata["has_canary"] = True
                except lief.not_found:
                    pass
            # rpath check
            try:
                if parsed_obj.get(lief.ELF.DYNAMIC_TAGS.RPATH):
                    metadata["has_rpath"] = True
            except lief.not_found:
                pass
            # runpath check
            try:
                if parsed_obj.get(lief.ELF.DYNAMIC_TAGS.RUNPATH):
                    metadata["has_runpath"] = True
            except lief.not_found:
                pass
            static_symbols = parsed_obj.static_symbols
            if len(static_symbols):
                metadata["stripped"] = True
            dynamic_entries = parsed_obj.dynamic_entries
            if len(dynamic_entries):
                metadata["dynamic_entries"] = []
                for entry in dynamic_entries:
                    if entry.tag == ELF.DYNAMIC_TAGS.NULL:
                        continue
                    if entry.tag in [
                        ELF.DYNAMIC_TAGS.SONAME,
                        ELF.DYNAMIC_TAGS.NEEDED,
                        ELF.DYNAMIC_TAGS.RUNPATH,
                        ELF.DYNAMIC_TAGS.RPATH,
                    ]:
                        metadata["dynamic_entries"].append(
                            {
                                "name": entry.name,
                                "tag": str(entry.tag).split(".")[-1],
                                "value": entry.value,
                            }
                        )
            try:
                symbols_version = parsed_obj.symbols_version
                if len(symbols_version):
                    metadata["symbols_version"] = []
                    for entry in symbols_version:
                        metadata["symbols_version"].append(
                            {
                                "name": entry.symbol_version_auxiliary,
                                "value": entry.value,
                            }
                        )
            except lief.exception:
                metadata["symbols_version"] = []
            try:
                notes = parsed_obj.notes
                if notes:
                    metadata["notes"] = parse_notes(parsed_obj)
            except lief.exception:
                pass
        elif isinstance(parsed_obj, MachO.Binary):
            metadata["name"] = parsed_obj.name
            metadata["imagebase"] = parsed_obj.imagebase
            metadata["is_pie"] = parsed_obj.is_pie
            metadata["has_nx"] = parsed_obj.has_nx
            try:
                version = parsed_obj.version_min.version
                sdk = parsed_obj.version_min.sdk
                source_version = parsed_obj.source_version.version
                metadata["source_version"] = "{:d}.{:d}.{:d}.{:d}.{:d}".format(
                    *source_version
                )
                metadata["version"] = "{:d}.{:d}.{:d}".format(*version)
                metadata["sdk"] = "{:d}.{:d}.{:d}".format(*sdk)
            except lief.exception:
                pass
            build_version = parsed_obj.build_version
            metadata["platform"] = str(build_version.platform).split(".")[-1]
            metadata["minos"] = "{:d}.{:d}.{:d}".format(*build_version.minos)
            metadata["sdk"] = "{:d}.{:d}.{:d}".format(*build_version.sdk)
            tools = build_version.tools
            if len(tools) > 0:
                metadata["tools"] = []
                for tool in tools:
                    tool_str = str(tool.tool).split(".")[-1]
                    metadata["tools"].append(
                        {"tool": tool_str, "version": "{}.{}.{}".format(*tool.version)}
                    )
            try:
                encryption_info = parsed_obj.encryption_info
                if encryption_info:
                    metadata["encryption_info"] = {
                        "crypt_offset": encryption_info.crypt_offset,
                        "crypt_size": encryption_info.crypt_size,
                        "crypt_id": encryption_info.crypt_id,
                    }
            except lief.exception:
                pass
            try:
                sinfo = parsed_obj.sub_framework
                metadata["umbrella"] = sinfo.umbrella
            except lief.exception:
                pass
            try:
                cmd = parsed_obj.rpath
                metadata["rpath"] = cmd.path
            except lief.exception:
                pass
            try:
                cmd = parsed_obj.uuid
                uuid_str = " ".join(map(parse_uuid, cmd.uuid))
                metadata["uuid"] = str(uuid_str)
            except lief.exception:
                pass
            try:
                if parsed_obj.libraries:
                    metadata["libraries"] = []
                    for library in parsed_obj.libraries:
                        current_version_str = "{:d}.{:d}.{:d}".format(
                            *library.current_version
                        )
                        compatibility_version_str = "{:d}.{:d}.{:d}".format(
                            *library.compatibility_version
                        )
                        metadata["libraries"].append(
                            {
                                "name": library.name,
                                "timestamp": library.timestamp,
                                "version": current_version_str,
                                "compatibility_version": compatibility_version_str,
                            }
                        )
            except lief.exception:
                pass
            try:
                header = parsed_obj.header
                flags_str = " - ".join(
                    [str(s).split(".")[-1] for s in header.flags_list]
                )
                metadata["magic"] = str(header.magic).split(".")[-1]
                metadata["cpu_type"] = str(header.cpu_type).split(".")[-1]
                metadata["cpu_subtype"] = header.cpu_subtype
                metadata["file_type"] = str(header.file_type).split(".")[-1]
                metadata["flags"] = flags_str
                metadata["number_commands"] = header.nb_cmds
                metadata["size_commands"] = header.sizeof_cmds
                metadata["reserved"] = header.reserved
            except lief.exception:
                pass
    except lief.exception as e:
        print(e)
    return metadata
