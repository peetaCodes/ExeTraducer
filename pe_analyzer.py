import pefile


class PEAnalyzer:
    def __init__(self, pe_path):
        self.pe_path = pe_path
        self.pe = pefile.PE(pe_path)

    def get_imported_apis(self):
        imported = []
        if not hasattr(self.pe, 'DIRECTORY_ENTRY_IMPORT'):
            return imported
        for entry in self.pe.DIRECTORY_ENTRY_IMPORT:
            dll = entry.dll.decode('utf-8')
            for imp in entry.imports:
                func = imp.name.decode('utf-8') if imp.name else f"Ordinal_{imp.ordinal}"
                imported.append((dll, func))
        return imported

    def get_entry_point_rva(self):
        return self.pe.OPTIONAL_HEADER.AddressOfEntryPoint

    def get_section_by_rva(self, rva):
        for section in self.pe.sections:
            if section.contains_rva(rva):
                return section
        return None

    def get_code_at_rva(self, rva, size):
        section = self.get_section_by_rva(rva)
        if not section:
            return None
        offset = rva - section.VirtualAddress
        return section.get_data()[offset:offset + size]
