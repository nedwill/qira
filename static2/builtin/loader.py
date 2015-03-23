from elftools.elf.elffile import ELFFile
from elftools.elf.sections import SymbolTableSection
from elftools.elf.relocation import RelocationSection
from elftools.common.exceptions import ELFParseError, ELFError
import struct

def get_arch(fb):
  if fb == 0x28:
    return 'arm'
  elif fb == 0xb7:
    return 'aarch64'
  elif fb == 0x3e:
    return 'x86-64'
  elif fb == 0x03:
    return 'i386'
  elif fb == 0x1400:   # big endian...
    return 'ppc'
  elif fb == 0x800:
    return 'mips'


def load_binary(static):
  elf = ELFFile(open(static.path))

  # TODO: replace with elf['e_machine']
  progdat = open(static.path).read(0x20)
  fb = struct.unpack("H", progdat[0x12:0x14])[0]   # e_machine
  static['arch'] = get_arch(fb)
  static['entry'] = elf['e_entry']

  ncount = 0
  try:
    for segment in elf.iter_segments():
      addr = segment['p_vaddr']
      if segment['p_type'] == 'PT_LOAD':
        memsize = segment['p_memsz']
        static.add_memory_chunk(addr, segment.data().ljust(memsize, "\x00"))
  except (ELFParseError, ELFError, OverflowError): #stop processing if ELF is invalid
    print "Error: {} is an invalid ELF file.".format(static.path)
    return

  for section in elf.iter_sections():
    if static.debug >= 1:
      print "** found section", section.name, type(section)

    if isinstance(section, RelocationSection):
      symtable = elf.get_section(section['sh_link'])
      if symtable.is_null():
        continue

      try:
        for rel in section.iter_relocations():
          if isinstance(section, SymbolTableSection):
            symbol = symtable.get_symbol(rel['r_info_sym'])
            if static.debug >= 1: #suppress output for testing
              print "Relocation",rel, symbol.name
            if rel['r_offset'] != 0 and symbol.name != "":
              static[rel['r_offset']]['name'] = "__"+symbol.name
              ncount += 1
      except (ELFParseError, ELFError): #stop processing if ELF is invalid
        print "Error: {} is an invalid ELF file.".format(static.path)
        return

      # hacks for PLT
      # TODO: this is fucking terrible
      if section.name == '.rel.plt' or section.name == '.rela.plt':
        # first symbol is blank
        plt_symbols = []
        for rel in section.iter_relocations():
          symbol = symtable.get_symbol(rel['r_info_sym'])
          plt_symbols.append(symbol.name)

        # does this change?
        PLT_ENTRY_SIZE = 0x10

        for section in elf.iter_sections():
          if section.name == ".plt":
            for name, addr in zip(plt_symbols,
                     range(section['sh_addr'] + PLT_ENTRY_SIZE,
                           section['sh_addr'] + PLT_ENTRY_SIZE + PLT_ENTRY_SIZE*len(plt_symbols),
                           PLT_ENTRY_SIZE)):
              static[addr]['name'] = name
            print plt_symbols, section['sh_addr']


    if isinstance(section, SymbolTableSection):
      try:
        for nsym, symbol in enumerate(section.iter_symbols()):
          #print symbol['st_info'], symbol.name, hex(symbol['st_value'])
          if symbol['st_value'] != 0 and symbol.name != "" and symbol['st_info']['type'] == "STT_FUNC":
            if static.debug >= 1:
              print "Symbol",hex(symbol['st_value']), symbol.name
            static[symbol['st_value']]['name'] = symbol.name
            ncount += 1
      #note here that pyelftools has a bug in iter_symbols for an invalid ELF
      #where it calls get_string on a section that doesn't contain that method
      #I can upstream the bug but pyelftools looks kinda dead.
      except (ELFParseError, ELFError, AttributeError): #stop processing if ELF is invalid
        print "Error: {} is an invalid ELF file.".format(static.path)
        return

    # parse the DynamicSection to get the libraries
    #if isinstance(section, DynamicSection):
  if static.debug >= 1:
    print "** found %d names" % ncount

