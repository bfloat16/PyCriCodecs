from io import BytesIO, FileIO
from typing import BinaryIO
from struct import iter_unpack
from .chunk import *

class AWB:
    __slots__ = ["stream", "numfiles", "align", "subkey", "version", "ids", "ofs", "filename", "headersize", "id_alignment", "id_intsize"]
    stream: BinaryIO
    numfiles: int
    align: int
    subkey: bytes
    version: int
    ids: list
    ofs: list
    filename: str
    headersize: int
    id_alignment: int

    def __init__(self, stream):
        if type(stream) == str:
            self.stream = FileIO(stream)
            self.filename = stream
        else:
            self.stream = BytesIO(stream)
            self.filename = ""
        self.readheader()
    
    def readheader(self):
        # Reads header.
        magic, self.version, offset_intsize, self.id_intsize, self.numfiles, self.align, self.subkey = AWBChunkHeader.unpack(self.stream.read(AWBChunkHeader.size))
        if magic != b'AFS2':
            raise ValueError("Invalid AWB header.")
        
        # Reads data in the header.
        self.ids = list()
        self.ofs = list()
        for i in iter_unpack(f"<{self.stringtypes(self.id_intsize)}", self.stream.read(self.id_intsize*self.numfiles)):
            self.ids.append(i[0])
        for i in iter_unpack(f"<{self.stringtypes(offset_intsize)}", self.stream.read(offset_intsize*(self.numfiles+1))):
            self.ofs.append(i[0] if i[0] % self.align == 0 else (i[0] + (self.align - (i[0] % self.align))))
        
        # Seeks to files offset.
        self.headersize = 16 + (offset_intsize*(self.numfiles+1)) + (self.id_intsize*self.numfiles)
        if self.headersize % self.align != 0:
            self.headersize = self.headersize + (self.align - (self.headersize % self.align))
        self.stream.seek(self.headersize, 0)

    def extract(self):
        count = 0
        for i in self.getfiles():
            # Apparently AWB's can have many types of files, focusing on HCA's here though. So TODO.
            if self.filename:
                if i.startswith(HCAType.HCA.value) or i.startswith(HCAType.EHCA.value):
                    filename = self.filename.rsplit(".", 1)[0] + "_" + str(count) + ".hca"
                else:
                    raise ValueError("Not HCA.")
                open(filename, "wb").write(i)
                count += 1
            else:
                if i.startswith(HCAType.HCA.value) or i.startswith(HCAType.EHCA.value):
                    open(str(count)+".hca", "wb").write(i)
                else:
                    open(str(count)+".dat", "wb").write(i)
                count += 1

    def getfiles(self):

        for i in range(1, len(self.ofs)):
            data = self.stream.read((self.ofs[i] - self.ofs[i-1]))
            self.stream.seek(self.ofs[i], 0)
            yield data

    def stringtypes(self, intsize: int) -> str:
        if intsize == 1:
            return "B" # Probably impossible.
        elif intsize == 2:
            return "H"
        elif intsize == 4:
            return "I"
        elif intsize == 8:
            return "Q"
        else:
            raise ValueError("Unknown int size.")