from typing import BinaryIO, TypeVar, Type, List
T = TypeVar('T')
from io import BytesIO, FileIO
from struct import unpack, calcsize
from .chunk import *

# FIXME Really awful. Although works.
class UTF:
    """ Use this class to return a dict containing all @UTF chunk information. """
    __slots__ = ["magic", "table_size", "rows_offset", "string_offset", "data_offset", "table_name", "num_columns", "row_length", "num_rows", "stream", "table", "__payload", "encoding"]
    magic: bytes
    table_size: int
    rows_offset: int
    string_offset: int
    data_offset: int
    table_name: int
    num_columns: int
    row_length: int
    num_rows: int
    stream: BinaryIO
    table: dict
    __payload: list
    encoding: str
    def __init__(self, stream):
        if type(stream) == str:
            self.stream = FileIO(stream)
        else:
            self.stream = BytesIO(stream)
        self.magic, self.table_size, self.rows_offset, self.string_offset, self.data_offset, self.table_name, self.num_columns, self.row_length, self.num_rows = UTFChunkHeader.unpack(self.stream.read(UTFChunkHeader.size))
        if self.magic == UTFType.UTF.value:
            self.table = self.read_rows_and_columns()
            pass
        elif self.magic == UTFType.EUTF.value:
            self.stream.seek(0)
            data = memoryview(bytearray(self.stream.read()))
            m = 0x655f
            t = 0x4115
            for i in range(len(data)):
                data[i] ^= (0xFF & m)
                m = (m * t) & 0xFFFFFFFF
            self.stream = BytesIO(bytearray(data))
            self.magic, self.table_size, self.rows_offset, self.string_offset, self.data_offset, self.table_name, self.num_columns, self.row_length, self.num_rows = UTFChunkHeader.unpack(self.stream.read(UTFChunkHeader.size))
            if self.magic != UTFType.UTF.value:
                raise Exception("Decryption error.")
            self.table = self.read_rows_and_columns()
            pass
        else:
            raise ValueError("UTF chunk is not present.")
    
    def read_rows_and_columns(self) -> dict:
        stream = self.stream.read(self.data_offset-0x18)
        stream = BytesIO(stream)
        types = [[], [], [], []]
        target_data = []
        target_constant = []
        target_tuple = []
        for i in range(self.num_columns):
            flag = stream.read(1)[0]
            stflag = flag >> 4
            typeflag = flag & 0xF
            if stflag == 0x1:
                target_constant.append(int.from_bytes(stream.read(4), "big"))
                types[2].append((">"+self.stringtypes(typeflag), typeflag))
            elif stflag == 0x3:
                target_tuple.append((int.from_bytes(stream.read(4), "big"), unpack(">"+self.stringtypes(typeflag), stream.read(calcsize(self.stringtypes(typeflag))))))
                types[1].append((">"+self.stringtypes(typeflag), typeflag))
            elif stflag == 0x5:
                target_data.append(int.from_bytes(stream.read(4), "big"))
                types[0].append((">"+self.stringtypes(typeflag), typeflag))
            elif stflag == 0x7: # Exists in old CPK's.
                # target_tuple.append((int.from_bytes(stream.read(4), "big"), int.from_bytes(stream.read(calcsize(self.stringtypes(typeflag))), "big")))
                # types[3].append((">"+self.stringtypes(typeflag), typeflag))
                raise NotImplementedError("Unsupported 0x70 storage flag.")
            else:
                raise Exception("Unknown storage flag.")
        
        rows  = []
        table = dict()
        for j in range(self.num_rows):
            for i in types[0]:
                rows.append(unpack(i[0], stream.read(calcsize(i[0]))))

        for i in range(4):
            for j in range(len(types[i])):
                types[i][j] = (types[i][j][0][1:], types[i][j][1])
        strings = (stream.read()).split(b'\x00')
        strings_copy = strings[:]
        self.__payload = []
        self.encoding = 'utf-8'
        for i in range(len(strings)):
                try:
                    strings_copy[i] = strings[i].decode("utf-8")
                except:
                    for x in ["shift-jis", "utf-16"]:
                        try:
                            strings_copy[i] = strings[i].decode(x)
                            self.encoding = x
                            # This looks sketchy, but it will always work since @UTF only supports these 3 encodings. 
                            break
                        except:
                            continue
                    else:
                        # Probably useless.
                        raise UnicodeDecodeError(f"String of unknown encoding: {strings[i]}")
        t_t_dict = dict()
        self.table_name = strings_copy[self.finder(self.table_name, strings)]
        UTFTypeValuesList = list(UTFTypeValues)
        for i in range(len(target_constant)):
            if types[2][i][1] not in [0xA, 0xB]:
                val = self.finder(target_constant[i], strings)
                table.setdefault(strings_copy[val], []).append(0)
                t_t_dict.update({strings_copy[val]: (UTFTypeValuesList[types[2][i][1]], None)})
            elif types[2][i][1] == 0xA:
                val = self.finder(target_constant[i], strings)
                table.setdefault(strings_copy[val], []).append("<NULL>")
                t_t_dict.update({strings_copy[val]: (UTFTypeValues.string, "<NULL>")})
            else:
                # Most likely useless, since the code doesn seem to reach here.
                val = self.finder(target_constant[i], strings)
                table.setdefault(strings_copy[val], []).append(b'')
                t_t_dict.update({strings_copy[val]: (UTFTypeValues.bytes, b'')})
        for i in range(len(target_tuple)):
            if types[1][i%(len(types[1]))][1] not in [0xA, 0xB]:
                table.setdefault(strings_copy[self.finder(target_tuple[i][0], strings)], []).append(target_tuple[i][1])
                t_t_dict.update({strings_copy[self.finder(target_tuple[i][0], strings)]: (UTFTypeValuesList[types[1][i%len(types[1])][1]], target_tuple[i][1][0])})
            elif types[1][i%(len(types[1]))][1] == 0xA:
                table.setdefault(strings_copy[self.finder(target_tuple[i][0], strings)], []).append(strings_copy[self.finder(target_tuple[i][1][0], strings)])
                t_t_dict.update({strings_copy[self.finder(target_tuple[i][0], strings)]: (UTFTypeValues.string, strings_copy[self.finder(target_tuple[i][1][0], strings)])})
            else:
                self.stream.seek(self.data_offset+target_tuple[i][1][0]+0x8, 0)
                bin_val = self.stream.read((target_tuple[i][1][1]))
                table.setdefault(strings_copy[self.finder(target_tuple[i][0], strings)], []).append(bin_val)
                t_t_dict.update({strings_copy[self.finder(target_tuple[i][0], strings)]: (UTFTypeValues.bytes, bin_val)})
        temp_dict = dict()
        if len(rows) == 0:
            self.__payload.append(t_t_dict)
        for i in range(len(rows)):
            if types[0][i%(len(types[0]))][1] not in [0xA, 0xB]:
                table.setdefault(strings_copy[self.finder(target_data[i%(len(target_data))], strings)], []).append(rows[i][0])
                temp_dict.update({strings_copy[self.finder(target_data[i%(len(target_data))], strings)]: (UTFTypeValuesList[types[0][i%(len(types[0]))][1]], rows[i][0])})
            elif types[0][i%(len(types[0]))][1] == 0xA:
                table.setdefault(strings_copy[self.finder(target_data[i%(len(target_data))], strings)], []).append(strings_copy[self.finder(rows[i][0], strings)])
                temp_dict.update({strings_copy[self.finder(target_data[i%(len(target_data))], strings)]: (UTFTypeValues.string, strings_copy[self.finder(rows[i][0], strings)])})
            else:
                self.stream.seek(self.data_offset+rows[i][0]+0x8, 0)
                bin_val = self.stream.read((rows[i][1]))
                table.setdefault(strings_copy[self.finder(target_data[i%(len(target_data))], strings)], []).append(bin_val)
                temp_dict.update({strings_copy[self.finder(target_data[i%(len(target_data))], strings)]: (UTFTypeValues.bytes, bin_val)})
            if not (i+1)%(len(types[0])):
                temp_dict.update(t_t_dict)
                self.__payload.append(temp_dict)
                temp_dict = dict()
        return table
    
    def stringtypes(self, type: int) -> str:
        types = "BbHhIiQqfdI"
        if type != 0xB:
            return types[type]
        elif type == 0xB:
            return("II")
        else:
            raise Exception("Unkown data type.")

    def finder(self, pointer, strings) -> int:
        sum = 0
        for i in range(len(strings)):
            if sum < pointer:
                sum += len(strings[i]) + 1
                continue
            return i
        else:
            raise Exception("Failed string lookup.")
    
    def get_payload(self) -> list:
        """ Returns list of dictionaries used in the UTF. """
        # I am a noob, but I want to standardize the table output to Donmai WannaCri's payload type.
        # Since my table parser has a different approach (an awful one at that),
        # (And it's integrated with the other tools in this lib specifically),
        # So I can't change it. However this function will return a payload list of Donmai WannaCri's type.
        # And this format can be used to build custom @UTF tables in this lib as well.
        # As for key strings, according to Donmai, they are always in ASCII encoding
        # despite, what seems to me, nothing stopping it for being any of the other 3 encodings,
        # since the header allows it.
        return self.__payload

class UTFViewer(object):
    """Base class for a non-owning view of a UTF table dictionary, or a list of which.
    Nested classes are supported.
    
    Example:
    ```python
        class CueNameTable(UTFViewer):
            CueName : str
            CueIndex : int
        class ACBTable(UTFViewer):
            CueNameTable : List[CueNameTable]
            Awb : AWB

        src = ACB(ACB_sample)
        payload = ACBTable(src.payload)
        name = payload.CueNameTable
        name_str = name[0].CueName
    ```
    """
    _payload : dict
    def __init__(self, payload):
        assert isinstance(payload, dict), "Payload must be a dictionary"
        super().__setattr__('_payload', payload)

    def __getattr__(self, item):
        annotations = super().__getattribute__('__annotations__')
        # Nested definitions
        if item in annotations:
            sub = annotations[item]
            reduced = getattr(sub, "__args__", [None])[0]
            reduced = reduced or sub
            if issubclass(reduced, UTFViewer):
                return self._view_as(self._payload[item], reduced)
        payload = super().__getattribute__('_payload')
        if item not in payload:
            return super().__getattribute__(item)
        _, value = payload[item]
        return value

    def __setattr__(self, item, value):
        payload = super().__getattribute__('_payload')
        if item not in payload:
            raise AttributeError(f"{item} not in payload")
        typeof, _ = payload[item]
        payload[item] = (typeof, value)

    def __dir__(self):
        annotations = super().__getattribute__('__annotations__')
        return list(annotations.keys()) + list(super().__dir__())

    @staticmethod
    def _view_as(payload: dict, clazz: Type[T]) -> T:        
        if not issubclass(clazz, UTFViewer):
            raise TypeError("class must be a subclass of UTFViewer")
        return clazz(payload)

    def __new__(cls: Type[T], payload: list | dict) -> T | List[T]:
        if isinstance(payload, list):
            return [cls._view_as(item, cls) for item in payload]
        return super().__new__(cls)
    