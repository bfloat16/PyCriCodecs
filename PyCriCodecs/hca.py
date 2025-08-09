# -*- coding: utf-8 -*-
"""
HCA decryptor (no audio decode):
- Parse HCA header
- Build cipher table from ciph type + (keycode, subkey)
- Decrypt every frame to plaintext (equivalent to ciph=0)
- Rebuild per-frame CRC and write a brand-new HCA with ciph=0 and valid header CRC

Key combining rule you asked:
    keycode = keycode * ( ((uint64_t)subkey << 16u) | ((uint16_t)~subkey + 2u) )

Python: treat subkey as 16-bit; the multiplication is done in Python int then we pass
the (low 56 bits) to the cipher initializer.
"""
from __future__ import annotations
from dataclasses import dataclass
from typing import Optional, Iterator, Tuple
import struct
import argparse
import sys
import os

HCA_MASK = 0x7F7F7F7F
SYNC_WORD = 0xFFFF

# ----------------------------
# CRC16 (same table as clHCA)
# ----------------------------
_CRC_TABLE = [
    0x0000,0x8005,0x800F,0x000A,0x801B,0x001E,0x0014,0x8011,0x8033,0x0036,0x003C,0x8039,0x0028,0x802D,0x8027,0x0022,
    0x8063,0x0066,0x006C,0x8069,0x0078,0x807D,0x8077,0x0072,0x0050,0x8055,0x805F,0x005A,0x804B,0x004E,0x0044,0x8041,
    0x80C3,0x00C6,0x00CC,0x80C9,0x00D8,0x80DD,0x80D7,0x00D2,0x00F0,0x80F5,0x80FF,0x00FA,0x80EB,0x00EE,0x00E4,0x80E1,
    0x00A0,0x80A5,0x80AF,0x00AA,0x80BB,0x00BE,0x00B4,0x80B1,0x8093,0x0096,0x009C,0x8099,0x0088,0x808D,0x8087,0x0082,
    0x8183,0x0186,0x018C,0x8189,0x0198,0x819D,0x8197,0x0192,0x01B0,0x81B5,0x81BF,0x01BA,0x81AB,0x01AE,0x01A4,0x81A1,
    0x01E0,0x81E5,0x81EF,0x01EA,0x81FB,0x01FE,0x01F4,0x81F1,0x81D3,0x01D6,0x01DC,0x81D9,0x01C8,0x81CD,0x81C7,0x01C2,
    0x0140,0x8145,0x814F,0x014A,0x815B,0x015E,0x0154,0x8151,0x8173,0x0176,0x017C,0x8179,0x0168,0x816D,0x8167,0x0162,
    0x8123,0x0126,0x012C,0x8129,0x0138,0x813D,0x8137,0x0132,0x0110,0x8115,0x811F,0x011A,0x810B,0x010E,0x0104,0x8101,
    0x8303,0x0306,0x030C,0x8309,0x0318,0x831D,0x8317,0x0312,0x0330,0x8335,0x833F,0x033A,0x832B,0x032E,0x0324,0x8321,
    0x0360,0x8365,0x836F,0x036A,0x837B,0x037E,0x0374,0x8371,0x8353,0x0356,0x035C,0x8359,0x0348,0x834D,0x8347,0x0342,
    0x03C0,0x83C5,0x83CF,0x03CA,0x83DB,0x03DE,0x03D4,0x83D1,0x83F3,0x03F6,0x03FC,0x83F9,0x03E8,0x83ED,0x83E7,0x03E2,
    0x83A3,0x03A6,0x03AC,0x83A9,0x03B8,0x83BD,0x83B7,0x03B2,0x0390,0x8395,0x839F,0x039A,0x838B,0x038E,0x0384,0x8381,
    0x0280,0x8285,0x828F,0x028A,0x829B,0x029E,0x0294,0x8291,0x82B3,0x02B6,0x02BC,0x82B9,0x02A8,0x82AD,0x82A7,0x02A2,
    0x82E3,0x02E6,0x02EC,0x82E9,0x02F8,0x82FD,0x82F7,0x02F2,0x02D0,0x82D5,0x82DF,0x02DA,0x82CB,0x02CE,0x02C4,0x82C1,
    0x8243,0x0246,0x024C,0x8249,0x0258,0x825D,0x8257,0x0252,0x0270,0x8275,0x827F,0x027A,0x826B,0x026E,0x0264,0x8261,
    0x0220,0x8225,0x822F,0x022A,0x823B,0x023E,0x0234,0x8231,0x8213,0x0216,0x021C,0x8219,0x0208,0x820D,0x8207,0x0202,
]

def crc16_sum(data: bytes) -> int:
    s = 0
    for b in data:
        s = ((s << 8) & 0xFFFF) ^ _CRC_TABLE[((s >> 8) ^ b) & 0xFF]
    return s

# quick inversion helper: compute last 2 bytes so that crc(full)==0
from collections import defaultdict
_VAL2IDX = defaultdict(list)
for idx,val in enumerate(_CRC_TABLE):
    _VAL2IDX[val].append(idx)

def crc16_tail_bytes(prefix: bytes) -> tuple[int,int]:
    s = 0
    for b in prefix:
        s = ((s << 8) & 0xFFFF) ^ _CRC_TABLE[((s >> 8) ^ b) & 0xFF]
    # choose x and compute y directly via inverse table
    for x in range(256):
        s1 = ((s << 8) & 0xFFFF) ^ _CRC_TABLE[((s >> 8) ^ x) & 0xFF]
        target = (s1 << 8) & 0xFFFF
        idxs = _VAL2IDX.get(target)
        if idxs:
            idx = idxs[0]
            y = idx ^ (s1 >> 8)
            return x, y
    raise RuntimeError("CRC tail solving failed")

# ----------------------------
# Bitreader
# ----------------------------
class BitReader:
    def __init__(self, data: bytes):
        self.data = data
        self.size_bits = len(data)*8
        self.bit = 0
    def peek(self, n:int) -> int:
        if n == 0 or self.bit + n > self.size_bits:
            return 0
        byte_index = self.bit >> 3
        bit_rem = self.bit & 7
        val = 0
        need = (bit_rem + n + 7) // 8
        chunk = self.data[byte_index: byte_index + min(need, 4)]
        for b in chunk:
            val = (val << 8) | b
        total = len(chunk) * 8
        val &= (0xFFFFFFFF >> bit_rem)
        val >>= (total - bit_rem - n)
        return val
    def read(self, n:int) -> int:
        v = self.peek(n)
        self.bit += n
        return v
    def skip(self, n:int):
        self.bit += n

# ----------------------------
# Cipher tables
# ----------------------------
def _cipher_init0() -> bytes:
    return bytes(range(256))

def _cipher_init1() -> bytes:
    table = bytearray(256)
    table[0] = 0
    table[0xFF] = 0xFF
    mul, add = 13, 11
    v = 0
    for i in range(1, 255):
        v = (v * mul + add) & 0xFF
        if v == 0 or v == 0xFF:
            v = (v * mul + add) & 0xFF
        table[i] = v
    return bytes(table)

def _cipher_init56_create_table(key_byte: int) -> list[int]:
    mul = ((key_byte & 1) << 3) | 5
    add = (key_byte & 0xE) | 1
    key = (key_byte >> 4) & 0xF
    r = []
    for _ in range(16):
        key = (key * mul + add) & 0xF
        r.append(key)
    return r

def _cipher_init56(keycode: int) -> bytes:
    # follow clHCA: if key != 0 then key--
    if keycode != 0:
        keycode = (keycode - 1) & ((1 << 56) - 1)

    kc = [0]*8
    for i in range(7):
        kc[i] = keycode & 0xFF
        keycode >>= 8

    seed = [0]*16
    seed[0x00] = kc[1]
    seed[0x01] = kc[1] ^ kc[6]
    seed[0x02] = kc[2] ^ kc[3]
    seed[0x03] = kc[2]
    seed[0x04] = kc[2] ^ kc[1]
    seed[0x05] = kc[3] ^ kc[4]
    seed[0x06] = kc[3]
    seed[0x07] = kc[3] ^ kc[2]
    seed[0x08] = kc[4] ^ kc[5]
    seed[0x09] = kc[4]
    seed[0x0A] = kc[4] ^ kc[3]
    seed[0x0B] = kc[5] ^ kc[6]
    seed[0x0C] = kc[5]
    seed[0x0D] = kc[5] ^ kc[4]
    seed[0x0E] = kc[6] ^ kc[1]
    seed[0x0F] = kc[6]

    base_r = _cipher_init56_create_table(kc[0])
    base = [0]*256
    for r in range(16):
        base_c = _cipher_init56_create_table(seed[r])
        nb = (base_r[r] & 0xF) << 4
        for c in range(16):
            base[r*16 + c] = nb | (base_c[c] & 0xF)

    table = bytearray(256)
    table[0] = 0
    table[0xFF] = 0xFF
    pos = 1
    x = 0
    for _ in range(256):
        x = (x + 17) & 0xFF
        bx = base[x]
        if bx != 0 and bx != 0xFF:
            if pos < 0xFF:
                table[pos] = bx
                pos += 1
    return bytes(table)

def build_cipher_table(ciph_type: int, keycode: int) -> bytes:
    if ciph_type == 56 and keycode == 0:
        ciph_type = 0
    if ciph_type == 0:
        return _cipher_init0()
    elif ciph_type == 1:
        return _cipher_init1()
    elif ciph_type == 56:
        return _cipher_init56(keycode)
    else:
        raise ValueError(f"Unsupported ciph type: {ciph_type}")

# ----------------------------
# Header parsing
# ----------------------------
@dataclass
class HCAHeader:
    version: int
    header_size: int
    channels: int
    sample_rate: int
    frame_count: int
    encoder_delay: int
    encoder_padding: int
    frame_size: int
    min_resolution: int
    max_resolution: int
    track_count: int
    channel_config: int
    stereo_type: Optional[int]
    total_band_count: int
    base_band_count: int
    stereo_band_count: int
    bands_per_hfr_group: int
    ms_stereo: int
    vbr_max_frame_size: Optional[int]
    vbr_noise_level: Optional[int]
    ath_type: int
    loop_flag: int
    loop_start_frame: int
    loop_end_frame: int
    loop_start_delay: int
    loop_end_padding: int
    ciph_type: int
    rva_volume: Optional[float]
    comment: str
    data_offset: int
    raw_chunks: list

class HCAParseError(Exception): pass

def parse_hca_header(data: bytes) -> HCAHeader:
    if len(data) < 8:
        raise HCAParseError("Too small")
    br = BitReader(data)
    if (br.peek(32) & HCA_MASK) != 0x48434100:
        raise HCAParseError("Not HCA")
    # base
    _ = br.read(32)
    version = br.read(16)
    header_size = br.read(16)
    if len(data) < header_size:
        raise HCAParseError("Short header")
    if crc16_sum(data[:header_size]) != 0:
        raise HCAParseError("Header CRC failed")

    left = header_size - 8
    chunks = []

    # fmt
    if (br.peek(32) & HCA_MASK) != 0x666D7400:
        raise HCAParseError("Missing fmt")
    _ = br.read(32); left -= 4
    channels = br.read(8)
    sample_rate = br.read(24)
    frame_count = br.read(32)
    encoder_delay = br.read(16)
    encoder_padding = br.read(16)
    left -= 12
    chunks.append(("fmt", None))

    # comp/dec
    frame_size=min_resolution=max_resolution=0
    track_count=channel_config=0
    stereo_type=None
    total_band_count=base_band_count=stereo_band_count=0
    bands_per_hfr_group=0
    ms_stereo=0

    nxt = (br.peek(32) & HCA_MASK)
    if nxt == 0x636F6D70:  # comp
        _ = br.read(32); left -= 4
        frame_size = br.read(16)
        min_resolution = br.read(8)
        max_resolution = br.read(8)
        track_count = br.read(8)
        channel_config = br.read(8)
        total_band_count = br.read(8)
        base_band_count = br.read(8)
        stereo_band_count = br.read(8)
        bands_per_hfr_group = br.read(8)
        ms_stereo = br.read(8)
        _ = br.read(8)  # reserved
        left -= 12
        chunks.append(("comp", None))
    elif nxt == 0x64656300:  # dec\0
        _ = br.read(32); left -= 4
        frame_size = br.read(16)
        min_resolution = br.read(8)
        max_resolution = br.read(8)
        total_band_count = br.read(8) + 1
        base_band_count = br.read(8) + 1
        track_count = br.read(4)
        channel_config = br.read(4)
        stereo_type = br.read(8)
        stereo_band_count = total_band_count - base_band_count if stereo_type != 0 else 0
        bands_per_hfr_group = 0
        left -= 8
        chunks.append(("dec", None))
    else:
        raise HCAParseError("Missing comp/dec")

    # vbr?
    vbr_max_frame_size=vbr_noise_level=None
    nxt = (br.peek(32) & HCA_MASK)
    if nxt == 0x76627200:
        _ = br.read(32); left -= 4
        vbr_max_frame_size = br.read(16)
        vbr_noise_level = br.read(16)
        left -= 4
        chunks.append(("vbr", (vbr_max_frame_size, vbr_noise_level)))

    # ath?
    nxt = (br.peek(32) & HCA_MASK)
    if nxt == 0x61746800:
        _ = br.read(32); left -= 4
        ath_type = br.read(16)
        left -= 2
        chunks.append(("ath", ath_type))
    else:
        ath_type = 1 if version < 0x0200 else 0

    # loop?
    loop_flag=0
    loop_start_frame = loop_end_frame = loop_start_delay = loop_end_padding = 0
    nxt = (br.peek(32) & HCA_MASK)
    if nxt == 0x6C6F6F70:
        _ = br.read(32); left -= 4
        loop_start_frame = br.read(32)
        loop_end_frame = br.read(32)
        loop_start_delay = br.read(16)
        loop_end_padding = br.read(16)
        loop_flag = 1
        left -= 12
        chunks.append(("loop", (loop_start_frame, loop_end_frame, loop_start_delay, loop_end_padding)))

    # ciph?
    nxt = (br.peek(32) & HCA_MASK)
    if nxt == 0x63697068:
        _ = br.read(32); left -= 4
        ciph_type = br.read(16)
        left -= 2
        chunks.append(("ciph", ciph_type))
    else:
        ciph_type = 0

    # rva?
    rva_volume=None
    nxt = (br.peek(32) & HCA_MASK)
    if nxt == 0x72766100:
        _ = br.read(32); left -= 4
        u32 = br.read(32)
        rva_volume = struct.unpack(">f", struct.pack(">I", u32))[0]
        left -= 4
        chunks.append(("rva", rva_volume))

    # comm?
    comment=""
    nxt = (br.peek(32) & HCA_MASK)
    if nxt == 0x636F6D6D:
        _ = br.read(32); left -= 4
        clen = br.read(8)
        bs = bytearray()
        for _i in range(clen):
            bs.append(br.read(8))
        comment = bytes(bs).decode("utf-8", errors="replace")
        left -= (1 + clen)
        chunks.append(("comm", comment))

    # pad?
    nxt = (br.peek(32) & HCA_MASK)
    if nxt == 0x70616400:
        _ = br.read(32)
        left = 2
        chunks.append(("pad", None))

    # left should be 2 (crc)
    return HCAHeader(
        version=version, header_size=header_size,
        channels=channels, sample_rate=sample_rate, frame_count=frame_count,
        encoder_delay=encoder_delay, encoder_padding=encoder_padding,
        frame_size=frame_size, min_resolution=min_resolution, max_resolution=max_resolution,
        track_count=track_count, channel_config=channel_config, stereo_type=stereo_type,
        total_band_count=total_band_count, base_band_count=base_band_count, stereo_band_count=stereo_band_count,
        bands_per_hfr_group=bands_per_hfr_group, ms_stereo=ms_stereo,
        vbr_max_frame_size=vbr_max_frame_size, vbr_noise_level=vbr_noise_level,
        ath_type=ath_type, loop_flag=loop_flag, loop_start_frame=loop_start_frame, loop_end_frame=loop_end_frame,
        loop_start_delay=loop_start_delay, loop_end_padding=loop_end_padding,
        ciph_type=ciph_type, rva_volume=rva_volume, comment=comment,
        data_offset=header_size, raw_chunks=chunks
    )

def _pack_u24_be(x:int)->bytes:
    return bytes([(x>>16)&0xFF,(x>>8)&0xFF,x&0xFF])

def build_plain_header_bytes(src: HCAHeader) -> bytes:
    chunks = bytearray()

    # fmt
    chunks += b'fmt\x00'
    chunks.append(src.channels & 0xFF)
    chunks += _pack_u24_be(src.sample_rate)
    chunks += src.frame_count.to_bytes(4,'big')
    chunks += src.encoder_delay.to_bytes(2,'big')
    chunks += src.encoder_padding.to_bytes(2,'big')

    # comp / dec（保持原类型）
    has_comp = any(name == "comp" for name,_ in src.raw_chunks)
    if has_comp:
        chunks += b'comp'
        chunks += src.frame_size.to_bytes(2,'big')
        chunks += bytes([
            src.min_resolution & 0xFF, src.max_resolution & 0xFF,
            src.track_count & 0xFF, src.channel_config & 0xFF,
            src.total_band_count & 0xFF, src.base_band_count & 0xFF,
            src.stereo_band_count & 0xFF, src.bands_per_hfr_group & 0xFF,
            src.ms_stereo & 0xFF, 0x00
        ])
    else:
        chunks += b'dec\x00'
        chunks += src.frame_size.to_bytes(2,'big')
        chunks += bytes([src.min_resolution & 0xFF, src.max_resolution & 0xFF])
        chunks += bytes([(src.total_band_count - 1) & 0xFF, (src.base_band_count - 1) & 0xFF])
        chunks += bytes([((src.track_count & 0xF) << 4) | (src.channel_config & 0xF)])
        chunks += bytes([src.stereo_type or 0])

    # vbr
    if src.vbr_max_frame_size is not None and src.vbr_noise_level is not None:
        chunks += b'vbr\x00'
        chunks += src.vbr_max_frame_size.to_bytes(2,'big')
        chunks += src.vbr_noise_level.to_bytes(2,'big')

    # 只在原文件出现过时才写 ath/loop/rva/comm
    if any(name == "ath" for name,_ in src.raw_chunks):
        chunks += b'ath\x00'
        chunks += src.ath_type.to_bytes(2,'big')

    if src.loop_flag:
        chunks += b'loop'
        chunks += src.loop_start_frame.to_bytes(4,'big')
        chunks += src.loop_end_frame.to_bytes(4,'big')
        chunks += src.loop_start_delay.to_bytes(2,'big')
        chunks += src.loop_end_padding.to_bytes(2,'big')

    if any(name == "ciph" for name,_ in src.raw_chunks):
        chunks += b'ciph'
        chunks += (0).to_bytes(2,'big')

    if src.rva_volume is not None and any(name == "rva" for name,_ in src.raw_chunks):
        chunks += b'rva\x00'
        chunks += struct.pack('>f', src.rva_volume)

    if src.comment and any(name == "comm" for name,_ in src.raw_chunks):
        cb = src.comment.encode('utf-8')
        chunks += b'comm'
        chunks += bytes([len(cb) & 0xFF])
        chunks += cb

    # 重新计算 header_size 与 CRC
    header_size = 8 + len(chunks) + 2
    base = bytearray()
    base += b'HCA\x00'
    base += src.version.to_bytes(2,'big')
    base += header_size.to_bytes(2,'big')
    header_wo_crc = bytes(base + chunks)
    x,y = crc16_tail_bytes(header_wo_crc)
    return header_wo_crc + bytes([x,y])

# ----------------------------
# Key + subkey combine
# ----------------------------
def combine_keycode_with_subkey(keycode: int, subkey: int) -> int:
    subkey64 = subkey & 0xFFFFFFFFFFFFFFFF
    hi = (subkey64 << 16) & 0xFFFFFFFFFFFFFFFF
    lo = ((~subkey64) + 2) & 0xFFFF      # 等价于 (uint16_t)~subkey + 2，再取低16位
    factor = hi | lo                      # uint64 合并
    new_key = (keycode * factor) & ((1 << 56) - 1)   # clHCA 实际只用低56位
    return new_key

# ----------------------------
# Main conversion
# ----------------------------
def decrypt_hca_to_plain(in_path: str, out_path: str, keycode: int, subkey: Optional[int]):
    with open(in_path, 'rb') as f:
        data = f.read()

    header = parse_hca_header(data)

    # derive final key
    effective_key = keycode
    if subkey is not None:
        effective_key = combine_keycode_with_subkey(effective_key, subkey)

    # Build cipher table from source ciph + final key
    table = build_cipher_table(header.ciph_type, effective_key)

    # Build plaintext header (ciph=0), with fresh CRC and data_offset
    out_header = build_plain_header_bytes(header)

    # Iterate frames: decrypt and fix CRC
    frame_size = header.frame_size
    off = header.data_offset
    total = header.frame_count
    out = bytearray()
    out += out_header

    for i in range(total):
        if off + frame_size > len(data):
            # Stop if file is truncated
            break
        frame = bytearray(data[off: off+frame_size])
        # decrypt in place using table
        for j in range(frame_size):
            frame[j] = table[frame[j]]
        # rebuild tail CRC (last 2 bytes)
        tail_x, tail_y = crc16_tail_bytes(frame[:-2])
        frame[-2] = tail_x
        frame[-1] = tail_y
        out += frame
        off += frame_size

    with open(out_path, 'wb') as f:
        f.write(out)

    # quick sanity
    # - header crc must be 0
    assert crc16_sum(out[:len(out_header)]) == 0, "Header CRC not zero"
    # - each frame crc must be 0
    for i in range(total):
        s = len(out_header) + i*frame_size
        e = s + frame_size
        if e > len(out): break
        assert crc16_sum(out[s:e]) == 0, f"Frame {i} CRC not zero"

# ----------------------------
# CLI
# ----------------------------
def _parse_int(x: str) -> int:
    x = x.strip().lower()
    if x.startswith("0x"):
        return int(x, 16)
    return int(x, 10)

if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("--input",   default=r"doc\vo_adv_1001011_000.hca")
    p.add_argument("--output",  default=r"1.hca")
    p.add_argument("--keycode", default=r"0x5F3F")
    p.add_argument("--subkey",  default=r"0x000000000030D9E8")
    args = p.parse_args()

    keycode = _parse_int(args.keycode)
    subkey =  _parse_int(args.subkey)
    decrypt_hca_to_plain(args.input, args.output, keycode, subkey)
    print(f"Done. Wrote: {args.output}")