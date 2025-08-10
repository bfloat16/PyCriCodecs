#include <pybind11/pybind11.h>
namespace py = pybind11;

static constexpr uint32_t HCA_MASK  = 0x7F7F7F7F;
static constexpr uint16_t SYNC_WORD = 0xFFFF;

static constexpr uint16_t CRC_TABLE[256] = {
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
};

static inline uint16_t crc16_sum(const uint8_t* p, size_t n)
{
    uint16_t s = 0;
    while (n--) {
        s = uint16_t((s << 8) ^ CRC_TABLE[(s >> 8) ^ *p++]);
    }
    return s;
}

static inline std::pair<uint8_t, uint8_t> crc16_tail_bytes(const uint8_t* prefix, size_t n)
{
    const uint16_t s = crc16_sum(prefix, n);
    return {uint8_t(s >> 8), uint8_t(s)};
}

static inline uint16_t be16(const uint8_t* p)
{
    return (uint16_t)((p[0] << 8) | p[1]);
}
static inline uint32_t be24(const uint8_t* p)
{
    return (uint32_t)((p[0] << 16) | (p[1] << 8) | p[2]);
}
static inline uint32_t be32(const uint8_t* p)
{
    return (uint32_t)((p[0] << 24) | (p[1] << 16) | (p[2] << 8) | p[3]);
}

static inline void put_be16(std::vector<uint8_t>& o, uint16_t v)
{
    o.push_back((v >> 8) & 0xFF);
    o.push_back(v & 0xFF);
}
static inline void put_be24(std::vector<uint8_t>& o, uint32_t v)
{
    o.push_back((v >> 16) & 0xFF);
    o.push_back((v >> 8) & 0xFF);
    o.push_back(v & 0xFF);
}
static inline void put_be32(std::vector<uint8_t>& o, uint32_t v)
{
    o.push_back((v >> 24) & 0xFF);
    o.push_back((v >> 16) & 0xFF);
    o.push_back((v >> 8) & 0xFF);
    o.push_back(v & 0xFF);
}

struct HCAHeader
{
    uint16_t version         = 0;
    uint16_t header_size     = 0;
    uint8_t  channels        = 0;
    uint32_t sample_rate     = 0;
    uint32_t frame_count     = 0;
    uint16_t encoder_delay   = 0;
    uint16_t encoder_padding = 0;

    uint16_t frame_size          = 0;
    uint8_t  min_resolution      = 0;
    uint8_t  max_resolution      = 0;
    uint8_t  track_count         = 0;
    uint8_t  channel_config      = 0;
    int      stereo_type         = -1;
    uint8_t  total_band_count    = 0;
    uint8_t  base_band_count     = 0;
    uint8_t  stereo_band_count   = 0;
    uint8_t  bands_per_hfr_group = 0;
    uint8_t  ms_stereo           = 0;

    // Optional
    bool        has_vbr            = false;
    uint16_t    vbr_max_frame_size = 0;
    uint16_t    vbr_noise_level    = 0;
    int         ath_type           = -1;
    bool        has_ath            = false;
    bool        loop_flag          = false;
    uint32_t    loop_start_frame   = 0;
    uint32_t    loop_end_frame     = 0;
    uint16_t    loop_start_delay   = 0;
    uint16_t    loop_end_padding   = 0;
    bool        has_ciph           = false;
    uint16_t    ciph_type          = 0;
    bool        has_rva            = false;
    float       rva_volume         = 0.f;
    bool        has_comm           = false;
    std::string comment;

    size_t data_offset = 0;
    bool   used_comp   = true;
};

static HCAHeader parse_hca_header(const std::vector<uint8_t>& buf)
{
    if (buf.size() < 8)
        throw std::runtime_error("Error: File too small !");
    const uint8_t* p   = buf.data();
    uint32_t       tag = be32(p);
    p += 4;
    if ((tag & HCA_MASK) != 0x48434100)
        throw std::runtime_error("Error: Not encrypted HCA !");
    HCAHeader h{};
    h.version = be16(p);
    p += 2;
    h.header_size = be16(p);
    p += 2;
    if (buf.size() < h.header_size)
        throw std::runtime_error("Error: HCA head is too short !");
    if (crc16_sum(buf.data(), h.header_size) != 0)
        throw std::runtime_error("Error: HCA header CRC failed !");

    // fmt
    tag = be32(p);
    if ((tag & HCA_MASK) != 0x666D7400)
        throw std::runtime_error("Error: HCA missing fmt !");
    p += 4;
    h.channels    = *p++;
    h.sample_rate = be24(p);
    p += 3;
    h.frame_count = be32(p);
    p += 4;
    h.encoder_delay = be16(p);
    p += 2;
    h.encoder_padding = be16(p);
    p += 2;

    // comp / dec
    tag = be32(p);
    if ((tag & HCA_MASK) == 0x636F6D70) {   // comp
        p += 4;
        h.used_comp  = true;
        h.frame_size = be16(p);
        p += 2;
        h.min_resolution      = *p++;
        h.max_resolution      = *p++;
        h.track_count         = *p++;
        h.channel_config      = *p++;
        h.total_band_count    = *p++;
        h.base_band_count     = *p++;
        h.stereo_band_count   = *p++;
        h.bands_per_hfr_group = *p++;
        h.ms_stereo           = *p++;
        p++;   // reserved
    }
    else if ((tag & HCA_MASK) == 0x64656300) {   // dec\0
        p += 4;
        h.used_comp  = false;
        h.frame_size = be16(p);
        p += 2;
        h.min_resolution      = *p++;
        h.max_resolution      = *p++;
        h.total_band_count    = (uint8_t)(*p++ + 1);
        h.base_band_count     = (uint8_t)(*p++ + 1);
        uint8_t tc_cc         = *p++;
        h.track_count         = (tc_cc >> 4) & 0xF;
        h.channel_config      = tc_cc & 0xF;
        h.stereo_type         = *p++;
        h.stereo_band_count   = (h.stereo_type == 0) ? 0 : (h.total_band_count - h.base_band_count);
        h.bands_per_hfr_group = 0;
    }
    else {
        throw std::runtime_error("Error: HCA missing comp/dec !");
    }

    // vbr?
    tag = be32(p);
    if ((tag & HCA_MASK) == 0x76627200) {
        p += 4;
        h.has_vbr            = true;
        h.vbr_max_frame_size = be16(p);
        p += 2;
        h.vbr_noise_level = be16(p);
        p += 2;
        tag = be32(p);
    }

    // ath?
    if ((tag & HCA_MASK) == 0x61746800) {
        p += 4;
        h.has_ath  = true;
        h.ath_type = be16(p);
        p += 2;
        tag = be32(p);
    }
    else {
        h.ath_type = (h.version < 0x0200) ? 1 : 0;
    }

    // loop?
    if ((tag & HCA_MASK) == 0x6C6F6F70) {
        p += 4;
        h.loop_flag        = true;
        h.loop_start_frame = be32(p);
        p += 4;
        h.loop_end_frame = be32(p);
        p += 4;
        h.loop_start_delay = be16(p);
        p += 2;
        h.loop_end_padding = be16(p);
        p += 2;
        tag = be32(p);
    }

    // ciph?
    if ((tag & HCA_MASK) == 0x63697068) {
        p += 4;
        h.has_ciph  = true;
        h.ciph_type = be16(p);
        p += 2;
        tag = be32(p);
    }
    else {
        h.ciph_type = 0;
    }

    // rva?
    if ((tag & HCA_MASK) == 0x72766100) {
        p += 4;
        uint32_t u = be32(p);
        p += 4;
        float f;
        std::memcpy(&f, &u, 4);
        h.has_rva    = true;
        h.rva_volume = f;
        tag          = be32(p);
    }

    // comm?
    if ((tag & HCA_MASK) == 0x636F6D6D) {
        p += 4;
        h.has_comm   = true;
        uint8_t clen = *p++;
        h.comment.assign((const char*)p, (const char*)p + clen);
        p += clen;
        tag = be32(p);
    }

    // pad?
    if ((tag & HCA_MASK) == 0x70616400) {
        size_t used      = (size_t)(p - buf.data());
        size_t pad_bytes = (h.header_size - 2) - used;
        p += pad_bytes;
    }
    else {
        // Without pad, p points to the end before the last CRC (2 bytes)
    }

    h.data_offset = h.header_size;
    return h;
}

static std::vector<uint8_t> build_plain_header_bytes(const HCAHeader& s)
{
    std::vector<uint8_t> chunks;

    // fmt
    chunks.insert(chunks.end(), {'f', 'm', 't', 0x00});
    chunks.push_back(s.channels);
    put_be24(chunks, s.sample_rate);
    put_be32(chunks, s.frame_count);
    put_be16(chunks, s.encoder_delay);
    put_be16(chunks, s.encoder_padding);

    // comp / dec
    if (s.used_comp) {
        chunks.insert(chunks.end(), {'c', 'o', 'm', 'p'});
        put_be16(chunks, s.frame_size);
        chunks.push_back(s.min_resolution);
        chunks.push_back(s.max_resolution);
        chunks.push_back(s.track_count);
        chunks.push_back(s.channel_config);
        chunks.push_back(s.total_band_count);
        chunks.push_back(s.base_band_count);
        chunks.push_back(s.stereo_band_count);
        chunks.push_back(s.bands_per_hfr_group);
        chunks.push_back(s.ms_stereo);
        chunks.push_back(0x00);   // reserved
    }
    else {
        chunks.insert(chunks.end(), {'d', 'e', 'c', 0x00});
        put_be16(chunks, s.frame_size);
        chunks.push_back(s.min_resolution);
        chunks.push_back(s.max_resolution);
        chunks.push_back((uint8_t)(s.total_band_count - 1));
        chunks.push_back((uint8_t)(s.base_band_count - 1));
        chunks.push_back((uint8_t)(((s.track_count & 0xF) << 4) | (s.channel_config & 0xF)));
        chunks.push_back((uint8_t)((s.stereo_type < 0) ? 0 : s.stereo_type));
    }

    // vbr
    if (s.has_vbr) {
        chunks.insert(chunks.end(), {'v', 'b', 'r', 0x00});
        put_be16(chunks, s.vbr_max_frame_size);
        put_be16(chunks, s.vbr_noise_level);
    }

    if (s.has_ath) {
        chunks.insert(chunks.end(), {'a', 't', 'h', 0x00});
        put_be16(chunks, (uint16_t)s.ath_type);
    }

    if (s.loop_flag) {
        chunks.insert(chunks.end(), {'l', 'o', 'o', 'p'});
        put_be32(chunks, s.loop_start_frame);
        put_be32(chunks, s.loop_end_frame);
        put_be16(chunks, s.loop_start_delay);
        put_be16(chunks, s.loop_end_padding);
    }

    if (s.has_ciph) {
        chunks.insert(chunks.end(), {'c', 'i', 'p', 'h'});
        put_be16(chunks, 0);   // Set to 0 (plain text)
    }

    if (s.has_rva) {
        chunks.insert(chunks.end(), {'r', 'v', 'a', 0x00});
        uint32_t u;
        std::memcpy(&u, &s.rva_volume, 4);
        put_be32(chunks, u);
    }

    if (s.has_comm && !s.comment.empty()) {
        chunks.insert(chunks.end(), {'c', 'o', 'm', 'm'});
        chunks.push_back((uint8_t)std::min<size_t>(255, s.comment.size()));
        chunks.insert(chunks.end(), s.comment.begin(), s.comment.begin() + std::min<size_t>(255, s.comment.size()));
    }

    // base + CRC
    std::vector<uint8_t> out;
    out.insert(out.end(), {'H', 'C', 'A', 0x00});
    put_be16(out, s.version);
    uint16_t header_size = (uint16_t)(8 + chunks.size() + 2);
    put_be16(out, header_size);
    out.insert(out.end(), chunks.begin(), chunks.end());
    auto tail = crc16_tail_bytes(out.data(), out.size());
    out.push_back(tail.first);
    out.push_back(tail.second);
    return out;
}

static std::array<uint8_t, 256> cipher_init0()
{
    std::array<uint8_t, 256> t{};
    for (int i = 0; i < 256; ++i)
        t[i] = (uint8_t)i;
    return t;
}
static std::array<uint8_t, 256> cipher_init1()
{
    std::array<uint8_t, 256> t{};
    t[0]    = 0;
    t[0xFF] = 0xFF;
    int mul = 13, add = 11;
    int v = 0;
    for (int i = 1; i < 255; ++i) {
        v = (v * mul + add) & 0xFF;
        if (v == 0 || v == 0xFF)
            v = (v * mul + add) & 0xFF;
        t[i] = (uint8_t)v;
    }
    return t;
}
static void cipher_init56_create_table(uint8_t key_byte, uint8_t out16[16])
{
    int     mul = ((key_byte & 1) << 3) | 5;
    int     add = (key_byte & 0xE) | 1;
    uint8_t key = (key_byte >> 4) & 0xF;
    for (int i = 0; i < 16; ++i) {
        key      = (uint8_t)((key * mul + add) & 0xF);
        out16[i] = key;
    }
}
static std::array<uint8_t, 256> cipher_init56(uint64_t keycode_low56)
{
    if (keycode_low56 != 0)
        keycode_low56 = (keycode_low56 - 1) & ((1ULL << 56) - 1);
    uint8_t kc[8]{};
    for (int i = 0; i < 7; ++i) { // Only 7 bytes
        kc[i] = (uint8_t)(keycode_low56 & 0xFF);
        keycode_low56 >>= 8;
    }

    uint8_t seed[16]{};
    seed[0x00] = kc[1];
    seed[0x01] = kc[1] ^ kc[6];
    seed[0x02] = kc[2] ^ kc[3];
    seed[0x03] = kc[2];
    seed[0x04] = kc[2] ^ kc[1];
    seed[0x05] = kc[3] ^ kc[4];
    seed[0x06] = kc[3];
    seed[0x07] = kc[3] ^ kc[2];
    seed[0x08] = kc[4] ^ kc[5];
    seed[0x09] = kc[4];
    seed[0x0A] = kc[4] ^ kc[3];
    seed[0x0B] = kc[5] ^ kc[6];
    seed[0x0C] = kc[5];
    seed[0x0D] = kc[5] ^ kc[4];
    seed[0x0E] = kc[6] ^ kc[1];
    seed[0x0F] = kc[6];

    uint8_t base_r[16];
    cipher_init56_create_table(kc[0], base_r);
    uint8_t base[256]{};
    for (int r = 0; r < 16; ++r) {
        uint8_t base_c[16];
        cipher_init56_create_table(seed[r], base_c);
        uint8_t nb = (uint8_t)((base_r[r] & 0xF) << 4);
        for (int c = 0; c < 16; ++c)
            base[r * 16 + c] = nb | (base_c[c] & 0xF);
    }

    std::array<uint8_t, 256> t{};
    t[0]    = 0;
    t[0xFF] = 0xFF;
    int pos = 1, x = 0;
    for (int i = 0; i < 256; ++i) {
        x          = (x + 17) & 0xFF;
        uint8_t bx = base[x];
        if (bx != 0 && bx != 0xFF) {
            if (pos < 0xFF) {
                t[pos] = bx;
                ++pos;
            }
        }
    }
    return t;
}
static std::array<uint8_t, 256> build_cipher_table(uint16_t ciph_type, uint64_t key_low56)
{
    if (ciph_type == 56 && key_low56 == 0)
        ciph_type = 0;
    if (ciph_type == 0)
        return cipher_init0();
    if (ciph_type == 1)
        return cipher_init1();
    if (ciph_type == 56)
        return cipher_init56(key_low56);
    throw std::runtime_error("Error: Unsupported ciph type !");
}

static inline uint64_t combine_keycode_with_subkey(uint64_t keycode, uint64_t subkey)
{
    uint64_t subkey64 = subkey & 0xFFFFFFFFFFFFFFFFULL;
    uint64_t hi       = (subkey64 << 16);
    uint64_t lo       = ((~subkey64) + 2ULL) & 0xFFFFULL;   // (uint16_t)~subkey + 2
    uint64_t factor   = hi | lo;
    uint64_t new_key  = (keycode * factor) & ((1ULL << 56) - 1);
    return new_key;
}

static std::vector<uint8_t> decrypt_hca_to_plain_bytes(const std::vector<uint8_t>& in_bytes, uint64_t mainkey, py::object py_subkey)
{
    HCAHeader H = parse_hca_header(in_bytes);

    uint64_t effective_key = mainkey & ((1ULL << 56) - 1);
    if (!py_subkey.is_none()) {
        uint64_t subkey = py_subkey.cast<uint64_t>();
        effective_key   = combine_keycode_with_subkey(effective_key, subkey);
    }

    auto                 table = build_cipher_table(H.ciph_type, effective_key);
    std::vector<uint8_t> out   = build_plain_header_bytes(H);

    size_t off = H.data_offset;
    size_t fsz = H.frame_size;
    for (uint32_t i = 0; i < H.frame_count; ++i) {
        if (off + fsz > in_bytes.size())
            break;
        std::vector<uint8_t> frame(in_bytes.begin() + off, in_bytes.begin() + off + fsz);

        for (size_t j = 0; j < frame.size(); ++j)
            frame[j] = table[frame[j]];

        auto tail               = crc16_tail_bytes(frame.data(), frame.size() - 2);
        frame[frame.size() - 2] = tail.first;
        frame[frame.size() - 1] = tail.second;

        out.insert(out.end(), frame.begin(), frame.end());
        off += fsz;
    }
    const size_t new_hdr_sz = (out.size() >= 8) ? (size_t)((out[6] << 8) | out[7]) : 0;
    if (crc16_sum(out.data(), new_hdr_sz) != 0) {
        throw std::runtime_error("Error: Header CRC not zero after rebuild (post-build check)");
    }

    return out;
}

PYBIND11_MODULE(hcadecrypt, m)
{
    m.doc() = "HCA decryptor (no audio decode): decrypt to ciph=0 and rebuild CRCs";

    // Python: decrypt(data: bytes, mainkey: int, subkey: Optional[int]) -> bytes
    m.def("decrypt", [](py::bytes data, uint64_t mainkey, py::object subkey) -> py::bytes {
              std::string in = data;
              std::vector<uint8_t> buf(in.begin(), in.end());
              auto out = decrypt_hca_to_plain_bytes(buf, mainkey, subkey);
              return py::bytes(reinterpret_cast<const char*>(out.data()), out.size()); }, py::arg("data"), py::arg("mainkey"), py::arg("subkey") = py::none(),
          R"pbdoc(
Decrypt an HCA file (bytes) to a new HCA with ciph=0, rebuilding header & per-frame CRCs.

Args:
  data:    original .hca file content (bytes)
  mainkey: base keycode (int)
  subkey:  optional subkey (int); combined as: key' = key * (((subkey<<16) | ((~subkey+2)&0xFFFF))) then low 56 bits

Returns:
  bytes of the decrypted .hca file
)pbdoc");
}