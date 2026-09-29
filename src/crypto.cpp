// SteamCore - crypto (Linux port of Core/include/steamcore/crypto.cpp)
// AES-256-CBC + zlib pipeline (exact recovered keys from Core.dll), plus
// AES-CTR / AES-CCM / SHA-256 / MD5 / base64 for the stable/beta client.
//
// Original used mbedTLS; this port uses OpenSSL EVP (same AES-256-CBC,
// AES-CTR, AES-CCM behavior).  Keys are byte-for-byte identical, so the
// pipeline is behavior-identical to the original.
#include "steamcore.h"

#include <zlib.h>

#include <cstring>
#include <stdexcept>
#include <string>
#include <vector>

#include <openssl/evp.h>
#include <openssl/types.h>

namespace steamcore {

// Recovered verbatim (hex) from IDA data section.
const std::vector<uint8_t> kVersionKey = {
    0x09, 0x51, 0x3c, 0x19, 0x34, 0xd7, 0xc0, 0xb2, 0x16, 0x4b, 0x57, 0xe2,
    0xc2, 0x66, 0xc4, 0x1d, 0x2e, 0xa1, 0x83, 0x75, 0x1c, 0xc5, 0xe0, 0x1b,
    0xc6, 0x34, 0x2a, 0xdf, 0x98, 0x7d, 0x90, 0x73};
const std::vector<uint8_t> kCoreKey = {
    0x31, 0x4c, 0x20, 0x86, 0x15, 0x05, 0x74, 0xe1, 0x5c, 0xf1, 0x1d, 0x1b,
    0xc1, 0x71, 0x25, 0x1a, 0x47, 0x08, 0x6c, 0x00, 0x26, 0x93, 0x55, 0xcd,
    0x51, 0xc9, 0x3a, 0x42, 0x3c, 0x14, 0x02, 0x94};

namespace {

constexpr size_t kIvLen = 16;
constexpr size_t kTailLen = 4;

std::vector<uint8_t> aes_cbc_dec(const std::vector<uint8_t>& ct,
                                const std::vector<uint8_t>& iv,
                                const std::vector<uint8_t>& key) {
    if (key.size() != 32) throw std::runtime_error("aes setkey_dec (key 32)");
    if (ct.empty()) return {};
    // Match the reference (mbedtls_aes_crypt_cbc): return exactly ct.size() bytes
    // with the PKCS7 padding left in place.  zlib_inflate is self-terminating so
    // the trailing padding is simply never read.
    std::vector<uint8_t> out(ct.size());
    unsigned char iv_copy[16]{};
    memcpy(iv_copy, iv.data(), kIvLen);
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    int fl = 0, fl2 = 0;
    if (!EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, key.data(), iv_copy)) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("aes crypt_cbc init");
    }
    // Keep the padding in place (reference uses raw AES, no auto-stripping).
    EVP_CIPHER_CTX_set_flags(ctx, EVP_CIPH_NO_PADDING);
    if (!EVP_DecryptUpdate(ctx, out.data(), &fl, ct.data(), static_cast<int>(ct.size()))) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("aes crypt_cbc update");
    }
    // With NO_PADDING, Final returns the same count with no extra padding bytes;
    // we just keep fl (which already equals ct.size()).
    (void)EVP_DecryptFinal(ctx, out.data() + fl, &fl2);
    EVP_CIPHER_CTX_free(ctx);
    (void)fl2;
    return out;
}

// Match the reference (mbedtls_aes_crypt_cbc): output ct.size() bytes with
// PKCS7 padding applied.  The caller sizes the zlib-encrypted blob exactly,
// so padding is self-contained within the AES block.
std::vector<uint8_t> aes_cbc_enc(const std::vector<uint8_t>& pt,
                                const std::vector<uint8_t>& iv,
                                const std::vector<uint8_t>& key) {
    if (key.size() != 32) throw std::runtime_error("aes setkey_enc (key 32)");
    // AES-256-CBC + PKCS7: output is padded to a full 16-byte block, which
    // is strictly larger than the input unless the input is already aligned.
    size_t padded_size = ((pt.size() + 15) / 16) * 16;
    std::vector<uint8_t> out(padded_size);
    unsigned char iv_copy[16]{};
    memcpy(iv_copy, iv.data(), kIvLen);
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, key.data(), iv_copy)) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("aes crypt_cbc init");
    }
    // PKCS7 padding (EVP default): Final pads to 16-byte block.
    int fl = 0;
    if (!EVP_EncryptUpdate(ctx, out.data(), &fl, pt.data(), static_cast<int>(pt.size()))) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("aes crypt_cbc update");
    }
    int fl2 = 0;
    if (!EVP_EncryptFinal(ctx, out.data() + fl, &fl2)) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("aes crypt_cbc final");
    }
    out.resize(fl + fl2);
    EVP_CIPHER_CTX_free(ctx);
    return out;
}

std::vector<uint8_t> zlib_inflate_impl(const uint8_t* data, size_t len) {
    z_stream z{};
    inflateInit(&z);
    std::vector<uint8_t> out;
    const size_t chunk = 1 << 16;
    std::vector<uint8_t> buf(chunk);
    z.next_in = const_cast<uint8_t*>(data);
    z.avail_in = static_cast<uInt>(len);
    int ret;
    do {
        z.next_out = buf.data();
        z.avail_out = static_cast<u_int32_t>(chunk);
        ret = inflate(&z, Z_NO_FLUSH);
        if (ret != Z_OK && ret != Z_STREAM_END && ret != Z_BUF_ERROR)
            throw std::runtime_error("zlib inflate");
        out.insert(out.end(), buf.data(), buf.data() + (chunk - z.avail_out));
    } while (ret != Z_STREAM_END && z.avail_in > 0);
    inflateEnd(&z);
    return out;
}

std::vector<uint8_t> zlib_inflate(const uint8_t* data, size_t len,
                                  uint32_t expected) {
    (void)expected;
    return zlib_inflate_impl(data, len);
}

std::vector<uint8_t> zlib_deflate(const std::vector<uint8_t>& in) {
    z_stream z{};
    deflateInit(&z, Z_DEFAULT_COMPRESSION);
    std::vector<uint8_t> out;
    const size_t chunk = 1 << 16;
    std::vector<uint8_t> buf(chunk);
    z.next_in = const_cast<uint8_t*>(in.data());
    z.avail_in = static_cast<uInt>(in.size());
    int ret;
    do {
        z.next_out = buf.data();
        z.avail_out = static_cast<u_int32_t>(chunk);
        ret = deflate(&z, Z_FINISH);
        out.insert(out.end(), buf.data(), buf.data() + (chunk - z.avail_out));
    } while (ret != Z_STREAM_END);
    deflateEnd(&z);
    return out;
}

std::string md5_hex_impl(const uint8_t* data, size_t len) {
    uint8_t out[16]{};
    unsigned int outl = 16;
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(ctx, EVP_md5(), nullptr);
    EVP_DigestUpdate(ctx, data, len);
    EVP_DigestFinal_ex(ctx, out, &outl);
    EVP_MD_CTX_free(ctx);
    static const char* hx = "0123456789abcdef";
    std::string s;
    s.reserve(32);
    for (int i = 0; i < 16; ++i) {
        s.push_back(hx[out[i] >> 4]);
        s.push_back(hx[out[i] & 0xF]);
    }
    return s;
}

std::string sha256_hex_impl(const uint8_t* data, size_t len) {
    uint8_t out[32]{};
    unsigned int outl = 32;
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr);
    EVP_DigestUpdate(ctx, data, len);
    EVP_DigestFinal_ex(ctx, out, &outl);
    EVP_MD_CTX_free(ctx);
    static const char* hx = "0123456789abcdef";
    std::string s;
    s.reserve(64);
    for (int i = 0; i < 32; ++i) {
        s.push_back(hx[out[i] >> 4]);
        s.push_back(hx[out[i] & 0xF]);
    }
    return s;
}

std::string sha1_hex_impl(const uint8_t* data, size_t len) {
    uint8_t out[20]{};
    unsigned int outl = 20;
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(ctx, EVP_sha1(), nullptr);
    EVP_DigestUpdate(ctx, data, len);
    EVP_DigestFinal_ex(ctx, out, &outl);
    EVP_MD_CTX_free(ctx);
    static const char* hx = "0123456789abcdef";
    std::string s;
    s.reserve(40);
    for (int i = 0; i < 20; ++i) {
        s.push_back(hx[out[i] >> 4]);
        s.push_back(hx[out[i] & 0xF]);
    }
    return s;
}

void sha1_impl(const uint8_t* data, size_t len, uint8_t* out20) {
    unsigned int outl = 20;
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(ctx, EVP_sha1(), nullptr);
    EVP_DigestUpdate(ctx, data, len);
    EVP_DigestFinal_ex(ctx, out20, &outl);
    EVP_MD_CTX_free(ctx);
}

static const char* kBase64 =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

std::string b64_encode_impl(const uint8_t* data, size_t len) {
    if (len == 0) return std::string();
    std::string out;
    out.reserve((len + 2) / 3 * 4);
    uint8_t* p = const_cast<uint8_t*>(data);
    size_t remaining = len;
    while (remaining >= 3) {
        out.push_back(kBase64[p[0] >> 2]);
        out.push_back(kBase64[((p[0] & 0x3) << 4) | (p[1] >> 4)]);
        out.push_back(kBase64[((p[1] & 0xF) << 2) | (p[2] >> 6)]);
        out.push_back(kBase64[p[2] & 0x3]);
        p += 3;
        remaining -= 3;
    }
    if (remaining == 1) {
        out.push_back(kBase64[p[0] >> 2]);
        out.push_back(kBase64[(p[0] & 0x3) << 4]);
        out.push_back('=');
        out.push_back('=');
    } else if (remaining == 2) {
        out.push_back(kBase64[p[0] >> 2]);
        out.push_back(kBase64[((p[0] & 0x3) << 4) | (p[1] >> 4)]);
        out.push_back(kBase64[((p[1] & 0xF) << 2)]);
        out.push_back('=');
    }
    return out;
}

}  // namespace (anon)

// ---------------------------------------------------------------------------
// AES-256-CBC + zlib pipeline  (aes256cbc_zlib_* from crypto.cpp)
// ---------------------------------------------------------------------------
// Real wire format (verified against the live /version and a captured
// version.bin, both 688 bytes):
//   [ 16-byte IV ][ AES-256-CBC(  [4-byte LE uncompressed_size] [ zlib stream ]  ) ]
//   i.e. the whole payload after the IV is AES-encrypted; the 4-byte LE
//   size + zlib stream live INSIDE the plaintext.  (This is why the saved
//   version.bin, whose raw[0..3] == 1286 and raw[4] == 0x78, decrypts to
//   a JSON manifest.)
std::vector<uint8_t> aes256cbc_zlib_decrypt(const std::vector<uint8_t>& blob,
                                            const std::vector<uint8_t>& key) {
    if (blob.size() < kIvLen + 1)
        throw std::runtime_error("blob too small");
    std::vector<uint8_t> iv(blob.begin(), blob.begin() + kIvLen);
    size_t ct_len = blob.size() - kIvLen;
    std::vector<uint8_t> ct(blob.begin() + kIvLen, blob.begin() + kIvLen + ct_len);
    std::vector<uint8_t> plaintext = aes_cbc_dec(ct, iv, key);
    // plaintext = [4-byte LE uncompressed_size][zlib stream]
    if (plaintext.size() < kTailLen + 1)
        throw std::runtime_error("decrypted blob too small");
    uint32_t plain_len =
        static_cast<uint32_t>(plaintext[0]) |
        (static_cast<uint32_t>(plaintext[1]) << 8) |
        (static_cast<uint32_t>(plaintext[2]) << 16) |
        (static_cast<uint32_t>(plaintext[3]) << 24);
    std::vector<uint8_t> zstream(plaintext.begin() + kTailLen, plaintext.end());
    return zlib_inflate(zstream.data(), zstream.size(), plain_len);
}

std::vector<uint8_t> aes256cbc_zlib_encrypt(const std::vector<uint8_t>& plain,
                                            const std::vector<uint8_t>& key) {
    std::vector<uint8_t> def = zlib_deflate(plain);
    std::vector<uint8_t> iv(kIvLen, 0);  // original derives IV per-request
    // Plaintext fed to AES = [4-byte LE uncompressed_size][zlib stream].
    std::vector<uint8_t> plaintext;
    plaintext.reserve(kTailLen + def.size());
    {
        uint32_t plain_len = static_cast<uint32_t>(plain.size());
        plaintext.insert(plaintext.end(),
                         reinterpret_cast<const uint8_t*>(&plain_len),
                         reinterpret_cast<const uint8_t*>(&plain_len) + kTailLen);
        plaintext.insert(plaintext.end(), def.begin(), def.end());
    }
    std::vector<uint8_t> ct = aes_cbc_enc(plaintext, iv, key);
    std::vector<uint8_t> out;
    out.reserve(kIvLen + ct.size());
    out.insert(out.end(), iv.begin(), iv.end());
    out.insert(out.end(), ct.begin(), ct.end());
    return out;
}

// ---------------------------------------------------------------------------
// AES-CTR / AES-CCM / SHA / MD5 / base64 (stable + beta)
// ---------------------------------------------------------------------------
namespace crypto {

void aes_ctr_decrypt(const uint8_t* data, size_t len, const uint8_t* key_iv, uint8_t* out) {
    if (len == 0) return;
    int fl = 0;
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx, EVP_aes_128_ctr(), nullptr, key_iv, key_iv + 16);
    EVP_EncryptUpdate(ctx, out, &fl, data, static_cast<int>(len));
    EVP_EncryptFinal(ctx, out + len, &fl);
    EVP_CIPHER_CTX_free(ctx);
}

// AES-CCM 128 (key 16, nonce 12, aad optional, 16-byte auth).
void aes_ccm_decrypt(const uint8_t* data, size_t len, const uint8_t* key,
                     const uint8_t* nonce, const uint8_t* aad, size_t aad_len,
                     uint8_t* tag_out16, uint8_t* out) {
    int fl = 0;
    if (len == 0) {
        if (aad && aad_len) {
            EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
            if (nonce) {
                EVP_EncryptInit_ex(ctx, EVP_aes_128_ccm(), nullptr, key, nonce);
            } else {
                static uint8_t n[12]{};
                EVP_EncryptInit_ex(ctx, EVP_aes_128_ccm(), nullptr, key, n);
            }
            EVP_EncryptUpdate(ctx, nullptr, &fl, aad, static_cast<int>(aad_len));
            EVP_EncryptFinal(ctx, out + len, &fl);
            if (tag_out16 && fl > 0) memcpy(tag_out16, out + len, 16);
            EVP_CIPHER_CTX_free(ctx);
        }
        return;
    }
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (nonce) {
        EVP_DecryptInit_ex(ctx, EVP_aes_128_ccm(), nullptr, key, nonce);
    } else {
        static uint8_t n[12]{};
        EVP_DecryptInit_ex(ctx, EVP_aes_128_ccm(), nullptr, key, n);
    }
    if (aad && aad_len) {
        EVP_DecryptUpdate(ctx, nullptr, &fl, aad, static_cast<int>(aad_len));
    }
    // out must have room for len + 16 (tag appended by Final)
    EVP_DecryptUpdate(ctx, out, &fl, data, static_cast<int>(len));
    EVP_DecryptFinal(ctx, out + len, &fl);
    if (tag_out16) memcpy(tag_out16, out + len, 16);
    EVP_CIPHER_CTX_free(ctx);
}

void sha256(const uint8_t* data, size_t len, uint8_t* out32) {
    unsigned int outl = 32;
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr);
    EVP_DigestUpdate(ctx, data, len);
    EVP_DigestFinal_ex(ctx, out32, &outl);
    EVP_MD_CTX_free(ctx);
}

std::string sha256_hex(const uint8_t* data, size_t len) {
    return sha256_hex_impl(data, len);
}

// Beta channel needs SHA-1 (envelope sKey/data), so expose it here
// using the same OpenSSL EVP approach as sha256/md5.
void sha1(const uint8_t* data, size_t len, uint8_t* out20) {
    sha1_impl(data, len, out20);
}

std::string sha1_hex(const uint8_t* data, size_t len) {
    return sha1_hex_impl(data, len);
}

std::string md5_hex(const uint8_t* data, size_t len) {
    return md5_hex_impl(data, len);
}

std::string base64_encode(const uint8_t* data, size_t len) {
    return b64_encode_impl(data, len);
}

// base64 decoder (returns std::vector<uint8_t>)
std::vector<uint8_t> base64_decode(const char* data, size_t len) {
    std::string in(data, len);
    // Remove whitespace
    std::string clean;
    for (char c : in)
        if (!std::isspace(static_cast<unsigned char>(c)))
            clean.push_back(c);
    static const std::string alphabet =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::vector<uint8_t> out;
    int val = 0;      // accumulated bits (max 24 = 3 bytes worth)
    int bits = 0;     // number of accumulated bits (multiple of 6)
    for (size_t i = 0; i < clean.size(); i++) {
        if (clean[i] == '=') break;  // padding
        size_t pos = alphabet.find(clean[i]);
        if (pos == std::string::npos) continue;  // skip invalid char
        val = (val << 6) | (int)pos;
        bits += 6;
        while (bits >= 8) {
            out.push_back(static_cast<uint8_t>(val >> (bits - 8)));
            val >>= 8;
            bits -= 8;
        }
    }
    return out;
}

// zlib inflate/deflate wrappers (public, take/return std::vector<uint8_t>)
std::vector<uint8_t> zlib_inflate(const std::vector<uint8_t>& compressed) {
    if (compressed.empty()) return std::vector<uint8_t>();
    return zlib_inflate_impl(compressed.data(), compressed.size());
}
std::vector<uint8_t> zlib_inflate(const uint8_t* data, size_t len) {
    if (data == nullptr || len == 0) return std::vector<uint8_t>();
    return zlib_inflate_impl(data, len);
}
}  // namespace crypto
}  // namespace steamcore