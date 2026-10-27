"""
AES manual (tanpa library kripto) untuk tugas Keamanan Informasi.
Key 16/24/32 karakter ASCII (AES-128/192/256). Plaintext ASCII, ciphertext hex.
Mode ECB atau CBC dengan padding PKCS7.
"""
import secrets

AES_MODE = "CBC"   # ganti ke "ECB" kalau mau hasil deterministik (gampang dicocokkan ke tool online)
BLOK = 16


# ---------------- Aritmetika GF(2^8) ----------------
def xtime(a):
    a <<= 1
    if a & 0x100:
        a ^= 0x11B          # polinomial x^8 + x^4 + x^3 + x + 1
    return a & 0xFF


def gmul(a, b):
    hasil = 0
    while b:
        if b & 1:
            hasil ^= a
        a = xtime(a)
        b >>= 1
    return hasil


def _bangun_sbox():
    # tabel eksponen/logaritma dengan generator 3, dipakai untuk mencari invers perkalian
    eksp = [0] * 255
    logt = [0] * 256
    x = 1
    for i in range(255):
        eksp[i] = x
        logt[x] = i
        x ^= xtime(x)       # x = x * 3
    sbox = []
    for a in range(256):
        b = 0 if a == 0 else eksp[(255 - logt[a]) % 255]
        s = b
        for k in range(1, 5):
            s ^= ((b << k) | (b >> (8 - k))) & 0xFF    # transformasi affine
        sbox.append(s ^ 0x63)
    return sbox


SBOX = _bangun_sbox()
INV_SBOX = [0] * 256
for _i, _v in enumerate(SBOX):
    INV_SBOX[_v] = _i

MUL = {n: [gmul(x, n) for x in range(256)] for n in (2, 3, 9, 11, 13, 14)}

RCON = [0x00, 0x01]
for _ in range(2, 11):
    RCON.append(xtime(RCON[-1]))


# ---------------- Key expansion ----------------
def expand_key(key_bytes):
    nk = len(key_bytes) // 4          # 4, 6, atau 8 word
    nr = nk + 6                       # 10, 12, atau 14 ronde
    w = [list(key_bytes[4 * i:4 * i + 4]) for i in range(nk)]
    for i in range(nk, 4 * (nr + 1)):
        temp = w[i - 1][:]
        if i % nk == 0:
            temp = temp[1:] + temp[:1]                 # RotWord
            temp = [SBOX[b] for b in temp]             # SubWord
            temp[0] ^= RCON[i // nk]
        elif nk > 6 and i % nk == 4:
            temp = [SBOX[b] for b in temp]
        w.append([w[i - nk][j] ^ temp[j] for j in range(4)])
    round_keys = []
    for r in range(nr + 1):
        rk = []
        for c in range(4):
            rk.extend(w[4 * r + c])
        round_keys.append(rk)
    return round_keys, nr


# ---------------- Transformasi ronde ----------------
# state disimpan sebagai list 16 byte, urutan kolom (indeks = baris + 4 * kolom)
def add_round_key(s, rk):
    for i in range(16):
        s[i] ^= rk[i]


def sub_bytes(s):
    for i in range(16):
        s[i] = SBOX[s[i]]


def inv_sub_bytes(s):
    for i in range(16):
        s[i] = INV_SBOX[s[i]]


def shift_rows(s):
    baru = s[:]
    for r in range(4):
        for c in range(4):
            baru[r + 4 * c] = s[r + 4 * ((c + r) % 4)]
    s[:] = baru


def inv_shift_rows(s):
    baru = s[:]
    for r in range(4):
        for c in range(4):
            baru[r + 4 * ((c + r) % 4)] = s[r + 4 * c]
    s[:] = baru


def mix_columns(s):
    for c in range(4):
        a0, a1, a2, a3 = s[4 * c:4 * c + 4]
        s[4 * c + 0] = MUL[2][a0] ^ MUL[3][a1] ^ a2 ^ a3
        s[4 * c + 1] = a0 ^ MUL[2][a1] ^ MUL[3][a2] ^ a3
        s[4 * c + 2] = a0 ^ a1 ^ MUL[2][a2] ^ MUL[3][a3]
        s[4 * c + 3] = MUL[3][a0] ^ a1 ^ a2 ^ MUL[2][a3]


def inv_mix_columns(s):
    for c in range(4):
        a0, a1, a2, a3 = s[4 * c:4 * c + 4]
        s[4 * c + 0] = MUL[14][a0] ^ MUL[11][a1] ^ MUL[13][a2] ^ MUL[9][a3]
        s[4 * c + 1] = MUL[9][a0] ^ MUL[14][a1] ^ MUL[11][a2] ^ MUL[13][a3]
        s[4 * c + 2] = MUL[13][a0] ^ MUL[9][a1] ^ MUL[14][a2] ^ MUL[11][a3]
        s[4 * c + 3] = MUL[11][a0] ^ MUL[13][a1] ^ MUL[9][a2] ^ MUL[14][a3]


def enc_blok(blok, rks, nr):
    s = list(blok)
    add_round_key(s, rks[0])
    for r in range(1, nr):
        sub_bytes(s)
        shift_rows(s)
        mix_columns(s)
        add_round_key(s, rks[r])
    sub_bytes(s)
    shift_rows(s)
    add_round_key(s, rks[nr])
    return bytes(s)


def dec_blok(blok, rks, nr):
    s = list(blok)
    add_round_key(s, rks[nr])
    for r in range(nr - 1, 0, -1):
        inv_shift_rows(s)
        inv_sub_bytes(s)
        add_round_key(s, rks[r])
        inv_mix_columns(s)
    inv_shift_rows(s)
    inv_sub_bytes(s)
    add_round_key(s, rks[0])
    return bytes(s)


# ---------------- Padding & validasi ----------------
def pad(data):
    n = BLOK - len(data) % BLOK
    return data + bytes([n]) * n


def unpad(data):
    if not data or len(data) % BLOK:
        raise ValueError("panjang ciphertext tidak valid")
    n = data[-1]
    if n < 1 or n > BLOK or data[-n:] != bytes([n]) * n:
        raise ValueError("padding rusak, kemungkinan key salah")
    return data[:-n]


def cek_key(key):
    try:
        kb = key.encode("ascii")
    except UnicodeEncodeError:
        raise ValueError("key harus ASCII") from None
    if len(kb) not in (16, 24, 32):
        raise ValueError("panjang key harus 16, 24, atau 32 karakter (sekarang %d)" % len(kb))
    return kb


# ---------------- API: ASCII <-> HEX ----------------
def encrypt(plaintext, key, mode=None):
    mode = (mode or AES_MODE).upper()
    rks, nr = expand_key(cek_key(key))
    try:
        data = plaintext.encode("ascii")
    except UnicodeEncodeError:
        raise ValueError("plaintext harus ASCII") from None
    data = pad(data)
    if mode == "ECB":
        out = b"".join(enc_blok(data[i:i + 16], rks, nr) for i in range(0, len(data), 16))
    elif mode == "CBC":
        iv = secrets.token_bytes(16)
        prev, out = iv, iv
        for i in range(0, len(data), 16):
            x = bytes(a ^ b for a, b in zip(data[i:i + 16], prev))
            prev = enc_blok(x, rks, nr)
            out += prev
    else:
        raise ValueError("mode harus ECB atau CBC")
    return out.hex()


def decrypt(hex_cipher, key, mode=None):
    mode = (mode or AES_MODE).upper()
    rks, nr = expand_key(cek_key(key))
    try:
        raw = bytes.fromhex(hex_cipher.strip())
    except ValueError:
        raise ValueError("ciphertext bukan hex yang valid") from None
    if mode == "ECB":
        if not raw or len(raw) % 16:
            raise ValueError("panjang ciphertext tidak valid")
        plain = b"".join(dec_blok(raw[i:i + 16], rks, nr) for i in range(0, len(raw), 16))
    elif mode == "CBC":
        if len(raw) < 32 or len(raw) % 16:
            raise ValueError("panjang ciphertext tidak valid")
        prev, plain = raw[:16], b""
        for i in range(16, len(raw), 16):
            blok = raw[i:i + 16]
            d = dec_blok(blok, rks, nr)
            plain += bytes(a ^ b for a, b in zip(d, prev))
            prev = blok
    else:
        raise ValueError("mode harus ECB atau CBC")
    plain = unpad(plain)
    try:
        return plain.decode("ascii")
    except UnicodeDecodeError:
        raise ValueError("hasil dekripsi bukan ASCII, kemungkinan key salah") from None


# ---------------- Uji mandiri ----------------
def _uji_fips197():
    pt = bytes.fromhex("00112233445566778899aabbccddeeff")
    kasus = [
        (16, "69c4e0d86a7b0430d8cdb78070b4c55a"),
        (24, "dda97ca4864cdfe06eaf70a0ec0d7191"),
        (32, "8ea2b7ca516745bfeafc49904b496089"),
    ]
    semua_ok = True
    for panjang, harapan in kasus:
        key = bytes(range(panjang))
        rks, nr = expand_key(key)
        c = enc_blok(pt, rks, nr)
        d = dec_blok(c, rks, nr)
        ok = c.hex() == harapan and d == pt
        semua_ok = semua_ok and ok
        print("AES-%d  hasil: %s  %s" % (panjang * 8, c.hex(), "COCOK" if ok else "SALAH"))
    return semua_ok


if __name__ == "__main__":
    print("=== Uji vektor FIPS-197 ===")
    _uji_fips197()
    print("\n=== Uji interaktif (kosongkan key untuk keluar) ===")
    print("Mode saat ini:", AES_MODE)
    while True:
        k = input("Key (16/24/32 char): ").strip()
        if not k:
            break
        p = input("Plaintext         : ")
        try:
            c = encrypt(p, k)
            print("Ciphertext (hex)  :", c)
            print("Dekripsi balik    :", decrypt(c, k))
        except ValueError as e:
            print("Error:", e)