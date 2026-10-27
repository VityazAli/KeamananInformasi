"""Konfigurasi dan fungsi bantu yang dipakai bersama oleh KDC, Alice, dan Bob."""
import socket
import secrets

from aes_manual import cek_key, decrypt

ID_A = "Alice"
ID_B = "Bob"
SESSION_KEY_LEN = 16      # panjang Ks yang dibuat KDC (16 = AES-128)
PORT_KDC = 9000
PORT_BOB = 9001


class Saluran:
    """Pembungkus socket TCP dengan protokol satu pesan per baris."""

    def __init__(self, sock):
        self.sock = sock
        self.buf = b""

    def kirim(self, teks):
        self.sock.sendall((teks + "\n").encode("ascii", "replace"))

    def terima(self):
        while b"\n" not in self.buf:
            data = self.sock.recv(4096)
            if not data:
                raise ConnectionError("koneksi ditutup oleh lawan bicara")
            self.buf += data
        baris, _, self.buf = self.buf.partition(b"\n")
        return baris.decode("ascii", "replace").strip()

    def tutup(self):
        try:
            self.sock.shutdown(socket.SHUT_RDWR)   # bangunkan thread yang sedang recv
        except OSError:
            pass
        try:
            self.sock.close()
        except OSError:
            pass


def ip_lokal():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("10.255.255.255", 1))     # tidak ada paket yang benar-benar dikirim
        return s.getsockname()[0]
    except OSError:
        try:
            return socket.gethostbyname(socket.gethostname())
        except OSError:
            return "tidak terdeteksi"
    finally:
        s.close()


def nonce():
    return str(secrets.randbelow(90_000_000) + 10_000_000)


def fungsi_f(n):
    """f(N2) pada langkah 5: tambah satu."""
    return str(int(n) + 1)


def minta_key(label):
    while True:
        k = input(label).strip()
        try:
            cek_key(k)
            return k
        except ValueError as e:
            print("  Key ditolak:", e)


def loop_terima(saluran, ks, nama_lawan):
    """Baca pesan chat terenkripsi sampai koneksi putus. Mengembalikan alasan putus."""
    while True:
        try:
            baris = saluran.terima()
        except (ConnectionError, OSError, ValueError) as e:
            return str(e)
        if not baris.startswith("MSG|"):
            continue
        cipher = baris[4:]
        try:
            plain = decrypt(cipher, ks)
        except ValueError as e:
            print("\n[!] Pesan dari %s gagal didekripsi: %s" % (nama_lawan, e))
            continue
        print("\n[%s] cipher (hex): %s" % (nama_lawan, cipher))
        print("[%s] plaintext   : %s" % (nama_lawan, plain))