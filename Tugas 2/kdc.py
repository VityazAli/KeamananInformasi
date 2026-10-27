import argparse
import secrets
import socket
import string
import threading

from aes_manual import encrypt, cek_key
from common import (ID_A, ID_B, PORT_KDC, SESSION_KEY_LEN, Saluran, ip_lokal, minta_key)

kunci = {ID_A: None, ID_B: None}
kunci_lock = threading.Lock()


def buat_session_key(panjang):
    abjad = string.ascii_letters + string.digits      # semua karakter ASCII yang aman
    return "".join(secrets.choice(abjad) for _ in range(panjang))


def layani(conn, alamat):
    sal = Saluran(conn)
    try:
        conn.settimeout(10)
        baris = sal.terima()
        print("\n[KDC] koneksi dari %s:%d" % alamat)
        print("[STEP 1] Alice -> KDC : %s" % baris)
        bagian = baris.split("|")
        if len(bagian) != 4 or bagian[0] != "REQ":
            sal.kirim("ERR|format permintaan salah")
            return
        _, id_a, id_b, n1 = bagian
        with kunci_lock:
            ka, kb = kunci.get(id_a), kunci.get(id_b)
        if ka is None or kb is None:
            sal.kirim("ERR|ID tidak dikenal")
            print("[KDC] ditolak, ID tidak dikenal: %s / %s" % (id_a, id_b))
            return

        ks = buat_session_key(SESSION_KEY_LEN)
        tiket_plain = "%s|%s" % (ks, id_a)
        tiket = encrypt(tiket_plain, kb)                    # E(Kb, [Ks || ID_A])
        isi_plain = "%s|%s|%s|%s" % (ks, id_b, n1, tiket)   # Ks || ID_B || N1 || tiket
        balasan = encrypt(isi_plain, ka)                    # E(Ka, [...])

        print("[KDC] Ks dibuat            : %s" % ks)
        print("[KDC] tiket plaintext      : %s" % tiket_plain)
        print("[KDC] tiket (hex, pakai Kb): %s" % tiket)
        print("[KDC] isi plaintext        : %s" % isi_plain)
        print("[STEP 2] KDC -> Alice : E(Ka, [Ks||ID_B||N1||E(Kb,[Ks||ID_A])])")
        print("         cipher (hex)  : %s" % balasan)
        sal.kirim("RESP|" + balasan)
    except Exception as e:
        print("[KDC] error saat melayani klien: %s" % e)
    finally:
        sal.tutup()


def dengarkan(srv):
    while True:
        conn, alamat = srv.accept()
        threading.Thread(target=layani, args=(conn, alamat), daemon=True).start()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=PORT_KDC)
    args = ap.parse_args()

    print("=== KDC ===")
    print("IP perangkat ini :", ip_lokal())
    print("Port             :", args.port)
    kunci[ID_A] = minta_key("Key Alice (Ka), 16/24/32 karakter: ")
    kunci[ID_B] = minta_key("Key Bob   (Kb), 16/24/32 karakter: ")

    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("0.0.0.0", args.port))
    srv.listen(5)
    threading.Thread(target=dengarkan, args=(srv,), daemon=True).start()
    print("KDC siap. Ketik 'help' untuk daftar perintah.\n")

    while True:
        try:
            baris = input("KDC> ").strip()
        except (EOFError, KeyboardInterrupt):
            break
        if not baris:
            continue
        cmd, _, arg = baris.partition(" ")
        if cmd == "help":
            print("  keys                  tampilkan Ka dan Kb saat ini")
            print("  setkey alice <key>    ganti Ka")
            print("  setkey bob <key>      ganti Kb")
            print("  quit                  keluar")
        elif cmd == "keys":
            with kunci_lock:
                print("  Ka (Alice) = %s" % kunci[ID_A])
                print("  Kb (Bob)   = %s" % kunci[ID_B])
        elif cmd == "setkey":
            nama, _, baru = arg.strip().partition(" ")
            nama = nama.capitalize()
            baru = baru.strip()
            if nama not in kunci:
                print("  pakai: setkey alice <key>  atau  setkey bob <key>")
                continue
            try:
                cek_key(baru)
            except ValueError as e:
                print("  key ditolak:", e)
                continue
            with kunci_lock:
                kunci[nama] = baru
            print("  key %s diganti" % nama)
        elif cmd == "quit":
            break
        else:
            print("  perintah tidak dikenal, ketik 'help'")


if __name__ == "__main__":
    main()