import argparse
import socket
import threading

from aes_manual import encrypt, decrypt, cek_key
from common import (PORT_BOB, ID_A, Saluran, ip_lokal, minta_key, nonce, fungsi_f, loop_terima)

state = {"kb": None, "sal": None, "ks": None}
state_lock = threading.Lock()


def tutup_sesi():
    with state_lock:
        sal = state["sal"]
        state["sal"] = None
        state["ks"] = None
    if sal:
        sal.tutup()


def sesi_baru(conn, alamat):
    sal = Saluran(conn)
    try:
        conn.settimeout(15)
        # ---- langkah 3: tiket dari Alice ----
        baris = sal.terima()
        print("\n[Bob] koneksi dari %s:%d" % alamat)
        print("[STEP 3] Alice -> Bob : %s" % baris)
        if not baris.startswith("TICKET|"):
            raise ValueError("format tiket salah")
        tiket = baris[7:]
        try:
            isi = decrypt(tiket, state["kb"])
        except ValueError:
            raise ValueError("tiket tidak bisa dibuka, Kb Bob tidak sama dengan Kb di KDC") from None
        ks, id_a = isi.split("|", 1)
        cek_key(ks)
        print("[Bob] tiket dibuka   : %s" % isi)
        print("[Bob] session key Ks : %s (dari %s)" % (ks, id_a))

        # ---- langkah 4: Bob kirim E(Ks, N2) ----
        n2 = nonce()
        c4 = encrypt(n2, ks)
        print("[STEP 4] Bob -> Alice : E(Ks, N2)   N2=%s" % n2)
        print("         cipher (hex)  : %s" % c4)
        sal.kirim("N2|" + c4)

        # ---- langkah 5: Alice balas E(Ks, f(N2)) ----
        baris = sal.terima()
        print("[STEP 5] Alice -> Bob : %s" % baris)
        if not baris.startswith("N2F|"):
            raise ValueError("format langkah 5 salah")
        jawab = decrypt(baris[4:], ks)
        print("[Bob] f(N2) dari Alice = %s, harapan = %s" % (jawab, fungsi_f(n2)))
        if jawab != fungsi_f(n2):
            sal.kirim("FAIL|f(N2) salah")
            raise ValueError("f(N2) tidak cocok")
        sal.kirim("ACK|OK")
    except Exception as e:
        print("[Bob] distribusi key GAGAL: %s" % e)
        try:
            sal.kirim("FAIL|%s" % e)
        except OSError:
            pass
        sal.tutup()
        return

    conn.settimeout(None)
    tutup_sesi()                       # kalau ada sesi lama, ganti dengan yang baru
    with state_lock:
        state["sal"], state["ks"] = sal, ks
    print("\n[Bob] sesi aman terbentuk dengan %s. Silakan chat (AES, Ks=%s)." % (id_a, ks))

    alasan = loop_terima(sal, ks, "Alice")
    with state_lock:
        masih_aktif = state["sal"] is sal
    if masih_aktif:
        tutup_sesi()
        print("\n[Bob] sesi berakhir (%s)" % alasan)


def dengarkan(port):
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("0.0.0.0", port))
    srv.listen(5)
    while True:
        conn, alamat = srv.accept()
        threading.Thread(target=sesi_baru, args=(conn, alamat), daemon=True).start()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=PORT_BOB)
    args = ap.parse_args()

    print("=== BOB ===")
    print("IP perangkat ini :", ip_lokal())
    print("Port             :", args.port)
    state["kb"] = minta_key("Key Bob (Kb), 16/24/32 karakter: ")
    threading.Thread(target=dengarkan, args=(args.port,), daemon=True).start()
    print("Bob menunggu Alice. Ketik /help untuk perintah, teks biasa = kirim pesan.\n")

    while True:
        try:
            teks = input("Bob> ")
        except (EOFError, KeyboardInterrupt):
            break
        if not teks.strip():
            continue
        if teks.startswith("/"):
            cmd, _, arg = teks.partition(" ")
            if cmd == "/help":
                print("  /setkey <key>   ganti Kb (harus sama dengan Kb di KDC)")
                print("  /status         lihat key dan sesi saat ini")
                print("  /close          tutup sesi chat")
                print("  /quit           keluar")
            elif cmd == "/setkey":
                try:
                    cek_key(arg.strip())
                    state["kb"] = arg.strip()
                    print("  Kb diganti jadi:", state["kb"])
                except ValueError as e:
                    print("  key ditolak:", e)
            elif cmd == "/status":
                print("  Kb    :", state["kb"])
                print("  Ks    :", state["ks"] or "(belum ada sesi)")
            elif cmd == "/close":
                tutup_sesi()
                print("  sesi ditutup")
            elif cmd == "/quit":
                break
            else:
                print("  perintah tidak dikenal, ketik /help")
            continue

        with state_lock:
            sal, ks = state["sal"], state["ks"]
        if not sal:
            print("  belum ada sesi dengan Alice")
            continue
        try:
            c = encrypt(teks, ks)
            sal.kirim("MSG|" + c)
            print("[kirim] plaintext   : %s" % teks)
            print("[kirim] cipher (hex): %s" % c)
        except (ValueError, OSError) as e:
            print("  gagal kirim:", e)
    tutup_sesi()


if __name__ == "__main__":
    main()