import argparse
import socket
import threading

from aes_manual import encrypt, decrypt, cek_key
from common import (ID_A, ID_B, PORT_KDC, PORT_BOB, Saluran, ip_lokal,
                    minta_key, nonce, fungsi_f, loop_terima)

state = {"ka": None, "sal": None, "ks": None}
state_lock = threading.Lock()


def tutup_sesi():
    with state_lock:
        sal = state["sal"]
        state["sal"] = None
        state["ks"] = None
    if sal:
        sal.tutup()


def sambung(alamat):
    s = socket.create_connection(alamat, timeout=10)
    s.settimeout(15)
    return Saluran(s)


def distribusi_kunci(kdc_addr, bob_addr):
    ka = state["ka"]

    # ---- langkah 1: Alice -> KDC ----
    n1 = nonce()
    pesan1 = "REQ|%s|%s|%s" % (ID_A, ID_B, n1)
    print("[STEP 1] Alice -> KDC : ID_A || ID_B || N1")
    print("         pesan        : %s" % pesan1)
    kdc = sambung(kdc_addr)
    try:
        kdc.kirim(pesan1)
        resp = kdc.terima()
    finally:
        kdc.tutup()

    # ---- langkah 2: KDC -> Alice ----
    if resp.startswith("ERR|"):
        raise RuntimeError("KDC menolak: " + resp[4:])
    if not resp.startswith("RESP|"):
        raise RuntimeError("format balasan KDC tidak dikenal")
    cipher2 = resp[5:]
    print("[STEP 2] KDC -> Alice : cipher (hex) = %s" % cipher2)
    try:
        plain2 = decrypt(cipher2, ka)
    except ValueError:
        raise RuntimeError("balasan KDC tidak bisa didekripsi, Ka Alice tidak sama dengan Ka di KDC") from None
    bagian = plain2.split("|", 3)
    if len(bagian) != 4:
        raise RuntimeError("isi balasan KDC tidak sesuai format")
    ks, id_b, n1_balik, tiket = bagian
    print("[Alice] hasil dekripsi dengan Ka : %s" % plain2)
    print("[Alice] Ks = %s | ID_B = %s | N1 = %s" % (ks, id_b, n1_balik))
    if id_b != ID_B or n1_balik != n1:
        raise RuntimeError("ID_B atau N1 tidak cocok, balasan ditolak")
    cek_key(ks)

    # ---- langkah 3: Alice -> Bob (tiket) ----
    bob = sambung(bob_addr)
    try:
        print("[STEP 3] Alice -> Bob : E(Kb, [Ks||ID_A])")
        print("         cipher (hex)  : %s" % tiket)
        bob.kirim("TICKET|" + tiket)

        # ---- langkah 4: Bob -> Alice ----
        baris = bob.terima()
        if not baris.startswith("N2|"):
            raise RuntimeError("Bob menolak tiket atau balasan tidak dikenal: " + baris)
        print("[STEP 4] Bob -> Alice : cipher (hex) = %s" % baris[3:])
        n2 = decrypt(baris[3:], ks)
        print("[Alice] N2 dari Bob = %s" % n2)

        # ---- langkah 5: Alice -> Bob ----
        jawab = fungsi_f(n2)
        c5 = encrypt(jawab, ks)
        print("[STEP 5] Alice -> Bob : E(Ks, f(N2))   f(N2)=%s" % jawab)
        print("         cipher (hex)  : %s" % c5)
        bob.kirim("N2F|" + c5)

        konfirmasi = bob.terima()
        if konfirmasi != "ACK|OK":
            raise RuntimeError("Bob menolak langkah 5: " + konfirmasi)
    except Exception:
        bob.tutup()
        raise
    bob.sock.settimeout(None)
    return bob, ks


def jalankan_sesi(sal, ks):
    alasan = loop_terima(sal, ks, "Bob")
    with state_lock:
        masih_aktif = state["sal"] is sal
    if masih_aktif:
        tutup_sesi()
        print("\n[Alice] sesi berakhir (%s)" % alasan)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--kdc", required=True, help="IP KDC")
    ap.add_argument("--kdc-port", type=int, default=PORT_KDC)
    ap.add_argument("--bob", required=True, help="IP Bob")
    ap.add_argument("--bob-port", type=int, default=PORT_BOB)
    args = ap.parse_args()
    kdc_addr = (args.kdc, args.kdc_port)
    bob_addr = (args.bob, args.bob_port)

    print("=== ALICE ===")
    print("IP perangkat ini :", ip_lokal())
    print("KDC              : %s:%d" % kdc_addr)
    print("Bob              : %s:%d" % bob_addr)
    state["ka"] = minta_key("Key Alice (Ka), 16/24/32 karakter: ")
    print("Ketik /start untuk mulai distribusi key, /help untuk perintah.\n")

    while True:
        try:
            teks = input("Alice> ")
        except (EOFError, KeyboardInterrupt):
            break
        if not teks.strip():
            continue
        if teks.startswith("/"):
            cmd, _, arg = teks.partition(" ")
            if cmd == "/help":
                print("  /setkey <key>   ganti Ka (harus sama dengan Ka di KDC)")
                print("  /start          jalankan langkah 1 sampai 5 (buat sesi baru)")
                print("  /status         lihat key dan sesi saat ini")
                print("  /close          tutup sesi chat")
                print("  /quit           keluar")
            elif cmd == "/setkey":
                try:
                    cek_key(arg.strip())
                    state["ka"] = arg.strip()
                    print("  Ka diganti jadi:", state["ka"])
                except ValueError as e:
                    print("  key ditolak:", e)
            elif cmd == "/status":
                print("  Ka    :", state["ka"])
                print("  Ks    :", state["ks"] or "(belum ada sesi)")
            elif cmd == "/close":
                tutup_sesi()
                print("  sesi ditutup")
            elif cmd == "/start":
                tutup_sesi()
                try:
                    sal, ks = distribusi_kunci(kdc_addr, bob_addr)
                except Exception as e:
                    print("\n[Alice] distribusi key GAGAL: %s" % e)
                    continue
                with state_lock:
                    state["sal"], state["ks"] = sal, ks
                threading.Thread(target=jalankan_sesi, args=(sal, ks), daemon=True).start()
                print("\n[Alice] sesi aman terbentuk dengan Bob. Silakan chat (AES, Ks=%s)." % ks)
            elif cmd == "/quit":
                break
            else:
                print("  perintah tidak dikenal, ketik /help")
            continue

        with state_lock:
            sal, ks = state["sal"], state["ks"]
        if not sal:
            print("  belum ada sesi, ketik /start dulu")
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