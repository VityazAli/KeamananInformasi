import socket
from config import HOST, PORT
from network import send_encrypted, recv_decrypted

LABEL = "Sender"


def main():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.connect((HOST, PORT))
        print(f"[{LABEL}] Terhubung ke Receiver di {HOST}:{PORT}\n")

        while True:
            pesan = input(f"[{LABEL}] Ketik plaintext (atau 'exit' untuk keluar): ")
            send_encrypted(sock, pesan, LABEL)

            if pesan.strip().lower() == 'exit':
                print(f"[{LABEL}] Menutup program.")
                break

            balasan = recv_decrypted(sock, LABEL)
            if balasan is None:
                print(f"[{LABEL}] Koneksi ditutup oleh Receiver.")
                break

            print(f"[{LABEL}] Balasan hasil dekripsi: \"{balasan}\"\n")

            if balasan.strip().lower() == 'exit':
                print(f"[{LABEL}] Receiver meminta keluar. Menutup program.")
                break


if __name__ == '__main__':
    main()