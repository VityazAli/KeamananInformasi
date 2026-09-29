import socket
from config import HOST, PORT
from network import send_encrypted, recv_decrypted

LABEL = "Receiver"


def main():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_sock:
        server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_sock.bind((HOST, PORT))
        server_sock.listen(1)
        print(f"[{LABEL}] Menunggu koneksi Sender di {HOST}:{PORT} ...")

        conn, addr = server_sock.accept()
        with conn:
            print(f"[{LABEL}] Terhubung dengan Sender {addr}\n")

            while True:
                plaintext = recv_decrypted(conn, LABEL)
                if plaintext is None:
                    print(f"[{LABEL}] Koneksi ditutup oleh Sender.")
                    break

                print(f"[{LABEL}] Plaintext hasil dekripsi: \"{plaintext}\"\n")

                if plaintext.strip().lower() == 'exit':
                    print(f"[{LABEL}] Sender meminta keluar. Menutup program.")
                    break

                balasan = input(f"[{LABEL}] Ketik pesan balasan: ")
                send_encrypted(conn, balasan, LABEL)

                if balasan.strip().lower() == 'exit':
                    print(f"[{LABEL}] Menutup program.")
                    break


if __name__ == '__main__':
    main()