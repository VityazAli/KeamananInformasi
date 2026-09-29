import struct
from crypto import des_encrypt, des_decrypt
from config import SHARED_KEY


def recv_exact(sock, n):
    data = bytearray()
    while len(data) < n:
        packet = sock.recv(n - len(data))
        if not packet:
            return None
        data.extend(packet)
    return bytes(data)


def send_encrypted(sock, plaintext: str, label: str):
    data = plaintext.encode('utf-8')
    ciphertext = des_encrypt(SHARED_KEY, data)
    header = struct.pack('!I', len(ciphertext))
    sock.sendall(header + ciphertext)
    print(f"[{label}] >> Mengirim ciphertext ({len(ciphertext)} byte, hex): {ciphertext.hex()}")


def recv_decrypted(sock, label: str):
    header = recv_exact(sock, 4)
    if header is None:
        return None
    (length,) = struct.unpack('!I', header)
    ciphertext = recv_exact(sock, length)
    if ciphertext is None:
        return None
    print(f"[{label}] << Menerima ciphertext ({len(ciphertext)} byte, hex): {ciphertext.hex()}")
    plaintext_bytes = des_decrypt(SHARED_KEY, ciphertext)
    return plaintext_bytes.decode('utf-8')