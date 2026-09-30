import unittest
from crypto import (
    des_encrypt, des_decrypt,
    des_encrypt_block, generate_round_keys,
    bytes_to_bits, bits_to_bytes
)


class TestDES(unittest.TestCase):

    def test_encrypt_decrypt_roundtrip(self):
        key = b'KunciKI1'
        plaintext = "Halo Receiver, ini pesan rahasia".encode('utf-8')

        ciphertext = des_encrypt(key, plaintext)
        decrypted = des_decrypt(key, ciphertext)

        self.assertNotEqual(ciphertext, plaintext)
        self.assertEqual(decrypted, plaintext)

    def test_empty_message(self):
        key = b'KunciKI1'
        plaintext = b''
        ciphertext = des_encrypt(key, plaintext)
        self.assertEqual(des_decrypt(key, ciphertext), plaintext)

    def test_known_des_test_vector(self):
        key = bytes.fromhex('133457799BBCDFF1')
        plaintext = bytes.fromhex('0123456789ABCDEF')
        expected_hex = '85e813540f0ab405'

        round_keys = generate_round_keys(key)
        block_bits = bytes_to_bits(plaintext)
        encrypted_bits = des_encrypt_block(block_bits, round_keys)
        ciphertext = bits_to_bytes(encrypted_bits)

        self.assertEqual(ciphertext.hex(), expected_hex)

    def test_different_keys_give_different_ciphertext(self):
        plaintext = b'Data rahasia'
        ct1 = des_encrypt(b'KunciSat', plaintext)
        ct2 = des_encrypt(b'KunciDua', plaintext)
        self.assertNotEqual(ct1, ct2)


if __name__ == '__main__':
    unittest.main()
