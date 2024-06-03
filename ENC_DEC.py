import struct
import os
from PIL import Image


def tea_encrypt(v, k, rounds=32):
    y, z = v
    delta = 0x9E3779B9
    summ = 0

    for _ in range(rounds):
        summ = (summ + delta) & 0xFFFFFFFF
        y = (y + (((z << 4) + k[0]) ^ (z + summ)
             ^ ((z >> 5) + k[1]))) & 0xFFFFFFFF
        z = (z + (((y << 4) + k[2]) ^ (y + summ)
             ^ ((y >> 5) + k[3]))) & 0xFFFFFFFF

    return [y, z]


def tea_decrypt(v, k, rounds=32):
    y, z = v
    delta = 0x9E3779B9
    summ = (delta * rounds) & 0xFFFFFFFF

    for _ in range(rounds):
        z = (z - (((y << 4) + k[2]) ^ (y + summ)
             ^ ((y >> 5) + k[3]))) & 0xFFFFFFFF
        y = (y - (((z << 4) + k[0]) ^ (z + summ)
             ^ ((z >> 5) + k[1]))) & 0xFFFFFFFF
        summ = (summ - delta) & 0xFFFFFFFF

    return [y, z]


def block_to_ints(block):
    return list(struct.unpack('>2I', block))


def ints_to_block(ints):
    return struct.pack('>2I', *ints)


def pad_data(data):
    padding_length = 8 - (len(data) % 8)
    if padding_length != 8:
        data += b'\x00' * padding_length
    return data, padding_length


def unpad_data(data, padding_length):
    if padding_length != 0:
        data = data[:-padding_length]
    return data


def tea_ecb_encrypt(plaintext, key, rounds=32):
    ciphertext = bytearray()
    plaintext, _ = pad_data(plaintext)

    for i in range(0, len(plaintext), 8):
        block = plaintext[i:i+8]
        if i < 80:
            ciphertext.extend(block)
        else:
            v = block_to_ints(block)
            encrypted_block = tea_encrypt(v, key, rounds)
            ciphertext.extend(ints_to_block(encrypted_block))

    return bytes(ciphertext)


def tea_ecb_decrypt(ciphertext, key, rounds=32):
    plaintext = bytearray()

    for i in range(0, len(ciphertext), 8):
        block = ciphertext[i:i+8]
        if i < 80:
            plaintext.extend(block)
        else:
            v = block_to_ints(block)
            decrypted_block = tea_decrypt(v, key, rounds)
            plaintext.extend(ints_to_block(decrypted_block))

    return bytes(plaintext)


def tea_cbc_encrypt(plaintext, key, iv, rounds=32):
    ciphertext = bytearray()
    prev_block = iv
    plaintext, _ = pad_data(plaintext)

    for i in range(0, len(plaintext), 8):
        block = plaintext[i:i+8]
        if i < 80:
            ciphertext.extend(block)
            prev_block = block
        else:
            v = block_to_ints(block)
            prev_v = block_to_ints(prev_block)
            v[0] ^= prev_v[0]
            v[1] ^= prev_v[1]
            encrypted_block = tea_encrypt(v, key, rounds)
            encrypted_block_bytes = ints_to_block(encrypted_block)
            ciphertext.extend(encrypted_block_bytes)
            prev_block = encrypted_block_bytes

    return bytes(ciphertext)


def tea_cbc_decrypt(ciphertext, key, iv, rounds=32):
    plaintext = bytearray()
    prev_block = iv

    for i in range(0, len(ciphertext), 8):
        block = ciphertext[i:i+8]
        if i < 80:
            plaintext.extend(block)
            prev_block = block
        else:
            v = block_to_ints(block)
            decrypted_block = tea_decrypt(v, key, rounds)
            prev_v = block_to_ints(prev_block)
            decrypted_block[0] ^= prev_v[0]
            decrypted_block[1] ^= prev_v[1]
            plaintext.extend(ints_to_block(decrypted_block))
            prev_block = block

    return bytes(plaintext)


def read_bmp(file_path):
    with open(file_path, 'rb') as f:
        bmp_header = f.read(54)
        pixel_data = f.read()
    return bmp_header, pixel_data


def write_bmp(file_path, bmp_header, pixel_data):
    with open(file_path, 'wb') as f:
        f.write(bmp_header)
        f.write(pixel_data)


def encrypt_decrypt_bmp(input_file, output_file, iv, key, mode, encrypt):
    bmp_header, pixel_data = read_bmp(input_file)
    pixel_data, padding_length = pad_data(pixel_data)

    if mode == 'ECB':
        if encrypt:
            result_data = tea_ecb_encrypt(pixel_data, key)
        else:
            result_data = tea_ecb_decrypt(pixel_data, key)
    elif mode == 'CBC':
        if encrypt:
            result_data = tea_cbc_encrypt(pixel_data, key, iv)
        else:
            result_data = tea_cbc_decrypt(pixel_data, key, iv)

    if not encrypt:
        result_data = unpad_data(result_data, padding_length)

    write_bmp(output_file, bmp_header, result_data)


def bmp_to_grayscale_data(file_path):
    with Image.open(file_path) as img:
        grayscale_img = img.convert('L')
        width, height = grayscale_img.size
        pixel_data = list(grayscale_img.getdata())

    return width, height, pixel_data


def hex_to_int(hex_string):
    return int(hex_string, 16)


def main():
    while True:
        key_input = input(
            "Enter the key (4 hexadecimal values separated by spaces):").split()
        if len(key_input) != 4:
            print("Error: Please enter exactly 4 hexadecimal values.")
            continue
        try:
            key = [hex_to_int(x) for x in key_input]
        except ValueError:
            print("Error: Please enter valid hexadecimal values.")
            continue
        break

    while True:
        try:
            iv = int(input("Enter the iv:"))
            if iv < 0 or iv > 8:
                print("Error: IV must be an integer between 0 and 8.")
                continue
        except ValueError:
            print("Error: Please enter a valid integer.")
            continue
        break

    while True:
        choice = input("Do you want to encrypt Text or Image? (T/I):").upper()
        if choice == 'T':
            user_text = input("Enter the text you want to encrypt:")
            plaintext = user_text.encode()
            plaintext, _ = pad_data(plaintext)

            print("ECB Mode:")
            ciphertext_ecb = tea_ecb_encrypt(plaintext, key)
            decrypted_ecb = tea_ecb_decrypt(ciphertext_ecb, key)
            print(f"Ciphertext (ECB): {ciphertext_ecb}")
            print("\n")
            print(f"Decrypted (ECB): {decrypted_ecb.decode('utf-8').strip()}")
            print(
                "==================================================================")
            print("\nCBC Mode:")
            ciphertext_cbc = tea_cbc_encrypt(plaintext, key, iv)
            decrypted_cbc = tea_cbc_decrypt(ciphertext_cbc, key, iv)
            print(f"Ciphertext (CBC): {ciphertext_cbc}")
            print("\n")
            print(f"Decrypted (CBC): {decrypted_cbc.decode('utf-8').strip()}")
            print("\n")
        elif choice == 'I':
            image_path = input(
                "Enter the path of the image you want to encrypt:")
            encrypt_decrypt_bmp(image_path, 'encrypted_ecb.bmp',
                                iv, key, mode='ECB', encrypt=True)
            encrypt_decrypt_bmp(
                'encrypted_ecb.bmp', 'decrypted_ecb.bmp', iv, key, mode='ECB', encrypt=False)

            encrypt_decrypt_bmp(image_path, 'encrypted_cbc.bmp',
                                iv, key, mode='CBC', encrypt=True)
            encrypt_decrypt_bmp(
                'encrypted_cbc.bmp', 'decrypted_cbc.bmp', iv, key, mode='CBC', encrypt=False)

        terminate_cond = input(
            "Do you want to end the program? (Y/N):").upper()
        if terminate_cond == 'Y':
            break


if __name__ == "__main__":
    main()
