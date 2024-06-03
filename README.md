# CRYPTO_ENCS4320_ASSIGNMENT2
## TEA Encryption and Decryption

This Python code implements the Tiny Encryption Algorithm (TEA), a lightweight symmetric block cipher designed for simplicity and efficiency. TEA operates on 64-bit blocks of data with a 128-bit key, providing a fast and secure encryption method. 

### Methodology
TEA works by iteratively applying a set of operations including bitwise XOR, addition, and shifting, in multiple rounds (typically 32) to encrypt and decrypt data. This process ensures a high level of security while maintaining efficiency.

### Functionality
The code offers versatile functions for encrypting and decrypting both text and BMP image files. It supports two modes of operation: Electronic Codebook (ECB) and Cipher Block Chaining (CBC), enhancing flexibility and usability.

## Usage
1. Ensure Python 3.x is installed.
2. Import necessary functions or execute code directly.
3. Follow prompts to input key and choose encryption mode.
4. View encrypted and decrypted data as per chosen mode.

## Running the Code in CMD

To use the TEA encryption and decryption code in the command prompt (CMD), follow these steps:

1. Open the command prompt (CMD) on your computer.

2. Navigate to the directory containing the Python script using the `cd` command followed by the path to the directory.

3. Run the Python script by typing `python ENC_DEc.py` and press Enter.

4. Follow the prompts displayed in the command prompt to enter the key (4 hexadecimal values separated by spaces), IV (an integer between 0 and 8), and choose whether to encrypt text or an image (T for text, I for image).

5. If encrypting text, enter the text when prompted. The encrypted and decrypted results will be displayed for both ECB and CBC modes.

6. If encrypting an image, enter the path of the image file when prompted. The encrypted and decrypted images will be saved as 'encrypted_ecb.bmp', 'decrypted_ecb.bmp', 'encrypted_cbc.bmp', and 'decrypted_cbc.bmp' in the same directory as the script.

7. After completing encryption or decryption, you'll be asked if you want to end the program (Y/N). Enter Y to exit the program or N to continue using it.

8. You're done! You've successfully used the TEA encryption and decryption code in the command prompt.
