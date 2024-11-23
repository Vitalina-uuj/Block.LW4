
S_BOX = [
    [0x0, 0x4, 0x8, 0xC],  # Row for nibble 0
    [0x1, 0x5, 0x9, 0xD],  # Row for nibble 1
    [0x2, 0x6, 0xA, 0xE],  # Row for nibble 2
    [0x3, 0x7, 0xB, 0xF]   # Row for nibble 3
]

def s_block_encrypt(input_byte):
    """Encrypts a byte using the S-box."""
    high_nibble = (input_byte >> 4) & 0xF
    low_nibble = input_byte & 0xF

    encrypted_high = S_BOX[high_nibble // 4][high_nibble % 4]
    encrypted_low = S_BOX[low_nibble // 4][low_nibble % 4]

    return (encrypted_high << 4) | encrypted_low

def generate_inverse_s_box(s_box):
    """Generates the inverse of an S-box."""
    inverse_s_box = [0] * 16
    for i in range(16):
        for j in range(4):
            inverse_s_box[s_box[j][i % 4]] = (j << 2) | i % 4
    return inverse_s_box

INVERSE_S_BOX = generate_inverse_s_box(S_BOX)

def s_block_decrypt(input_byte):
    """Decrypts a byte using the inverse S-box."""
    high_nibble = (input_byte >> 4) & 0xF
    low_nibble = input_byte & 0xF

    decrypted_high = INVERSE_S_BOX[high_nibble]
    decrypted_low = INVERSE_S_BOX[low_nibble]

    return (decrypted_high << 4) | decrypted_low

PERMUTATION = [2, 0, 3, 1, 6, 4, 7, 5]

def p_block_encrypt(input_byte):
    """Encrypts a byte using the P-block permutation."""
    output_byte = 0
    for i, bit in enumerate(PERMUTATION):
        if input_byte & (1 << i):
            output_byte |= (1 << bit)
    return output_byte

def generate_inverse_permutation(permutation):
    """Generates the inverse of a permutation."""
    inverse_permutation = [0] * len(permutation)
    for i, pos in enumerate(permutation):
        inverse_permutation[pos] = i
    return inverse_permutation

INVERSE_PERMUTATION = generate_inverse_permutation(PERMUTATION)

def p_block_decrypt(input_byte):
    """Decrypts a byte using the inverse P-block permutation."""
    output_byte = 0
    for i, bit in enumerate(INVERSE_PERMUTATION):
        if input_byte & (1 << i):
            output_byte |= (1 << bit)
    return output_byte

def test_s_p_blocks():
    """Tests the S-block and P-block implementations."""
    test_byte = 0b10101010

    # S-block
    encrypted_s = s_block_encrypt(test_byte)
    decrypted_s = s_block_decrypt(encrypted_s)
    assert decrypted_s == test_byte, "S-block: Test failed"

    encrypted_p = p_block_encrypt(test_byte)
    decrypted_p = p_block_decrypt(encrypted_p)
    assert decrypted_p == test_byte, "P-block: Test failed"

    print("All tests passed successfully!")


if __name__ == "__main__":
    test_byte = 0b10101010
    print(f"Original byte: {bin(test_byte)}")

    encrypted_s = s_block_encrypt(test_byte)
    print(f"S-block encryption: {bin(encrypted_s)}")

    decrypted_s = s_block_decrypt(encrypted_s)
    print(f"S-block decryption: {bin(decrypted_s)}")

    encrypted_p = p_block_encrypt(test_byte)
    print(f"P-block encryption: {bin(encrypted_p)}")

    decrypted_p = p_block_decrypt(encrypted_p)
    print(f"P-block decryption: {bin(decrypted_p)}")

    test_s_p_blocks()
