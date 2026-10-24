"""独立矩阵参考实现，不导入生产算法；S 盒由有限域求逆和仿射变换生成。"""


def multiply(left, right):
    polynomial = 0
    for bit in range(4):
        if right & (1 << bit):
            polynomial ^= left << bit
    for degree in range(6, 3, -1):
        if polynomial & (1 << degree):
            polynomial ^= 0b10011 << (degree - 4)
    return polynomial


def make_sbox():
    matrix = ((1, 0, 1, 1), (1, 1, 0, 1), (1, 1, 1, 0), (0, 1, 1, 1))
    constant = (1, 0, 0, 1)
    box = []
    for value in range(16):
        reciprocal = next((candidate for candidate in range(1, 16) if multiply(value, candidate) == 1), 0)
        bits = [(reciprocal >> bit) & 1 for bit in (3, 2, 1, 0)]
        mapped = [sum(matrix[row][column] * bits[column] for column in range(4)) % 2 ^ constant[row] for row in range(4)]
        box.append(int("".join(map(str, mapped)), 2))
    return tuple(box)


BOX = make_sbox()


def round_keys(key):
    byte_words = [key // 256, key % 256]
    for rcon in (128, 48):
        high, low = divmod(byte_words[-1], 16)
        transformed = BOX[low] * 16 + BOX[high]
        next_word = byte_words[-2] ^ rcon ^ transformed
        byte_words += [next_word, next_word ^ byte_words[-1]]
    return [byte_words[i] * 256 + byte_words[i + 1] for i in (0, 2, 4)]


def encrypt(plain, key):
    def matrix(value):
        digits = [int(c, 16) for c in f"{value:04x}"]
        return [[digits[0], digits[2]], [digits[1], digits[3]]]

    state = matrix(plain)

    def add_key(value):
        addition = matrix(value)
        for row in range(2):
            for column in range(2):
                state[row][column] ^= addition[row][column]

    keys = round_keys(key)
    add_key(keys[0])
    for round_index in (1, 2):
        for row in range(2):
            for column in range(2):
                state[row][column] = BOX[state[row][column]]
        state[1] = list(reversed(state[1]))
        if round_index == 1:
            old = [row[:] for row in state]
            for column in range(2):
                state[0][column] = old[0][column] ^ multiply(4, old[1][column])
                state[1][column] = multiply(4, old[0][column]) ^ old[1][column]
        add_key(keys[round_index])
    return int("".join(f"{state[row][column]:x}" for column in range(2) for row in range(2)), 16)
