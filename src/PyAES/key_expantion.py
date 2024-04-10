# ---------------
# Key expansion setup
# ---------------
# Key expansion function
# This function is used to expand the key to the correct number of round
# keys for the encryption and decryption rounds.
def keyExpansion(key):
    # Format key correctly for the key expansion
    key = [key[i:i+2] for i in range(0, len(key), 2)]

    # Key expansion setup
    # This part determines the number of rounds and the number of words
    # using the key length.
    if len(key) == 16:
        words = key_schedule(key, 4, 11)
        nr = 11
    if len(key) == 24:
        words = key_schedule(key, 6, 13)
        nr = 13
    if len(key) == 32:
        words = key_schedule(key, 8, 15)
        nr = 15

    # Create list for storing the round keys & tmp list for storing
    # for temporary storage.
    round_keys = [None for i in range(nr)]
    tmp = [None for i in range(4)]

    # Formats the words to a list of tuples
    for i in range(nr * 4):
        for index, t in enumerate(words[i]):
            tmp[index] = int(t, 16)  # type: ignore
        words[i] = tuple(tmp)

    # Formats teh words to a list of numpy arrays where each
    # array is a 4x4 matrix representing a round key.
    for i in range(nr):
        round_keys[i] = np.array(words[i * 4] + words[i * 4 + 1] + words[i * 4 + 2] + words[i * 4 + 3]).reshape(4, 4)  # type: ignore

    # Returns the list of round keys and the number of rounds
    return round_keys, nr


# Key schedule (nk = number of colums, nr = number of rounds)
# This function is used to expand the key to the correct number of round
def key_schedule(key, nk, nr):
    # Create list for storing the words and populates the first
    # 4 with the specified key.
    words = [(key[4*i], key[4*i+1], key[4*i+2], key[4*i+3]) for i in range(nk)]

    # Fill out the rest based on previews four words using the fucnitons, rotword,
    # subword and rcon values
    limit = False
    for i in range(nk, (nr * nk)):
        # Get required previous keywords
        temp, word = words[i-1], words[i-nk]

        # If multiple of nk use rot, sub, rcon etc
        if i % nk == 0:
            x = SubWord(RotWord(temp))
            rcon = round_constant[int(i/nk)]
            temp = hexor(x, hex(rcon)[2:])
            limit = False
        elif i % 4 == 0:
            limit = True

        if i % 4 == 0 and limit and nk >= 8:
            temp = SubWord(temp)

        # Xor the two hex values
        xord = hexor(''.join(word), ''.join(temp))
        # Add to list
        words.append((xord[:2], xord[2:4], xord[4:6], xord[6:8]))
    # Return the list of words
    return words


# Takes two hex values and calculates hex1 xor hex2
def hexor(hex1, hex2):
    # Convert to binary
    bin1 = hex2binary(hex1)
    bin2 = hex2binary(hex2)

    # Calculate
    xord = int(bin1, 2) ^ int(bin2, 2)

    # Cut prefix
    hexed = hex(xord)[2:]

    # Leading 0s get cut above, if not length 8 add a leading 0
    if len(hexed) != 8:
        hexed = '0' + hexed

    # Return hex
    return hexed


# Takes a hex value and returns binary
def hex2binary(hex):
    return bin(int(str(hex), 16))


# Takes from 1 to the end, adds on from the start to 1
def RotWord(word):
    return word[1:] + word[:1]


# Selects correct values from sbox based on the current word
# and replaces the word with the new values.
def SubWord(word):
    # Create list for storing the new word
    sWord = []

    # Loop through the current word
    for i in range(4):

        # Check first char, if its a letter(a-f) get corresponding decimal
        # otherwise just take the value and add 1
        if word[i][0].isdigit() is False:
            row = ord(word[i][0]) - 86
        else:
            row = int(word[i][0])+1

        # Repeat above for the seoncd char
        if word[i][1].isdigit() is False:
            col = ord(word[i][1]) - 86
        else:
            col = int(word[i][1])+1

        # Get the index base on row and col (16x16 grid)
        sBoxIndex = (row*16) - (17-col)

        # Get the value from sbox and removes prefix (0x)
        piece = hex(subBytesTable[sBoxIndex])[2:]

        # Check length to ensure leading 0s are not forgotton
        if len(piece) != 2:
            piece = '0' + piece

        # Adds the new value to the list
        sWord.append(piece)

    # Returning word as string
    return ''.join(sWord)
