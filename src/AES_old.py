# ---------------
#    Imports
# ---------------
from os.path import getsize
from os import remove
import numpy as np
from immutables import *


# Adds a padding to ensure a bloke size of 16 bytes
def __add_padding(data):
    length = 16 - len(data)
    for i in range(length):
        data.append(0)
    return data, length


# Removes the padding from the data
def __remove_padding(data, identifier):
    if identifier[-1] == 0:
        return data
    elif identifier[-1] > 0 and identifier[-1] < 16:
        return data[:-identifier[-1]]
    else:
        raise ValueError('Invalid padding')


# ---------------
# Running modes setup
# ---------------
# ECB encryption function
def ecb_enc(key, file_path):
    file_size = getsize(file_path)
    round_keys, nr = keyExpansion(key)

    with open(f"{file_path}.enc", 'wb') as output, open(file_path, 'rb') as data:
        for i in range(int(file_size/16)):
            raw = np.array([i for i in data.read(16)]).reshape(4, 4)
            result = bytes((encryption_rounds(raw, round_keys, nr).flatten()).tolist())
            output.write(result)

        if file_size % 16 != 0:
            raw = [i for i in data.read()]  # type: ignore
            raw, length = add_padding(raw)

            result = bytes((encryption_rounds(np.array(raw).reshape(4, 4), round_keys, nr).flatten()).tolist())
            identifier = bytes((encryption_rounds(np.array([0 for i in range(15)] + [length]).reshape(4, 4), round_keys, nr).flatten()).tolist())

            output.write(result + identifier)
        else:
            identifier = bytes((encryption_rounds(np.array([0 for i in range(16)]).reshape(4, 4), round_keys, nr).flatten()).tolist())
            output.write(identifier)
    remove(file_path)


# ECB decryption function
def ecb_dec(key, file_path):
    file_size = getsize(file_path)
    file_name = file_path[:-4]
    round_keys, nr = keyExpansion(key)

    with open(f"{file_name}", 'wb') as output, open(file_path, 'rb') as data:
        for i in range(int(file_size/16) - 2):
            raw = np.array([i for i in data.read(16)]).reshape(4, 4)
            result = bytes((decryption_rounds(raw, round_keys, nr).flatten()).tolist())
            output.write(result)

        data_pice = np.array([i for i in data.read(16)]).reshape(4, 4)
        identifier = np.array([i for i in data.read()]).reshape(4, 4)

        result = (decryption_rounds(data_pice, round_keys, nr).flatten()).tolist()
        identifier = (decryption_rounds(identifier, round_keys, nr).flatten()).tolist()

        result = bytes(remove_padding(result, identifier))

        output.write(result)
    remove(file_path)


# CBC encryption function
def cbc_enc(key, file_path, iv):
    file_size = getsize(file_path)
    vector = np.array([int(iv[i:i+2], 16) for i in range(0, len(iv), 2)]).reshape(4, 4)
    round_keys, nr = keyExpansion(key)

    with open(f"{file_path}.enc", 'wb') as output, open(file_path, 'rb') as data:
        for i in range(int(file_size/16)):
            raw = np.array([i for i in data.read(16)]).reshape(4, 4)
            raw = np.bitwise_xor(raw, vector)
            vector = encryption_rounds(raw, round_keys, nr)
            output.write(bytes((vector.flatten()).tolist()))

        if file_size % 16 != 0:
            raw = [i for i in data.read()]  # type: ignore
            raw, length = add_padding(raw)

            raw = np.bitwise_xor(np.array(raw).reshape(4, 4), vector)
            vector = encryption_rounds(raw, round_keys, nr)

            identifier = np.bitwise_xor(np.array([0 for i in range(15)] + [length]).reshape(4, 4), vector)
            identifier = encryption_rounds(identifier, round_keys, nr)

            output.write(bytes((vector.flatten()).tolist() + (identifier.flatten()).tolist()))
        else:
            identifier = np.bitwise_xor(np.array([0 for i in range(16)]).reshape(4, 4), vector)
            identifier = bytes(((encryption_rounds(identifier, round_keys, nr)).flatten()).tolist())  # type: ignore
            output.write(identifier)  # type: ignore
    remove(file_path)


# CBC decryption function
def cbc_dec(key, file_path, iv):
    iv = np.array([int(iv[i:i+2], 16) for i in range(0, len(iv), 2)]).reshape(4, 4)
    file_size = getsize(file_path)
    file_name = file_path[:-4]
    round_keys, nr = keyExpansion(key)

    with open(f"{file_name}", 'wb') as output, open(file_path, 'rb') as data:
        if int(file_size/16) - 3 >= 0:
            vector = np.array([i for i in data.read(16)]).reshape(4, 4)
            raw = decryption_rounds(vector, round_keys, nr)
            result = np.bitwise_xor(raw, iv)
            output.write(bytes((result.flatten()).tolist()))

            for i in range(int(file_size/16) - 3):
                raw = np.array([i for i in data.read(16)]).reshape(4, 4)
                result = decryption_rounds(raw, round_keys, nr)
                result = np.bitwise_xor(result, vector)
                vector = raw
                output.write(bytes((result.flatten()).tolist()))
        else:
            vector = iv

        data_pice = np.array([i for i in data.read(16)]).reshape(4, 4)
        vector_1, identifier = data_pice, np.array([i for i in data.read()]).reshape(4, 4)

        result = decryption_rounds(data_pice, round_keys, nr)
        identifier = decryption_rounds(identifier, round_keys, nr)

        identifier = np.bitwise_xor(identifier, vector_1)
        data_pice = np.bitwise_xor(result, vector)

        result = bytes(remove_padding((data_pice.flatten()).tolist(), (identifier.flatten()).tolist()))

        output.write(result)
    remove(file_path)


# PCBC encryption function
def pcbc_enc(key, file_path, iv):
    file_size = getsize(file_path)
    vector = np.array([int(iv[i:i+2], 16) for i in range(0, len(iv), 2)]).reshape(4, 4)
    round_keys, nr = keyExpansion(key)

    with open(f"{file_path}.enc", 'wb') as output, open(file_path, 'rb') as data:
        for i in range(int(file_size/16)):
            raw = np.array([i for i in data.read(16)]).reshape(4, 4)
            tmp = np.bitwise_xor(raw, vector)
            vector = encryption_rounds(tmp, round_keys, nr)
            output.write(bytes((vector.flatten()).tolist()))
            vector = np.bitwise_xor(vector, raw)

        if file_size % 16 != 0:
            raw = [i for i in data.read()]  # type: ignore
            raw, length = add_padding(raw)
            raw = np.array(raw).reshape(4, 4)

            tmp = np.bitwise_xor(raw, vector)
            vector1 = encryption_rounds(tmp, round_keys, nr)
            vector = np.bitwise_xor(vector1, raw)

            identifier = np.bitwise_xor(np.array([0 for i in range(15)] + [length]).reshape(4, 4), vector)
            identifier = encryption_rounds(identifier, round_keys, nr)

            output.write(bytes((vector1.flatten()).tolist() + (identifier.flatten()).tolist()))
        else:
            identifier = np.bitwise_xor(np.array([0 for i in range(16)]).reshape(4, 4), vector)
            identifier = bytes((encryption_rounds(identifier, round_keys, nr).flatten()).tolist())  # type: ignore
            output.write(identifier)  # type: ignore
    remove(file_path)


# PCBC decryption function
def pcbc_dec(key, file_path, iv):
    iv = np.array([int(iv[i:i+2], 16) for i in range(0, len(iv), 2)]).reshape(4, 4)
    file_size = getsize(file_path)
    file_name = file_path[:-4]
    round_keys, nr = keyExpansion(key)

    with open(f"{file_name}", 'wb') as output, open(file_path, 'rb') as data:
        if int(file_size/16) - 3 >= 0:
            vector = np.array([i for i in data.read(16)]).reshape(4, 4)
            raw = decryption_rounds(vector, round_keys, nr)
            result = np.bitwise_xor(raw, iv)
            vector = np.bitwise_xor(vector, result)
            output.write(bytes((result.flatten()).tolist()))

            for i in range(int(file_size/16) - 3):
                raw = np.array([i for i in data.read(16)]).reshape(4, 4)
                result = decryption_rounds(raw, round_keys, nr)
                result = np.bitwise_xor(result, vector)
                vector = np.bitwise_xor(raw, result)
                output.write(bytes((result.flatten()).tolist()))
        else:
            vector = iv

        data_pice = np.array([i for i in data.read(16)]).reshape(4, 4)
        vector_1, identifier = data_pice, np.array([i for i in data.read()]).reshape(4, 4)

        result = decryption_rounds(data_pice, round_keys, nr)
        data_pice = np.bitwise_xor(result, vector)

        vector_1 = np.bitwise_xor(vector_1, data_pice)
        identifier = decryption_rounds(identifier, round_keys, nr)
        identifier = np.bitwise_xor(identifier, vector_1)

        result = bytes(remove_padding((data_pice.flatten()).tolist(), (identifier.flatten()).tolist()))

        output.write(result)
    remove(file_path)


# OFB encryption function
def ofb_enc(key, file_path, iv):
    file_size = getsize(file_path)
    round_keys, nr = keyExpansion(key)
    mix = np.array([int(iv[i:i+2], 16) for i in range(0, len(iv), 2)]).reshape(4, 4)
    iv = mix

    with open(f"{file_path}.enc", 'wb') as output, open(file_path, 'rb') as data:
        for i in range(int(file_size/16)):
            raw = np.array([i for i in data.read(16)]).reshape(4, 4)
            mix = encryption_rounds(mix, round_keys, nr)
            result = np.bitwise_xor(raw, mix)
            output.write(bytes((result.flatten()).tolist()))

        if file_size % 16 != 0:
            raw = [i for i in data.read()]  # type: ignore
            raw, length = add_padding(raw)
            raw = np.array(raw).reshape(4, 4)

            if file_size < 16:
                mix = encryption_rounds(iv, round_keys, nr)
            else:
                mix = encryption_rounds(mix, round_keys, nr)
            result = np.bitwise_xor(mix, raw)

            mix = encryption_rounds(mix, round_keys, nr)
            identifier = np.bitwise_xor(np.array([0 for i in range(15)] + [length]).reshape(4, 4), mix)

            output.write(bytes((result.flatten()).tolist() + (identifier.flatten()).tolist()))
        else:
            mix = encryption_rounds(mix, round_keys, nr)
            identifier = np.bitwise_xor(np.array([0 for i in range(16)]).reshape(4, 4), mix)
            output.write(bytes((identifier.flatten()).tolist()))
    remove(file_path)


# OFB decryption function
def ofb_dec(key, file_path, iv):
    iv = np.array([int(iv[i:i+2], 16) for i in range(0, len(iv), 2)]).reshape(4, 4)
    file_size = getsize(file_path)
    file_name = file_path[:-4]
    round_keys, nr = keyExpansion(key)

    with open(f"{file_name}", 'wb') as output, open(file_path, 'rb') as data:
        if int(file_size/16) - 3 >= 0:
            raw = np.array([i for i in data.read(16)]).reshape(4, 4)
            mix = encryption_rounds(iv, round_keys, nr)
            result = np.bitwise_xor(raw, mix)
            output.write(bytes((result.flatten()).tolist()))

            for i in range(int(file_size/16) - 3):
                raw = np.array([i for i in data.read(16)]).reshape(4, 4)
                mix = encryption_rounds(mix, round_keys, nr)
                result = np.bitwise_xor(raw, mix)
                output.write(bytes((result.flatten()).tolist()))
        else:
            mix = iv

        data_pice = np.array([i for i in data.read(16)]).reshape(4, 4)
        identifier = np.array([i for i in data.read()]).reshape(4, 4)

        mix = encryption_rounds(mix, round_keys, nr)
        data_pice = np.bitwise_xor(data_pice, mix)

        mix = encryption_rounds(mix, round_keys, nr)
        identifier = np.bitwise_xor(identifier, mix)

        result = bytes(remove_padding((data_pice.flatten()).tolist(), (identifier.flatten()).tolist()))  # type: ignore

        output.write(result)  # type: ignore
    remove(file_path)
