# ---------------------------------------------------------------
#                   Background structure
# ---------------------------------------------------------------

# Imports the encrypt function from the AES-Python module
from PyAES.encrypt import encrypt
# Imports the timer and random number generator
from time import perf_counter
from random import randint
# Imports the remove function for deleting files
from os import remove


# For displaying progress during test runs
def progress_bar(progress, total_progress):
    percent = 100 * (float(progress) / float(total_progress))
    bar_progress = int(100 * (float(progress) / float(total_progress)))

    if bar_progress > 100 or percent > 100:
        bar_progress = 100
        percent = 100

    bar_remaining = 100 - bar_progress
    bar = '#' * bar_progress + '-' * bar_remaining
    print(f"\r[{bar}] {percent:.2f}%", end="\r")
    return progress + 1


# Writes the resulting data to a text file
def write_data(data, name_f):
    # Creates a text file with the specified name
    with open(name_f + '.txt', 'w') as f:
        for i in data:
            # Writes the data to the text file
            f.write(str(i) + '\n')
        f.write(str('\n'))


# Creates a text file with specified size and fills it with random bytes
def setup(count):
        # Creates a text file with the name test_speed.txt
        with open("test_speed.txt", 'wb') as f:
            for j in range(count):
                # Writes random bytes to the text file
                f.write(bytes([randint(0, 255)]))


# Runs the specified function and returns the time it takes to run
def speed_test(count, key, mode, iv):
    # Creates a text file with the specified size
    setup(count)
    # Starts the timer
    start = perf_counter()
    # Executes the function
    encrypt(key, "test_speed.txt", mode, iv=iv)
    # Stops the timer
    end = perf_counter()
    # Deletes the text file
    remove("test_speed.txt.enc")
    return end - start

# Executes the code if the file is run directly
if __name__ == '__main__':
    # Test parameters
    keys = ["2b7e151628aed2a6abf7158809cf4f3c",
            "8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b",
    "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4"]
    iv = "000102030405060708090a0b0c0d0e0f"
    file_size = 1000000
    runs = 25

    # ---------------------------------------------------------------
    #     Test time difference between 128, 192 and 256 bit keys
    # ---------------------------------------------------------------
    data = []
    progress = 0
    # Loops through the different key sizes
    for i in keys:
        data_tmp = []
        # Runs the test the specified amount of times
        for j in range(runs):
            # Displays the progress
            progress = progress_bar(progress, 150)
            # Runs the test and saves the result
            test = speed_test(file_size, i, 'ECB', iv)
            # Saves the result
            data_tmp.append(test)
        # Writes the the results of every run to a text file
        write_data(data_tmp, 'keys_test_raw ' + str(len(i) * 4))
        # Saves the average of the results
        data.append(sum(data_tmp)/len(data_tmp))
    # Writes the average of the results to a text file
    write_data(data, 'keys_test')

    # ---------------------------------------------------------------
    #      Test time difference between ECB, CBC and OFB modes
    # ---------------------------------------------------------------
    data = []
    data_tmp = []

    # Runs the time test for OFB the specified amount of times
    for i in range(runs):
        # Displays the progress
        progress = progress_bar(progress, 150)
        # Runs the test for OFB
        test = speed_test(file_size, keys[0], 'OFB', iv)
        # Saves the result in a temporary list
        data_tmp.append(test)
    # Writes the the results of every run to a text file
    write_data(data_tmp, 'modes_test_raw OFB')
    # Saves the average of the results in a list and clears the temporary list
    data.append(sum(data_tmp)/len(data_tmp))
    data_tmp = []

    # Runs the time test for CBC the specified amount of times
    for i in range(runs):
        # Displays the progress
        progress = progress_bar(progress, 150)
        # Runs the test for CBC
        test = speed_test(file_size, keys[0], 'CBC', iv)
        # Saves the result in a temporary list
        data_tmp.append(test)
    # Writes the the results of every run to a text file
    write_data(data_tmp, 'modes_test_raw CBC')
    # Saves the average of the results in a list and clears the temporary list
    data.append(sum(data_tmp)/len(data_tmp))
    data_tmp = []

    # Runs the time test for ECB the specified amount of times
    for i in range(runs):
        # Displays the progress
        progress = progress_bar(progress, 150)
        # Runs the test for ECB
        test = speed_test(file_size, keys[0], 'ECB', iv)
        # Saves the result in a temporary list
        data_tmp.append(test)
    # Writes the the results of every run to a text file
    write_data(data_tmp, 'modes_test_raw ECB')
    # Saves the average of the results in a list
    data.append(sum(data_tmp)/len(data_tmp))
    # Writes the averages from every run to a text file
    write_data(data, 'modes_test')

    # Dilsapys the progress finished
    progress = progress_bar(progress, 150)
    # Prints that the tests is completed
    print("\n")
    print("Completed")
