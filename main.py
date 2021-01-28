# Project  AES implementation
from tkinter import *

import pygame

from AES import AES

# Default values below in case no entry given
# 16 bytes; 128 bits; 10 rounds; need 44 words for 11 rounds ( 10 + 1 initial)
master_key_128_bits = 0x2b7e151628aed2a6abf7158809cf4f3c


# 24 bytes; 192 bits; 12 rounds; need 52 words for 13 rounds (12+ 1 initial)
master_key_192_bits = 0x2b7e151628aed2a6abf7158809cf4f3c1234567891234567
# 32 bytes; 256 bits; 14 rounds; need 60 words for 15 rounds (14 + 1 initial)
master_key_256_bits = 0x2b7e151628aed2a6abf7158809cf4f3c1234567891234567891234ab

plaintext = 0x3243f6a8885a308d313198a2e0370734

# encrypted = AES_instance.encrypt(plaintext)
#
# # ciphertext = 0x3925841d02dc09fbdc118597196a0b32
# decrypted = AES_instance.decrypt(encrypted)

#  print(encrypted)
# print(hex(encrypted))
# print(hex(decrypted))


#######################################################################################################################
#######################################################################################################################
# AES_instance = AES(master_key_128_bits)




def initializer():
    # global AES_instance

    if \
            key_128bit.get() == "" \
                    and key_192bit.get() == "" \
                    and key_256bit.get() == "":
        Label(root, text="default key 0x2b7e151628aed2a6abf7158809cf4f3c").grid(row=7, column=1)
        root.geometry("530x350")
        return AES(master_key_128_bits)



    if \
            key_128bit.get() != "" \
                    and key_192bit.get() != "":
        Label(root, text="Error...Only one key is to be supplied...").grid(row=7, column=1)
        return AES(master_key_128_bits)
    if \
            key_192bit.get() != "" \
                    and key_256bit.get() != "":
        Label(root, text="Error...Only one key is to be supplied...").grid(row=7, column=1)
        return AES(master_key_128_bits)
    if \
            key_128bit.get() != "" \
                    and key_256bit.get() != "":
        Label(root, text="Error...Only one key is to be supplied...").grid(row=7, column=1)
        return AES(master_key_128_bits)

    if key_128bit.get() != "":

        temp = key_128bit.get()
        temp = int(temp, 16)
        AES_instance = AES(temp)

    elif key_192bit.get() != "":
        str_temp = key_192bit.get()

        temp = int(str_temp, 16)

        AES_instance = AES(temp)

    elif key_256bit.get() != "":

        str_temp = key_256bit.get()
        temp = int(str_temp, 16)
        AES_instance = AES(temp)

    return AES_instance


#######################################################################################################################
#######################################################################################################################
#######################################################################################################################
#######################################################################################################################

def get_aes():

    aes_instance = initializer()

    keys_list = aes_instance.round_keys

    new_window = Toplevel(root, bg="#383838")
    new_window.title("Key Expansion")
    new_window.geometry("1840x100")
    # row
    i = 0
    # col
    j = 0

    for x in keys_list:

        for y in x:
            llabel = Label(new_window, text=hex(y), fg="lightblue", bg="#383838")
            llabel.grid(row=i, column=j)
            i += 1

        j += 1
        i = 0


    encryption_window = Toplevel(root, bg="#383838")
    encryption_window.title("Encryption Rounds")

    encryption_window.geometry("1840x100")


    if plain_text.get() != "":
        temp_plaintext = plain_text.get()
        temp_plaintext = int(temp_plaintext, 16)
        encrypted = aes_instance.encrypt(temp_plaintext)
    else:
        encrypted = aes_instance.encrypt(plaintext)

    # row
    i = 0
    # col
    j = 0

    for index in range(len(encrypted)):

        llabel = Label(encryption_window, text=encrypted[index], fg="lightblue", bg="#383838")
        llabel.grid(row=i, column=j)
        i += 1

        if (index + 1) % 4 == 0:
            i = 0
            j += 1

    decryption_window = Toplevel(root, bg="#383838")
    decryption_window.title("Decryption Rounds")
    decryption_window.geometry("1840x100")

    # reference for on join method:
    # https://stackoverflow.com/questions/22204142/how-to-append-a-list-of-hex-to-one-hex-number
    last_round = encrypted[-16:]
    result = '0x' + ''.join([format(int(c, 16), '02X') for c in last_round])
    result = int(result, 16)
    decrypted = aes_instance.decrypt(result)

    # row
    i = 0
    # col
    j = 0

    for index in range(len(decrypted)):

        llabel = Label(decryption_window, text=decrypted[index], fg="lightblue", bg="#383838")
        llabel.grid(row=i, column=j)
        i += 1

        if (index + 1) % 4 == 0:
            i = 0
            j += 1

    print("--------------------------------------------------------------------------------------------")
    print("--------------------------------------------------------------------------------------------")


#######################################################################################################################
#######################################################################################################################
def clear_entries():
    key_128bit.delete(first=0, last=300)
    key_192bit.delete(first=0, last=300)
    key_256bit.delete(first=0, last=300)
    plain_text.delete(first=0, last=300)

#######################################################################################################################
#######################################################################################################################
root = Tk()
root.title("The AES Encrypter")
root.geometry("450x360")

label_128bit_key = Label(root, text="128-bit Key: ", fg="lightblue", bg="#383838")
label_192bit_key = Label(root, text="192-bit Key: ", fg="lightblue", bg="#383838")
label_256bit_key = Label(root, text="256-bit Key: ", fg="lightblue", bg="#383838")
label_plaintext = Label(root, text="plaintext: ", fg="lightblue", bg="#383838")

label_128bit_key.grid(row=0, column=0, pady=2)
label_192bit_key.grid(row=1, column=0, pady=2)
label_256bit_key.grid(row=2, column=0, pady=2)
label_plaintext.grid(row=4, column=0, pady=2)

key_128bit = Entry(root, fg="lightblue", bg="#383838")
key_192bit = Entry(root, fg="lightblue", bg="#383838")
key_256bit = Entry(root, fg="lightblue", bg="#383838")
plain_text = Entry(root, fg="lightblue", bg="#383838")

key_128bit.grid(row=0, column=1, pady=2)
key_192bit.grid(row=1, column=1, pady=2)
key_256bit.grid(row=2, column=1, pady=2)
plain_text.grid(row=4, column=1, pady=2)

# initialize_button = Button(root, text="Click to Initialize", command=initializer, fg="lightblue")
# initialize_button.grid(row=5, column=1, columnspan=2)

# encrypt_button = Button(root, text="Encrypt", command=get_encryption, fg="lightblue")
# encrypt_button.grid(row=6, column=0, pady=2)

keys_button = Button(root, text="Perform AES", command=get_aes, fg="lightblue")
keys_button.grid(row=6, column=1, columnspan=3, pady=2)

# decrypt_button = Button(root, text="Decrypt", command=get_decryption, fg="lightblue")
# decrypt_button.grid(row=6, column=4)

clear_button = Button(root, text="Clear", command=clear_entries, fg="lightblue")
clear_button.grid(row=7, column=0, pady=2)

exit_button = Button(root, text="Exit", command=root.quit, fg="red")
exit_button.grid(row=7, column=4, pady=2)
#######################################################################################################################
#######################################################################################################################
# reference of method: https://platform6.io/2019/03/20/protecting-data-through-encryption-in-a-public-blockchain/
# adding image (remember image should be PNG and not JPG)
# reference for image: https://edit.co.uk/blog/encrypt-data-capture-using-google-tag-manager/
img = PhotoImage(file="encr.png")
img1 = img.subsample(2, 2)
Label(root, image=img1).grid(row=9, column=1,
       columnspan =1, rowspan=2, padx=5, pady=5)
#######################################################################################################################
#######################################################################################################################
root.configure(bg="#383838")
#######################################################################################################################
#######################################################################################################################
root.mainloop()
#######################################################################################################################
#######################################################################################################################
