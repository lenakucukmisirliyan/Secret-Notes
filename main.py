import tkinter
import tkinter.messagebox
from PIL import Image, ImageTk

window = tkinter.Tk()
window.title("Secret Notes")
window.minsize(width=350, height=600)
window.config(padx=50, pady=50)

#photo
img = Image.open("top_secret.jpeg")
img = ImageTk.PhotoImage(img)
image_label = tkinter.Label(window, image=img)
image_label.pack()

#title
title_label = tkinter.Label(text="Enter Your Title")
title_label.pack()

title_input = tkinter.Entry(width=40)
title_input.pack()

#secret
secret_label = tkinter.Label(text="Enter Your Secret")
secret_label.pack()

secret_input = tkinter.Text(width=30,height=15)
secret_input.pack()

#master key
master_key_label = tkinter.Label(text="Enter Your Master Key")
master_key_label.pack()

master_key_input = tkinter.Entry(width=40)
master_key_input.pack()

import base64
def encode(key, clear):
    enc = []
    for i in range(len(clear)):
        key_c = key[i % len(key)]
        enc_c = chr((ord(clear[i]) + ord(key_c)) % 256)
        enc.append(enc_c)
    return base64.urlsafe_b64encode("".join(enc).encode()).decode()

def decode(key, enc):
    dec = []
    enc = base64.urlsafe_b64decode(enc).decode()
    for i in range(len(enc)):
        key_c = key[i % len(key)]
        dec_c = chr((256 + ord(enc[i]) - ord(key_c)) % 256)
        dec.append(dec_c)
    return "".join(dec)

def save_and_encrypt():
    title = title_input.get()
    secret_message = secret_input.get("1.0", tkinter.END)
    master_key = master_key_input.get()

    if title == "" or secret_message == "" or master_key == "":
        tkinter.messagebox.showerror(title=None, message="Please enter all info")
    else:
        message_encrypted = encode(master_key, secret_message)

        with open("my_file.txt", mode= "a") as file_object:
            file_object.write(title + "\n" + message_encrypted + "\n")
    def cleaning_widget():
        title_input.delete(0,tkinter.END)
        secret_input.delete("1.0",tkinter.END)
        master_key_input.delete(0,tkinter.END)
    cleaning_widget()

def decrypt():
    master_key = master_key_input.get()
    message_encrypted = secret_input.get("1.0", tkinter.END)

    if message_encrypted == "" or master_key == "":
        tkinter.messagebox.showerror(title="Error", message="Please enter all info")
    else:
        try:
            decrypted_message = decode(master_key, message_encrypted)
            secret_input.delete("1.0", tkinter.END)
            secret_input.insert("1.0", decrypted_message)
        except:
            tkinter.messagebox.showerror(title="Error", message="Please enter encrypted text!")

#buttons
save_and_encrypt_button = tkinter.Button(text="Save & Encrypt",command=save_and_encrypt)
save_and_encrypt_button.pack()

decrypt_button = tkinter.Button(text="Decrypt", command=decrypt)
decrypt_button.pack()

window.mainloop()