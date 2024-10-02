from tkinter import *
from tkinter import messagebox
from tkinter import filedialog
import random
import tkinter as tk
from math import sqrt



def screen_one():
    global screen1
    screen1 = tk.Toplevel(screen)
    screen1.title("Shift Cipher")
    screen1.geometry("500x500")

    mode = tk.StringVar()
    mode.set("Encrypt")

    def caesar(plainText, shift, mode):
        result = ""
        for ch in plainText:
            if ch.isalpha():
                stayInAlphabet = ord(ch) + shift if mode == "Encrypt" else ord(ch) - shift
                if ch.islower():
                    if stayInAlphabet > ord('z'):
                        stayInAlphabet -= 26
                    elif stayInAlphabet < ord('a'):
                        stayInAlphabet += 26
                elif ch.isupper():
                    if stayInAlphabet > ord('Z'):
                        stayInAlphabet -= 26
                    elif stayInAlphabet < ord('A'):
                        stayInAlphabet += 26
                result += chr(stayInAlphabet)
            else:
                result += ch
        return result

    def process():
        plain_text = plaintext_entry.get().strip()
        shift = shift_entry.get().strip()
        current_mode = mode.get()

        if not plain_text:
            messagebox.showerror("Error", "Please enter a text")
            return

        if not shift:
            messagebox.showerror("Error", "Please enter a shift value")
            return

        if not plain_text.isalpha():
            messagebox.showerror("Error", "Input text should only contain alphabetic characters")
            return

        try:
            shift = int(shift)
            if current_mode == "Encrypt":
                result = caesar(plain_text, shift, "Encrypt")
                encrypted_text_display.delete(1.0, tk.END)
                encrypted_text_display.insert(tk.END, result)
            else:
                result = caesar(plain_text, shift, "Decrypt")
                decrypted_text_display.delete(1.0, tk.END)
                decrypted_text_display.insert(tk.END, result)
        except ValueError:
            messagebox.showerror("Error", "Shift value should be an integer")

    def encrypt_file():
        file_path = filedialog.askopenfilename()
        if file_path:
            with open(file_path, 'r') as file:
                plain_text = file.read()
            shift = int(shift_entry.get())
            result = caesar(plain_text, shift, "Encrypt")
            encrypted_file_path = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text files", "*.txt")])
            if encrypted_file_path:
                with open(encrypted_file_path, 'w') as encrypted_file:
                    encrypted_file.write(result)
                messagebox.showinfo("Success", "File encrypted successfully.")

    def decrypt_file():
        file_path = filedialog.askopenfilename()
        if file_path:
            with open(file_path, 'r') as file:
                encrypted_text = file.read()
            shift = int(shift_entry.get())
            result = caesar(encrypted_text, shift, "Decrypt")
            decrypted_file_path = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text files", "*.txt")])
            if decrypted_file_path:
                with open(decrypted_file_path, 'w') as decrypted_file:
                    decrypted_file.write(result)
                messagebox.showinfo("Success", "File decrypted successfully.")

    plaintext_label = tk.Label(screen1, text="Text:", font=("Arial", 12), padx=10, pady=5, anchor="w")
    plaintext_label.grid(row=0, column=0)

    plaintext_entry = tk.Entry(screen1, width=30, font=("Arial", 12))
    plaintext_entry.grid(row=0, column=1)

    shift_label = tk.Label(screen1, text="Shift:", font=("Arial", 12), padx=10, pady=5, anchor="w")
    shift_label.grid(row=1, column=0)

    shift_entry = tk.Entry(screen1, width=30, font=("Arial", 12))
    shift_entry.grid(row=1, column=1)

    mode_label = tk.Label(screen1, text="Mode:", font=("Arial", 12), padx=10, pady=5, anchor="w")
    mode_label.grid(row=2, column=0)

    mode_menu = tk.OptionMenu(screen1, mode, "Encrypt", "Decrypt")
    mode_menu.config(width=27, font=("Arial", 12), padx=10, pady=5)
    mode_menu.grid(row=2, column=1)

    process_button = tk.Button(screen1, text="Process", command=process, font=("Arial", 12), padx=10, pady=5)
    process_button.grid(row=3, column=0, columnspan=2)

    encrypted_label = tk.Label(screen1, text="Encrypted Text:", font=("Arial", 12), padx=10, pady=5, anchor="w")
    encrypted_label.grid(row=4, column=0, sticky="w")

    decrypted_label = tk.Label(screen1, text="Decrypted Text:", font=("Arial", 12), padx=10, pady=5, anchor="w")
    decrypted_label.grid(row=5, column=0, sticky="w")

    encrypted_text_display = tk.Text(screen1, width=40, height=5, font=("Arial", 12), padx=10, pady=5)
    encrypted_text_display.grid(row=4, column=1)

    decrypted_text_display = tk.Text(screen1, width=40, height=5, font=("Arial", 12), padx=10, pady=5)
    decrypted_text_display.grid(row=5, column=1)

    encrypt_file_button = tk.Button(screen1, text="Encrypt File", command=encrypt_file, font=("Arial", 12), padx=10,
                                    pady=5)
    encrypt_file_button.grid(row=6, column=0, padx=10, pady=10)

    decrypt_file_button = tk.Button(screen1, text="Decrypt File", command=decrypt_file, font=("Arial", 12), padx=10,
                                    pady=5)
    decrypt_file_button.grid(row=6, column=1, padx=10, pady=10)


    for widget in screen1.winfo_children():
        if isinstance(widget, tk.Button):
            widget.config(bg="#007bff", fg="white", activebackground="#0056b3", activeforeground="white")

        if isinstance(widget, (tk.Entry, tk.Text)):
            widget.config(bg="#f0f0f0", relief="solid", borderwidth=1)

    screen1.grid_columnconfigure(1, weight=1)  # Make second column expandable


    for child in screen1.winfo_children():
        child.grid_configure(padx=10, pady=5)


def screen_two():

    global screen2
    screen2 = Toplevel(screen)
    screen2.title("Affine Cipher")

    def are_coprime(a, b):
        while b != 0:
            a, b = b, a % b
        return a == 1

    def is_numeric(s):
        return s.isdigit()


    def mod_inverse(a, m):
        for x in range(1, m):
            if (a * x) % m == 1:
                return x
        return None


    def affine_cipher_encrypt(plaintext, key_a, key_b):
        ciphertext = ""
        for char in plaintext:
            if char.isalpha():
                is_upper = char.isupper()
                x = ord(char.upper()) - ord('A')
                encrypted_value = (key_a * x + key_b) % 26
                encrypted_char = chr(encrypted_value + ord('A'))
                if not is_upper:
                    encrypted_char = encrypted_char.lower()
                ciphertext += encrypted_char
            else:
                messagebox.showerror("Error", "Message must contain only alphabetic characters")
                return ""
        return ciphertext

    def affine_cipher_decrypt(ciphertext, key_a, key_b):
        a_inv = 0
        for i in range(26):
            if (key_a * i) % 26 == 1:
                a_inv = i
                break
        plaintext = ""
        for char in ciphertext:
            if char.isalpha():
                is_upper = char.isupper()
                x = ord(char.upper()) - ord('A')
                decrypted_value = (a_inv * (x - key_b)) % 26
                decrypted_char = chr(decrypted_value + ord('A'))
                if not is_upper:
                    decrypted_char = decrypted_char.lower()
                plaintext += decrypted_char
            else:
                messagebox.showerror("Error", "Ciphertext must contain only alphabetic characters")
                return ""
        return plaintext

    def encrypt():
        plaintext = entry_plain.get().strip()
        key_a = entry_key_a.get().strip()
        key_b = entry_key_b.get().strip()

        if not plaintext:
            messagebox.showerror("Error", "Please enter a message")
            return

        if not is_numeric(key_a) or not is_numeric(key_b):
            messagebox.showerror("Error", "Keys must be numeric")
            return

        key_a_int = int(key_a)
        key_b_int = int(key_b)

        if not are_coprime(key_a_int, 26):
            messagebox.showerror("Error", "Key 'a' must be coprime with 26")
            return

        if not (0 <= key_b_int <= 25):
            messagebox.showerror("Error", "Key 'b' must be in the range 0 to 25")
            return

        ciphertext = affine_cipher_encrypt(plaintext, key_a_int, key_b_int)
        entry_result.delete(0, END)
        entry_result.insert(0, ciphertext)

    def decrypt():
        ciphertext = entry_plain.get().strip()
        key_a = entry_key_a.get().strip()
        key_b = entry_key_b.get().strip()

        if not ciphertext:
            messagebox.showerror("Error", "Please enter a ciphertext")
            return

        if not is_numeric(key_a) or not is_numeric(key_b):
            messagebox.showerror("Error", "Keys must be numeric")
            return

        key_a_int = int(key_a)
        key_b_int = int(key_b)

        if not are_coprime(key_a_int, 26):
            messagebox.showerror("Error", "Key 'a' must be coprime with 26")
            return

        if not (0 <= key_b_int <= 25):
            messagebox.showerror("Error", "Key 'b' must be in the range 0 to 25")
            return

        plaintext = affine_cipher_decrypt(ciphertext, key_a_int, key_b_int)
        entry_result.delete(0, END)
        entry_result.insert(0, plaintext)


    def encrypt_file():
        filename = filedialog.askopenfilename(title="Select file to encrypt")
        if filename:
            try:
                with open(filename, 'r') as file:
                    plaintext = file.read()
            except Exception as e:
                messagebox.showerror("Error", f"Failed to read file: {e}")
                return

            key_a = int(entry_key_a.get())
            key_b = int(entry_key_b.get())

            if not are_coprime(key_a, 26):
                messagebox.showerror("Error", "Key 'a' must be coprime with 26")
                return

            ciphertext = affine_cipher_encrypt(plaintext, key_a, key_b)

            save_filename = filedialog.asksaveasfilename(title="Save encrypted file as", defaultextension=".txt")
            if save_filename:
                try:
                    with open(save_filename, 'w') as file:
                        file.write(ciphertext)
                    messagebox.showinfo("Success", "File encrypted and saved successfully")
                except Exception as e:
                    messagebox.showerror("Error", f"Failed to save encrypted file: {e}")


    def decrypt_file():
        filename = filedialog.askopenfilename(title="Select file to decrypt")
        if filename:
            try:
                with open(filename, 'r') as file:
                    ciphertext = file.read()
            except Exception as e:
                messagebox.showerror("Error", f"Failed to read file: {e}")
                return

            key_a = int(entry_key_a.get())
            key_b = int(entry_key_b.get())

            if not are_coprime(key_a, 26):
                messagebox.showerror("Error", "Key 'a' must be coprime with 26")
                return

            plaintext = affine_cipher_decrypt(ciphertext, key_a, key_b)

            save_filename = filedialog.asksaveasfilename(title="Save decrypted file as", defaultextension=".txt")
            if save_filename:
                try:
                    with open(save_filename, 'w') as file:
                        file.write(plaintext)
                    messagebox.showinfo("Success", "File decrypted and saved successfully")
                except Exception as e:
                    messagebox.showerror("Error", f"Failed to save decrypted file: {e}")

    label_plain = tk.Label(screen2, text="Message:", font=("Arial", 12))
    label_plain.grid(row=0, column=0, padx=10, pady=5, sticky="w")
    entry_plain = tk.Entry(screen2, width=50, font=("Arial", 12))
    entry_plain.grid(row=0, column=1, padx=10, pady=5)

    label_key_a = tk.Label(screen2, text="Key 'a' (must be coprime with 26):", font=("Arial", 12))
    label_key_a.grid(row=1, column=0, padx=10, pady=5, sticky="w")
    entry_key_a = tk.Entry(screen2, width=10, font=("Arial", 12))
    entry_key_a.grid(row=1, column=1, padx=10, pady=5)

    label_key_b = tk.Label(screen2, text="Key 'b':", font=("Arial", 12))
    label_key_b.grid(row=2, column=0, padx=10, pady=5, sticky="w")
    entry_key_b = tk.Entry(screen2, width=10, font=("Arial", 12))
    entry_key_b.grid(row=2, column=1, padx=10, pady=5)

    button_encrypt = tk.Button(screen2, text="Encrypt", width=10, command=encrypt, font=("Arial", 12))
    button_encrypt.grid(row=3, column=0, padx=10, pady=10)

    button_decrypt = tk.Button(screen2, text="Decrypt", width=10, command=decrypt, font=("Arial", 12))
    button_decrypt.grid(row=3, column=1, padx=10, pady=10)

    label_result = tk.Label(screen2, text="Result:", font=("Arial", 12))
    label_result.grid(row=4, column=0, padx=10, pady=5, sticky="w")
    entry_result = tk.Entry(screen2, width=50, font=("Arial", 12))
    entry_result.grid(row=4, column=1, padx=10, pady=5)

    button_encrypt_file = tk.Button(screen2, text="Encrypt File", width=12, command=encrypt_file, font=("Arial", 12))
    button_encrypt_file.grid(row=5, column=0, padx=10, pady=10)

    button_decrypt_file = tk.Button(screen2, text="Decrypt File", width=12, command=decrypt_file, font=("Arial", 12))
    button_decrypt_file.grid(row=5, column=1, padx=10, pady=10)


    for widget in screen2.winfo_children():
        if isinstance(widget, tk.Button):
            widget.config(bg="#007bff", fg="white", activebackground="#0056b3", activeforeground="white")

        if isinstance(widget, tk.Entry):
            widget.config(bg="#f0f0f0", relief="solid", font=("Arial", 12), borderwidth=1)

    screen2.grid_columnconfigure(1, weight=1)


    for child in screen2.winfo_children():
        child.grid_configure(padx=10, pady=5)



def rot13_encrypt(plain_text, key):
    encrypted_text = ""
    for char in plain_text:
        if 'A' <= char <= 'Z':
            encrypted_text += chr((ord(char) - ord('A') + key) % 26 + ord('A'))
        elif 'a' <= char <= 'z':
            encrypted_text += chr((ord(char) - ord('a') + key) % 26 + ord('a'))
        else:
            encrypted_text += char
    return encrypted_text

#
def rot13_decrypt(encrypted_text, key):
    return rot13_encrypt(encrypted_text, key)


def process_operation(operation):
    global counter
    key = counter * 13
    counter += 1

    if operation == "Encrypt":
        plain_text = input_text.get("1.0", "end-1c").strip()
        if not plain_text:
            messagebox.showerror("Error", "Input text cannot be empty")
            return
        if not plain_text.isalpha():
            messagebox.showerror("Error", "Plaintext should only contain alphabetic characters")
            return
        encrypted_text = rot13_encrypt(plain_text, key)
        output_text.delete("1.0", tk.END)
        output_text.insert(tk.END, encrypted_text)
    elif operation == "Decrypt":
        encrypted_text = input_text.get("1.0", "end-1c").strip()
        if not encrypted_text:
            messagebox.showerror("Error", "Input text cannot be empty")
            return
        decrypted_text = rot13_decrypt(encrypted_text, key)
        output_text.delete("1.0", tk.END)
        output_text.insert(tk.END, decrypted_text)
    else:
        messagebox.showerror("Error", "Invalid operation selected")

def encrypt_file():
    file_path = filedialog.askopenfilename()
    if file_path:
        with open(file_path, 'r') as file:
            text = file.read().strip()
        result = rot13_encrypt(text, counter * 13)
        save_file(result)

def decrypt_file():
    file_path = filedialog.askopenfilename()
    if file_path:
        with open(file_path, 'r') as file:
            text = file.read().strip()
        result = rot13_decrypt(text, counter * 13)
        save_file(result)

def save_file(result):
    file_path = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text files", "*.txt")])
    if file_path:
        with open(file_path, 'w') as encrypted_file:
            encrypted_file.write(result)



def screen_three():
    global counter
    counter = 1
    screen3 = tk.Toplevel(screen)
    screen3.title("Rote 13 Cipher")
    screen3.geometry("400x400")
    screen3.config(bg="#f0f0f0")


    operation_var = tk.StringVar()
    operation_var.set("Encrypt")
    operation_label = tk.Label(screen3, text="Select Operation:", bg="#f0f0f0")
    operation_label.pack(pady=5)


    encrypt_button = tk.Button(screen3, text="Encrypt", command=lambda: process_operation("Encrypt"), bg="#4CAF50",
                               fg="white", bd=0)
    encrypt_button.pack(anchor="w")

    decrypt_button = tk.Button(screen3, text="Decrypt", command=lambda: process_operation("Decrypt"), bg="#4CAF50",
                               fg="white", bd=0)
    decrypt_button.pack(anchor="w")


    encrypt_file_button = tk.Button(screen3, text="Encrypt File", command=encrypt_file, bg="#4CAF50", fg="white", bd=0)
    encrypt_file_button.pack(anchor="w")

    decrypt_file_button = tk.Button(screen3, text="Decrypt File", command=decrypt_file, bg="#4CAF50", fg="white", bd=0)
    decrypt_file_button.pack(anchor="w")


    input_label = tk.Label(screen3, text="Enter Text:", bg="#f0f0f0")
    input_label.pack(pady=5)
    global input_text
    input_text = tk.Text(screen3, width=50, height=4)
    input_text.pack()


    output_label = tk.Label(screen3, text="Result:", bg="#f0f0f0")
    output_label.pack(pady=5)
    global output_text
    output_text = tk.Text(screen3, width=50, height=4)
    output_text.pack()


    process_button = tk.Button(screen3, text="Process", command=lambda: process_operation(operation_var.get()),
                               bg="#4CAF50", fg="white", bd=0)
    process_button.pack(pady=10)

def screen_four():
    def vigenere_encrypt(plain_text, key):
        encrypted_text = ""
        key_length = len(key)
        j = 0
        for i, char in enumerate(plain_text):
            if char.isalpha():
                shift = ord(key[j % key_length].upper()) - ord('A')
                j += 1
                if char.isupper():
                    encrypted_text += chr((ord(char) + shift - ord('A')) % 26 + ord('A'))
                else:
                    encrypted_text += chr((ord(char) + shift - ord('a')) % 26 + ord('a'))
            else:
                encrypted_text += char
        return encrypted_text

    def vigenere_decrypt(encrypted_text, key):
        decrypted_text = ""
        key_length = len(key)
        j = 0
        for i, char in enumerate(encrypted_text):
            if char.isalpha():
                shift = ord(key[j % key_length].upper()) - ord('A')
                j += 1
                if char.isupper():
                    decrypted_text += chr((ord(char) - shift - ord('A')) % 26 + ord('A'))
                else:
                    decrypted_text += chr((ord(char) - shift - ord('a')) % 26 + ord('a'))
            else:
                decrypted_text += char
        return decrypted_text

    def process_operation(operation):
        input_text = plain_text_entry.get().strip()
        key = key_entry.get().strip()

        if not input_text:
            messagebox.showerror("Error", "Input text cannot be empty")
            return
        if not input_text.isalpha():
            messagebox.showerror("Error", "Input text should only contain alphabetic characters")
            return
        if not key:
            messagebox.showerror("Error", "Key cannot be empty")
            return
        if not key.isalpha():
            messagebox.showerror("Error", "Key should only contain alphabetic characters")
            return

        if operation == "Encrypt":
            result = vigenere_encrypt(input_text, key)
        elif operation == "Decrypt":
            result = vigenere_decrypt(input_text, key)
        else:
            messagebox.showerror("Error", "Invalid operation selected")
            return

        output_text.delete(1.0, tk.END)
        output_text.insert(tk.END, result)

    def encrypt_file():
        file_path = filedialog.askopenfilename()
        if file_path:
            with open(file_path, 'r') as file:
                text = file.read().strip()
            key = key_entry.get()
            if not text.isalpha():
                messagebox.showerror("Error", "Input text in the file should only contain alphabetic characters")
                return
            result = vigenere_encrypt(text, key)
            encrypted_file_path = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text files", "*.txt")])
            if encrypted_file_path:
                with open(encrypted_file_path, 'w') as encrypted_file:
                    encrypted_file.write(result)

    def decrypt_file():
        file_path = filedialog.askopenfilename()
        if file_path:
            with open(file_path, 'r') as file:
                text = file.read().strip()
            key = key_entry.get()
            if not text.isalpha():
                messagebox.showerror("Error", "Input text in the file should only contain alphabetic characters")
                return
            result = vigenere_decrypt(text, key)
            decrypted_file_path = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text files", "*.txt")])
            if decrypted_file_path:
                with open(decrypted_file_path, 'w') as decrypted_file:
                    decrypted_file.write(result)

    screen4 = tk.Toplevel(screen)
    screen4.title("Vigenere Cipher")
    screen4.geometry("450x500")
    screen4.config(bg="#f0f0f0")


    label_font = ("Helvetica", 12)
    button_font = ("Helvetica", 12, "bold")


    plain_text_label = tk.Label(screen4, text="Enter Text:", font=label_font, bg="#f0f0f0")
    plain_text_label.pack(pady=5)
    plain_text_entry = tk.Entry(screen4, width=40, font=label_font)
    plain_text_entry.pack()

    key_label = tk.Label(screen4, text="Enter Key:", font=label_font, bg="#f0f0f0")
    key_label.pack(pady=5)
    key_entry = tk.Entry(screen4, width=40, font=label_font)
    key_entry.pack()


    operation_var = tk.StringVar()
    operation_var.set("Encrypt")
    operation_label = tk.Label(screen4, text="Select Operation:", font=label_font, bg="#f0f0f0")
    operation_label.pack(pady=5)
    encrypt_radio = tk.Radiobutton(screen4, text="Encrypt", variable=operation_var, value="Encrypt", font=label_font, bg="#f0f0f0")
    encrypt_radio.pack(anchor="center")
    decrypt_radio = tk.Radiobutton(screen4, text="Decrypt", variable=operation_var, value="Decrypt", font=label_font, bg="#f0f0f0")
    decrypt_radio.pack(anchor="center")


    process_button = tk.Button(screen4, text="Process", command=lambda: process_operation(operation_var.get()),
                               font=button_font, bg="#4CAF50", fg="white")
    process_button.pack(pady=10)


    encrypt_file_button = tk.Button(screen4, text="Encrypt File", command=encrypt_file, font=button_font, bg="#4CAF50", fg="white")
    encrypt_file_button.pack(pady=5)

    decrypt_file_button = tk.Button(screen4, text="Decrypt File", command=decrypt_file, font=button_font, bg="#4CAF50", fg="white")
    decrypt_file_button.pack(pady=5)


    output_label = tk.Label(screen4, text="Result:", font=label_font, bg="#f0f0f0")
    output_label.pack(pady=5)
    output_text = tk.Text(screen4, width=40, height=6, font=label_font)
    output_text.pack()

def screen_five():

    def remove_spaces(key):
        return ''.join(key.split())

    def substitute(message, key, decrypt=False):
        translated = ''
        for symbol in message:
            if symbol.upper() in LETTERS:
                if decrypt:
                    sym_index = key.find(symbol.upper())
                else:
                    sym_index = LETTERS.find(symbol.upper())
                if symbol.isupper():
                    translated += key[sym_index].upper()
                else:
                    translated += key[sym_index].lower()
            else:
                translated += symbol
        return translated

    def process_message():
        message = plain_text_entry.get()
        operation = operation_var.get()

        key = GENERATED_KEY


        if not message.isalpha():
            messagebox.showerror("Error", "Invalid input. The message must contain only alphabetic characters.")
            return

        if operation == "Encrypt":
            translated = substitute(message, key)
        elif operation == "Decrypt":
            translated = substitute(message, key, decrypt=True)
        else:
            messagebox.showerror("Error", "Invalid operation selected")
            return

        result_text.delete(1.0, tk.END)
        result_text.insert(tk.END, f"{operation}ed message: {translated}")


    LETTERS = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    GENERATED_KEY = ''.join(random.sample(LETTERS, len(LETTERS)))

    screen5 = tk.Toplevel(screen)
    screen5.title("Substitution Cipher")
    screen5.geometry("400x300")
    screen5.configure(bg="#f0f0f0")


    plain_text_label = tk.Label(screen5, text="Enter Plain Text:", bg="#f0f0f0", font=("Arial", 12))
    plain_text_label.pack(pady=(10, 5))


    plain_text_entry = tk.Entry(screen5, width=50, font=("Arial", 10))
    plain_text_entry.pack(pady=5)

    operation_label = tk.Label(screen5, text="Select Operation:", bg="#f0f0f0", font=("Arial", 12))
    operation_label.pack()




    operation_var = tk.StringVar()
    operation_var.set("Encrypt")
    encrypt_radio = tk.Radiobutton(screen5, text="Encrypt", variable=operation_var, value="Encrypt", bg="#f0f0f0", font=("Arial", 10))
    encrypt_radio.pack(anchor="center")
    decrypt_radio = tk.Radiobutton(screen5, text="Decrypt", variable=operation_var, value="Decrypt", bg="#f0f0f0", font=("Arial", 10))
    decrypt_radio.pack(anchor="center")

    key_label = tk.Label(screen5, text="Generated Key:", bg="#f0f0f0", font=("Arial", 12))
    key_label.pack()


    generated_key_label = tk.Label(screen5, text=GENERATED_KEY, bg="#f0f0f0", font=("Arial", 10))
    generated_key_label.pack(pady=(0, 10))


    process_button = tk.Button(screen5, text="Process", command=process_message, bg="#007bff", fg="white", font=("Arial", 12))
    process_button.pack(pady=(5, 10))


    result_text = tk.Text(screen5, width=60, height=5, font=("Arial", 10))
    result_text.pack()


def screen_six():
    global screen6
    screen6 = Toplevel(screen)
    screen6.title("Rail Fence Cipher")
    screen6.geometry("750x400")
    screen6.configure(bg="#f0f0f0")

    def encrypt(text, key):
        rail = [''] * key
        direction = 1
        index = 0

        for char in text:
            rail[index] += char
            index += direction

            if index == key - 1 or index == 0:
                direction *= -1

        return ''.join(rail)

    def decrypt(text, key):
        rail = [''] * key
        direction = 1
        index = 0

        for char in text:
            rail[index] += '*'
            index += direction

            if index == key - 1 or index == 0:
                direction *= -1

        plaintext = ''
        text_index = 0

        for r in range(key):
            for c in range(len(text)):
                if c < len(rail[r]) and rail[r][c] == '*':
                    rail[r] = rail[r][:c] + text[text_index] + rail[r][c + 1:]
                    text_index += 1

        direction = 1
        index = 0
        result = ''

        for i in range(len(text)):
            if index < len(rail) and rail[index]:
                result += rail[index][0]
                rail[index] = rail[index][1:]
                index += direction

                if index == key - 1 or index == 0:
                    direction *= -1

        return result

    def is_valid_input(text):
        return all(char.isalpha() or char.isspace() for char in text)

    def encrypt_text():
        plaintext = plaintext_entry.get()
        if not is_valid_input(plaintext):
            messagebox.showerror("Error", "Plaintext must contain only alphabetic characters")
            return
        key = int(key_entry.get())
        ciphertext = encrypt(plaintext, key)
        ciphertext_display.delete(1.0, "end")
        ciphertext_display.insert("end", ciphertext)

    def decrypt_text():
        ciphertext = ciphertext_entry.get()
        if not is_valid_input(ciphertext):
            messagebox.showerror("Error", "Ciphertext must contain only alphabetic characters")
            return
        key = int(key_entry.get())
        plaintext = decrypt(ciphertext, key)
        plaintext_display.delete(1.0, "end")
        plaintext_display.insert("end", plaintext)

    def encrypt_file():
        file_path = filedialog.askopenfilename()
        if not file_path:
            return
        try:
            with open(file_path, 'r') as file:
                plaintext = file.read()
        except Exception as e:
            messagebox.showerror("Error", f"Error reading file: {str(e)}")
            return
        key = int(key_entry.get())
        ciphertext = encrypt(plaintext, key)
        with open(file_path + '.enc', 'w') as file:
            file.write(ciphertext)
        messagebox.showinfo("Success", "File encrypted successfully")

    def decrypt_file():
        file_path = filedialog.askopenfilename()
        if not file_path:
            return
        try:
            with open(file_path, 'r') as file:
                ciphertext = file.read()
        except Exception as e:
            messagebox.showerror("Error", f"Error reading file: {str(e)}")
            return
        key = int(key_entry.get())
        plaintext = decrypt(ciphertext, key)
        with open(file_path[:-4], 'w') as file:
            file.write(plaintext)
        messagebox.showinfo("Success", "File decrypted successfully")


    plaintext_label = Label(screen6, text="Plaintext:", bg="#f0f0f0", font=("Arial", 12))
    plaintext_label.grid(row=0, column=0, padx=10, pady=5)

    ciphertext_label = Label(screen6, text="Ciphertext:", bg="#f0f0f0", font=("Arial", 12))
    ciphertext_label.grid(row=0, column=1, padx=10, pady=5)

    key_label = Label(screen6, text="Number of Key:", bg="#f0f0f0", font=("Arial", 12))
    key_label.grid(row=2, column=0, padx=10, pady=5)


    plaintext_entry = Entry(screen6, width=50, font=("Arial", 10))
    plaintext_entry.grid(row=1, column=0, padx=10, pady=5)

    ciphertext_entry = Entry(screen6, width=50, font=("Arial", 10))
    ciphertext_entry.grid(row=1, column=1, padx=10, pady=5)

    key_entry = Entry(screen6, width=10, font=("Arial", 10))
    key_entry.grid(row=3, column=0, padx=10, pady=5)


    plaintext_display = Text(screen6, width=50, height=5, font=("Arial", 10))
    plaintext_display.grid(row=4, column=0, padx=10, pady=5)

    ciphertext_display = Text(screen6, width=50, height=5, font=("Arial", 10))
    ciphertext_display.grid(row=4, column=1, padx=10, pady=5)


    encrypt_button = Button(screen6, text="Encrypt", command=encrypt_text, bg="#007bff", fg="white", font=("Arial", 12))
    encrypt_button.grid(row=5, column=0, padx=10, pady=5)

    decrypt_button = Button(screen6, text="Decrypt", command=decrypt_text, bg="#007bff", fg="white", font=("Arial", 12))
    decrypt_button.grid(row=5, column=1, padx=10, pady=5)

    encrypt_file_button = Button(screen6, text="Encrypt File", command=encrypt_file, bg="#007bff", fg="white", font=("Arial", 12))
    encrypt_file_button.grid(row=6, column=0, padx=10, pady=5)

    decrypt_file_button = Button(screen6, text="Decrypt File", command=decrypt_file, bg="#007bff", fg="white", font=("Arial", 12))
    decrypt_file_button.grid(row=6, column=1, padx=10, pady=5)


def screen_seven():
    global screen7
    screen7 = Toplevel(screen)
    screen7.title("Hill Cipher")
    screen7.geometry("500x500")
    screen7.configure(bg="#f0f0f0")


    def convert_key_to_matrix(key):
        key = key.replace(" ", "").upper()
        key_size = int(sqrt(len(key)))
        if key_size * key_size != len(key):
            return None
        key_matrix = [[ord(char) - ord('A') for char in key[i:i + key_size]] for i in range(0, len(key), key_size)]
        return key_matrix


    def encrypt_hill(message, key):
        key_matrix = convert_key_to_matrix(key)
        if key_matrix is None:
            return "Error: Key must be a square matrix of letters."
        while len(message) % len(key_matrix) != 0:
            message += 'X'
        message_matrix = [[ord(char) - ord('A') for char in message.upper()]]
        message_matrix = [message_matrix[0][i:i + len(key_matrix)] for i in
                          range(0, len(message_matrix[0]), len(key_matrix))]

        encrypted_matrix = []
        for row in message_matrix:
            encrypted_row = []
            for i in range(len(key_matrix)):
                sum_val = 0
                for j in range(len(key_matrix)):
                    sum_val += row[j] * key_matrix[i][j]
                encrypted_row.append(sum_val % 26)
            encrypted_matrix.append(encrypted_row)

        encrypted_message = ''.join([chr(num + ord('A')) for row in encrypted_matrix for num in row])
        return encrypted_message


    def decrypt_hill(message, key):
        key_matrix = convert_key_to_matrix(key)
        if key_matrix is None:
            return "Error: Key must be a square matrix of letters."

        key_size = len(key_matrix)
        if key_size != 2 and key_size != 3:
            return "Error: Key matrix size must be 2x2 or 3x3."

        try:
            if key_size == 2:
                determinant = key_matrix[0][0] * key_matrix[1][1] - key_matrix[0][1] * key_matrix[1][0]
                det_inv = pow(determinant, -1, 26)
                key_matrix_inv = [
                    [(key_matrix[1][1] * det_inv) % 26, (-key_matrix[0][1] * det_inv) % 26],
                    [(-key_matrix[1][0] * det_inv) % 26, (key_matrix[0][0] * det_inv) % 26]
                ]
            else:
                determinant = key_matrix[0][0] * key_matrix[1][1] * key_matrix[2][2] + \
                              key_matrix[0][1] * key_matrix[1][2] * key_matrix[2][0] + \
                              key_matrix[0][2] * key_matrix[1][0] * key_matrix[2][1] - \
                              key_matrix[0][2] * key_matrix[1][1] * key_matrix[2][0] - \
                              key_matrix[0][1] * key_matrix[1][0] * key_matrix[2][2] - \
                              key_matrix[0][0] * key_matrix[1][2] * key_matrix[2][1]
                det_inv = pow(determinant, -1, 26)
                adjugate_matrix = [
                    [
                        (key_matrix[1][1] * key_matrix[2][2] - key_matrix[1][2] * key_matrix[2][1]) * det_inv % 26,
                        (key_matrix[0][2] * key_matrix[2][1] - key_matrix[0][1] * key_matrix[2][2]) * det_inv % 26,
                        (key_matrix[0][1] * key_matrix[1][2] - key_matrix[0][2] * key_matrix[1][1]) * det_inv % 26
                    ],
                    [
                        (key_matrix[1][2] * key_matrix[2][0] - key_matrix[1][0] * key_matrix[2][2]) * det_inv % 26,
                        (key_matrix[0][0] * key_matrix[2][2] - key_matrix[0][2] * key_matrix[2][0]) * det_inv % 26,
                        (key_matrix[0][2] * key_matrix[1][0] - key_matrix[0][0] * key_matrix[1][2]) * det_inv % 26
                    ],
                    [
                        (key_matrix[1][0] * key_matrix[2][1] - key_matrix[1][1] * key_matrix[2][0]) * det_inv % 26,
                        (key_matrix[0][1] * key_matrix[2][0] - key_matrix[0][0] * key_matrix[2][1]) * det_inv % 26,
                        (key_matrix[0][0] * key_matrix[1][1] - key_matrix[0][1] * key_matrix[1][0]) * det_inv % 26
                    ]
                ]
                key_matrix_inv = adjugate_matrix

        except ValueError:
            return "Error: Key is not invertible."

        message_matrix = [[ord(char) - ord('A') for char in message]]
        message_matrix = [message_matrix[0][i:i + key_size] for i in range(0, len(message_matrix[0]), key_size)]

        decrypted_matrix = []
        for row in message_matrix:
            decrypted_row = []
            for i in range(key_size):
                sum_val = 0
                for j in range(key_size):
                    sum_val += row[j] * key_matrix_inv[i][j]
                decrypted_row.append(sum_val % 26)
            decrypted_matrix.append(decrypted_row)

        decrypted_message = ''.join([chr(int(num) + ord('A')) for row in decrypted_matrix for num in row])
        return decrypted_message

    def contains_only_alpha(input_str):
        return input_str.isalpha()


    def process_encryption():
        message = input_text.get()
        key = key_entry.get()

        if not contains_only_alpha(message) or not contains_only_alpha(key):
            messagebox.showerror("Error", "Input must contain only alphabetic characters.")
            return

        encrypted_message = encrypt_hill(message, key)
        output_text.delete(0, END)
        output_text.insert(0, encrypted_message)


    def process_decryption():
        message = input_text.get()
        key = key_entry.get()

        if not contains_only_alpha(message) or not contains_only_alpha(key):
            messagebox.showerror("Error", "Input must contain only alphabetic characters.")
            return

        decrypted_message = decrypt_hill(message, key)
        output_text.delete(0, END)
        output_text.insert(0, decrypted_message)


    def encrypt_file_hill():
        filename = filedialog.askopenfilename(initialdir="/", title="Select file",
                                              filetypes=(("Text files", "*.txt"), ("All files", "*.*")))
        if filename:
            with open(filename, "r") as file:
                message = file.read()
            key = key_entry.get()
            encrypted_message = encrypt_hill(message, key)
            output_text.delete(0, END)
            output_text.insert(0, encrypted_message)


    def decrypt_file_hill():
        filename = filedialog.askopenfilename(initialdir="/", title="Select file",
                                              filetypes=(("Text files", "*.txt"), ("All files", "*.*")))
        if filename:
            with open(filename, "r") as file:
                message = file.read()
            key = key_entry.get()
            decrypted_message = decrypt_hill(message, key)
            output_text.delete(0, END)
            output_text.insert(0, decrypted_message)


    input_label = Label(screen7, text="Enter Message:", bg="#f0f0f0", font=("Calibri", 12))
    input_label.pack(pady=(20, 5))
    input_text = Entry(screen7, font=("Calibri", 12), width=40)
    input_text.pack()

    key_label = Label(screen7, text="Enter Key:", bg="#f0f0f0", font=("Calibri", 12))
    key_label.pack(pady=(10, 5))
    key_entry = Entry(screen7, font=("Calibri", 12), width=40)
    key_entry.pack()

    encrypt_button = Button(screen7, text="Encrypt", command=process_encryption, bg="#007bff", fg="white", font=("Calibri", 12), width=10)
    encrypt_button.pack(pady=(20, 5))

    decrypt_button = Button(screen7, text="Decrypt", command=process_decryption, bg="#007bff", fg="white", font=("Calibri", 12), width=10)
    decrypt_button.pack(pady=(5, 5))

    encrypt_file_button = Button(screen7, text="Encrypt File", command=encrypt_file_hill, bg="#007bff", fg="white", font=("Calibri", 12), width=15)
    encrypt_file_button.pack(pady=(20, 5))

    decrypt_file_button = Button(screen7, text="Decrypt File", command=decrypt_file_hill, bg="#007bff", fg="white", font=("Calibri", 12), width=15)
    decrypt_file_button.pack(pady=(5, 20))

    output_label = Label(screen7, text="Result:", bg="#f0f0f0", font=("Calibri", 12))
    output_label.pack()

    output_text = Entry(screen7, font=("Calibri", 12), width=40)
    output_text.pack()
def main_screen():
    global screen

    screen = Tk()
    screen.title("Encryption and Decryption Algorithms")
    screen.geometry("400x500")
    screen.config(bg="#e6e6e6")


    title_label = Label(screen, text="Select Algorithm", fg="#333", font=("Helvetica", 16, "bold"), bg="#e6e6e6")
    title_label.pack(pady=(20, 10))


    button_styles = {
        "height": 2,
        "width": 30,
        "bg": "#4CAF50",
        "fg": "white",
        "bd": 0,
        "font": ("Helvetica", 12),
        "activebackground": "#45a049"
    }

    algorithms = [
        ("Shift Cipher", screen_one),
        ("Affine Cipher", screen_two),
        ("Rote 13 Cipher", screen_three),
        ("Vigenere Cipher", screen_four),
        ("Substitution Cipher", screen_five),
        ("Rail fence", screen_six),
        ("Hill Cipher", screen_seven)
    ]


    button_frame = Frame(screen, bg="#e6e6e6", bd=2, relief=SOLID)
    button_frame.pack(pady=(0, 20), padx=20)


    row_num = 0
    for text, command in algorithms:
        Button(button_frame, text=text, command=command, **button_styles).grid(row=row_num, column=0, pady=5)
        row_num += 1

    screen.mainloop()

main_screen()