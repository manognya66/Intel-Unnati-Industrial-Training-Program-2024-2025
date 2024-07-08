import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext
import crypto_utils
from string import ascii_letters, digits

# Tkinter functions
def select_input_file():
    file_path = filedialog.askopenfilename(title="Select Input File")
    if file_path:
        input_file_path.set(file_path)

def execute_operation():
    input_file = input_file_path.get()
    passphrase = passphrase_entry.get()

    if not input_file or not passphrase:
        messagebox.showerror("Error", "Input file and passphrase must be provided!")
        return

    try:
        if operation_var.get() == "Encrypt":
            result = crypto_utils.encrypt_file_inplace(input_file, passphrase)
            if result:
                dek_salt, kek_salt, dek_nonce, encrypted_dek, passphrase_hash, file_nonce, ciphertext = result
                messagebox.showinfo("Success", "File encrypted successfully!")
                
                # Display debug information
                debug_info = (
                    f"DEK Salt: {dek_salt}\n"
                    f"KEK Salt: {kek_salt}\n"
                    f"DEK Nonce: {dek_nonce}\n"
                    f"Encrypted DEK: {encrypted_dek}\n"
                    f"Passphrase Hash: {passphrase_hash}\n"
                    f"File Nonce: {file_nonce}\n"
                    f"Ciphertext: {ciphertext[:64]}... (truncated)"
                )
                debug_text.config(state=tk.NORMAL)
                debug_text.delete(1.0, tk.END)
                debug_text.insert(tk.END, debug_info)
                debug_text.config(state=tk.DISABLED)
            else:
                messagebox.showerror("Error", "Encryption failed!")
        elif operation_var.get() == "Decrypt":
            result = crypto_utils.decrypt_file_inplace(input_file, passphrase)
            if result:
                dek_salt, kek_salt, dek_nonce, encrypted_dek, stored_passphrase_hash, file_nonce, ciphertext, plaintext = result
                messagebox.showinfo("Success", "File decrypted successfully!")
                
                # Display debug information
                debug_info = (
                    f"DEK Salt: {dek_salt}\n"
                    f"KEK Salt: {kek_salt}\n"
                    f"DEK Nonce: {dek_nonce}\n"
                    f"Encrypted DEK: {encrypted_dek}\n"
                    f"Stored Passphrase Hash: {stored_passphrase_hash}\n"
                    f"File Nonce: {file_nonce}\n"
                    f"Ciphertext: {ciphertext[:64]}... (truncated)\n"
                    f"Plaintext: {plaintext[:64]}... (truncated)"
                )
                debug_text.config(state=tk.NORMAL)
                debug_text.delete(1.0, tk.END)
                debug_text.insert(tk.END, debug_info)
                debug_text.config(state=tk.DISABLED)
            else:
                messagebox.showerror("Error", "Decryption failed!")
    except Exception as e:
        messagebox.showerror("Error", f"Operation failed: {str(e)}")

def execute_brute_force():
    input_file = input_file_path.get()
    charset = charset_entry.get()
    max_length = int(max_length_entry.get())

    if not input_file or not charset or not max_length:
        messagebox.showerror("Error", "Input file, charset, and max length must be provided!")
        return

    try:
        def update_brute_force_text(current_passphrase):
            debug_text.config(state=tk.NORMAL)
            debug_text.delete(1.0, tk.END)
            debug_text.insert(tk.END, f"Trying passphrase: {current_passphrase}")
            debug_text.config(state=tk.DISABLED)

        passphrase, result = crypto_utils.brute_force_decrypt(input_file, charset, max_length, update_brute_force_text)
        if passphrase:
            dek_salt, kek_salt, dek_nonce, encrypted_dek, stored_passphrase_hash, file_nonce, ciphertext, plaintext = result
            messagebox.showinfo("Success", f"Passphrase found: {passphrase}")

            # Display debug information
            debug_info = (
                f"DEK Salt: {dek_salt}\n"
                f"KEK Salt: {kek_salt}\n"
                f"DEK Nonce: {dek_nonce}\n"
                f"Encrypted DEK: {encrypted_dek}\n"
                f"Stored Passphrase Hash: {stored_passphrase_hash}\n"
                f"File Nonce: {file_nonce}\n"
                f"Ciphertext: {ciphertext[:64]}... (truncated)\n"
                f"Plaintext: {plaintext[:64]}... (truncated)"
            )
            debug_text.config(state=tk.NORMAL)
            debug_text.delete(1.0, tk.END)
            debug_text.insert(tk.END, debug_info)
            debug_text.config(state=tk.DISABLED)
        else:
            messagebox.showerror("Error", "Brute-force attempt failed to find the passphrase!")
    except Exception as e:
        messagebox.showerror("Error", f"Brute-force operation failed: {str(e)}")

def update_ui():
    action_button.config(text=operation_var.get(), command=execute_operation)
    input_file_path.set("")
    passphrase_entry.delete(0, tk.END)
    debug_text.config(state=tk.NORMAL)
    debug_text.delete(1.0, tk.END)
    debug_text.config(state=tk.DISABLED)

    if operation_var.get() == "Decrypt":
        brute_force_frame.pack(pady=10, fill=tk.BOTH, expand=True)
    else:
        brute_force_frame.pack_forget()

# Tkinter application
app = tk.Tk()
app.title("File Encryption/Decryption")
app.geometry("600x700")

input_file_path = tk.StringVar()

tk.Label(app, text="Select Operation:").pack(pady=5)
operation_var = tk.StringVar(value="Encrypt")
tk.Radiobutton(app, text="Encrypt", variable=operation_var, value="Encrypt", command=update_ui).pack()
tk.Radiobutton(app, text="Decrypt", variable=operation_var, value="Decrypt", command=update_ui).pack()

tk.Label(app, text="Input File:").pack(pady=5)
tk.Entry(app, textvariable=input_file_path, width=50).pack()
tk.Button(app, text="Browse...", command=select_input_file).pack(pady=5)

tk.Label(app, text="Passphrase:").pack(pady=5)
passphrase_entry = tk.Entry(app, show="*", width=50)
passphrase_entry.pack()

action_button = tk.Button(app, text="Encrypt", command=execute_operation)
action_button.pack(pady=20)

# Frame for brute-force recovery options
brute_force_frame = tk.Frame(app)
tk.Label(brute_force_frame, text="Brute-Force Recovery:").pack(pady=5)
tk.Label(brute_force_frame, text="Charset:").pack(pady=5)
charset_entry = tk.Entry(brute_force_frame, width=50)
charset_entry.insert(0, ascii_letters + digits)
charset_entry.pack()

tk.Label(brute_force_frame, text="Max Length:").pack(pady=5)
max_length_entry = tk.Entry(brute_force_frame, width=50)
max_length_entry.insert(0, "5")  # Default max length
max_length_entry.pack()

tk.Button(brute_force_frame, text="Brute-Force Recover", command=execute_brute_force).pack(pady=20)

# Add a scrolled text widget for displaying debug information
debug_text = scrolledtext.ScrolledText(app, wrap=tk.WORD, height=10, state=tk.DISABLED)
debug_text.pack(pady=10, fill=tk.BOTH, expand=True)

update_ui()  # Initialize UI

app.mainloop()
