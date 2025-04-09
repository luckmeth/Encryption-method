import tkinter as tk
from tkinter import ttk, scrolledtext, filedialog, messagebox
from PIL import Image, ImageTk
import os
import pyttsx3
from tkVideoPlayer import TkinterVideo
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

# 🔧 Initialize Window
root = tk.Tk()

root.title("🔐 AI Secure Encryption System")
root.geometry("900x650")
root.resizable(False, False)

# 🔄 Text-to-speech
engine = pyttsx3.init()

def speak(text):
    engine.say(text)
    engine.runAndWait()

# 🎬 Background video
video_player = TkinterVideo(master=root, scaled=True)
video_player.load("0403.mp4")  # Make sure video exists
video_player.pack(fill="both", expand=True)
video_player.play()
video_player.bind("<<Ended>>", lambda e: video_player.seek(0))

# 🔳 Transparent Blue Overlay Frame
overlay = tk.Frame(root, bg="#001f3f", bd=5)
overlay.place(relx=0.5, rely=0.5, anchor="center")
overlay.config(highlightbackground="#00aced", highlightthickness=2)

# 🧠 AI Assistant Logic
def ai_chatbot_response(user_input):
    user_input = user_input.lower()
    if "encrypt" in user_input:
        return "Click the encrypt button after typing your message."
    elif "decrypt" in user_input:
        return "Paste the encrypted message and press decrypt."
    elif "clear" in user_input:
        return "Use the clear button to reset all fields."
    elif "save" in user_input:
        return "Click the save button to store messages in a file."
    else:
        return "I’m your encryption assistant. Try asking me about encrypting, decrypting, or saving."

# 🔐 Generate RSA & AES Keys
private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
public_key = private_key.public_key()
shared_secret = os.urandom(32)
encrypted_secret = public_key.encrypt(shared_secret, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
hkdf = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b'aes-key', backend=default_backend())
aes_key = hkdf.derive(private_key.decrypt(encrypted_secret, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)))

def aes_encrypt(msg, key):
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    pad_len = 16 - (len(msg) % 16)
    padded = msg + bytes([pad_len] * pad_len)
    return iv + encryptor.update(padded) + encryptor.finalize()

def aes_decrypt(data, key):
    try:
        iv, ct = data[:16], data[16:]
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        result = decryptor.update(ct) + decryptor.finalize()
        return result[:-result[-1]]
    except Exception as e:
        return b"DECRYPTION ERROR!"

# 🌟 Functions
def encrypt_message():
    text = message_input.get("1.0", tk.END).strip().encode()
    if not text:
        return
    encrypted = aes_encrypt(text, aes_key).hex()
    encrypted_var.set(encrypted)
    status.config(text="🔐 Encrypted!", fg="lightgreen")
    speak("Encryption completed.")

def decrypt_message():
    enc_text = encrypted_var.get()
    try:
        decrypted = aes_decrypt(bytes.fromhex(enc_text), aes_key).decode()
        decrypted_var.set(decrypted)
        status.config(text="🔓 Decrypted!", fg="lightblue")
        speak("Decryption completed.")
    except:
        messagebox.showerror("Error", "Decryption failed!")
        speak("Decryption failed.")

def clear_all():
    message_input.delete("1.0", tk.END)
    encrypted_var.set("")
    decrypted_var.set("")
    status.config(text="🔄 Cleared", fg="gray")
    speak("All fields cleared.")

def save_to_file():
    content = f"Original:\n{message_input.get('1.0', tk.END)}\nEncrypted:\n{encrypted_var.get()}\nDecrypted:\n{decrypted_var.get()}"
    filepath = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text files", "*.txt")])
    if filepath:
        with open(filepath, "w") as f:
            f.write(content)
        messagebox.showinfo("Saved", "Message saved successfully!")
        speak("Message saved successfully.")

def ask_ai():
    query = ai_entry.get()
    if not query:
        return
    reply = ai_chatbot_response(query)
    ai_response.set(reply)
    speak(reply)

# 🔣 UI Elements
title = tk.Label(overlay, text="🔐 Secure Encryption AI System", font=("Arial", 16, "bold"), fg="cyan", bg="#001f3f")
title.pack(pady=5)

tk.Label(overlay, text="Enter your message:", font=("Arial", 11), fg="white", bg="#001f3f").pack(anchor="w")
message_input = scrolledtext.ScrolledText(overlay, width=60, height=4, bg="#002b5c", fg="white", insertbackground="white", font=("Consolas", 11))
message_input.pack(pady=5)

ttk.Button(overlay, text="Encrypt 🔐", command=encrypt_message).pack(pady=5)

tk.Label(overlay, text="Encrypted Message:", font=("Arial", 11), fg="white", bg="#001f3f").pack(anchor="w")
encrypted_var = tk.StringVar()
tk.Entry(overlay, textvariable=encrypted_var, width=60, font=("Consolas", 10), bg="#002b5c", fg="white").pack(pady=5)

ttk.Button(overlay, text="Decrypt 🔓", command=decrypt_message).pack(pady=5)

tk.Label(overlay, text="Decrypted Message:", font=("Arial", 11), fg="white", bg="#001f3f").pack(anchor="w")
decrypted_var = tk.StringVar()
tk.Entry(overlay, textvariable=decrypted_var, width=60, font=("Consolas", 10), bg="#002b5c", fg="white").pack(pady=5)

# 🎤 AI Chat Assistant
tk.Label(overlay, text="Ask Assistant (AI):", font=("Arial", 11), fg="white", bg="#001f3f").pack(anchor="w", pady=(10,0))
ai_entry = tk.Entry(overlay, width=40, font=("Arial", 10))
ai_entry.pack(pady=3)
ttk.Button(overlay, text="Ask 🤖", command=ask_ai).pack(pady=3)
ai_response = tk.StringVar()
tk.Label(overlay, textvariable=ai_response, wraplength=400, fg="lightyellow", bg="#001f3f", font=("Arial", 10, "italic")).pack()

# 🔘 Buttons
ttk.Button(overlay, text="💾 Save to File", command=save_to_file).pack(pady=3)
ttk.Button(overlay, text="🧹 Clear All", command=clear_all).pack(pady=5)

status = tk.Label(overlay, text="🔹 Ready", font=("Arial", 10), fg="gray", bg="#001f3f")
status.pack(pady=5)

root.mainloop()
