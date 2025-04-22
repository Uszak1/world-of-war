import socket
import threading
import tkinter as tk
from tkinter import messagebox, scrolledtext
import re

client_socket = None
nickname = ""

def connect_to_server(ip, port):
    global client_socket
    try:
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client_socket.connect((ip, port))
        return True
    except Exception as e:
        messagebox.showerror("Błąd połączenia", str(e))
        return False

def is_password_strong(password, login):
    if len(password) < 8:
        return "Hasło musi mieć co najmniej 8 znaków."
    if login.lower() in password.lower():
        return "Hasło nie może zawierać loginu."
    if not re.search(r"[A-Z]", password):
        return "Hasło musi zawierać przynajmniej jedną wielką literę."
    if not re.search(r"[a-z]", password):
        return "Hasło musi zawierać przynajmniej jedną małą literę."
    if not re.search(r"[0-9]", password):
        return "Hasło musi zawierać przynajmniej jedną cyfrę."
    if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
        return "Hasło musi zawierać znak specjalny."
    return None

def handle_login(mode, ip, nick, pwd):
    if ' ' in nick or ' ' in pwd or not nick or not pwd:
        messagebox.showwarning("Błąd", "Login i hasło nie mogą zawierać spacji.")
        return

    if mode == "register":
        validation_error = is_password_strong(pwd, nick)
        if validation_error:
            messagebox.showwarning("Nieprawidłowe hasło", validation_error)
            return

    if not connect_to_server(ip, 12345):
        return

    try:
        client_socket.send(mode.encode())
        client_socket.recv(1024)
        client_socket.send(f"{nick}:{pwd}".encode())
        response = client_socket.recv(1024).decode()

        if response == "OK" or response == "CREATED":
            global nickname
            nickname = nick
            root.after(0, show_chat)
        elif response == "EXISTS":
            messagebox.showerror("Błąd", "Taki użytkownik już istnieje.")
        elif response == "FAIL":
            messagebox.showerror("Błąd", "Niepoprawny login lub hasło.")
        elif response == "INVALID":
            messagebox.showerror("Błąd", "Niedozwolone znaki lub niewłaściwe hasło.")
        else:
            messagebox.showerror("Błąd", "Wystąpił problem.")
    except Exception as e:
        messagebox.showerror("Błąd", f"Wystąpił wyjątek: {e}")

def threaded_login(mode, ip, login, pwd):
    threading.Thread(target=handle_login, args=(mode, ip, login, pwd), daemon=True).start()

def send_msg(event=None):
    msg = msg_entry.get("1.0", tk.END).strip()
    if msg and len(msg) <= 50:
        try:
            client_socket.send(msg.encode())
            msg_entry.delete("1.0", tk.END)
        except:
            messagebox.showerror("Błąd", "Utracono połączenie z serwerem.")
    elif len(msg) > 50:
        messagebox.showwarning("Limit znaków", "Wiadomość może zawierać maksymalnie 50 znaków.")

def receive_loop():
    while True:
        try:
            msg = client_socket.recv(1024).decode()
            if not msg:
                break
            chat_box.config(state='normal')
            chat_box.insert(tk.END, msg + "\n")
            chat_box.yview(tk.END)
            chat_box.config(state='disabled')
        except:
            break

def show_chat():
    global chat_box, msg_entry

    for widget in root.winfo_children():
        widget.destroy()

    root.geometry("500x600")
    root.minsize(500, 600)
    root.configure(bg="#d3d3d3")

    main_frame = tk.Frame(root, bg="#d3d3d3")
    main_frame.pack(fill=tk.BOTH, expand=True)

    chat_frame = tk.Frame(main_frame)
    chat_frame.place(relx=0, rely=0, relwidth=1, relheight=0.85)

    chat_box = scrolledtext.ScrolledText(chat_frame, wrap=tk.WORD, font=("Helvetica", 10))
    chat_box.pack(fill=tk.BOTH, expand=True)
    chat_box.config(state='disabled')

    bottom_frame = tk.Frame(main_frame)
    bottom_frame.place(relx=0, rely=0.85, relwidth=1, relheight=0.15)

    msg_entry = tk.Text(bottom_frame, height=2, font=("Helvetica", 10), wrap=tk.WORD)
    msg_entry.place(relx=0, rely=0, relwidth=0.8, relheight=1)
    msg_entry.bind("<Return>", send_msg)
    msg_entry.bind("<Shift-Return>", lambda e: None)

    send_btn = tk.Button(bottom_frame, text="Wyślij", command=send_msg)
    send_btn.place(relx=0.8, rely=0, relwidth=0.2, relheight=1)

    threading.Thread(target=receive_loop, daemon=True).start()

# GUI logowania
root = tk.Tk()
root.title("💬 Chat Logowanie")
root.geometry("400x300")
root.resizable(False, False)
root.configure(bg="#d3d3d3")

login_frame = tk.Frame(root, bg="#d3d3d3")
login_frame.pack(pady=30)

tk.Label(login_frame, text="IP Serwera:", bg="#d3d3d3").grid(row=0, column=0, sticky="e")
ip_entry = tk.Entry(login_frame)
ip_entry.insert(0, "127.0.0.1")
ip_entry.grid(row=0, column=1)

tk.Label(login_frame, text="Login:", bg="#d3d3d3").grid(row=1, column=0, sticky="e")
login_entry = tk.Entry(login_frame)
login_entry.grid(row=1, column=1)

tk.Label(login_frame, text="Hasło:", bg="#d3d3d3").grid(row=2, column=0, sticky="e")
password_entry = tk.Entry(login_frame, show="*")
password_entry.grid(row=2, column=1)

login_btn = tk.Button(login_frame, text="Zaloguj się", width=15,
                      command=lambda: threaded_login("login", ip_entry.get(), login_entry.get(), password_entry.get()))
login_btn.grid(row=3, column=0, pady=10)

register_btn = tk.Button(login_frame, text="Stwórz konto", width=15,
                         command=lambda: threaded_login("register", ip_entry.get(), login_entry.get(), password_entry.get()))
register_btn.grid(row=3, column=1, pady=10)

root.mainloop()

