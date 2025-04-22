
import tkinter as tk
from tkinter import ttk, messagebox, filedialog, simpledialog
from auth_module import register_user, authenticate_user, generate_static_otp, get_all_users
from file_ops_module import *

root = tk.Tk()
root.title("Secure File Manager")
root.geometry("500x600")

username_var = tk.StringVar()
password_var = tk.StringVar()
status_var = tk.StringVar(value="Not logged in")
logged_in_user = None

def check_login_required():
    if not logged_in_user:
        messagebox.showerror("Access Denied", "You must log in first!")
        return False
    return True

def handle_register():
    user = username_var.get().strip()
    pwd = password_var.get().strip()
    if register_user(user, pwd):
        messagebox.showinfo("Success", "Registration successful!")
    else:
        messagebox.showerror("Error", "Username already exists!")

def handle_login():
    global logged_in_user
    user = username_var.get().strip()
    pwd = password_var.get().strip()
    if authenticate_user(user, pwd):
        otp = generate_static_otp()
        entry = simpledialog.askstring("OTP Verification", f"Enter OTP (demo: {otp}):")
        if entry == otp:
            logged_in_user = user
            status_var.set(f"Logged in as: {user}")
            messagebox.showinfo("Success", "Login successful!")
        else:
            messagebox.showerror("Error", "Invalid OTP.")
    else:
        messagebox.showerror("Error", "Invalid credentials.")

def handle_encrypt():
    if not check_login_required(): return
    path = filedialog.askopenfilename(title="Select File to Encrypt")
    if path:
        if not validate_input(path):
            log_threat(logged_in_user, path, "Invalid input")
            messagebox.showerror("Error", "Invalid file path.")
            return
        if detect_malware(path):
            log_threat(logged_in_user, path, "Malware detected")
            messagebox.showerror("Threat", "Malware detected. Aborting.")
            return
        enc = encrypt_file(path)
        set_initial_permissions(enc, logged_in_user)
        messagebox.showinfo("Encrypted", f"File encrypted:\n{enc}")

def handle_decrypt():
    if not check_login_required(): return
    path = filedialog.askopenfilename(title="Select File to Decrypt")
    if path and has_permission(path, logged_in_user, "read"):
        out = decrypt_file(path)
        if out:
            messagebox.showinfo("Decrypted", f"File decrypted to:\n{out}")
        else:
            messagebox.showwarning("Warning", "Not a valid encrypted file.")
    else:
        messagebox.showerror("Access Denied", "No read permission.")

def handle_metadata():
    if not check_login_required(): return
    path = filedialog.askopenfilename(title="Select File for Metadata")
    if path:
        meta = get_file_metadata(path)
        info = f"Name: {meta['name']}\nSize: {meta['size']} bytes\nCreated: {meta['created']}\nModified: {meta['modified']}"
        messagebox.showinfo("Metadata", info)

def handle_permissions():
    if not check_login_required(): return
    path = filedialog.askopenfilename(title="Select File to Manage Permissions")
    if not path: return
    perms = get_permissions(path)
    top = tk.Toplevel(root)
    top.title(f"Permissions: {os.path.basename(path)}")
    top.geometry("400x300")

    rf = ttk.LabelFrame(top, text="Readers")
    rf.pack(side="left", fill="both", expand=True, padx=5, pady=5)
    rb = tk.Listbox(rf)
    rb.pack(fill="both", expand=True, padx=5, pady=5)
    for u in perms.get("read", []): rb.insert(tk.END, u)

    wf = ttk.LabelFrame(top, text="Writers")
    wf.pack(side="right", fill="both", expand=True, padx=5, pady=5)
    wb = tk.Listbox(wf)
    wb.pack(fill="both", expand=True, padx=5, pady=5)
    for u in perms.get("write", []): wb.insert(tk.END, u)

    def modify_perm(file, perm_type, listbox, remove=False):
        ans = simpledialog.askstring("User", f"Enter username:")
        if ans and ans in get_all_users():
            if remove:
                remove_permission(file, ans, perm_type)
            else:
                add_permission(file, ans, perm_type)
            listbox.delete(0, tk.END)
            for u in get_permissions(file)[perm_type]:
                listbox.insert(tk.END, u)

    btn_frame = ttk.Frame(top)
    btn_frame.pack(fill="x", pady=5)
    ttk.Button(btn_frame, text="Add Reader", command=lambda: modify_perm(path, "read", rb)).pack(side="left", expand=True)
    ttk.Button(btn_frame, text="Remove Reader", command=lambda: modify_perm(path, "read", rb, remove=True)).pack(side="left", expand=True)
    ttk.Button(btn_frame, text="Add Writer", command=lambda: modify_perm(path, "write", wb)).pack(side="left", expand=True)
    ttk.Button(btn_frame, text="Remove Writer", command=lambda: modify_perm(path, "write", wb, remove=True)).pack(side="left", expand=True)

# GUI Layout
ttk.Label(root, text="Secure File Manager", font=("Arial", 16, "bold")).pack(pady=10)
auth_frame = ttk.LabelFrame(root, text="Authentication")
auth_frame.pack(fill="x", padx=20, pady=10)

tk.Label(auth_frame, text="Username:").grid(row=0, column=0, padx=5, pady=5, sticky="e")
ttk.Entry(auth_frame, textvariable=username_var).grid(row=0, column=1, padx=5, pady=5)
tk.Label(auth_frame, text="Password:").grid(row=1, column=0, padx=5, pady=5, sticky="e")
ttk.Entry(auth_frame, textvariable=password_var, show="*").grid(row=1, column=1, padx=5, pady=5)

btn_frame = ttk.Frame(auth_frame)
btn_frame.grid(row=2, column=0, columnspan=2, pady=10)
ttk.Button(btn_frame, text="Register", command=handle_register).pack(side="left", padx=5)
ttk.Button(btn_frame, text="Login", command=handle_login).pack(side="right", padx=5)

ops_frame = ttk.LabelFrame(root, text="File Operations")
ops_frame.pack(fill="both", expand=True, padx=20, pady=10)
ttk.Button(ops_frame, text="Encrypt File", command=handle_encrypt).pack(fill="x", pady=5)
ttk.Button(ops_frame, text="Decrypt File", command=handle_decrypt).pack(fill="x", pady=5)
ttk.Button(ops_frame, text="View Metadata", command=handle_metadata).pack(fill="x", pady=5)
ttk.Button(ops_frame, text="Manage Permissions", command=handle_permissions).pack(fill="x", pady=5)

ttk.Label(root, textvariable=status_var, relief="sunken", anchor="w").pack(fill="x", side="bottom")

root.mainloop()