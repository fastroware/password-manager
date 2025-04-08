import tkinter as tk
from tkinter import ttk, messagebox, simpledialog
import json
import os
import base64
import hashlib
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import uuid
from PIL import Image, ImageTk
import random
import datetime


class PasswordManager:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("Password Manager")
        self.root.geometry("900x600")
        self.root.resizable(True, True)
        self.root.configure(bg="#f0f2f5")

        # Set application icon
        self.root.iconbitmap(default="lock.ico") if os.path.exists("lock.ico") else None

        # Current language
        self.current_lang = "en"
        self.language_data = {}
        self.load_languages()

        # Current user
        self.current_user = None

        # Path for data
        self.data_dir = "data"
        self.users_file = os.path.join(self.data_dir, "users.json")

        # Create necessary directories
        if not os.path.exists(self.data_dir):
            os.makedirs(self.data_dir)

        # Initialize users data
        if not os.path.exists(self.users_file):
            with open(self.users_file, "w") as f:
                json.dump({}, f)

        # Global styling
        self.style = ttk.Style()
        self.style.theme_use("clam")
        self.style.configure(
            "TButton",
            font=("Helvetica", 10, "bold"),
            background="#3498db",
            foreground="white",
            padding=5,
        )
        self.style.configure("TLabel", font=("Helvetica", 10), background="#f0f2f5")
        self.style.configure("TEntry", padding=5)
        self.style.configure("TFrame", background="#f0f2f5")
        self.style.configure("Folder.TFrame", background="#ffffff", relief="raised")
        self.style.configure(
            "Header.TLabel", font=("Helvetica", 16, "bold"), background="#f0f2f5"
        )

        # Define colors
        self.colors = [
            "#3498db",
            "#2ecc71",
            "#e74c3c",
            "#f39c12",
            "#9b59b6",
            "#1abc9c",
            "#e67e22",
            "#34495e",
        ]

        # Show login frame first
        self.show_login_frame()

        # Create a footer
        self.footer_frame = ttk.Frame(self.root, style="TFrame")
        self.footer_frame.pack(side=tk.BOTTOM, fill=tk.X, pady=5)

        # Language selector
        self.lang_label = ttk.Label(
            self.footer_frame, text=self.get_text("language") + ":", style="TLabel"
        )
        self.lang_label.pack(side=tk.LEFT, padx=10)

        self.lang_var = tk.StringVar(value=self.current_lang)
        self.lang_combo = ttk.Combobox(
            self.footer_frame,
            textvariable=self.lang_var,
            values=list(self.language_data.keys()),
            width=5,
            state="readonly",
        )
        self.lang_combo.pack(side=tk.LEFT)
        self.lang_combo.bind("<<ComboboxSelected>>", self.change_language)

        # Add copyright info
        copyright_text = f"© {datetime.datetime.now().year} Password Manager"
        self.copyright_label = ttk.Label(
            self.footer_frame, text=copyright_text, style="TLabel"
        )
        self.copyright_label.pack(side=tk.RIGHT, padx=10)

    def load_languages(self):
        """Load available languages from the lang directory"""
        lang_dir = "lang"
        if not os.path.exists(lang_dir):
            os.makedirs(lang_dir)
            # Create default English language file
            self.create_default_lang_files(lang_dir)

        # Load all language files
        for file in os.listdir(lang_dir):
            if file.startswith("lang-") and file.endswith(".json"):
                lang_code = file[5:-5]  # Extract language code
                try:
                    with open(os.path.join(lang_dir, file), "r", encoding="utf-8") as f:
                        self.language_data[lang_code] = json.load(f)
                except Exception as e:
                    print(f"Error loading language file {file}: {e}")

        # If no language files were found, create default
        if not self.language_data:
            self.create_default_lang_files(lang_dir)
            with open(
                os.path.join(lang_dir, "lang-en.json"), "r", encoding="utf-8"
            ) as f:
                self.language_data["en"] = json.load(f)

    def create_default_lang_files(self, lang_dir):
        """Create default language files"""
        english = {
            "login": "Login",
            "register": "Register",
            "username": "Username",
            "password": "Password",
            "confirm_password": "Confirm Password",
            "submit": "Submit",
            "create_account": "Create Account",
            "back_to_login": "Back to Login",
            "logout": "Logout",
            "welcome": "Welcome",
            "add_folder": "Add Folder",
            "enter_folder_name": "Enter folder name:",
            "folder_name": "Folder Name",
            "delete": "Delete",
            "edit": "Edit",
            "add_password": "Add Password",
            "save": "Save",
            "cancel": "Cancel",
            "site_name": "Site Name",
            "url": "URL",
            "email": "Email",
            "notes": "Notes",
            "show": "Show",
            "hide": "Hide",
            "confirm_delete": "Are you sure you want to delete this?",
            "yes": "Yes",
            "no": "No",
            "language": "Language",
            "search": "Search",
            "password_manager": "Password Manager",
            "back": "Back",
            "copy": "Copied to clipboard",
            "generate_password": "Generate Password",
            "password_strength": "Password Strength",
            "weak": "Weak",
            "medium": "Medium",
            "strong": "Strong",
            "folders": "Folders",
        }

        indonesian = {
            "login": "Masuk",
            "register": "Daftar",
            "username": "Nama Pengguna",
            "password": "Kata Sandi",
            "confirm_password": "Konfirmasi Kata Sandi",
            "submit": "Kirim",
            "create_account": "Buat Akun",
            "back_to_login": "Kembali ke Login",
            "logout": "Keluar",
            "welcome": "Selamat Datang",
            "add_folder": "Tambah Folder",
            "enter_folder_name": "Masukkan nama folder:",
            "folder_name": "Nama Folder",
            "delete": "Hapus",
            "edit": "Edit",
            "add_password": "Tambah Password",
            "save": "Simpan",
            "cancel": "Batal",
            "site_name": "Nama Situs",
            "url": "URL",
            "email": "Email",
            "notes": "Catatan",
            "show": "Tampilkan",
            "hide": "Sembunyikan",
            "confirm_delete": "Anda yakin ingin menghapus ini?",
            "yes": "Ya",
            "no": "Tidak",
            "language": "Bahasa",
            "search": "Cari",
            "password_manager": "Pengelola Kata Sandi",
            "back": "Kembali",
            "copy": "Disalin ke clipboard",
            "generate_password": "Buat Kata Sandi",
            "password_strength": "Kekuatan Kata Sandi",
            "weak": "Lemah",
            "medium": "Sedang",
            "strong": "Kuat",
            "folders": "Folder",
        }

        # Save default language files
        with open(os.path.join(lang_dir, "lang-en.json"), "w", encoding="utf-8") as f:
            json.dump(english, f, ensure_ascii=False, indent=4)

        with open(os.path.join(lang_dir, "lang-id.json"), "w", encoding="utf-8") as f:
            json.dump(indonesian, f, ensure_ascii=False, indent=4)

    def get_text(self, key):
        """Get text based on current language"""
        try:
            return self.language_data[self.current_lang][key]
        except KeyError:
            # Fallback to English if key not found in current language
            return self.language_data.get("en", {}).get(key, key)

    def change_language(self, event=None):
        """Change the application language"""
        selected_lang = self.lang_var.get()
        if selected_lang != self.current_lang and selected_lang in self.language_data:
            self.current_lang = selected_lang

            # Update all text in the current frame
            if hasattr(self, "current_frame"):
                self.current_frame.destroy()

                if self.current_user:
                    self.show_home_frame()
                else:
                    self.show_login_frame()

            # Update footer text
            self.lang_label.config(text=self.get_text("language") + ":")

    def generate_key(self, password, salt=None):
        """Generate encryption key from password"""
        if salt is None:
            salt = os.urandom(16)

        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )

        key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
        return key, salt

    def encrypt_data(self, data, key):
        """Encrypt data using Fernet"""
        fernet = Fernet(key)
        return fernet.encrypt(json.dumps(data).encode())

    def decrypt_data(self, encrypted_data, key):
        """Decrypt data using Fernet"""
        fernet = Fernet(key)
        return json.loads(fernet.decrypt(encrypted_data).decode())

    def save_user_data(self, user_id, data, key):
        """Save encrypted user data to file"""
        user_file = os.path.join(self.data_dir, f"{user_id}.dat")
        encrypted_data = self.encrypt_data(data, key)

        with open(user_file, "wb") as f:
            f.write(encrypted_data)

    def load_user_data(self, user_id, key):
        """Load and decrypt user data from file"""
        user_file = os.path.join(self.data_dir, f"{user_id}.dat")

        if not os.path.exists(user_file):
            return {"folders": {}}

        try:
            with open(user_file, "rb") as f:
                encrypted_data = f.read()

            return self.decrypt_data(encrypted_data, key)
        except Exception as e:
            messagebox.showerror("Error", f"Failed to load user data: {e}")
            return {"folders": {}}

    def register_user(self, username, password):
        """Register a new user"""
        with open(self.users_file, "r") as f:
            users = json.load(f)

        if username in users:
            messagebox.showerror("Error", "Username already exists")
            return False

        # Generate salt and key for the user
        key, salt = self.generate_key(password)

        # Hash password with salt for storage
        password_hash = hashlib.sha256(
            (password + base64.b64encode(salt).decode()).encode()
        ).hexdigest()

        # Create user entry
        user_id = str(uuid.uuid4())
        users[username] = {
            "id": user_id,
            "password": password_hash,
            "salt": base64.b64encode(salt).decode(),
        }

        # Save users data
        with open(self.users_file, "w") as f:
            json.dump(users, f)

        # Create initial user data
        initial_data = {"folders": {}}
        self.save_user_data(user_id, initial_data, key)

        return True

    def login_user(self, username, password):
        """Login a user and return user data"""
        try:
            with open(self.users_file, "r") as f:
                users = json.load(f)

            if username not in users:
                messagebox.showerror("Error", "Invalid username or password")
                return None

            user = users[username]
            salt = base64.b64decode(user["salt"])

            # Hash the entered password with stored salt
            password_hash = hashlib.sha256(
                (password + user["salt"]).encode()
            ).hexdigest()

            if password_hash != user["password"]:
                # Try alternative method for backward compatibility
                password_hash = hashlib.sha256(
                    (password + base64.b64encode(salt).decode()).encode()
                ).hexdigest()
                if password_hash != user["password"]:
                    messagebox.showerror("Error", "Invalid username or password")
                    return None

            # Generate encryption key from password
            key, _ = self.generate_key(password, salt)

            self.current_user = {"username": username, "id": user["id"], "key": key}

            return self.load_user_data(user["id"], key)

        except Exception as e:
            messagebox.showerror("Error", f"Login failed: {e}")
            return None

    def clear_frame(self):
        """Clear the main frame for new content"""
        for widget in self.root.winfo_children():
            if widget != self.footer_frame:
                widget.destroy()

    def show_login_frame(self):
        """Show the login frame"""
        self.clear_frame()

        self.current_frame = ttk.Frame(self.root, style="TFrame")
        self.current_frame.pack(expand=True, fill=tk.BOTH)

        # Center content
        content_frame = ttk.Frame(self.current_frame, style="TFrame")
        content_frame.place(relx=0.5, rely=0.5, anchor=tk.CENTER)

        # Header
        header_label = ttk.Label(
            content_frame,
            text=self.get_text("password_manager"),
            font=("Helvetica", 24, "bold"),
            style="Header.TLabel",
        )
        header_label.pack(pady=20)

        # Login form
        form_frame = ttk.Frame(content_frame, style="TFrame")
        form_frame.pack(pady=10, padx=20)

        username_label = ttk.Label(
            form_frame, text=self.get_text("username"), style="TLabel"
        )
        username_label.grid(row=0, column=0, sticky=tk.W, pady=5)

        self.username_entry = ttk.Entry(form_frame, width=30)
        self.username_entry.grid(row=0, column=1, pady=5, padx=10)

        password_label = ttk.Label(
            form_frame, text=self.get_text("password"), style="TLabel"
        )
        password_label.grid(row=1, column=0, sticky=tk.W, pady=5)

        self.password_entry = ttk.Entry(form_frame, width=30, show="•")
        self.password_entry.grid(row=1, column=1, pady=5, padx=10)

        # Buttons
        button_frame = ttk.Frame(content_frame, style="TFrame")
        button_frame.pack(pady=20)

        login_button = ttk.Button(
            button_frame, text=self.get_text("login"), command=self.do_login
        )
        login_button.pack(side=tk.LEFT, padx=10)

        register_button = ttk.Button(
            button_frame,
            text=self.get_text("register"),
            command=self.show_register_frame,
        )
        register_button.pack(side=tk.LEFT, padx=10)

        # Bind enter key to login
        self.root.bind("<Return>", lambda event: self.do_login())

    def show_register_frame(self):
        """Show the registration frame"""
        self.clear_frame()

        self.current_frame = ttk.Frame(self.root, style="TFrame")
        self.current_frame.pack(expand=True, fill=tk.BOTH)

        # Center content
        content_frame = ttk.Frame(self.current_frame, style="TFrame")
        content_frame.place(relx=0.5, rely=0.5, anchor=tk.CENTER)

        # Header
        header_label = ttk.Label(
            content_frame,
            text=self.get_text("create_account"),
            font=("Helvetica", 20, "bold"),
            style="Header.TLabel",
        )
        header_label.pack(pady=20)

        # Register form
        form_frame = ttk.Frame(content_frame, style="TFrame")
        form_frame.pack(pady=10, padx=20)

        username_label = ttk.Label(
            form_frame, text=self.get_text("username"), style="TLabel"
        )
        username_label.grid(row=0, column=0, sticky=tk.W, pady=5)

        self.reg_username_entry = ttk.Entry(form_frame, width=30)
        self.reg_username_entry.grid(row=0, column=1, pady=5, padx=10)

        password_label = ttk.Label(
            form_frame, text=self.get_text("password"), style="TLabel"
        )
        password_label.grid(row=1, column=0, sticky=tk.W, pady=5)

        self.reg_password_entry = ttk.Entry(form_frame, width=30, show="•")
        self.reg_password_entry.grid(row=1, column=1, pady=5, padx=10)

        confirm_label = ttk.Label(
            form_frame, text=self.get_text("confirm_password"), style="TLabel"
        )
        confirm_label.grid(row=2, column=0, sticky=tk.W, pady=5)

        self.reg_confirm_entry = ttk.Entry(form_frame, width=30, show="•")
        self.reg_confirm_entry.grid(row=2, column=1, pady=5, padx=10)

        # Password strength indicator
        strength_frame = ttk.Frame(form_frame, style="TFrame")
        strength_frame.grid(row=3, column=1, pady=5, sticky=tk.W)

        self.strength_label = ttk.Label(
            strength_frame,
            text=self.get_text("password_strength") + ": ",
            style="TLabel",
        )
        self.strength_label.pack(side=tk.LEFT)

        self.strength_value = ttk.Label(strength_frame, text="", style="TLabel")
        self.strength_value.pack(side=tk.LEFT)

        # Password strength check
        self.reg_password_entry.bind("<KeyRelease>", self.check_password_strength)

        # Buttons
        button_frame = ttk.Frame(content_frame, style="TFrame")
        button_frame.pack(pady=20)

        register_button = ttk.Button(
            button_frame, text=self.get_text("submit"), command=self.do_register
        )
        register_button.pack(side=tk.LEFT, padx=10)

        back_button = ttk.Button(
            button_frame,
            text=self.get_text("back_to_login"),
            command=self.show_login_frame,
        )
        back_button.pack(side=tk.LEFT, padx=10)

        # Bind enter key to register
        self.root.bind("<Return>", lambda event: self.do_register())

    def check_password_strength(self, event=None):
        """Check and display password strength"""
        password = self.reg_password_entry.get()

        if len(password) < 8:
            strength = self.get_text("weak")
            color = "#e74c3c"  # Red
        elif (
            any(c.isdigit() for c in password)
            and any(c.isalpha() for c in password)
            and len(password) >= 8
        ):
            if (
                any(c.isupper() for c in password)
                and any(c.islower() for c in password)
                and any(not c.isalnum() for c in password)
                and len(password) >= 12
            ):
                strength = self.get_text("strong")
                color = "#2ecc71"  # Green
            else:
                strength = self.get_text("medium")
                color = "#f39c12"  # Orange
        else:
            strength = self.get_text("weak")
            color = "#e74c3c"  # Red

        self.strength_value.config(text=strength, foreground=color)

    def generate_random_password(self, length=16):
        """Generate a strong random password"""
        chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()-_=+[]{}|;:,.<>?"
        password = "".join(random.choice(chars) for _ in range(length))
        return password

    def do_login(self):
        """Perform login"""
        username = self.username_entry.get()
        password = self.password_entry.get()

        if not username or not password:
            messagebox.showerror("Error", "Please enter username and password")
            return

        user_data = self.login_user(username, password)
        if user_data:
            self.user_data = user_data
            self.show_home_frame()

    def do_register(self):
        """Perform registration"""
        username = self.reg_username_entry.get()
        password = self.reg_password_entry.get()
        confirm = self.reg_confirm_entry.get()

        if not username or not password or not confirm:
            messagebox.showerror("Error", "All fields are required")
            return

        if password != confirm:
            messagebox.showerror("Error", "Passwords do not match")
            return

        if len(password) < 8:
            messagebox.showerror("Error", "Password must be at least 8 characters")
            return

        if self.register_user(username, password):
            messagebox.showinfo("Success", "Registration successful. Please login.")
            self.show_login_frame()

    def do_logout(self):
        """Logout the current user"""
        self.current_user = None
        self.user_data = None
        self.show_login_frame()

    def show_home_frame(self):
        """Show the home frame with folders"""
        self.clear_frame()

        self.current_frame = ttk.Frame(self.root, style="TFrame")
        self.current_frame.pack(expand=True, fill=tk.BOTH)

        # Top toolbar
        toolbar = ttk.Frame(self.current_frame, style="TFrame")
        toolbar.pack(fill=tk.X, padx=10, pady=10)

        welcome_label = ttk.Label(
            toolbar,
            text=f"{self.get_text('welcome')}, {self.current_user['username']}",
            font=("Helvetica", 12, "bold"),
            style="TLabel",
        )
        welcome_label.pack(side=tk.LEFT, padx=10)

        search_frame = ttk.Frame(toolbar, style="TFrame")
        search_frame.pack(side=tk.LEFT, padx=20)

        search_label = ttk.Label(
            search_frame, text=f"{self.get_text('search')}:", style="TLabel"
        )
        search_label.pack(side=tk.LEFT, padx=5)

        self.search_entry = ttk.Entry(search_frame, width=20)
        self.search_entry.pack(side=tk.LEFT)
        self.search_entry.bind("<KeyRelease>", self.search_passwords)

        logout_button = ttk.Button(
            toolbar, text=self.get_text("logout"), command=self.do_logout
        )
        logout_button.pack(side=tk.RIGHT, padx=10)

        # Main content area with folders
        self.content_frame = ttk.Frame(self.current_frame, style="TFrame")
        self.content_frame.pack(expand=True, fill=tk.BOTH, padx=20, pady=10)

        # Header for folders
        folders_header = ttk.Frame(self.content_frame, style="TFrame")
        folders_header.pack(fill=tk.X, pady=10)

        folders_label = ttk.Label(
            folders_header,
            text=self.get_text("folders"),
            font=("Helvetica", 16, "bold"),
            style="Header.TLabel",
        )
        folders_label.pack(side=tk.LEFT)

        add_folder_button = ttk.Button(
            folders_header, text=self.get_text("add_folder"), command=self.add_folder
        )
        add_folder_button.pack(side=tk.RIGHT)

        # Folders container with scrollbar
        folders_container = ttk.Frame(self.content_frame, style="TFrame")
        folders_container.pack(expand=True, fill=tk.BOTH)

        self.folders_canvas = tk.Canvas(
            folders_container, bg="#f0f2f5", highlightthickness=0
        )
        scrollbar = ttk.Scrollbar(
            folders_container, orient="vertical", command=self.folders_canvas.yview
        )

        self.folders_frame = ttk.Frame(self.folders_canvas, style="TFrame")

        self.folders_frame.bind(
            "<Configure>",
            lambda e: self.folders_canvas.configure(
                scrollregion=self.folders_canvas.bbox("all")
            ),
        )

        self.folders_canvas.create_window(
            (0, 0), window=self.folders_frame, anchor="nw"
        )
        self.folders_canvas.configure(yscrollcommand=scrollbar.set)

        self.folders_canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

        # Display folders
        self.display_folders()

    def search_passwords(self, event=None):
        """Search through all passwords"""
        search_term = self.search_entry.get().lower()

        if not search_term:
            self.display_folders()
            return

        # Clear current display
        for widget in self.folders_frame.winfo_children():
            widget.destroy()

        # Search through all folders and passwords
        found_items = []

        for folder_id, folder in self.user_data["folders"].items():
            for password_id, password in folder.get("passwords", {}).items():
                # Check if search term is in any of the password fields
                if (
                    search_term in password.get("site_name", "").lower()
                    or search_term in password.get("username", "").lower()
                    or search_term in password.get("email", "").lower()
                    or search_term in password.get("url", "").lower()
                    or search_term in password.get("notes", "").lower()
                ):

                    found_items.append(
                        {
                            "folder_id": folder_id,
                            "folder_name": folder["name"],
                            "password_id": password_id,
                            "password": password,
                        }
                    )

        # Display search results
        if found_items:
            results_label = ttk.Label(
                self.folders_frame,
                text=f"Search results for '{search_term}':",
                font=("Helvetica", 12, "bold"),
                style="TLabel",
            )
            results_label.grid(row=0, column=0, sticky=tk.W, pady=10, padx=10)

            for i, item in enumerate(found_items):
                result_frame = ttk.Frame(self.folders_frame, style="Folder.TFrame")
                result_frame.grid(row=i + 1, column=0, sticky=tk.EW, padx=10, pady=5)

                site_label = ttk.Label(
                    result_frame,
                    text=item["password"]["site_name"],
                    font=("Helvetica", 10, "bold"),
                    style="TLabel",
                )
                site_label.grid(row=0, column=0, sticky=tk.W, padx=10, pady=5)

                folder_label = ttk.Label(
                    result_frame,
                    text=f"({self.get_text('folder_name')}: {item['folder_name']})",
                    style="TLabel",
                )
                folder_label.grid(row=0, column=1, sticky=tk.W, padx=10, pady=5)

                username_label = ttk.Label(
                    result_frame,
                    text=f"{self.get_text('username')}: {item['password']['username']}",
                    style="TLabel",
                )
                username_label.grid(row=1, column=0, sticky=tk.W, padx=10, pady=2)

                view_button = ttk.Button(
                    result_frame,
                    text=self.get_text("show"),
                    command=lambda fid=item["folder_id"], pid=item[
                        "password_id"
                    ]: self.show_password_details(fid, pid),
                )
                view_button.grid(row=1, column=1, sticky=tk.E, padx=10, pady=5)
        else:
            no_results_label = ttk.Label(
                self.folders_frame,
                text=f"No results found for '{search_term}'",
                style="TLabel",
            )
            no_results_label.grid(row=0, column=0, sticky=tk.W, pady=10, padx=10)

    def display_folders(self):
        """Display all folders in the home view"""
        # Clear current display
        for widget in self.folders_frame.winfo_children():
            widget.destroy()

        # Get folders
        folders = self.user_data.get("folders", {})

        if not folders:
            no_folders_label = ttk.Label(
                self.folders_frame,
                text="No folders yet. Create one by clicking 'Add Folder'.",
                style="TLabel",
            )
            no_folders_label.grid(row=0, column=0, sticky=tk.W, pady=10, padx=10)
            return

        # Display each folder
        for i, (folder_id, folder) in enumerate(folders.items()):
            folder_frame = ttk.Frame(self.folders_frame, style="Folder.TFrame")
            folder_frame.grid(row=i, column=0, sticky=tk.EW, padx=10, pady=5)

            # Use a random color as folder indicator
            color_indicator = tk.Frame(
                folder_frame, bg=random.choice(self.colors), width=10, height=50
            )
            color_indicator.grid(row=0, column=0, rowspan=2, sticky=tk.NS)

            folder_name = ttk.Label(
                folder_frame,
                text=folder["name"],
                font=("Helvetica", 12, "bold"),
                style="TLabel",
            )
            folder_name.grid(row=0, column=1, sticky=tk.W, padx=10, pady=5)

            # Count passwords
            password_count = len(folder.get("passwords", {}))
            count_text = (
                f"{password_count} {'passwords' if password_count != 1 else 'password'}"
            )

            count_label = ttk.Label(folder_frame, text=count_text, style="TLabel")
            count_label.grid(row=1, column=1, sticky=tk.W, padx=10, pady=2)

            # Buttons
            button_frame = ttk.Frame(folder_frame, style="TFrame")
            button_frame.grid(row=0, column=2, rowspan=2, sticky=tk.E, padx=10)

            open_button = ttk.Button(
                button_frame,
                text=self.get_text("show"),
                command=lambda fid=folder_id: self.open_folder(fid),
            )
            open_button.pack(side=tk.LEFT, padx=5)

            edit_button = ttk.Button(
                button_frame,
                text=self.get_text("edit"),
                command=lambda fid=folder_id, name=folder["name"]: self.edit_folder(
                    fid, name
                ),
            )
            edit_button.pack(side=tk.LEFT, padx=5)

            delete_button = ttk.Button(
                button_frame,
                text=self.get_text("delete"),
                command=lambda fid=folder_id: self.delete_folder(fid),
            )
            delete_button.pack(side=tk.LEFT, padx=5)

            # Make the folder frame expand horizontally
            self.folders_frame.columnconfigure(0, weight=1)

    def add_folder(self):
        """Add a new folder"""
        folder_name = simpledialog.askstring(
            self.get_text("add_folder"), self.get_text("enter_folder_name")
        )

        if folder_name:
            # Create new folder
            folder_id = str(uuid.uuid4())

            if "folders" not in self.user_data:
                self.user_data["folders"] = {}

            self.user_data["folders"][folder_id] = {
                "name": folder_name,
                "passwords": {},
            }

            # Save user data
            self.save_user_data(
                self.current_user["id"], self.user_data, self.current_user["key"]
            )

            # Refresh display
            self.display_folders()

    def edit_folder(self, folder_id, current_name):
        """Edit folder name"""
        new_name = simpledialog.askstring(
            self.get_text("edit"),
            self.get_text("folder_name"),
            initialvalue=current_name,
        )

        if new_name:
            self.user_data["folders"][folder_id]["name"] = new_name

            # Save user data
            self.save_user_data(
                self.current_user["id"], self.user_data, self.current_user["key"]
            )

            # Refresh display
            self.display_folders()

    def delete_folder(self, folder_id):
        """Delete a folder"""
        confirm = messagebox.askyesno(
            self.get_text("delete"), self.get_text("confirm_delete")
        )

        if confirm:
            del self.user_data["folders"][folder_id]

            # Save user data
            self.save_user_data(
                self.current_user["id"], self.user_data, self.current_user["key"]
            )

            # Refresh display
            self.display_folders()

    def open_folder(self, folder_id):
        """Open a folder to view passwords"""
        self.clear_frame()

        self.current_frame = ttk.Frame(self.root, style="TFrame")
        self.current_frame.pack(expand=True, fill=tk.BOTH)

        # Get folder data
        folder = self.user_data["folders"][folder_id]

        # Top toolbar
        toolbar = ttk.Frame(self.current_frame, style="TFrame")
        toolbar.pack(fill=tk.X, padx=10, pady=10)

        # Back button
        back_button = ttk.Button(
            toolbar, text=self.get_text("back"), command=self.show_home_frame
        )
        back_button.pack(side=tk.LEFT, padx=10)

        # Folder name
        folder_label = ttk.Label(
            toolbar,
            text=folder["name"],
            font=("Helvetica", 16, "bold"),
            style="Header.TLabel",
        )
        folder_label.pack(side=tk.LEFT, padx=20)

        # Password list with scrollbar
        content_container = ttk.Frame(self.current_frame, style="TFrame")
        content_container.pack(expand=True, fill=tk.BOTH, padx=20, pady=10)

        # Button to add password
        add_password_button = ttk.Button(
            content_container,
            text=self.get_text("add_password"),
            command=lambda: self.add_edit_password(folder_id),
        )
        add_password_button.pack(anchor=tk.NE, pady=10)

        # Passwords container
        passwords_container = ttk.Frame(content_container, style="TFrame")
        passwords_container.pack(expand=True, fill=tk.BOTH)

        self.passwords_canvas = tk.Canvas(
            passwords_container, bg="#f0f2f5", highlightthickness=0
        )
        scrollbar = ttk.Scrollbar(
            passwords_container, orient="vertical", command=self.passwords_canvas.yview
        )

        self.passwords_frame = ttk.Frame(self.passwords_canvas, style="TFrame")

        self.passwords_frame.bind(
            "<Configure>",
            lambda e: self.passwords_canvas.configure(
                scrollregion=self.passwords_canvas.bbox("all")
            ),
        )

        self.passwords_canvas.create_window(
            (0, 0), window=self.passwords_frame, anchor="nw"
        )
        self.passwords_canvas.configure(yscrollcommand=scrollbar.set)

        self.passwords_canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

        # Display passwords
        self.display_passwords(folder_id)

    def display_passwords(self, folder_id):
        """Display passwords in a folder"""
        # Clear current display
        for widget in self.passwords_frame.winfo_children():
            widget.destroy()

        # Get passwords
        passwords = self.user_data["folders"][folder_id].get("passwords", {})

        if not passwords:
            no_passwords_label = ttk.Label(
                self.passwords_frame,
                text="No passwords yet. Add one by clicking 'Add Password'.",
                style="TLabel",
            )
            no_passwords_label.grid(row=0, column=0, sticky=tk.W, pady=10, padx=10)
            return

        # Display each password
        for i, (password_id, password) in enumerate(passwords.items()):
            password_frame = ttk.Frame(self.passwords_frame, style="Folder.TFrame")
            password_frame.grid(row=i, column=0, sticky=tk.EW, padx=10, pady=5)

            # Password info
            site_name = ttk.Label(
                password_frame,
                text=password["site_name"],
                font=("Helvetica", 12, "bold"),
                style="TLabel",
            )
            site_name.grid(row=0, column=0, sticky=tk.W, padx=10, pady=5)

            username_label = ttk.Label(
                password_frame,
                text=f"{self.get_text('username')}: {password['username']}",
                style="TLabel",
            )
            username_label.grid(row=1, column=0, sticky=tk.W, padx=10, pady=2)

            # Buttons
            button_frame = ttk.Frame(password_frame, style="TFrame")
            button_frame.grid(row=0, column=1, rowspan=2, sticky=tk.E, padx=10)

            view_button = ttk.Button(
                button_frame,
                text=self.get_text("show"),
                command=lambda pid=password_id: self.show_password_details(
                    folder_id, pid
                ),
            )
            view_button.pack(side=tk.LEFT, padx=5)

            edit_button = ttk.Button(
                button_frame,
                text=self.get_text("edit"),
                command=lambda pid=password_id: self.add_edit_password(folder_id, pid),
            )
            edit_button.pack(side=tk.LEFT, padx=5)

            delete_button = ttk.Button(
                button_frame,
                text=self.get_text("delete"),
                command=lambda pid=password_id: self.delete_password(folder_id, pid),
            )
            delete_button.pack(side=tk.LEFT, padx=5)

            # Make the password frame expand horizontally
            self.passwords_frame.columnconfigure(0, weight=1)

    def show_password_details(self, folder_id, password_id):
        """Show full password details"""
        password = self.user_data["folders"][folder_id]["passwords"][password_id]

        # Create a new top-level window
        details_window = tk.Toplevel(self.root)
        details_window.title(password["site_name"])
        details_window.geometry("500x400")
        details_window.configure(bg="#f0f2f5")

        # Add some padding
        main_frame = ttk.Frame(details_window, style="TFrame")
        main_frame.pack(expand=True, fill=tk.BOTH, padx=20, pady=20)

        # Site name
        site_label = ttk.Label(
            main_frame,
            text=password["site_name"],
            font=("Helvetica", 16, "bold"),
            style="Header.TLabel",
        )
        site_label.pack(anchor=tk.W, pady=10)

        # Fields
        details_frame = ttk.Frame(main_frame, style="TFrame")
        details_frame.pack(fill=tk.BOTH, expand=True)

        fields = [
            ("url", "URL", password.get("url", "")),
            ("username", "Username", password.get("username", "")),
            ("email", "Email", password.get("email", "")),
            ("password", "Password", password.get("password", "")),
            ("notes", "Notes", password.get("notes", "")),
        ]

        for i, (field_id, field_name, value) in enumerate(fields):
            field_frame = ttk.Frame(details_frame, style="TFrame")
            field_frame.pack(fill=tk.X, pady=5)

            label = ttk.Label(
                field_frame,
                text=self.get_text(field_id.lower()) + ":",
                width=10,
                style="TLabel",
            )
            label.pack(side=tk.LEFT, padx=5)

            if field_id == "password":
                # Create a frame for password with show/hide toggle
                password_frame = ttk.Frame(field_frame, style="TFrame")
                password_frame.pack(side=tk.LEFT, fill=tk.X, expand=True)

                # Password field (starts hidden)
                password_var = tk.StringVar(value=value)
                password_entry = ttk.Entry(
                    password_frame,
                    textvariable=password_var,
                    state="readonly",
                    show="•",
                )
                password_entry.pack(side=tk.LEFT, fill=tk.X, expand=True)

                # Toggle button
                show_password = tk.BooleanVar(value=False)

                def toggle_password():
                    if show_password.get():
                        password_entry.config(show="")
                        toggle_button.config(text=self.get_text("hide"))
                    else:
                        password_entry.config(show="•")
                        toggle_button.config(text=self.get_text("show"))

                toggle_button = ttk.Button(
                    password_frame,
                    text=self.get_text("show"),
                    command=lambda: [
                        show_password.set(not show_password.get()),
                        toggle_password(),
                    ],
                )
                toggle_button.pack(side=tk.LEFT, padx=5)

                # Copy button
                copy_button = ttk.Button(
                    password_frame,
                    text="📋",
                    width=3,
                    command=lambda: [
                        details_window.clipboard_clear(),
                        details_window.clipboard_append(value),
                        messagebox.showinfo("", self.get_text("copy")),
                    ],
                )
                copy_button.pack(side=tk.LEFT)

            elif field_id == "notes":
                # Notes can be multiline
                text_widget = tk.Text(
                    field_frame, height=5, width=40, bg="white", wrap=tk.WORD
                )
                text_widget.insert(tk.END, value)
                text_widget.config(state=tk.DISABLED)
                text_widget.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=5)
            else:
                # Regular field
                value_var = tk.StringVar(value=value)
                value_entry = ttk.Entry(
                    field_frame, textvariable=value_var, state="readonly"
                )
                value_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)

                # Copy button
                if value:  # Only show copy button if there's a value
                    copy_button = ttk.Button(
                        field_frame,
                        text="📋",
                        width=3,
                        command=lambda v=value: [
                            details_window.clipboard_clear(),
                            details_window.clipboard_append(v),
                            messagebox.showinfo("", self.get_text("copy")),
                        ],
                    )
                    copy_button.pack(side=tk.LEFT)

        # Close button
        close_button = ttk.Button(
            main_frame,
            text=(
                self.get_text("close")
                if "close" in self.language_data[self.current_lang]
                else "Close"
            ),
            command=details_window.destroy,
        )
        close_button.pack(pady=10)

    def add_edit_password(self, folder_id, password_id=None):
        """Add a new password or edit existing one"""
        # Get existing password data if editing
        password_data = {}
        if password_id:
            password_data = self.user_data["folders"][folder_id]["passwords"][
                password_id
            ].copy()

        # Create a new top-level window
        password_window = tk.Toplevel(self.root)
        password_window.title(
            self.get_text("add_password") if not password_id else self.get_text("edit")
        )
        password_window.geometry("500x500")
        password_window.configure(bg="#f0f2f5")

        # Add some padding
        main_frame = ttk.Frame(password_window, style="TFrame")
        main_frame.pack(expand=True, fill=tk.BOTH, padx=20, pady=20)

        # Form title
        title_label = ttk.Label(
            main_frame,
            text=(
                self.get_text("add_password")
                if not password_id
                else self.get_text("edit")
            ),
            font=("Helvetica", 16, "bold"),
            style="Header.TLabel",
        )
        title_label.pack(anchor=tk.W, pady=10)

        # Form fields
        form_frame = ttk.Frame(main_frame, style="TFrame")
        form_frame.pack(fill=tk.BOTH, expand=True)

        # Field entries
        entries = {}
        fields = [
            ("site_name", "Site Name"),
            ("url", "URL"),
            ("username", "Username"),
            ("email", "Email"),
            ("password", "Password"),
            ("notes", "Notes"),
        ]

        for i, (field_id, field_name) in enumerate(fields):
            field_frame = ttk.Frame(form_frame, style="TFrame")
            field_frame.pack(fill=tk.X, pady=5)

            label = ttk.Label(
                field_frame,
                text=self.get_text(field_id.lower()) + ":",
                width=10,
                style="TLabel",
            )
            label.pack(side=tk.LEFT, padx=5)

            if field_id == "password":
                # Password field with generate button
                password_frame = ttk.Frame(field_frame, style="TFrame")
                password_frame.pack(side=tk.LEFT, fill=tk.X, expand=True)

                password_var = tk.StringVar(value=password_data.get(field_id, ""))
                entry = ttk.Entry(password_frame, textvariable=password_var, show="•")
                entry.pack(side=tk.LEFT, fill=tk.X, expand=True)
                entries[field_id] = password_var

                # Toggle button
                show_password = tk.BooleanVar(value=False)

                def toggle_password():
                    if show_password.get():
                        entry.config(show="")
                        toggle_button.config(text=self.get_text("hide"))
                    else:
                        entry.config(show="•")
                        toggle_button.config(text=self.get_text("show"))

                toggle_button = ttk.Button(
                    password_frame,
                    text=self.get_text("show"),
                    command=lambda: [
                        show_password.set(not show_password.get()),
                        toggle_password(),
                    ],
                )
                toggle_button.pack(side=tk.LEFT, padx=5)

                # Generate button
                def generate_and_set():
                    new_password = self.generate_random_password()
                    password_var.set(new_password)

                generate_button = ttk.Button(
                    password_frame,
                    text=self.get_text("generate_password"),
                    command=generate_and_set,
                )
                generate_button.pack(side=tk.LEFT)

            elif field_id == "notes":
                # Notes field (multiline)
                text_widget = tk.Text(
                    field_frame, height=5, width=40, bg="white", wrap=tk.WORD
                )
                text_widget.insert(tk.END, password_data.get(field_id, ""))
                text_widget.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=5)
                entries[field_id] = text_widget
            else:
                # Regular field
                var = tk.StringVar(value=password_data.get(field_id, ""))
                entry = ttk.Entry(field_frame, textvariable=var)
                entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)
                entries[field_id] = var

        # Buttons
        button_frame = ttk.Frame(main_frame, style="TFrame")
        button_frame.pack(fill=tk.X, pady=20)

        def save_password():
            # Validate required fields
            if (
                not entries["site_name"].get()
                or not entries["username"].get()
                or not entries["password"].get()
            ):
                messagebox.showerror(
                    "Error", "Site name, username and password are required"
                )
                return

            # Collect data
            new_data = {}
            for field_id, field_var in entries.items():
                if field_id == "notes":
                    # Get text from text widget
                    new_data[field_id] = field_var.get("1.0", tk.END).strip()
                else:
                    # Get string from StringVar
                    new_data[field_id] = field_var.get()

            # Save to user data
            if not password_id:
                # New password
                new_password_id = str(uuid.uuid4())
                self.user_data["folders"][folder_id]["passwords"][
                    new_password_id
                ] = new_data
            else:
                # Update existing
                self.user_data["folders"][folder_id]["passwords"][
                    password_id
                ] = new_data

            # Save user data
            self.save_user_data(
                self.current_user["id"], self.user_data, self.current_user["key"]
            )

            # Close window and refresh passwords display
            password_window.destroy()
            self.display_passwords(folder_id)

        save_button = ttk.Button(
            button_frame, text=self.get_text("save"), command=save_password
        )
        save_button.pack(side=tk.LEFT, padx=10)

        cancel_button = ttk.Button(
            button_frame, text=self.get_text("cancel"), command=password_window.destroy
        )
        cancel_button.pack(side=tk.LEFT, padx=10)

    def delete_password(self, folder_id, password_id):
        """Delete a password"""
        confirm = messagebox.askyesno(
            self.get_text("delete"), self.get_text("confirm_delete")
        )

        if confirm:
            del self.user_data["folders"][folder_id]["passwords"][password_id]

            # Save user data
            self.save_user_data(
                self.current_user["id"], self.user_data, self.current_user["key"]
            )

            # Refresh display
            self.display_passwords(folder_id)

    def run(self):
        """Run the application"""
        self.root.mainloop()


if __name__ == "__main__":
    app = PasswordManager()
    app.run()
