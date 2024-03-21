import tkinter as tk
from tkinter import ttk
import tkinter.messagebox as messagebox
import sqlite3
import hashlib
import re
import sys
sys.path.append('/home/kl45h/Desktop/MyProject/display_module/')
import display_module


# Hashing function for passwords
def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

# Database connection
conn = sqlite3.connect('user_data.db')
c = conn.cursor()

# Create user table
c.execute('''CREATE TABLE IF NOT EXISTS users
             (id INTEGER PRIMARY KEY AUTOINCREMENT, 
              first_name TEXT,
              last_name TEXT,
              username TEXT UNIQUE, 
              email TEXT,
              password TEXT)''')

class LoginForm(ttk.Frame):
    def __init__(self, master, root):
        super().__init__(master, padding=(20, 10))
        self.pack(fill=tk.BOTH, expand=tk.YES)
        self.root = root

        # form variables
        self.user_name = tk.StringVar(value="")
        self.password = tk.StringVar(value="")

        # form header
        hdr_txt = "Enter Username and Password" 
        hdr = ttk.Label(master=self, text=hdr_txt, width=50)
        hdr.pack(fill=tk.X, pady=10)

        # form entries
        self.create_form_entry("Username", self.user_name)
        self.create_form_entry("Password", self.password)
        self.create_buttonbox()

    def create_form_entry(self, label, variable):
        """Create a single form entry"""
        container = ttk.Frame(self)
        container.pack(fill=tk.X, expand=tk.YES, pady=5)

        lbl = ttk.Label(master=container, text=label.title(), width=10)
        lbl.pack(side=tk.LEFT, padx=5)

        ent = ttk.Entry(master=container, textvariable=variable)
        ent.pack(side=tk.LEFT, padx=5, fill=tk.X, expand=tk.YES)

    def create_buttonbox(self):
        """Create the application buttonbox"""
        container = ttk.Frame(self)
        container.pack(fill=tk.X, expand=tk.YES, pady=(15, 10))

        sub_btn = ttk.Button(
            master=container,
            text="Login",
            command=self.on_submit,
            width=6,
        )
        sub_btn.pack(side=tk.RIGHT, padx=5)
        sub_btn.focus_set()

        cnl_btn = ttk.Button(
            master=container,
            text="Sign Up",
            command=self.switchWindows,
            width=6,
        )
        cnl_btn.pack(side=tk.RIGHT, padx=5)

    def show_successful_login_message():
        messagebox.showinfo("Success", "Login successful!")

    def show_wrong_credentials_message():
        messagebox.showerror("Error", "Invalid username or password!")

    def on_submit(self, root):
        """Login operation"""
        username = self.user_name.get().strip()  # Remove leading/trailing whitespace
        password = self.password.get().strip()  # Remove leading/trailing whitespace
        
        if not username or not password:
            messagebox.showerror("Error", "Please enter both username and password.")
            return

        # Validate username format (no spacing)
        if ' ' in username:
            messagebox.showerror("Error", "Username cannot contain spaces.")
            return

        # Validate email format (optional)
        if not is_valid_email(username):
            messagebox.showerror("Error", "Invalid username format.")
            return

        # Validate password format (at least 8 characters long, containing nums, symbols, caps, and small letters)
        if not is_valid_password(password):
            messagebox.showerror("Error", "Invalid password format. Password must be at least 8 characters long and contain at least one uppercase letter, one lowercase letter, one digit, and one symbol.")
            return

        # Perform login operation
        password = hash_password(password)  # Hash the password before checking in the database
        
        c.execute("SELECT * FROM users WHERE username=? AND password=?", (username, password))
        result = c.fetchone()
        conn.close()
        
        if result:
            self.master.destroy()
            display_window = display_module.GUI(root)
            display_window.mainloop()
            messagebox.showinfo("Success", "Login successful!")
            print("Login Successful")
        else:
            messagebox.showerror("Error", "Invalid username or password.")
            

    def switchWindows(self):
        self.master.switch_to_signup()


class SignUpForm(ttk.Frame):

    def __init__(self, master):
        super().__init__(master, padding=(20, 10))
        self.pack(fill=tk.BOTH, expand=tk.YES)

        # form variables
        self.first_name = tk.StringVar(value="")
        self.last_name = tk.StringVar(value="")
        self.user_name = tk.StringVar(value="")
        self.email = tk.StringVar(value="")
        self.password = tk.StringVar(value="")

        # form header
        hdr_txt = "Enter your credentials " 
        hdr = ttk.Label(master=self, text=hdr_txt, width=50)
        hdr.pack(fill=tk.X, pady=10)

        # form entries
        self.create_form_entry("First Name", self.first_name)
        self.create_form_entry("Last Name", self.last_name)
        self.create_form_entry("Username", self.user_name)
        self.create_form_entry("Email", self.email)
        self.create_form_entry("Password", self.password)
        self.create_buttonbox()

    def create_form_entry(self, label, variable):
        """Create a single form entry"""
        container = ttk.Frame(self)
        container.pack(fill=tk.X, expand=tk.YES, pady=5)

        lbl = ttk.Label(master=container, text=label.title(), width=10)
        lbl.pack(side=tk.LEFT, padx=5)

        ent = ttk.Entry(master=container, textvariable=variable)
        ent.pack(side=tk.LEFT, padx=5, fill=tk.X, expand=tk.YES)
        
    def create_buttonbox(self):
        """Create the application buttonbox"""
        container = ttk.Frame(self)
        container.pack(fill=tk.X, expand=tk.YES, pady=(15, 10))

        sub_btn = ttk.Button(
            master=container,
            text="Sign Up",
            command=self.on_submit,
            width=6,
        )
        sub_btn.pack(side=tk.RIGHT, padx=5)
        sub_btn.focus_set()

        cnl_btn = ttk.Button(
            master=container,
            text="Back",
            command=self.switchWindows,
            width=6,
        )
        cnl_btn.pack(side=tk.RIGHT, padx=5)

    def on_submit(self):
        """Signup operation"""
        first_name = self.first_name.get().strip() 
        last_name = self.last_name.get().strip() 
        username = self.user_name.get().strip()  
        email = self.email.get().strip()  
        password = self.password.get().strip()  
        
        if not first_name or not last_name or not username or not email or not password:
            messagebox.showerror("Error", "Please fill in all fields.")
            return

        # Validate username format (no spacing)
        if ' ' in username:
            messagebox.showerror("Error", "Username cannot contain spaces.")
            return

        # Validate email format
        if not is_valid_email(email):
            messagebox.showerror("Error", "Invalid email format.")
            return

        # Validate password format
        if not is_valid_password(password):
            messagebox.showerror("Error", "Invalid password format. Password must be at least 8 characters long and contain at least one uppercase letter, one lowercase letter, one digit, and one symbol.")
            return

        # Perform signup operation
        password = hash_password(password)  # Hash the password before storing in the database
        
        try:
            c.execute("INSERT INTO users (first_name, last_name, username, email, password) VALUES (?, ?, ?, ?, ?)", (first_name, last_name, username, email, password))
            conn.commit()
            messagebox.showinfo("Success", "Sign up successful!")
            print("User registered successfully")
        except sqlite3.IntegrityError:
            messagebox.showerror("Error", "Username or email already exists.")
            print("Username or email already exists")

    def switchWindows(self):
        self.master.switch_to_login()


class MainWindow(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Sign Up Form")
        self.geometry('800x600')
        self.resizable(False, False)

        self.login_form = LoginForm(self, self)
        self.signup_form = SignUpForm(self)
        self.current_form = self.login_form
        
        # Hide signup form initially
        self.signup_form.pack_forget()

    def switch_to_signup(self):
        self.login_form.pack_forget()
        self.signup_form.pack(fill=tk.BOTH, expand=tk.YES)

    def switch_to_login(self):
        self.signup_form.pack_forget()
        self.login_form.pack(fill=tk.BOTH, expand=tk.YES)


# Define email and password validation functions
def is_valid_email(email):
    email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(email_pattern, email)

def is_valid_password(password):
    password_pattern = r'^(?=.*[A-Z])(?=.*[a-z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$'
    return re.match(password_pattern, password)


if __name__ == "__main__":
    app = MainWindow()
    app.mainloop()
