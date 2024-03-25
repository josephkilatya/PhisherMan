import tkinter as tk
from tkinter import ttk
from tkinter import messagebox
import sqlite3
import hashlib
import re
import os
import sys

# Add the directory containing the display_module.py file to the system path
sys.path.append(os.path.dirname(os.path.abspath(__file__)) + '/display_module/')
import display_module
from login import LoginForm, SignUpForm, is_valid_email, is_valid_password, hash_password

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

    def switch_to_display(self):
        self.login_form.pack_forget()
        self.signup_form.pack_forget()
        self.display_window = display_module.GUI(root=self)  # Create an instance of the display window
        self.display_window.mainloop()

def main():
    app = MainWindow()
    app.mainloop()

if __name__ == "__main__":
    main()
