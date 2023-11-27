import tkinter as tk
from tkinter import messagebox, simpledialog
import json
import os
import pyotp
import qrcode
from PIL import ImageTk, Image
import os
import requests  

os.chdir(os.path.dirname(os.path.abspath(__file__)))
print("Current Working Directory:", os.getcwd())

class UserLoginSystem:
    def __init__(self):
        # GUI elements (they appear in order vertically downwards)
        self.users_file = "users.json"
        self.window = tk.Tk()
        self.window.title("Login System with 2FA")
        self.username_label = tk.Label(self.window, text="Username:")
        self.username_entry = tk.Entry(self.window)
        self.password_label = tk.Label(self.window, text="Password:")
        self.password_entry = tk.Entry(self.window, show="*")
        self.login_button = tk.Button(self.window, text="Login", command=self.login)
        self.register_button = tk.Button(self.window, text="Register", command=self.create_user)
        self.generate_key_button = tk.Button(self.window, text="Reset 2FA", command=self.generate_and_display_key)
        
        self.username_label.pack()
        self.username_entry.pack()
        self.password_label.pack()
        self.password_entry.pack()
        self.login_button.pack()
        self.register_button.pack()
        self.generate_key_button.pack()

        # Use this to change window dimensions
        self.window.geometry("400x350")

    # Main login function
    def login(self):
        username = self.username_entry.get()
        password = self.password_entry.get()

        # Check if the username and password are correct
        if self.check_credentials(username, password):
            # If correct, check if the user has OTP set up
            otp_secret = self.load_secret_key(username)
            # If OTP is set up, obtain the 2FA key from the server
            if otp_secret:
                # Make a request to the server to get the 2FA key
                response = self.get_2fa_key(username)
                if 'error' not in response:
                    otp_secret = response['secret_key']
                    current_code = response['current_code']
                    # Don't display the QR code, should only be displayed on user creation or email
                    entered_otp = simpledialog.askstring("OTP", "Enter OTP:")
                    if entered_otp and self.verify_otp(otp_secret, entered_otp):
                        # If OTP is valid, show success message
                        messagebox.showinfo("Success", "Login successful!")
                    else:
                        messagebox.showerror("Error", "Invalid OTP")
                else:
                    messagebox.showerror("Error", response['error'])
            else:
                # If OTP is not set up, show success message without OTP prompt
                messagebox.showinfo("Success", "Login successful!")
        else:
            messagebox.showerror("Error", "Invalid username or password")
            
        # If user doesn't have 2FA set up, provide an option to enable it
        if not otp_secret and messagebox.askyesno("Enable 2FA", "Do you want to enable 2FA?"):
            self.enable_2fa(username)

    # Generate a QR code for the OTP secret
    def generate_qr_code(self, otp_secret):
        username = self.username_entry.get()

        if otp_secret:
            totp = pyotp.TOTP(otp_secret)
            uri = totp.provisioning_uri(name=username, issuer_name="YourApp")
            img = qrcode.make(uri)

            # Display the QR code image
            img = img.resize((200, 200), Image.ANTIALIAS)
            img_tk = ImageTk.PhotoImage(img)
            qr_code_window = tk.Toplevel(self.window)
            qr_code_window.title("QR Code")
            qr_code_label = tk.Label(qr_code_window, image=img_tk)
            qr_code_label.image = img_tk
            qr_code_label.pack()
        else:
            messagebox.showerror("Error", "User does not have OTP set up")

    # Load users and passwords from the JSON file
    def check_credentials(self, username, password): 
        users = self.load_users()
        # Check if the username exists
        if username in users:
            # Compare the entered password with the password
            stored_password = users[username]["password"]
            if password == stored_password:
                return True
        return False

    # Load users and passwords from the JSON file (should be hashed, currently stored in plaintext)
    def load_users(self):
        users_file = "users.json"
        if users_file:
            with open(users_file, "r") as file:
                users = json.load(file)
            return users
        else:
            return {}

    # Load the secret key for OTP from the users dictionary
    def load_secret_key(self, username):
        users = self.load_users()
        return users.get(username, {}).get("secret_key", None)

    # Verify the entered OTP using pyotp
    def verify_otp(self, otp_secret, entered_otp):     
        totp = pyotp.TOTP(otp_secret)
        return totp.verify(entered_otp)

    # Method to make a request to the server to get the 2FA key
    def get_2fa_key(self, username):
        url = 'http://127.0.0.1:5000/get_2fa_key'
        data = {'username': username}
        response = requests.post(url, json=data)
        return response.json()

    def create_user(self):
        username = simpledialog.askstring("Create User", "Enter new username:")
        if not username:
            return  # User clicked Cancel

        # Check if the username already exists
        users = self.load_users()
        if username in users:
            messagebox.showerror("Error", "Username already exists")
            return

        # Get password and confirm password from user
        password = simpledialog.askstring("Create User", "Enter password:", show="*")
        if not password:
            return  # User clicked Cancel

        confirm_password = simpledialog.askstring("Create User", "Confirm password:", show="*")
        if password != confirm_password:
            messagebox.showerror("Error", "Passwords do not match")
            return

        # Add new user to the dictionary
        users[username] = {"password": password, "secret_key": None, "email": None}

        # Save the updated user dictionary to the JSON file
        self.save_users(users)

        enable_2fa = messagebox.askyesno("Enable 2FA", "Do you want to enable 2FA?")
        email = None
        secret_key = None

        # If 2FA is enabled, generate dynamic secret key from the server
        if enable_2fa:
            response = self.generate_dynamic_secret_key_from_server(username)
            if 'error' not in response:
                secret_key = response.get('secret_key')
                if secret_key:
                    self.generate_qr_code(secret_key)
                    email = simpledialog.askstring("Enable 2FA", "Enter your email for recovery:")
                else:
                    messagebox.showerror("Error", "Failed to generate secret key.")

        # Update the user dictionary with the generated secret key and email
        users[username]["secret_key"] = secret_key
        users[username]["email"] = email

        # Save the updated user dictionary to the JSON file again
        self.save_users(users)

        messagebox.showinfo("Success", "User created successfully!")
        
    def save_users(self, users):
        with open(self.users_file, "w") as file:
            json.dump(users, file)

    def enable_2fa(self, username):
        # Make a request to the server to generate the dynamic secret key
        response = self.generate_dynamic_secret_key_from_server(username)
        if 'error' not in response:
            secret_key = response['secret_key']

            # Update the user's secret key in the dictionary
            users = self.load_users()
            users[username]["secret_key"] = secret_key
            self.save_users(users)

            # Display the new QR code
            self.generate_qr_code(secret_key)

            # Optionally, allow the user to input their email address for recovery
            email = simpledialog.askstring("Enable 2FA", "Enter your email for recovery:")
            if email:
                # Update the user's email in the dictionary
                users[username]["email"] = email
                self.save_users(users)

            messagebox.showinfo("Success", "2FA enabled successfully!")
        else:
            messagebox.showerror("Error", response['error'])

    def generate_dynamic_secret_key_from_server(self, username):
        url = 'http://127.0.0.1:5000/generate_secret_key'
        data = {'username': username}  # Pass the username in the request data
        response = requests.post(url, json=data)
        
        if response.status_code == 200:
            return response.json()
        else:
            return {'error': f'Error generating secret key: {response.status_code}'}

    def generate_and_display_key(self):
        # Get the username and email from the user
        username = simpledialog.askstring("Generate New Key", "Enter your username:")
        if not username:
            return  # User clicked Cancel

        # Ensure the username exists
        users = self.load_users()
        if username not in users:
            messagebox.showerror("Error", "Username not found")
            return

        email = users[username].get("email")
        if not email:
            messagebox.showerror("Error", "No email address associated with the account")
            return

        # Get the email from the user
        entered_email = simpledialog.askstring("Generate New Key", "Enter your email:")
        if not entered_email or entered_email != email:
            messagebox.showerror("Error", "Invalid email address")
            return

        # Generate a new secret key
        response = self.generate_dynamic_secret_key_from_server(username)
        if 'error' in response:
            messagebox.showerror("Error", response['error'])
            return

        new_secret_key = response.get('secret_key')
        if not new_secret_key:
            messagebox.showerror("Error", "Failed to generate new secret key.")
            return

        # Update the user's secret key in the dictionary
        users[username]["secret_key"] = new_secret_key
        self.save_users(users)

        # Generate a new QR code and display it
        self.generate_qr_code(new_secret_key)

if __name__ == "__main__":
    app = UserLoginSystem()
    app.window.mainloop()