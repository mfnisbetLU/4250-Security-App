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
        self.username_label.pack()
        self.username_entry.pack()
        self.password_label.pack()
        self.password_entry.pack()
        self.login_button.pack()

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
                    # Display the QR code
                    self.generate_qr_code(otp_secret)
                    # Then, prompt for OTP
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

if __name__ == "__main__":
    app = UserLoginSystem()
    app.window.mainloop()