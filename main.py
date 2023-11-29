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

MIN_USERNAME_LENGTH = 3
MIN_PASSWORD_LENGTH = 5
MAX_USERNAME_LENGTH = 20
MAX_PASSWORD_LENGTH = 20

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
        username = self.username_entry.get()[:MAX_USERNAME_LENGTH]
        password = self.password_entry.get()[:MAX_PASSWORD_LENGTH]

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
                        role = self.get_user_role(username)
                        SuccessfulLoginWindow(self.window, username, role, self.on_successful_login)
                    else:
                        # Show error message on invalid OTP
                        messagebox.showerror("Error", "Invalid OTP")
                else:
                    # Show error message on server response error
                    messagebox.showerror("Error", response['error'])
            else:
                # If OTP is not set up, show success message without OTP prompt
                role = self.get_user_role(username)
                SuccessfulLoginWindow(self.window, username, role, self.on_successful_login)
        else:
            # Show error message on failed login attempt
            messagebox.showerror("Error", "Invalid username or password")

    def on_successful_login(self, username):
        role = self.get_user_role(username)
        program = self.get_user_program(username)  
        average = self.get_user_average(username)  
        MainMenuWindow(self.window, username, role, program, average)

    def get_user_role(self, username):
        # Get the role of the specified user
        users_data = self.load_users()
        return users_data.get(username, {}).get("role", "Unknown")

    def get_user_program(self, username):  # Added method
        users_data = self.load_users()
        return users_data.get(username, {}).get("program", "Unknown")

    def get_user_average(self, username):  # Added method
        users_data = self.load_users()
        return users_data.get(username, {}).get("average", "0")

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

        # Check if the username length exceeds the limit
        if len(username) > MAX_USERNAME_LENGTH or len(username) < MIN_USERNAME_LENGTH:
            messagebox.showerror("Error", f"Username must be between {MIN_USERNAME_LENGTH} and {MAX_USERNAME_LENGTH} characters")
            return

        # Check if the username already exists
        users = self.load_users()
        if username in users:
            messagebox.showerror("Error", "Username already exists")
            return

        # Get password and confirm password from the user
        password = simpledialog.askstring("Create User", "Enter password:", show="*")
        if not password:
            return  # User clicked Cancel

        # Ensure the password length is within the limit
        if len(password) > MAX_PASSWORD_LENGTH or len(password) < MIN_PASSWORD_LENGTH:
            messagebox.showerror("Error", f"Password must be between {MIN_PASSWORD_LENGTH} and {MAX_PASSWORD_LENGTH} characters")
            return

        confirm_password = simpledialog.askstring("Create User", "Confirm password:", show="*")
        if password != confirm_password:
            messagebox.showerror("Error", "Passwords do not match")
            return

        # Add a new user to the dictionary
        users[username] = {"password": password, "secret_key": None, "email": None, "role": "Student", "program": None, "average": "0"}

        # Save the updated user dictionary to the JSON file
        self.save_users(users)

        enable_2fa = messagebox.askyesno("Enable 2FA", "Do you want to enable 2FA?")
        email = None
        secret_key = None

        # If 2FA is enabled, generate a dynamic secret key from the server
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

class SuccessfulLoginWindow(tk.Toplevel):
    def __init__(self, master=None, username=None, role=None, on_successful_login=None):
        super().__init__(master)
        self.title("Successful Login")
        self.geometry("300x150")

        label = tk.Label(self, text=f"Login successful!\nUsername: {username}\nRole: {role}")
        label.pack(pady=20)

        ok_button = tk.Button(self, text="OK", command=lambda: self.on_ok_button_pressed(on_successful_login, username))
        ok_button.pack()

    def on_ok_button_pressed(self, on_successful_login, username):
        if on_successful_login:
            on_successful_login(username)
        self.destroy()

class MainMenuWindow(tk.Toplevel):
    def __init__(self, master=None, current_user=None, current_role=None, current_program=None, current_average=None):
        super().__init__(master)
        self.title("Main Menu")
        self.geometry("300x300")
        self.current_user = current_user
        self.current_role = current_role
        self.current_program = current_program
        self.current_average = current_average

        # Load users_data
        self.users_data = self.load_users()

        label = tk.Label(self, text=f"Welcome, {self.current_user}!\nRole: {self.current_role}")
        label.pack(pady=20)

        # Buttons for various actions
        self.create_action_button("Change User Program", self.create_change_program_window, self.is_admin() or self.is_dean())
        self.create_action_button("Change User Average", self.create_change_average_window, self.is_admin() or self.is_dean() or (self.is_professor() and self.same_program_with_students()))
        self.create_action_button("Change User Role", self.create_change_role_window, self.is_admin())

        # Create the initial dropdown for user selection only for Professor, Dean, and Admin
        if self.is_professor() or self.is_dean() or self.is_admin():
            self.user_dropdown_label = tk.Label(self, text="Select Student:")
            self.selected_user_var = tk.StringVar()
            self.user_dropdown = tk.OptionMenu(self, self.selected_user_var, ())
            self.user_dropdown_label.pack()

            # Update the user dropdown after creating it
            self.update_user_dropdown()
            self.user_dropdown.pack()

        self.create_action_button("Display Student Average", self.display_student_average, self.is_admin() or self.is_dean() or (self.is_professor() and self.same_program_with_students()))
        self.create_action_button("Display Average", self.display_average, self.is_student())
        self.create_action_button("Logout", self.logout, self.is_student() or self.is_admin() or self.is_professor() or self.is_dean())

    def update_user_dropdown(self):
        if self.is_professor():
            professor_program = self.users_data.get(self.current_user, {}).get("program")
            usernames = [username for username, data in self.users_data.items() if data.get("role") == "Student" and data.get("program") == professor_program]
        else:  # Admins and Deans can select any user
            usernames = list(self.users_data.keys())

        self.selected_user_var.set(usernames[0] if usernames else "")
        self.user_dropdown['menu'].delete(0, 'end')
        for username in usernames:
            self.user_dropdown['menu'].add_command(label=username, command=tk._setit(self.selected_user_var, username))

    def create_action_button(self, text, command, condition):
        if condition:
            button = tk.Button(self, text=text, command=command)
            button.pack()

    def display_student_average(self):
        selected_user = self.selected_user_var.get()
        if selected_user:
            student_average = self.users_data[selected_user].get("average", "N/A")
            messagebox.showinfo("Student Average", f"{selected_user}'s average is: {student_average}")

    def is_admin(self):
        users_data = self.load_users()
        return users_data.get(self.current_user, {}).get("role") == "Admin"

    def is_student(self):
        users_data = self.load_users()
        return users_data.get(self.current_user, {}).get("role") == "Student"

    def is_dean(self):
        users_data = self.load_users()
        return users_data.get(self.current_user, {}).get("role") == "Dean"

    def is_professor(self):
        users_data = self.load_users()
        return users_data.get(self.current_user, {}).get("role") == "Professor"

    def same_program_with_students(self):
        users_data = self.load_users()
        professor_program = users_data.get(self.current_user, {}).get("program")
        students_in_program = [username for username, data in users_data.items() if data.get("role") == "Student" and data.get("program") == professor_program]
        return len(students_in_program) > 0

    def display_average(self):
        messagebox.showinfo("Average", f"Your average is: {self.current_average}")

    def create_change_average_window(self):
        ChangeAverageWindow(self, self.users_data, self.current_user)

    def create_change_role_window(self):
        ChangeRoleWindow(self, self.users_data)

    def create_change_program_window(self):
        ChangeProgramWindow(self, self.users_data)

    def load_users(self):
        users_file = "users.json"
        if users_file:
            with open(users_file, "r") as file:
                users = json.load(file)
            return users
        else:
            return {}

    def logout(self):
        self.destroy()

class ChangeProgramWindow(tk.Toplevel):
    def __init__(self, master=None, users_data=None):
        super().__init__(master)
        self.title("Change User Program")
        self.geometry("300x200")

        # Make sure to set the users_data attribute
        self.users_data = users_data
        if self.users_data is None:
            self.load_users()

        # Dropdown menu for user selection
        usernames = list(self.users_data.keys())
        self.selected_user_var = tk.StringVar(value=usernames[0] if usernames else "")
        user_dropdown_label = tk.Label(self, text="Select User:")
        user_dropdown = tk.OptionMenu(self, self.selected_user_var, *usernames)
        user_dropdown_label.pack()
        user_dropdown.pack()

        # Entry for new program
        self.new_program_entry = tk.Entry(self)
        new_program_label = tk.Label(self, text="Enter New Program:")
        new_program_label.pack()
        self.new_program_entry.pack()

        # Button to change user program
        change_program_button = tk.Button(self, text="Change User Program", command=self.change_user_program)
        change_program_button.pack()

    def load_users(self):
        users_file = "users.json"
        if users_file:
            with open(users_file, "r") as file:
                self.users_data = json.load(file)
        else:
            self.users_data = {}

    def change_user_program(self):
        selected_user = self.selected_user_var.get()
        new_program = self.new_program_entry.get()

        if not selected_user:
            messagebox.showerror("Error", "Please select a user.")
            return

        if not new_program:
            messagebox.showerror("Error", "Please enter a new program.")
            return

        if selected_user not in self.users_data:
            messagebox.showerror("Error", f"User '{selected_user}' not found.")
            return

        # Check if the current user is a Dean and the selected user is not an Admin or Dean
        if self.is_dean() and self.users_data[selected_user]["role"] not in ["Admin", "Dean"]:
            self.users_data[selected_user]["program"] = new_program
            messagebox.showinfo("Success", f"Program for user '{selected_user}' changed to '{new_program}'.")
        # Check if the current user is an Admin and the selected user is not an Admin
        elif self.is_admin() and self.users_data[selected_user]["role"] != "Admin":
            self.users_data[selected_user]["program"] = new_program
            messagebox.showinfo("Success", f"Program for user '{selected_user}' changed to '{new_program}'.")
        else:
            messagebox.showerror("Error", "You do not have permission to change the program for this user.")
            return

        # Save the updated user dictionary to the JSON file
        users_file = "users.json"
        with open(users_file, "w") as file:
            json.dump(self.users_data, file)

    def is_admin(self):
        users_data = self.load_users()
        return users_data.get(self.master.current_user, {}).get("role") == "Admin"

    def is_dean(self):
        users_data = self.load_users()
        return users_data.get(self.master.current_user, {}).get("role") == "Dean"

    def load_users(self):
        # Load users from the JSON file
        users_file = "users.json"
        if users_file:
            with open(users_file, "r") as file:
                users = json.load(file)
            return users
        else:
            return {}

class ChangeAverageWindow(tk.Toplevel):
    def __init__(self, master=None, users_data=None, current_user=None):
        super().__init__(master)
        self.title("Change User Average")
        self.geometry("300x200")

        # Make sure to set the users_data attribute
        self.users_data = users_data
        if self.users_data is None:
            self.load_users()

        self.current_user = current_user

        # Filter students based on the same program as the professor
        professor_program = self.users_data.get(self.current_user, {}).get("program")
        usernames = [username for username, data in self.users_data.items() if data.get("role") == "Student" and data.get("program") == professor_program]

        self.selected_user_var = tk.StringVar(value=usernames[0] if usernames else "")
        user_dropdown_label = tk.Label(self, text="Select User:")
        user_dropdown = tk.OptionMenu(self, self.selected_user_var, *usernames)
        user_dropdown_label.pack()
        user_dropdown.pack()

        # Entry for new average
        self.new_average_entry = tk.Entry(self)
        new_average_label = tk.Label(self, text="Enter New Average:")
        new_average_label.pack()
        self.new_average_entry.pack()

        # Button to change user average
        change_average_button = tk.Button(self, text="Change User Average", command=self.change_user_average)
        change_average_button.pack()

    def load_users(self):
        users_file = "users.json"
        if users_file:
            with open(users_file, "r") as file:
                self.users_data = json.load(file)
        else:
            self.users_data = {}

    def change_user_average(self):
        selected_user = self.selected_user_var.get()
        new_average = self.new_average_entry.get()

        if not selected_user:
            messagebox.showerror("Error", "Please select a user.")
            return

        if not new_average:
            messagebox.showerror("Error", "Please enter a new average.")
            return

        if selected_user not in self.users_data:
            messagebox.showerror("Error", f"User '{selected_user}' not found.")
            return

        # Check if the current user is a Professor and the selected user is a Student in the same program
        if self.is_professor() and self.can_change_student_average(selected_user):
            self.users_data[selected_user]["average"] = new_average
            messagebox.showinfo("Success", f"Average for user '{selected_user}' changed to '{new_average}'.")
        elif self.is_dean() or self.is_admin():
            # Deans and admins can change the average for any user
            self.users_data[selected_user]["average"] = new_average
            messagebox.showinfo("Success", f"Average for user '{selected_user}' changed to '{new_average}'.")
        else:
            messagebox.showerror("Error", "You do not have permission to change the average for this user.")
            return

        # Save the updated user dictionary to the JSON file
        users_file = "users.json"
        with open(users_file, "w") as file:
            json.dump(self.users_data, file)

    def is_professor(self):
        return self.users_data.get(self.master.current_user, {}).get("role") == "Professor"

    def is_dean(self):
        return self.users_data.get(self.master.current_user, {}).get("role") == "Dean"

    def is_admin(self):
        return self.users_data.get(self.master.current_user, {}).get("role") == "Admin"

    def can_change_student_average(self, student_username):
        professor_program = self.users_data.get(self.current_user, {}).get("program")
        student_program = self.users_data.get(student_username, {}).get("program")
        return self.is_professor() and student_program == professor_program
    
class ChangeRoleWindow(tk.Toplevel):
    def __init__(self, master=None, users_data=None):
        super().__init__(master)
        self.title("Change User Role")
        self.geometry("300x200")

        # Make sure to set the users_data attribute
        self.users_data = users_data
        if self.users_data is None:
            self.load_users()

        # Dropdown menu for user selection
        usernames = list(self.users_data.keys())
        self.selected_user_var = tk.StringVar(value=usernames[0] if usernames else "")
        user_dropdown_label = tk.Label(self, text="Select User:")
        user_dropdown = tk.OptionMenu(self, self.selected_user_var, *usernames)
        user_dropdown_label.pack()
        user_dropdown.pack()

        # Dropdown menu for role assignment
        roles = ["Student", "Professor", "Dean", "Admin"]
        self.selected_role_var = tk.StringVar(value=roles[0])
        role_dropdown_label = tk.Label(self, text="Select Role:")
        role_dropdown = tk.OptionMenu(self, self.selected_role_var, *roles)
        role_dropdown_label.pack()
        role_dropdown.pack()

        # Button to change user role
        change_role_button = tk.Button(self, text="Change User Role", command=self.change_user_role)
        change_role_button.pack()

    def load_users(self):
        # Load users from the JSON file
        users_file = "users.json"
        if users_file:
            with open(users_file, "r") as file:
                self.users_data = json.load(file)
        else:
            self.users_data = {}

    def change_user_role(self):
        selected_user = self.selected_user_var.get()
        selected_role = self.selected_role_var.get()

        if not selected_user:
            messagebox.showerror("Error", "Please select a user.")
            return

        if not selected_role:
            messagebox.showerror("Error", "Please select a role.")
            return

        if selected_user not in self.users_data:
            messagebox.showerror("Error", f"User '{selected_user}' not found.")
            return

        # Update the user's role in the dictionary
        self.users_data[selected_user]["role"] = selected_role

        # Save the updated user dictionary to the JSON file
        users_file = "users.json"
        with open(users_file, "w") as file:
            json.dump(self.users_data, file)

        messagebox.showinfo("Success", f"Role for user '{selected_user}' changed to '{selected_role}'.")

if __name__ == "__main__":
    app = UserLoginSystem()
    app.window.mainloop()