import json
import re
import random
import string

# Caesar cipher encryption and decryption functions
def caesar_encrypt(text, shift):
    encrypted_text = ""
    for char in text:
        if char.isalpha():
            shifted = ord(char) + shift
            if char.islower():
                if shifted > ord('z'):
                    shifted -= 26
                encrypted_text += chr(shifted)
            elif char.isupper():
                if shifted > ord('Z'):
                    shifted -= 26
                encrypted_text += chr(shifted)
        else:
            encrypted_text += char
    return encrypted_text

def caesar_decrypt(text, shift):
    return caesar_encrypt(text, -shift)

# Password strength checker function
def is_strong_password(password):
    if (len(password) >= 8 and
        re.search(r"[A-Z]", password) and
        re.search(r"[a-z]", password) and
        re.search(r"[0-9]", password) and
        re.search(r"[!@#$%^&*(),.?\":{}|<>]", password)):
        return True
    return False

# Password generator function
def generate_password(length):
    """
    Generate a random strong password of the specified length.
    """
    if length < 8:
        raise ValueError("Password length should be at least 8 characters.")

    characters = string.ascii_letters + string.digits + "!@#$%^&*(),.?\":{}|<>"
    return ''.join(random.choice(characters) for _ in range(length))

# Global lists to store data
encrypted_passwords = []
websites = []
usernames = []

# Function to add a new password
def add_password():
    website = input("Enter website: ")
    username = input("Enter username: ")

    choice = input("Do you want to generate a strong password? (y/n): ").lower()
    if choice == 'y':
        length = int(input("Enter desired password length: "))
        password = generate_password(length)
        print(f"Generated password: {password}")
    else:
        password = input("Enter password: ")
        if not is_strong_password(password):
            print("Warning: The password is not strong!")

    shift = 3  # Example Caesar shift
    encrypted = caesar_encrypt(password, shift)

    websites.append(website)
    usernames.append(username)
    encrypted_passwords.append(encrypted)
    print("Password added successfully.")

# Function to retrieve a password
def get_password():
    website = input("Enter website to retrieve: ")
    if website in websites:
        index = websites.index(website)
        username = usernames[index]
        encrypted = encrypted_passwords[index]
        decrypted = caesar_decrypt(encrypted, 3)
        print(f"Username: {username}\nPassword: {decrypted}")
    else:
        print("Website not found.")

# Function to save passwords to a JSON file
def save_passwords():
    data = []
    for i in range(len(websites)):
        data.append({
            "website": websites[i],
            "username": usernames[i],
            "password": encrypted_passwords[i]
        })
    with open("vault.txt", "w") as file:
        json.dump(data, file, indent=4)
    print("Passwords saved successfully.")

# Function to load passwords from a JSON file
def load_passwords():
    global websites, usernames, encrypted_passwords
    try:
        with open("vault.txt", "r") as file:
            data = json.load(file)
        websites = [entry["website"] for entry in data]
        usernames = [entry["username"] for entry in data]
        encrypted_passwords = [entry["password"] for entry in data]
        print("Passwords loaded successfully!")
    except FileNotFoundError:
        print("No saved vault found.")
    except json.JSONDecodeError:
        print("Error reading vault file.")

# Main method
def main():
    while True:
        print("\nPassword Manager Menu:")
        print("1. Add Password")
        print("2. Get Password")
        print("3. Save Passwords")
        print("4. Load Passwords")
        print("5. Quit")

        choice = input("Enter your choice: ")

        if choice == "1":
            add_password()
        elif choice == "2":
            get_password()
        elif choice == "3":
            save_passwords()
        elif choice == "4":
            load_passwords()
        elif choice == "5":
            print("Goodbye!")
            break
        else:
            print("Invalid choice. Please try again.")

if __name__ == "__main__":
    main()
