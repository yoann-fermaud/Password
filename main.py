import re
import json
import hashlib

security_requirements = """
Here are the security requirements for the password :
    ● It must contain at least 8 characters.
    ● It must contain at least one uppercase letter.
    ● It must contain at least one lowercase letter.
    ● It must contain at least one number.
    ● It must contain at least one special character (!, @, #, $, %, ^, &, *).
"""


def input_user():
    take_input = input("Password : ")
    return take_input


def check_password(password):
    if len(password) < 8:
        print("It must contain at least 8 characters.")
        return False
    if not re.search("[a-z]", password):
        print("It must contain at least one uppercase letter.")
        return False
    if not re.search("[A-Z]", password):
        print("It must contain at least one lowercase letter.")
        return False
    if not re.search("[0-9]", password):
        print("It must contain at least one number.")
        return False
    if not re.search("[!@#$%^&*]", password):
        print("It must contain at least one special character (!, @, #, $, %, ^, &, *).")
        return False
    return True


def encrypt_password(password):
    return hashlib.sha256(password.encode()).hexdigest()


def print_password(password):
    print(f"Valid password !\n"
          f"Password encrypt is : {encrypt_password(password)}")


def save_password(password):
    with open('password_hl.json', 'r') as f:
        list_password = json.load(f)
    if password not in list_password:
        print_password(password)
        list_password.append(password)
        with open('password_hl.json', 'w') as f:
            json.dump(list_password, f)
    else:
        # Saved password : Ex@mple1234
        print("This password already exists\n")
        main()


def main():
    while True:
        password = input_user()
        if check_password(password):
            save_password(encrypt_password(password))
            break
        else:
            print("Invalid password ! Please check the security requirements.\n")


if __name__ == '__main__':
    print(security_requirements)
    main()
