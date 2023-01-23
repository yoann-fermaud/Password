import re
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


def main():
    print(security_requirements)
    while True:
        password = input_user()
        if check_password(password):
            print(f"Valid password !\n"
                  f"Password encrypt is : {encrypt_password(password)}")
            break
        else:
            print("Invalid password ! Please check the security requirements.\n")


if __name__ == '__main__':
    main()
