from flask import flash


# Password length should be at least the min_len_val(10).
def min_len(password, min_len_val=10):
    if len(password) < min_len_val:
        flash(f'Your password length is less that {min_len_val} characters.', category='error')


# Check if the password contains any of the common password dictionary.
# https://cybernews.com/best-password-managers/most-common-passwords/
def common_pass_list(password):
    common_pass_dictionary = ["123456", "123456789", "qwerty", "password",
                             "12345", "qwerty123", "1q2w3e", "12345678",
                             "111111", "1234567890"]
    for common in common_pass_dictionary:
        if common in password:
            flash(f'Your password contains a common known keyword : {common}.', category='error')


# The password shouldn't be like any password that was used up till 3 changes ago.
def history(password):
    pass


# Check if there is at least one special character.
def special_char(password):
    special_characters = "_+{}\":;'[]~!@#$%^&*()"
    for special in special_characters:
        if special in password:
            return 1
    return 0


# Check if there is at least one lower case character.
def lower_case(password):
    for p in password:
        if p.islower():
            return 1
    return 0


# Check if there is at least one upper case character.
def upper_case(password):
    for p in password:
        if p.isupper():
            return 1
    return 0


# Check if there is at least one digit.
def dig(password):
    for p in password:
        if p.isdigit():
            return 1
    return 0


# 3 out of 4 check: [Upper case, Lower case, Digit, Special character]
def three_out_of_four(password):
    if special_char(password) + lower_case(password) + upper_case(password) + \
            dig(password) < 3:
        flash(
            f'Your password should contain at least 3 of the following: [Upper case, Lower case, Digit, Special character]',
            category='error')


# Main check password function.
def check_password(password):
    min_len(password)
    three_out_of_four(password)
    history(password)
    common_pass_list(password)
