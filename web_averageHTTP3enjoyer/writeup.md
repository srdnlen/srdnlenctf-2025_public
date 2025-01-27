# Average HTTP/3 Enjoyer

- **Category:** Web
- **Solves:** TBA
- **Tag:** 

## Description

HTTP/3 is just the best version of HTTP, wait a few years , until setting up an HTTP/3 server will not be a pain, and you’ll see. I hid a secret on /flag, you can only get it if you become a real HTTP/3 enjoyer.

NOTE: This challenge uses only HTTP/3, browsers are a bit hesitant in using it by default, so you’ll have to use explicit arguments to do so.

In chrome you can do the following:

`chrome --enable-quic --origin-to-force-quic-on=enjoyer.challs.ctf.srdnlen.it`

## Solution

We have a frontend (Haproxy) and a backend (flask).

The backend has a /flag endpoint, which returns the flag
```python
@app.route('/flag')
def flag():
    return "srdnlen{f4k3_fl4g}"
```

However, the Haproxy configuration file has the following ACL rule
```
acl restricted_flag path_sub,url_dec -m sub -i i /flag
http-request deny if restricted_flag
```
The above rule blocks access to every path containing the substring /flag (and also 'i', but that was not intended)


In HTTP/2 and HTTP/3, the concept of pseudo-header was introduced to replace the data sent in the first two request lines of HTTP/1.1 (GET /path HTTP/1.1\r\nHost: example.com\r\n). This is required since HTTP/2 and 3 use header compression instead of sending plain ASCII like HTTP/1.
Pseudo-headers (method, path, scheme, and authority) are mandatory, and tools like curl will fill them based on the URL provided to the command (e.g., curl https://google.com/test -> :method GET, :path /test, :scheme https, authority: google.com).


In our scenario, flask has a route "/flag" however, the leading slash is not mandatory, so a request to "flag" will match the route.
At this point, it becomes clear that in order to bypass the filter on /flag we need to omit the slash. However, most tools will prepend the '/' on every path. This happens because most tools ask you to type the entire URL with the path, and '/' acts as the separator between the hostname and the path. However, using the pseudo-header :path we don't need to specify the slash.
There are many ways to solve the challenge at this point, all we need is a tool or piece of code that allows us to set the :path value directly.
One way is to use the http3 client of the Aioquic library. At line 227 of /aioquic/examples/http3_client.py we can put `(b":path", "flag".encode())`.
By running the client on our target url we will bypass the ACL filter and get the flag.
`srdnlen{you_found_the_:path_for_becoming_a_real_http3_enjoyer}`
