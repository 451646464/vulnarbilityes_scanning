import requests
target = input("Target :")
payload = "<script>alert('velinerable');</script>"
req=requests.get(target + payload,"html.parser").text
if payload in req:
    print("XSS Vulnerablity discovered")
else:
    print("Don't found XSS")