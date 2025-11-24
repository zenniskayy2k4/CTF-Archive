// bypass.js
console.log("[*] Bắt đầu script bypass...");

Java.perform(function() {
    console.log("[*] Đang hook các hàm Java...");

    // 1. Bypass Anti-Debuggable Flag
    var ApplicationInfo = Java.use('android.content.pm.ApplicationInfo');
    var ContextWrapper = Java.use('android.content.ContextWrapper');
    ContextWrapper.getApplicationInfo.implementation = function() {
        var info = this.getApplicationInfo();
        info.flags.value &= ~ApplicationInfo.FLAG_DEBUGGABLE.value;
        console.log("[+] Đã vô hiệu hóa cờ FLAG_DEBUGGABLE.");
        return info;
    };

    // 2. Bypass Anti-Root (kiểm tra file)
    var File = Java.use('java.io.File');
    File.exists.implementation = function() {
        var path = this.getAbsolutePath();
        if (path.endsWith('/su') || path.includes('Superuser')) {
            console.log("[+] Đã bypass kiểm tra root cho file: " + path);
            return false;
        }
        return this.exists();
    };

    // 3. Bypass Anti-Root (thực thi lệnh 'su')
    var Runtime = Java.use('java.lang.Runtime');
    Runtime.getRuntime().exec.overload('java.lang.String').implementation = function(command) {
        if (command === 'su') {
            console.log("[+] Đã bypass kiểm tra root cho lệnh: " + command);
            throw Java.use('java.io.IOException').$new("Bypass");
        }
        return this.exec(command);
    };

    // 4. Bypass quét cổng Frida
    var Socket = Java.use('java.net.Socket');
    Socket.connect.overload('java.net.SocketAddress', 'int').implementation = function(endpoint, timeout) {
        var port = endpoint.getPort();
        if (port >= 27042 && port <= 27052) {
            console.log("[+] Đã bypass quét cổng Frida trên cổng: " + port);
            throw Java.use('java.io.IOException').$new("Bypass");
        }
        return this.connect(endpoint, timeout);
    };

    // 5. Ngăn chặn luồng giám sát Frida
    var Thread = Java.use('java.lang.Thread');
    Thread.$init.overload('java.lang.Runnable').implementation = function(runnable) {
        var runnableName = runnable.getClass().getName();
        if (runnableName.includes('RunnableC0154w')) { 
            console.log("[+] ĐÃ CHẶN luồng giám sát anti-debug!");
            return; // Không làm gì cả, luồng sẽ không được tạo
        }
        return this.$init(runnable);
    };
});

// 6. Bypass Anti-ptrace (Native)
var baseAddr = Module.findBaseAddress('libnative-lib.so');
if (baseAddr) {
    // Địa chỉ của hàm so sánh (bắt đầu của khối 0x7a8b)
    // Tìm đến khối `if (((((...` trong Ghidra
    var comparisonAddr = baseAddr.add(0x11b06c - 0x100000); // Offset của khối so sánh

    console.log("[*] Đang chờ để hook vào hàm so sánh tại: " + comparisonAddr);

    Interceptor.attach(comparisonAddr, {
        onEnter: function(args) {
            console.log("\n[!] ĐÃ VÀO HÀM SO SÁNH!");
            
            // Trong Assembly, con trỏ đến chuỗi bí mật (pbVar11) được lưu trong x21
            var secretPointer = this.context.x21;
            
            // Đọc 16 byte từ con trỏ đó
            var secretBytes = Memory.readByteArray(secretPointer, 16);
            
            // Chuyển đổi thành chuỗi
            var secretString = "";
            var uint8Array = new Uint8Array(secretBytes);
            for (var i = 0; i < uint8Array.length; i++) {
                secretString += String.fromCharCode(uint8Array[i]);
            }
            
            console.log("[+] Tìm thấy phần sau của flag: " + secretString);
            console.log("\nGHÉP VỚI PHẦN ĐẦU ĐỂ CÓ FLAG HOÀN CHỈNH!");
        }
    });
}