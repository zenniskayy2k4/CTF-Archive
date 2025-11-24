Lướt qua ta thấy có hàm `result` có 2 tham số là full và hash

Nhìn lên trên ta thấy được `full` được tạo thành từ `%frag1%%frag2%%frag3%`

hash ở đây chính là mã SHA256 của chính file `game.bat` gốc.

Ta chỉ cần lấy 2 tham số đó rồi gọi cùng với file result.bat là sẽ có flag

Vậy tham số `full` được tạo ra như nào.

Chú ý lại tên của chall là `duck_rpg`

Nhìn sơ trong file `game.bat` thì full có thể là `unlockthegoose`.

Nhưng cuối file lại có hàm `battle0` cũng gọi tới hàm victory như hàm `battle3`

Đây chính là mấu chốt, kết hợp với tên chall thì full chắc chắn là `unlocktheduck`

Từ đây ta gõ 1 dòng lệnh cơ bản là đã có flag rồi :)))

`call result.bat "unlocktheduck" "8392dcc7b6fdebd5a70211c1e21497a553b31f2c70408b772c4a313615df7b60"`

Chạy lệnh lấy flag thôi :))))

`v1t{p4tch_th3_b4tch_t0_g3t_th3_s3cr3t_3nd1ng}`