<?php
$shuffled_password = "7F6_23Ha8:5E4N3_/e27833D4S5cNaT_1i_O46STLf3r-4AH6133bdTO5p419U0n53Rdc80F4_Lb6_65BSeWb38f86{dGTf4}eE8__SW4Dp86_4f1VNH8H_C10e7L62154";
$length = strlen($shuffled_password);

// Gieo mầm giống hệt server
srand(0x1337);

// Tạo ra chính xác chuỗi số ngẫu nhiên mà hàm str_shuffle sử dụng
$random_indices = [];
for ($i = $length - 1; $i > 0; $i--) {
    $j = rand(0, $i);
    $random_indices[] = $j;
}

// In ra chuỗi số, cách nhau bởi dấu phẩy, để chúng ta dùng trong Python
echo implode(',', $random_indices);
?>