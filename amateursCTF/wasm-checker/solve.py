from z3 import *

# Định nghĩa 43 biến là Vecto Bit 32-bit (i32 trong WASM)
flag = [BitVec(f'f_{i}', 32) for i in range(43)]

# Tạo một trình giải
solver = Solver()

# SỬA LỖI CUỐI CÙNG: Chỉ ràng buộc giá trị tối thiểu là 32 (cho ' ')
# và tối đa là 255 (giới hạn byte) để tránh lỗi UNSAT.
for i in range(43):
    solver.add(flag[i] >= 32)
    solver.add(flag[i] <= 255) # Thay đổi từ 126 thành 255

# --- Dịch 60 phương trình từ file .wat (Đã xác minh logic) ---

val1_1 = (flag[6] + flag[38]) - flag[31]
val1_2 = (flag[21] ^ flag[41]) - ((flag[12] | flag[13]) * flag[26])
val1_3 = flag[3] - val1_2
val1_4 = val1_1 & val1_3
val1_5 = flag[2] | (flag[35] + flag[39])
val1_6 = val1_4 | val1_5
val1_7 = flag[20] - (flag[4] - flag[30])
val1_8 = val1_6 - val1_7
val1_final = val1_8 | flag[11]
solver.add(val1_final == 110)

solver.add((flag[10] | flag[36]) == 95)
solver.add(((flag[27] ^ flag[8]) & flag[15]) == 45)
# Phương trình 4: Logic đã sửa
val4_1 = (flag[42] * flag[37]) ^ (flag[24] * flag[18])
val4_2 = flag[1] * val4_1
val4_3 = val4_2 ^ flag[25]
val4_4 = flag[33] ^ val4_3
val4_final = val4_4 & flag[19]
solver.add(val4_final == 100)
solver.add((flag[0] ^ flag[28]) == 23)
solver.add((flag[34] & flag[16]) == 82)
solver.add((flag[22] & flag[29]) == 48)
solver.add((flag[5] | flag[14]) == 119)
solver.add((flag[7] & flag[17]) == 97)
solver.add((flag[40] - flag[9]) == 24)
solver.add(((flag[11] * flag[32]) - flag[23]) == 11569)
solver.add((flag[26] & (flag[21] ^ flag[6])) == 0)
solver.add(((flag[39] & flag[20]) ^ flag[10]) == 86)
solver.add((flag[35] & (flag[40] | (flag[19] * ((flag[9] - flag[27]) & flag[38])))) == 32)
solver.add((flag[1] & flag[41]) == 33)
solver.add((((flag[24] + (flag[34] * flag[22] * flag[14])) - (flag[29] ^ flag[23])) & flag[13]) == 16)
solver.add((flag[5] ^ (flag[17] - ((flag[30] + flag[33] + flag[18] + flag[36]) ^ flag[25]))) == BitVecVal(-504, 32))
solver.add((((flag[32] & flag[42]) * flag[4]) - (flag[3] - flag[8])) == 9344)
solver.add((flag[15] - (flag[0] * flag[37])) == BitVecVal(-9494, 32))
solver.add((flag[12] + flag[2]) == 216)
solver.add((flag[7] - flag[11]) == BitVecVal(-8, 32))
solver.add(((flag[16] | flag[28]) & (flag[31] ^ flag[13])) == 1)
solver.add(((flag[37] - flag[24]) & flag[38]) == 0)
solver.add((flag[23] * flag[12]) == 13804)
solver.add((flag[42] & flag[2]) == 97)
solver.add((flag[25] - flag[32]) == 20)
solver.add((flag[30] ^ (flag[5] & flag[17])) == 19)
solver.add((flag[18] | flag[6]) == 126)
solver.add((flag[16] | flag[22]) == 127)
solver.add((flag[29] ^ ((flag[14] * flag[3]) | flag[1])) == 13390)
solver.add((((flag[10] + flag[7]) * flag[31]) ^ flag[33]) == 9849)
solver.add(((flag[34] - (flag[39] + (flag[8] & flag[11]))) & flag[36]) == 95)
solver.add((flag[28] & (((flag[15] + (flag[20] ^ flag[21])) ^ flag[40]) * (flag[0] & flag[19]))) == 96)
solver.add((flag[41] ^ flag[9]) == 117)
solver.add(((flag[26] * flag[35]) - (flag[4] - flag[27])) == 2455)
solver.add(((flag[37] & flag[22]) * flag[0]) == 3104)
solver.add((((flag[3] & (flag[10] + flag[9])) - (flag[34] | flag[36]))) == BitVecVal(-111, 32))
solver.add((flag[28] + flag[24]) == 213)
solver.add((flag[26] | flag[39] | flag[12]) == 119)
solver.add((flag[6] - flag[27]) == 6)
solver.add((flag[42] - flag[33]) == 73)
solver.add(((flag[20] - (flag[7] * (flag[8] & (flag[5] ^ flag[30])))) ^ (flag[32] - flag[41])) == BitVecVal(-200, 32))
solver.add((flag[11] - flag[29]) == 72)
solver.add((flag[23] & flag[15]) == 100)
solver.add((flag[25] ^ flag[35]) == 64)
solver.add((flag[4] - flag[13]) == 49)
solver.add((flag[21] + flag[14]) == 230)
solver.add((((flag[18] | (flag[40] + (flag[19] ^ flag[17] ^ flag[16]))) - (flag[38] - flag[2])) ^ flag[2]) == 223)
solver.add((flag[31] - flag[1]) == BitVecVal(-56, 32))
solver.add((flag[36] | flag[3]) == 127)
solver.add((flag[42] * (flag[20] | (flag[25] + (flag[12] - flag[10])))) == 31875)
solver.add(((flag[27] - (flag[32] - (flag[22] - flag[5]))) | flag[6]) == BitVecVal(-2, 32))
solver.add(((flag[14] + (flag[4] * flag[31]))) == 5468)
solver.add((((flag[34] & flag[0]) * (flag[8] & (flag[9] + flag[1]))) - flag[11]) == 6117)
solver.add((flag[24] * flag[39]) == 4560)
solver.add((flag[28] * flag[15]) == 12862)
solver.add((((((((flag[40] ^ flag[41]) ^ (flag[17] + flag[30])) ^ (flag[37] - (flag[16] ^ flag[33]))) ^ (flag[18] & flag[21])) ^ flag[7]) + flag[23])) == BitVecVal(-21, 32))
solver.add((flag[35] + flag[26]) == 99)
solver.add((flag[13] * flag[2] * flag[29] * flag[38]) == 12347712)
solver.add((flag[19] + (flag[11] ^ (flag[30] ^ ((flag[4] * flag[5]) & flag[8])))) == 108)

# Yêu cầu Z3 giải
if solver.check() == sat:
    print("✅ Đã tìm thấy giải pháp!")
    m = solver.model()
    flag_str = ""
    for i in range(43):
        flag_str += chr(m[flag[i]].as_long())
    print("\nFLAG LÀ:")
    print(flag_str)
else:
    print("❌ Không tìm thấy giải pháp.")