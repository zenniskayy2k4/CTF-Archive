from PIL import Image
import numpy as np

def fix_qr_code(image, qr_size=29):
    height, width = image.shape

    avg_block_width = width / qr_size
    avg_block_height = height / qr_size

    fixed_qr = np.zeros((qr_size, qr_size), dtype=np.uint8)

    for y in range(qr_size):
        for x in range(qr_size):
            x_start = int(round(x * avg_block_width))
            x_end = int(round((x + 1) * avg_block_width))
            y_start = int(round(y * avg_block_height))
            y_end = int(round((y + 1) * avg_block_height))

            x_end = min(x_end, width)
            y_end = min(y_end, height)

            block = image[y_start:y_end, x_start:x_end]

            mean_val = np.mean(block)
            bit = 0 if mean_val < 127 else 1

            fixed_qr[y, x] = bit

    return fixed_qr

# Load your image as grayscale
img = Image.open('dino.png').convert('L')
img_arr = np.array(img)

# Fix the QR code bits
fixed_qr = fix_qr_code(img_arr)

# Save the fixed QR code as an image for visual verification (black and white)
fixed_img = Image.fromarray(fixed_qr * 255)  # scale from binary to 0/255
fixed_img.save('fixed_qr.png')

# Optionally, print the 29x29 fixed QR bit matrix
for n in fixed_qr:
    for m in n:
        print("_" if m else "#", end="")
    print()
    
    
### ["01000010","11011100","10010111","00100111","01000110","01100111","10110110","01110110","01010111","01000101","11110110","00100110","00010110","10010111","01000110","01010110","01001101","11110110","10110111","01000111","00110101","01110111","10010110","00110111","01000111","01001010","00010110","11000110","11000111","10010101","11110110","00010110","11100101","11110110","00010110","11100110","11110111","10011000","01000110","11110111","00110110","00010111","01010111","00100111","01010111","00110111","11010000","11101100","00011001","11101100","00000001","11101000","01110001","01101100","00010001","11000101","00101100","10001010","10010010","11000001","00110100","00000100","11011010","01101010","01001110","00111100","10110000","00101001","00001111","00110011"]