import cv2
import numpy as np
from sys import argv

def QR_fix(image_path, grid_size=21):
    img = cv2.imread(image_path, cv2.IMREAD_GRAYSCALE)
    if img is None:
        raise ValueError('Image cant load :(')

    _, binary = cv2.threshold(img, 0, 255, cv2.THRESH_BINARY + cv2.THRESH_OTSU)

    h, w = binary.shape
    module_height = h // grid_size
    module_width = w // grid_size

    normalized = np.zeros((grid_size, grid_size), dtype=np.uint8)

    for r in range(grid_size):
        for c in range(grid_size):
            cell = binary[r*module_height:(r+1)*module_height, c*module_width:(c+1)*module_width]
            normalized[r, c] = 255 if np.mean(cell) > 135 else 0

    normalized_img = cv2.resize(normalized, (w, h), interpolation=cv2.INTER_NEAREST)

    return normalized_img

if __name__ == '__main__':
    filename = argv[1]
    normalized_img = QR_fix(filename, grid_size=int(argv[2]))
    cv2.imwrite('fixed'+filename, normalized_img)