import tensorflow as tf
import numpy as np
from PIL import Image

# ============================================
# Các tham số từ file app.py và cho cuộc tấn công
# ============================================
IMG_HEIGHT, IMG_WIDTH = 224, 224
ORIGINAL_IMAGE_PATH = 'image.jpg' # Đảm bảo bạn có file này
TARGET_CLASS_ID = 101  # Lớp 'gibbon'

# Tham số cho cuộc tấn công
ITERATIONS = 100         # Số lần lặp để tối ưu
LEARNING_RATE = 0.01     # Tốc độ học (kích thước bước)
MSE_THRESHOLD = 0.05     # Ngưỡng MSE từ server

# ============================================
# Tải mô hình và ảnh gốc
# ============================================
print("[+] Loading MobileNetV2 model...")
model = tf.keras.applications.MobileNetV2(weights="imagenet")

print(f"[+] Loading original image from '{ORIGINAL_IMAGE_PATH}'...")
original_image_pil = Image.open(ORIGINAL_IMAGE_PATH)

# ============================================
# Hàm tiền xử lý (sao chép y hệt từ app.py)
# ============================================
def preprocess_image(img):
    img = img.convert('RGB').resize((IMG_HEIGHT, IMG_WIDTH))
    img_array = np.array(img)
    preprocessed_img = tf.keras.applications.mobilenet_v2.preprocess_input(img_array)
    return tf.convert_to_tensor(preprocessed_img, dtype=tf.float32)

# Tiền xử lý ảnh gốc để có tensor tham chiếu
original_image_tensor = preprocess_image(original_image_pil)
original_image_tensor_expanded = tf.expand_dims(original_image_tensor, axis=0)

# ============================================
# Thiết lập cuộc tấn công
# ============================================
# Tạo một biến tensor từ ảnh gốc để có thể tính gradient
adversarial_image = tf.Variable(original_image_tensor_expanded)

# Hàm loss: chúng ta muốn tối thiểu hóa cross-entropy so với lớp mục tiêu
loss_object = tf.keras.losses.CategoricalCrossentropy()
target_vector = tf.one_hot([TARGET_CLASS_ID], depth=1000)

print(f"[+] Starting adversarial attack for {ITERATIONS} iterations...")

for i in range(ITERATIONS):
    with tf.GradientTape() as tape:
        # Theo dõi các phép toán trên ảnh đối kháng
        tape.watch(adversarial_image)
        # Lấy dự đoán của mô hình
        prediction = model(adversarial_image)
        # Tính loss so với mục tiêu 'gibbon'
        loss = loss_object(target_vector, prediction)

    # Lấy gradient của loss đối với các pixel của ảnh
    gradients = tape.gradient(loss, adversarial_image)
    
    # Cập nhật ảnh bằng cách di chuyển một bước nhỏ theo hướng ngược lại của gradient (để tối thiểu hóa loss)
    adversarial_image.assign_sub(LEARNING_RATE * gradients)

    # --- Rất quan trọng: Giữ ảnh mới gần với ảnh gốc ---
    # Đảm bảo các thay đổi không vượt quá một ngưỡng nhất định để giữ MSE thấp.
    # Kỹ thuật này được gọi là "clipping" hoặc "projection"
    perturbation = adversarial_image - original_image_tensor_expanded
    
    # Giới hạn tổng thể sự thay đổi (epsilon) để kiểm soát MSE
    # Epsilon được chọn thực nghiệm để đảm bảo MSE < 0.05
    epsilon = np.sqrt(MSE_THRESHOLD) * 0.8 # An toàn một chút
    perturbation = tf.clip_by_value(perturbation, -epsilon, epsilon)
    
    adversarial_image.assign(tf.clip_by_value(original_image_tensor_expanded + perturbation, -1.0, 1.0))

    if (i + 1) % 10 == 0:
        print(f"    Iteration {i+1}/{ITERATIONS}, Loss: {loss.numpy():.4f}")

print("[+] Attack finished.")

# ============================================
# Chuyển đổi tensor trở lại thành ảnh và lưu
# ============================================
print("[+] Converting tensor back to image...")
# Lấy tensor đã tối ưu (loại bỏ chiều batch)
final_adversarial_tensor = adversarial_image[0]

# Kiểm tra MSE cuối cùng để chắc chắn
final_mse = tf.reduce_mean(tf.square(original_image_tensor - final_adversarial_tensor))
print(f"[+] Final MSE: {final_mse.numpy():.4f} (Threshold: {MSE_THRESHOLD})")
if final_mse.numpy() > MSE_THRESHOLD:
    print("[!] WARNING: Final MSE is above the threshold! Try reducing LEARNING_RATE.")

# Hàm "giải" tiền xử lý để chuyển tensor từ [-1, 1] về [0, 255]
deprocessed_array = (final_adversarial_tensor.numpy() + 1.0) * 127.5
deprocessed_array = np.clip(deprocessed_array, 0, 255).astype(np.uint8)

# Tạo ảnh từ mảng numpy
final_image = Image.fromarray(deprocessed_array)
output_path = "adversarial_gibbon.png"
final_image.save(output_path, "PNG")

print(f"[+] Adversarial image saved to '{output_path}'")

# ============================================
# Kiểm tra lại kết quả (tùy chọn nhưng nên làm)
# ============================================
print("[+] Verifying the generated image...")
verify_image_tensor = preprocess_image(final_image)
verify_pred = model.predict(np.expand_dims(verify_image_tensor, axis=0), verbose=0)
predicted_class_id = np.argmax(verify_pred[0])
decoded_preds = tf.keras.applications.mobilenet_v2.decode_predictions(verify_pred, top=1)[0]
predicted_class_name = decoded_preds[0][1]

print(f"    - Predicted as: '{predicted_class_name}' (ID: {predicted_class_id})")
if predicted_class_id == TARGET_CLASS_ID:
    print("[+] SUCCESS: The image is correctly classified as the target.")
else:
    print("[!] FAILURE: The image was NOT classified as the target. Try increasing ITERATIONS or adjusting LEARNING_RATE.")