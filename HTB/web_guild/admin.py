import hashlib

# Admin's email
email = "3232524a6e673759@master.guild"

# Generate SHA-256 hash of the email
hashed = hashlib.sha256(email.encode()).hexdigest()

# Construct the reset link
reset_link = f"http://94.237.54.145:50131/changepasswd/{hashed}"

print("Reset Link:", reset_link)