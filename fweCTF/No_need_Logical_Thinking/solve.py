# The full string from output.txt
encrypted_string = """gyhgyl|qoj\>@@xqDD|zyJyg}UD¡"""

# A list to hold the characters of our original flag
original_chars = []

# Loop through each character of the encrypted string with its index
# The Prolog script's index starts at 1, so we'll use i + 1
for i, char in enumerate(encrypted_string):
    # Get the numeric code (ASCII/Unicode value) of the character
    encrypted_code = ord(char)
    
    # The index to subtract (starts from 1)
    index_to_subtract = i + 1
    
    # Perform the reverse operation: subtraction
    original_code = encrypted_code - index_to_subtract
    
    # Convert the new code back to a character and add it to our list
    original_chars.append(chr(original_code))

# Join all the decrypted characters back into a single string
original_text = "".join(original_chars)

# Print the final result
print(original_text)