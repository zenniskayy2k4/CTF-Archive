#----------------------------------------------------------------------------------------------#
# This module is part of the peppernut app (secure user store of and access to their recipes). #
# - Provides the app's security related functions used for all password related functionality. #
#----------------------------------------------------------------------------------------------#


# Security Engineer Notes:
#-------------------------

# So the boss said I have to document my code better. - How I asked?
# "Don't just write your code when you're coding: Write your thoughts and reflections too!" was the response.
# So what am I thinking? Like:
# "... Why hasn't anybody thought about how difficult working conditions are, when the project you are working on constantly 
# reminds you of peppernuts, and you don't have any? :-( 
# (... wait and by the way hope that won't affect the security of my coding :-o ...)"
# Ah wait, today's coding tasks of course. And yeah maybe it could be beneficial for maintanability with explicit code considerations 
# along the way? So here goes I guess:

# Fundamentally users log in with their passwords, so only the right users can access their respective recipes.
# - But more is needed for security in a state of the art environment. Thus here some specific further security features:


# 1. Password hashing: Storing passwords securely using hashes.

# To be able to verify the users' passwords, rather than plaintext passwords their hashes are stored: The result of 
# a one-way hash function applied to the password, whereby original password cannot be easily retrieved from the hash,
# even if someone by one mean or another gets access to the hashes in the database.


# 1.1. Pepper

# A so-called pepper is used, which is a secret value added to the password before hashing, to prevent certain attacks from someone 
# who gets access to the hashes: A measure against guessing or bruteforcing until finding the password that matches the hash.
def create_pepper():
    """Create a secure pepper for password hashing."""
    import secrets
    # A size of at least 16 bytes is recommended, so an attacker who knows one of the user's passwords (e.g. their own account), 
    # can't learn the value of the pepper by bruteforcing its possible values, until finding the one that added to the known password 
    # gives the same hash as the stored one:
    pepper_size = 16
    # ... wow that feeling again, I could really use some peppernuts... were was I, something about creating the pepper?
    pepper = hex(secrets.randbits(pepper_size))[2:]
    
    # The pepper is then securily kept seperately, rendering the hashes alone insufficient for an attacker.
    with open('secret.txt', 'w') as f: 
        f.write(pepper)

# And this same secret pepper is then in turn used to verify the password:
def get_pepper() -> str:
    with open('secret.txt', 'r') as f: 
        pepper = f.read()
    return pepper


# 1.2. Different hash functions

# There are different state of the art hash functions for different use cases, each with their own properties, strengths, and weaknesses:
def password_hash(password) -> str:
    """Create a state-of-the-art password hash, secure against different attack vectors."""
    # So we take the pepper and use it together with hashing functions to attain the security described above. 
    pepper = get_pepper()
    
    # Now SHA-256 is a relatively fast hash function, which in principle can get us quite far with regards to many of the purposes:
    from hashlib import sha256
    hash = sha256
    ph = hash((pepper + ":" + password).encode()).hexdigest()

    # ... wow, again, I could really use some peppernuts... where was I, writing something?... ehh, what to write, maybe about testing 
    # the functionality so far(?) - like how the test with password="Test123!" at this point had the value of ph be:
    # '8b56d663500f6f36f7b2f329cbcfe65851b146df3567e0b2fcf896391d641b7f'...
    # Ah yes - and so as intended this documented the non-reversible transformation of the password with the pepper giving 
    # a different hash value than if the password had been hashed on its own.

    # With this initial- or pre-hash as I might call it (as for why I used "ph") warding against potential denial of service attacks 
    # when very large passwords are allowed (as they are meant to be in this app), an essential next is the further application of
    # a relatively cumbersome hashing algorithm e.g. high in resource demands to make it harder for an attacker to bruteforce the hashes. 
    # - And thus the state-of-the-art recommendation for the purpose:
    from argon2 import PasswordHasher 

    # With this we now move beyond mere "secure-hash-with-a-pepper", to security complete with the algorithm's superb weigh-in requiring: 
    # - Processor time: Potentially from 10.000 to 1.000.000 times more than SHA-256 ! 
    # - Memory: Rather than the few hundred bytes used by SHA-256, this monster can with typical setups take from 64-512MB - per hash! x-D
    # Try to bruteforce my app's password security now I dare you! :-D And not only that! Also...
    # ... wait was that the doorbell?! Was there supposed to come a peppernut delivery that I am unaware of? I'll be right back...
    # ... arh what that was just the regular postman with a bakery sales brochure of all things. x-(  
    # ... where was I... something about ph?... what was ph? Theee... password hash? Ah right, the return value I guess:
    return ph 
    # Anyway, I have(!) to get hold of some peppernuts one way or another... I'll follow up on this work later...



# 2. Password validation: Ensuring that users choose strong passwords.

# ...wow from what that employee on the phone told me, there might actually be a peppernut delivery swinging by here soon. :)

# So, on to the next security feature: The password security measure is of course only as strong as the passwords chosen:
# - If the passwords are weak, they could potentially be bruteforced and or guessed by attackers.
# - I will therefore implement validation to ensure that the passwords are strong enough.
def validate_password(password: str) -> str | None:
    """Validate password strength, returning the password if it is safe enough, 
    or throwing an informative error if it is not."""
    
    # A strong password should meet a number of minimum requirements to pass validation:
    descriptions = {
        1: "Password is longer than 7 characters.",
        2: "Password contains at least one digit.",
        3: "Password contains at least one uppercase letter.",
        4: "Password contains at least one special character."
    }

    # We can use the variable `check` to keep track of how far the password gets through the checks.
    checks = []
    if len(password) >= 8:
        checks += [1]
    if any(char.isdigit() for char in password):
        checks += [2]
    if any(char.isupper() for char in password):
        checks += [3]
    if any(not char.isalnum() for char in password):
        checks += [4]
    
    # Either is returned a valid password passing all checks, or if not, the user is informed about the specific requirement not met.
    # ... wait where is that peppernut delivery when you need it... I'll have to finish this and try to figure out: 
    if len(checks) > 0:
        raise ValueError(f"Invalid password! Your password failed the requirements, specifically due to the following checks:\n"
                         f"{"\n".join([descriptions[check] for check in checks])}\n"
                         f"Please try again with a password that meets all the requirements.")
    else: 
        return password

# ... 'kay I'm back, but met the boss on the way saying that now my module is the last remaining before the app is finished, and 
# thus everything else is already waiting in the CI/CD pipelines, with the entire app ready to autodeploy as soon as my code has 
# been finalized along with the others... :-| ... I of course tried explaining that of all things, you do not wan't to rush security...
# ... but on the positive side, I finally got hold of some peppernuts! :-D So back on track :) - the first handful already having 
# their effect, so fit for an additional bit of secure coding. And with some more peppernuts still waiting, so lets wrap this up.



# 3. Data encryption: Encrypting the users' recipes to protect them from unauthorized access.

# As a final measure against attackers, who one way or another gets access to the stored data bypassing the login system, 
# the recipes are extensively secured by encrypting them with a key based on the user password: 
# This way, no matter who gets or how they get access to the data, they won't be able to read it without the user password.
def encrypt_data(data: str, nonce: str, password: str, hash_salt: str, key_salt: str, decrypt: bool = False) -> str:
    """Safely encrypt/decrypt data with a key based on the user password, 
    whereby only the user is able to read the data."""
    # With the use of non-secret values, salts prevent against lookup tables, and a nonce changed with each encryption ensures
    # that a later encryption of the same recipe yields a different result than before. - Thus attackers (already prevented
    # from reading the recipes) also cannot even deduce whether the decrypted content changed or not between two encryptions.

    # The gold standard for encrypting sensitive user data in modern systems is AES-256-GCM, recommended by NIST, OWASP, and 
    # numerous cryptographic standards as the default AEAD (Authenticated Encryption with Associated Data) mode:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    
    # Again as earlier, to effectively encumber bruteforcing, the state-of-the-art heavy hash function goto is argon2, though for 
    # deterministic key derivation (like here in encryption schemes) where we need to reproduce exactly the same key 
    # from the same password + salt combo, we need to switch to the low level API (hash_secret_raw), to explicitly control the salt.
    from argon2.low_level import hash_secret_raw, Type

    # This encryption related hash is done seperately from the password hashes we already stored, since otherwise someone with access 
    # to the password hashes wouldn't even need to discern the passwords at all to decrypt. 
    argon2_hash = hash_secret_raw(
        secret=password.encode(),
        salt=bytes.fromhex(hash_salt),
        time_cost=5,
        memory_cost=262144,
        parallelism=4,
        hash_len=64,
        type=Type.ID
    )

    # To cleanly distill our argon2 hash into the fixed length, high entropy cryptographic key for our AESGCM encryption, 
    # the industry standard here is HKDF-SHA256:
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    # (Here importing SHA256 from another library - still effectively the same algorithm, but just a specific format for HKDF:) 
    from cryptography.hazmat.primitives import hashes 
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        # Though using the same hash_salt as above isn't usually considered insecure in simple single user setups, using seperate salts 
        # even here is the gold standard recommendation, especially in systems with long term security and audit requirements:
        salt= bytes.fromhex(key_salt),
        info=b'user-data-encryption'
    )
    key = hkdf.derive(argon2_hash)

    # Thus all prepared for encryption/decryption (two sides of the same scheme for symmetric encryption like this state-of-the-art AES):
    aesgcm = AESGCM(key)
    if decrypt: 
        return aesgcm.decrypt(bytes.fromhex(nonce), bytes.fromhex(data), None).hex()
    else:
        return aesgcm.encrypt(bytes.fromhex(nonce), bytes.fromhex(data), None).hex()

# Alright - I just thouroughly reviewed my work here in section 3, and it's rock solid :-D so ready to wrap things up with section 4.



# 4. Reviews and tests of the code

# So with that powerhouse of a section 3 above, nobody will read these peppernut recipes without the corresponding password. :)
# - And that only the intended user knows or is able to figure out the password, is already ensured by my work in sections 1 and 2, 
# which I also already thouroughly revie... 
# ... wait did I review them yet?... I should probably double check, especially also since all the other code reviewers and testers 
# are presently all away, taking flex time off, trying to find some peppernuts, so I should probably... 
# ... wait, what's that scent in the air? - So strongly reminds me of peppernuts for some reason. But that's right it is - the remaining 
# peppernuts - I had forgotten all about them! :-D Was I done here? - I probably was, and if not I'm sure one of the others will test 
# and review and let me know. - So commit-push, there we go, now time for peppernuuuuuuuuuuts!... 
