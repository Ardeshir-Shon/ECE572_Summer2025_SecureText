import hashlib
import bcrypt
import time

password = "ECE572_assignment!"


start_fast = time.time()
for _ in range(1000):
    hashlib.sha256(password.encode()).hexdigest()
end_fast = time.time()
sha_time = end_fast - start_fast


start_slow = time.time()
for _ in range(10):
    bcrypt.hashpw(password.encode(), bcrypt.gensalt(rounds=12))
end_slow = time.time()
bcrypt_time = end_slow - start_slow

print(f"SHA-256 hashing time for 1000 hashes: {sha_time:.4f} seconds")
print(f"bcrypt hashing time for 10 hashes: {bcrypt_time:.4f} seconds")
print(f"Average bcrypt hash time: {bcrypt_time / 10:.4f} seconds")
