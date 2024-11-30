# padding-oracle
This Repository contains code that makes it easier to recreate padding oracle attacks.

# Usage
1. Create a function `oracle` that fulfils the following requirements:

```
def oracle(iv, ct):
	if decrypt(iv, ct) is valid padding:
		do nothing
	else:
		raise ValueError
```


2. To decrypt a message:

```
message = decrypt(iv,ciphertext, oracle)
```

