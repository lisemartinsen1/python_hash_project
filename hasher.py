import hashlib


def hash_passwords(output_file, hash_algorithm):
    try:

        if hash_algorithm not in hashlib.algorithms_available:
            raise ValueError(f'Hash algorithm {hash_algorithm} is not supported')

        with open('common_passwords.txt', 'r') as infile, open(output_file, 'w') as outfile:
            for line in infile:
                line = line.strip()
                hash_obj = hashlib.new(hash_algorithm)
                hash_obj.update(line.encode('utf-8'))
                hashed_password = hash_obj.hexdigest()
                outfile.write(f"{hashed_password}\n")

    except FileNotFoundError as e:
        print(f"File not found: {e}")
    except ValueError as e:
        print(f"Error: {e}")
    except Exception as e:
        print(f"Error: {e}")
