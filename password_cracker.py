
# LÄGG IN I CONFIG?
md5_hash_file = "md5_hashes.txt"
sha256_hash_file = "sha256_hashes.txt"


def find_password(hash_input):

    line_number_md5 = find_matching_hash(hash_input, md5_hash_file)
    line_number_sha256 = find_matching_hash(hash_input, sha256_hash_file)

    if line_number_md5 is not None:
        return get_password_on_specific_line(line_number_md5)

    if line_number_sha256 is not None:
        return get_password_on_specific_line(line_number_sha256)

    return None


def find_matching_hash(hash_input, file):
    line_number = 0
    try:
        with open(file, 'r') as f:
            for line in f:
                if hash_input.strip() == line.strip():
                    return line_number
                line_number += 1

    except FileNotFoundError as e:
        print(f"File not found: {e}")
    except Exception as e:
        print(f"Error: {e}")

    return None


def get_password_on_specific_line(line_number_to_find):
    line_nr = 0
    try:
        with open('common_passwords.txt', 'r') as f:
            for line in f:
                if line_number_to_find == line_nr:
                    return line.strip()
                line_nr += 1

    except FileNotFoundError as e:
        print(f"File not found: {e}")
    except Exception as e:
        print(f"Error: {e}")

    return None
