import requests
import hashlib
import sys
# password  checker via web API
# password needs to be hashed in SHA1
# k-animinity: first 5 chacacters of the hash - for security reasons


def request_api_data(query_char):
    url = 'https://api.pwnedpasswords.com/range/' + query_char
    res = requests.get(url)
    if res.status_code != 200:
        raise RuntimeError(f'Error fetching: {res.status_code}, check the api - try again')
    return res


def get_password_leaks_count(hashes, hash_to_check):
    hashes = (line.split(':') for line in hashes.text.splitlines())
    for h, count in hashes:
        if h == hash_to_check:
            return count
    return 0

def read_res(response):
    print(response.text)

def pwned_api_check(password):
    sha1pwd = hashlib.sha1(password.encode('utf-8')).hexdigest().upper() # refer to hashlib docs for details , need to encode to utf-8, hexdigest to change to string
    first5_char, tail = sha1pwd[:5], sha1pwd[5:]
    response = request_api_data(first5_char)
    return get_password_leaks_count(response, tail)

def main(args):
    for password in args:
        count = pwned_api_check(password)
        if count:
            print(f'{password} was found {count} times... maybe change password? \n \n Checkout https://www.microsoft.com/en-us/microsoft-365-life-hacks/privacy-and-safety/keep-your-passwords-safe-with-these-tips')
        else:
            print(f'{password} not found - carry on')

if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
