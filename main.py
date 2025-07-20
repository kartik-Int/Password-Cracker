import hashlib 
from tqdm import tqdm
from concurrent.futures import ThreadPoolExecutor, as_completed
import itertools
import argparse
import shutil
import os
import sys



def hashing(to_be_hashed_password , hash_type):

    hash_fn = getattr(hashlib, hash_type)
    hashed = hash_fn(to_be_hashed_password.encode()).hexdigest()
    return hashed  #type str

#print(hashing("1234","md5"))


# chars="abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ123456789!@#$&-_"
chars ="abcdefghijklmnopqrstuvwxyz"
def generate_passwords(chars, length):
    for combo in itertools.product(chars, repeat=length):
        yield''.join(combo)

def threaded_bruteforce_attempt(hashed_password, hash_type, length, max_workers):
    flag = [False]
    result = [None]

    def try_password(pwd):
        if flag[0]:
            return
        hashed = hashing(pwd, hash_type)
        if check_hash(hashed, hashed_password):
            flag[0] = True
            result[0] = pwd

    with ThreadPoolExecutor(max_workers) as executor:
        futures = []
        for pwd in generate_passwords(chars, length):
            if flag[0]:
                break
            futures.append(executor.submit(try_password, pwd))
        for future in as_completed(futures):
            if flag[0]:
                break

    return result[0]



#Comparing computed hash to target hash
def check_hash(hash,hashed_password):
    return int(hash == hashed_password)


def crack_hash(hashed_password,hash_type,ipt,min_len, max_len,max_workers):
    global cracked_password
    flag=0

    #no optional is inputed
    if ipt=="none":
        print("Using Common passwords...")
        f = open("wordlist.txt")
        for line in tqdm(f.readlines(), desc="Checking common passwords"):
            password =line.strip()
            hashed = hashing(password,hash_type)
            flag = check_hash(hashed,hashed_password)
            if flag == 1:
                cracked_password = password
                break
        f.close()
            
        if flag == 0:
            print("Using Bruteforce....")
            for leng in tqdm(range(min_len, max_len + 1), desc="Bruteforcing"):
                result = threaded_bruteforce_attempt(hashed_password, hash_type, leng,max_workers)
                if result:
                    cracked_password = result
                    flag = 1
                    break
        if flag==0:
            print("Failed to get password!!")



    elif ipt=="range":                                               #If optional is length range
        print("Using Common passwords...")
        f = open("wordlist.txt")
        for line in tqdm(f.readlines(), desc="Trying Password..."):
            password =line.strip()
            if min_len <= len(password) <= max_len:
                hashed = hashing(password,hash_type)
                flag = check_hash(hashed,hashed_password)
                if flag==1:
                        print("hi")
                        cracked_password = password
                        return
            else:
                continue
        f.close()
            
        if flag == 0:
            print("Using Brute Force....")
            for leng in tqdm(range(min_len, max_len + 1), desc="Bruteforcing"):
                result = threaded_bruteforce_attempt(hashed_password, hash_type, leng,max_workers)
                if result:
                    cracked_password = result
                    flag = 1
                    break
        if flag==0:
            print("Failed to get password!!")


    elif ipt=="wordlist":
        f = open("input_wordlist.txt")
        for line in tqdm(f.readlines(),desc="Trying Wordlist"):
            password =line.strip()
            hashed = hashing(password,hash_type)
            flag = check_hash(hashed,hashed_password)
            if flag==1:
                cracked_password = password
                break

        f.close()

        if flag==0:
            print("Failed to get password!!")
    
    if flag==1:
        print(f"Password Cracked!\nPassword is {cracked_password}")
    

def parse_args():
    parser = argparse.ArgumentParser(description="Password Cracker")
    parser.add_argument("--hash",required=True, help="Input the target hased password")
    parser.add_argument("--type", required=True, help="Enter the Hash type (i.e. md5, sha256, etc.)")
    parser.add_argument("--wordlist",nargs ="*" ,help="Words or file path starting with @ sign. Usage: --wordlist @rockyou.txt or --wordlist pass1 pass2 ...")
    parser.add_argument("--range",nargs=2 ,type=int, default=[1, 4], help="Password length range. Usage: range 4 6. Length range by default is range 1 4")
    parser.add_argument("--workers",type=int, default=3, help="Worker use for threading")
    return parser.parse_args()


# Use if __name__ == "__main__": to parse args and run crack_hash().

if __name__ == "__main__":
    args = parse_args()
    ipt = 'none'
    
    if args.wordlist:
        ipt='wordlist'
        wordlist_input = args.wordlist
        if len(wordlist_input) == 1 and os.path.isfile(wordlist_input[0]):
            shutil.copy(wordlist_input[0], "input_wordlist.txt")
            # print("Wordlist file copied to input_wordlist.txt") #for my reference only

        # Case 2: it's a list of words
        else:
            with open("input_wordlist.txt", "w") as f:
                for word in wordlist_input:
                    f.write(word.strip() + "\n")
            # print("Words written to input_wordlist.txt") #for my reference only



    elif '--range' in sys.argv:
        ipt = 'range'
    else:
        ipt='none'

    crack_hash(args.hash, args.type, ipt, min_len=args.range[0], max_len=args.range[1],max_workers=args.workers)
