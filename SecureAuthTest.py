'''
Author: Naresh Adhikari, Sru
This is a skeletal program that students need to implement the declared
and defined functions under @TODO annotation, according to the logic/functional requirements stated in assigment-2.pdf.
Students are not expected to modify main() function.
'''

import os
import hashlib, uuid


def secure_hashed_passwd(username, password):
    '''
    @TODO: Students are required to implement this function.
    using salt+pepper+sha3-224 algorithm
    :param username: string repr of username
    :param passwd: a plain text password
    :return: True if given values are stored successfully in outfile var; else returns False
    '''
    #use salt and pepper to hash 'hpasswd' using sha-3-224 algorithm
    password = bytes(password, "utf-8")
    hpasswd = hashlib.sha224()
    hpasswd.update(password)
 #   digest = hpasswd.digest()

    # Add salt
    salt = uuid.uuid4().bytes
#    hpasswd.update(password)
    hpasswd.update(salt)
#    salteddigest = hpasswd.digest()

    # add pepper
    pepper = os.urandom(16)
    hpasswd.update(pepper)
    saltpepperdigest = hpasswd.hexdigest()

    # Salt + Pepper + Run(Iteration)
#    saltpepperdigest = hpasswd.digest()

#    N = pow(2, 10)                                 #pow(2, 10) = 2 to the 10 power
#    for i in range(0, N):
#        saltpepperdigest = hashlib.sha224(saltpepperdigest).digest()

    # return hex version salt,pepper,saltpepperdigest
    return salt.hex(), pepper.hex(), saltpepperdigest #s.hex()

def verify_hashed_passwd(username, passwd):
    '''
    @TODO: Students are required to implement this function.
    Server side verifies login credentials username and password
    :param username:
    :param hpasswd:
    :return:
    '''
    #databse file with username and hashed-password.

    infile = "hlogins.dat"

    #open the file to read
    fd = open(infile, "r")

    #read the infile line by line to retrive a matching row with first field value of username
    for line in fd:
        values = line.split(",")
        if username == values[0]:
            print("\tusername-found")
            salt = values[1]
            pepper = values[2]
            stored_hpasswd = values[3]
            print("\tstored-hash", stored_hpasswd)
            print("\t salt,pep",salt,"..",pepper)
            passwd = bytes(passwd, "utf-8")
            salt = bytes(salt, "utf-8")
            pepper = bytes(pepper, "utf-8")
            tempo_hash = hashlib.sha224()
            tempo_hash.update(passwd)
            tempo_hash.update(salt)
            tempo_hash.update(pepper)
            temp_hash2=tempo_hash.hexdigest()
            print("\tgen-hash", temp_hash2)
            if temp_hash2 == stored_hpasswd:
                #print("Authentication Successful!")
                #print(stored_hpasswd)
                return True
    #print("Authentication Unsuccessful!")
    #print(username)
    return False

    #To read the file line by line, use a for loop.
    #Hint: split each line by a comma "," to get list of username, salt, pepper, and stored_hashpassword values.
    #implement other logics inside loop.

def main():
    '''Do not modify this function.'''

    import hashlib, uuid
    import os

    lusername=["shyamal@gmail.com",
                "brutforce@yahoo.com",
                "lifegivesalot@protonmail.com",
                "rainbow@sru.edu",
                "ghana@makai.com",
                "david@inst.edu",
                "buttlerbusiness@sru.edu",
                "myChurch45@state.edu"]
    lpasswd=["pass$1290Red",
            "fail$567Blue",
            "rainB0w159$",
            "lglot$$$Tatoo",
            "ghana456$$909",
            "DavI0234$09",
            "IsBulltop345",
            "xCrosTop24"]

    # open file outfile in write mode.
    outfile="hlogins.dat"
    fd = open(outfile, "w+")
    #@server: call method for each usernames, passwords.
    for i in range(0,len(lusername)):
        username=lusername[i]
        passwd=lpasswd[i]
        salt,pepper,saltpepperdigest=secure_hashed_passwd(username,passwd)
        if i in [3,7,1]:continue
        fd.write(username + "," + salt + "," + pepper + "," + saltpepperdigest+","+"$\n")
    fd.close()

    for j in range(0,len(lusername)):
        uname=lusername[j]
        passwd=lpasswd[j]
        result=verify_hashed_passwd(uname,passwd)
        if not result:
            print("<!> Login failed for user ",uname)
        else:
            print("Login successful for user ",uname)

if __name__ == "__main__":
    main()
