import os
from Crypto.Protocol.KDF import scrypt
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES
from base64 import b64decode
import json
from base64 import b64encode
import os.path
import hashlib
import random
import string

# encryptFile: String(bytes) X String(bytes) -> JSON object of representing a zipped dictionary of 4 Key-Value Pairs
# encryptFile: The plaintext vault x The encryption key -> The encrypted vault represented as a zipped dictionary of 4 Key-Value Pairs
# The keys for the JSON zipped dictionary will be "nonce", "header", "ciphertext", and "tag"
# the tag here represents the message authentication code or MAC
# Use AES GCM for encryption
# Use the binary of Empty String as the "header" needed for AES GCM
def encryptFile(plaintextData,key):
    header = b''
    cipher = AES.new(key, AES.MODE_GCM)
    cipher.update(header)
    ciphertext, tag = cipher.encrypt_and_digest(plaintextData)
    json_k = ['nonce','header','ciphertext','tag']
    json_v = [b64encode(x).decode('ascii') for x in (cipher.nonce, header, ciphertext, tag)]
    encryptionResults = json.dumps(dict(zip(json_k, json_v)))
    return encryptionResults

# decryptFile: Encrypted JSON Object X String(bytes) -> String(bytes)
# decryptFile: Encrypted vault as a JSON object X the symmetric decryption key -> Just the plaintext (not nonce, header, or tag)
# Please make sure the tag/MAC value verifies before returning the plaintext JSON object
def decryptFile(encryptedJson,key):
    b64 = json.loads(encryptedJson)
    json_k = ['nonce','header','ciphertext','tag']
    jv = {k:b64decode(b64[k]) for k in json_k}
    cipher = AES.new(key, AES.MODE_GCM, nonce=jv['nonce'])
    cipher.update(jv['header'])
    decryptionResults = cipher.decrypt_and_verify(jv['ciphertext'], jv['tag'])
    return decryptionResults

# computeMasterKey: String -> String(bytes)
# This function calculates the encryption key from the input password
# Use the scrypt function with the appropriate arguments mentioned in the assignment document
def computeMasterKey(password):
    salt = '<\n<~\x0e\xeetGR\xfe;\xec \xfc)8'
    key_len = 16
    N = 2**14
    r = 8
    p = 1
    num_keys = 1
    key = scrypt(password, salt, key_len, N, r, p, num_keys)
    return key

# decryptAndReconstructVault : String x String -> List(Strings)'
# decryptAndReconstructVault: Name of the encrypted vault file X the password -> The decrypt password vault
# each String in the output list essentially has the form: "username:password:domain"
def decryptAndReconstructVault(hashedusername, password):
    key = computeMasterKey(password)
    magicString = '101010101010101010102020202020202020202030303030303030303030\n'
    with open(hashedusername, "r") as file:
        fileread = file.read()
    file.close()
    decryptedresults = decryptFile(fileread,key)
    decodedContent = decryptedresults.decode('utf-8')

    checkString = decodedContent[:len(magicString)]
    rawData = decodedContent[len(magicString):]
    if checkString != magicString:
      print('Decoded content does not include magic string')
      return
    passwordvault = []
    for line in decodedContent.splitlines():
        passwordvault.append(line)
    passwordvault.pop(0)
    return passwordvault

# checkVaultExistenceOrCreate: String x String -> String x String x String x List(Strings)
# In all honesty, the function does not explicitly take any arguments
# It gives a user the option to entry its username and password
# It then checks to see whether a password vault exists for the user name (Is there a file with the name SHA256(username)?)
# If it exists, then the decrypted password vault is returned
# Otherwise, a new password vault is created for the user
# The return value of the function is tuple <username, password, password vault file name, the plaintext password vault>
# recall that the plaintext password vault is nothing but a List of strings where each string has the form: "username:password:domain"
def checkVaultExistenceOrCreate():
    passwordvault = []
    while True:
        username = input('Enter vault username: ')
        password = input('Enter vault password: ')
        if username and password:
            break
    hashedusername = hashlib.sha256(username.encode('utf-8')).hexdigest()
    if (os.path.exists(hashedusername)):
        passwordvault = decryptAndReconstructVault(hashedusername,password)
    else:
        print("Password vault not found, creating a new one")
        pass
    return username, password, hashedusername, passwordvault

# generatePassword: VOID -> STRING
# When called this function returns a random password
def generatePassword():
    l1 = list(string.ascii_letters)
    l2 = ['0','1','2','3','4','5','6','7','8','9']
    l1.extend(l2)
    i = 16
    result = ""
    while (i > 0):
        result += random.choice(l1)
        i -= 1;
    return result


# AddPassword : List(String) -> VOID
# AddPassword : PLAINTEXT Password vault -> VOID
# It gives a user prompt to add a username, password, and a domain
# It then adds the triple to the Password vault
def AddPassword(passwordvault):
    username = input('Enter username: ')
    password = input('Enter password: ')
    domain = input('Enter domain: ')
    newEntry = username + ':' + password + ':' + domain
    passwordvault.append(newEntry)
    print('Record Entry added\n')

# CreatePassword : List(String) -> VOID
# CreatePassword : PLAINTEXT Password vault -> VOID
# It gives a user prompt to add a username, and domain
# It randomly generates the password
# It then adds the triple <username:password:domain> to the Password vault
def CreatePassword(passwordvault):
    username = input('Enter username: ')
    password = generatePassword()
    domain = input('Enter domain: ')
    newEntry = username + ':' + password + ':' + domain
    passwordvault.append(newEntry)
    print('Record Entry added\n')


# UpdatePassword: List(String) -> VOID
# UpdatePassword: PLAINTEXT Password vault -> VOID
# It takes as input from the user the name of the domain to change password and the password to update it with.
# It then updates the password vault of the domain with the new password
def UpdatePassword(passwordvault):
    domain = input('Enter domain: ')
    iterator = 0
    accountFound = 0
    for x in passwordvault:
      fields = x.split(':')
      if fields[2] == domain:
        password = input("Enter new password or 'G' to generate a password: ")
        if password == 'G':
          password = generatePassword()
        newLine = fields[0] + ':' + password + ':' + fields[2]
        passwordvault[iterator] = newLine
        accountFound = 1
        break
      iterator += 1
    if accountFound == 1:
      print('Record Entry Updated\n')
    else:
      print('No account associated with that domain\n')

# LookupPassword: List(String) -> VOID
# LookupPassword: PLAINTEXT Password vault -> VOID
# It takes as input from the user the name of the domain
# It then prints the username and password of that domain
def LookupPassword(passwordvault):
    domain = input('Enter domain: ')
    accountFound = 0
    for x in passwordvault:
      fields = x.split(':')
      if fields[2] == domain:
          print('Password for ' + fields[2] + ': ' + fields[1] + '\n')
          return
    print('No account associated with that domain\n')

# DeletePassword: List(String) -> VOID
# DeletePassword: PLAINTEXT Password vault -> VOID
# It takes as input from the user the name of the domain
# It then removes the entry of that domain from the password vault
def DeletePassword(passwordvault):
    domain = input('Enter domain: ')
    accountFound = 0
    for x in passwordvault:
      fields = x.split(':')
      if fields[2] == domain:
        passwordvault.remove(x)
        print('Record Entry Deleted\n')
        return
    print('No account associated with that domain\n')


# displayVault : List(String) -> VOID
# Given the PLAINTEXT password vault, this function prints it in the standard output
def displayVault(passwordvault):
    print(passwordvault)

# EncryptVaultAndSave: List(String) x String x String -> VOID
# EncryptVaultAndSave: PLAINTEXT PASSWORD VAULT  x PASSWORD x PASSWORD VAULT FILE NAME -> VOID
# This function essentially prepends the magic string in a separate line with the
# PLAINTEXT password vault, then writes it back in the encrypted format to the encrypted password vault file ....
def EncryptVaultAndSave(passwordvault, password, hashedusername):
    writeString = ''
    magicString = '101010101010101010102020202020202020202030303030303030303030\n'
    writeString + magicString
    key = computeMasterKey(password)
    finalString = ''
    finalString = finalString + magicString
    for i in passwordvault:
        record = i + '\n'
        finalString = finalString + record
    finaldbBytes = bytes(finalString, 'utf-8')
    finaldbBytesEncrypted = encryptFile(finaldbBytes,key)
    with open(hashedusername, "w") as file:
        file.write(finaldbBytesEncrypted)
    file.close()
    print("Password Vault encrypted and saved to file")



def main():
    username, password, hashedusername, passwordvault = checkVaultExistenceOrCreate()
    while(True):

        print('Password Management')
        print('-----------------------')
        print('-----------------------')
        print('1 - Add password')
        print('2 - Create password')
        print('3 - Update password')
        print('4 - Lookup password')
        print('5 - Delete password')
        print('6 - Display Vault')
        print('7 - Save Vault and Quit')
        choice = input('')

        if choice == ('1'):
            AddPassword(passwordvault)

        elif choice == ('2'):
            CreatePassword(passwordvault)

        elif choice == ('3'):
            UpdatePassword(passwordvault)

        elif choice == ('4'):
            LookupPassword(passwordvault)

        elif choice == ('5'):
            DeletePassword(passwordvault)
        elif choice == ('6'):
            displayVault(passwordvault)

        elif choice == ('7'):
            EncryptVaultAndSave(passwordvault, password, hashedusername)
            quit()
        else:
            print('Invalid choice please try again')

main()
