import RSA
import random
import maths


def read_ctf_key():
    # To read the public key of CTF stored in ctf_key.txt
    file = open('voter_data/ctf_key.txt', 'r')
    pub_key = list(map(int, file.readline().split()))
    return pub_key


def write_key(voter_id, pri_key):
    # To store the private key of a voter.
    file = open("voter_data/" + voter_id.__str__() + '.txt', 'w+')
    file.write(pri_key[0].__str__())
    file.write(" ")
    file.write(pri_key[1].__str__())


def read_key(voter_id):
    # To read the private key of a voter.
    file = open("voter_data/" + voter_id.__str__() + '.txt', 'r')
    pri_key = list(map(int, file.readline().split()))
    return pri_key


def read_blindfactor(voter_id):
    # To read the inverse of blind_factor to use for un-blinding purpose.
    file = open("voter_data/" + voter_id.__str__() + 'b.txt', 'r')
    blindfactor = int(file.readline())
    return blindfactor


def register_voter(voter_id):
    # Generate public and private keys for a voter and return the public key for further use to the CTF.
    pub_key, pri_key = RSA.generate_keysRSA2()
    write_key(voter_id, pri_key)
    return pub_key


def blind(vote, voter_id):
    """
    Following are its functions -
    1.) Generate blindfactor and its inverse using extended euclid algorithm.
    2.) Store in inverse blind factor for the voter.
    3.) Blind the encrypted vote.
    """
    blindfactor, d = 0, 0
    public_key = read_ctf_key()
    voter_key = read_key(voter_id)
    while True:
        blindfactor = random.randrange(2, min(voter_key[1], public_key[1]) / 2)
        gcd, d, temp = maths.extended_euclid(blindfactor, public_key[1])
        if gcd == 1 and d > 0:
            break
    # Writing the inverse of blindfactor...
    file = open("voter_data/" + voter_id.__str__() + 'b.txt', 'w+')
    # Writing the inverse blind factor...
    file.write(d.__str__())
    # Blinding vote.... blinder = (r ^ e) mod N {e and N are public key components of the CTF}
    blinder = maths.mod_exponent(blindfactor, public_key[0], public_key[1])
    vote = (vote * blinder) % public_key[1]
    return vote


def unblind(vote, voter_id):
    # Reading the inverse of blindfactor and un-blinding the message.
    inverse_blind = read_blindfactor(voter_id)
    public_key = read_ctf_key()
    vote = (vote * inverse_blind) % public_key[1]
    return vote


def generate_encryptedvotes(voter_id, candidates):
    """
    Following are its functions -
    1.) Enumerate the candidates and ask the voter for his choice
    2.) Append the candidate id to a randomly generated unique id for the vote.
    3.) Blind and then encrypt the vote with voter's private key.
    """

    print("Choose one of the following valid candidate ids: ")
    j = 1
    order = {}
    # Enumerating and and printing the candidate names for the voter to choose.
    for i in candidates:
        print(j, ":", candidates[i])
        order[j] = i
        j += 1
    while True:
        number = int(input("Enter your selection: "))
        if number == 0 or number >= j:
            print("Choose a valid index")
            continue
        candidate = order[number]
        # Generating the unique ID.
        unique_id = random.randrange(pow(10, 12), pow(10, 13))
        print("Your unique id for the vote is", unique_id)
        print("Please note it for future reference.")
        # Appending candidate id to vote id to generate final vote.
        vote = int(candidate.__str__() + unique_id.__str__())
        # Blinding the vote
        vote = blind(vote, voter_id)
        # Encrypting the vote
        vote = RSA.encrypt(vote, read_key(voter_id))
        return vote

