import os
import glob
import voter
import RSA
import random
import maths

"""
Code for the working of the CTF (Central Tabulating Facility).
This code when executed first generates the public - private key pair. (Done using RSA Algorithm)
The public key is made available to all the voters in the folder voter_data/ctf_key.txt
Candidates who are appearing for the elections are manually stored in candidates.txt
Each candidate is then assigned a 13-digit random id to uniquely determine the candidate.
"""

# Generating keys
public_key, private_key = RSA.generate_keysRSA1()
# Storing public key of CTF in voter_data/ctf_key.txt
file = open('voter_data/ctf_key.txt', 'w+')
file.write(public_key[0].__str__())
file.write(" ")
file.write(public_key[1].__str__())
# Reading Candidates List.
file = open('candidates.txt', 'r')
lines = file.readlines()

candidates = {}  # To store candidate ids.
number_of_candidates = 0
voters = {}  # To store public keys of voters. (Mapped to their voter - id)
voted = []  # To store who voted.
votes = []  # To store the votes.

# Assigning IDs to candidates.
for c in lines:
    # 13 digit candidate id generation.
    ids = random.randrange(pow(10, 12), pow(10, 13))
    # print(ids)
    candidates[ids] = c
    number_of_candidates += 1
    # print(ids) # Uncomment if you want to compare ids in final vote casted.


def blind_signature(vote):
    return maths.mod_exponent(vote, private_key[0], private_key[1])


print("Election has been started...")

while True:
    print("Choose one the options given below ->\n"
          "1. Register a voter\n"
          "2. Vote\n"
          "3. Stop elections ans show result\n")
    choose = input("Select an option: ")

    if choose == '1':
        """
        Registering the user.
        CTF randomly generates a 17-bit voter-id for a voter who comes in for registration.
        After that, a voter using voter.py file can generate it's own public - private key pair.
        Voter then returns it's public key to the CTF for further decryption process.
        """
        username = input("Enter your name: ")
        print("Hello ", username, ", you are being registered.")
        print("Generating a public - private key pair.... (Might take a while)")
        voter_id = random.randrange(1 << 16, 1 << 17)
        publi_key = voter.register_voter(voter_id) # This step is done by voter.py
        voters[voter_id] = publi_key # CTF stores public key of voter
        print("You have been registered successfully! Note your voter-id is", voter_id)

    elif choose == '2':
        """
        This is the main step i.e. the voting process itself.
        CTF asks the voter-id of a candidate and checks if the user already voted or registered or not.
        Each message should contain the unique identification number for the vote.
        These generated messages are blinded as well as encrypted.
        CTF decrypts the messages with public-key associated with the voter_id of the voter. {stored in voters}
        Then it signs the vote in the blinded message and sends it back to the voter. {Using Blind signature protocol used in RSA}
        This helps in dissociating the vote from the voter and still maintaining authentication.
        """
        voter_id = int(input("Enter your voter id: "))
        if voter_id not in voters:  # Checking if voter is registered.
            print("You are not registered.")
            continue
        if voter_id in voted:  # Checking if voter did not already sent his votes for signing.
            print("You already voted.")
            continue
        voted.append(voter_id)
        print("Generating Vote...")
        encrypted_vote = voter.generate_encryptedvotes(voter_id, candidates)

        decrypted_vote = RSA.decrypt(encrypted_vote, voters[voter_id])

        print("Signing Vote using blind signature protocol...")
        signed_vote = blind_signature(decrypted_vote)

        print("Un-blinding vote and casting...")
        """
        Important -> This step of receiving the un-blinding the votes should be anonymous.
        CTF SHOULD NOT know about the identity of the unblinded signed vote it received.
        Otherwise it can figure out who voted for whom and our protocol of blind signature will fail. 
        """
        unblinded_vote = voter.unblind(signed_vote, voter_id)

        final_vote = RSA.decrypt(unblinded_vote, public_key)
        votes.append(final_vote)
        print("Vote successfully casted!!")

    elif choose == '3':
        """
        This step check the votes and tabulate the results associated with the unique id.
        All the keys stored in voter_data are deleted.
        """
        print("Election completed!")
        print("Tabulating results... (Might take a while)")
        votes_for_candidates = {}  # To tabulate votes received for each candidate.
        # Storing and counting votes.
        for v in votes:
            # Decoupling the vote and the corresponding ID.
            vote_for = int(str(v)[0:13])
            id_ofvote = int(str(v)[13:26])

            if vote_for not in votes_for_candidates:
                votes_for_candidates[vote_for] = []
            votes_for_candidates[vote_for].append(id_ofvote)
        # Printing results -
        for can in candidates:
            if can not in votes_for_candidates:
                # If no one voted that candidate.
                print(candidates[can])
                print("Total votes -> 0")
            else:
                print(candidates[can])
                print("Total votes -> ", len(votes_for_candidates[can]))
                print("Anonymous IDs of vote")
                for ids in votes_for_candidates[can]:
                    print(ids)
            print()
        # The following lines delete all the data present in voter_data. (Blinding factors and keys.)
        files = glob.glob('voter_data/*')
        for f in files:
            os.remove(f)
        break

    else:
        """
        If input chosen is invalid.
        """
        print("Choose a valid input.")
