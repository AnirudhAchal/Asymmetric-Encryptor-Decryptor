import os
from time import sleep
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
backend = default_backend()


MESSAGES = {}


class String:

    @classmethod
    def add_spaces(cls, message):
        for i in range(len(message) % 32, 32):
            message += " "
        return message

    @classmethod
    def remove_spaces(cls, message):
        while message[-1] == ' ':
            message = message[:-1]
            if len(message) == 0:
                break
        return message


class Crypt:

    @classmethod
    def encrypt(cls, key, iv, message):
        message = String.add_spaces(message)
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
        encryptor = cipher.encryptor()
        return encryptor.update(message.encode('ascii')) + encryptor.finalize()

    @classmethod
    def decrypt(cls, key, iv, ct):
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
        decryptor = cipher.decryptor()
        message = decryptor.update(ct) + decryptor.finalize()
        message = String.remove_spaces(message.decode())
        return message

    @classmethod
    def encrypt_key(cls, sender_pem_private_key, receiver_pem_public_key, key, iv):
        receiver_public_key = serialization.load_pem_public_key(
            receiver_pem_public_key,
            backend=default_backend()
        )

        key_cipher_text = receiver_public_key.encrypt(
            key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None)
        )

        iv_cipher_text = receiver_public_key.encrypt(
            iv,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None)
        )

        sender_private_key = serialization.load_pem_private_key(
            sender_pem_private_key,
            password=None,
            backend=default_backend()
        )

        message = b"Signed message"
        signature = sender_private_key.sign(
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )

        return key_cipher_text, iv_cipher_text, signature

    @classmethod
    def decrypt_key(cls, sender_pem_public_key, receiver_pem_private_key, key_cipher_text, iv_cipher_text, signature):
        receiver_private_key = serialization.load_pem_private_key(
            receiver_pem_private_key,
            password=None,
            backend=default_backend()
        )

        key = receiver_private_key.decrypt(
            key_cipher_text,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        iv = receiver_private_key.decrypt(
            iv_cipher_text,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        sender_public_key = serialization.load_pem_public_key(
            sender_pem_public_key,
            backend=default_backend()
        )

        check_message = b"Signed message"
        try:
            sender_public_key.verify(
                signature,
                check_message,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
        except Exception as e:
            # Not from expected sender
            return False

        return key, iv

    @classmethod
    def secure_channel(cls, alice, bob):
        alice.send_session_key(bob)
        if bob.receive_session_key(alice) is not None:
            alice.delete_friend(bob)
            bob.delete_friend(alice)
            return "Could not establish secure channel"
        return "Secured channel established..."

    def __init__(self):
        self.__private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=backend)
        self.__public_key = self.__private_key.public_key()

    def generate_private_key(self):
        return self.__private_key

    def generate_pem_private_key(self):
        return self.__private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption()
                    )

    def generate_public_key(self):
        return self.__public_key

    def generate_pem_public_key(self):
        return self.__public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )


class Person:
    public_keys = {}
    def __init__(self, name):

        self.name = name

        # Creating Crypt instance
        crypt = Crypt()

        # Generating private key for self
        self.__private_key = crypt.generate_private_key()
        self.__pem_private_key = crypt.generate_pem_private_key()

        # Generating public key for self
        self.public_key = self.__private_key.public_key()
        self.pem_public_key = crypt.generate_pem_public_key()

        # Adding self and self's public key to public key list
        self.public_keys[self.name] = self.pem_public_key

        # Initializing friend list of self and friend key/iv list
        self.__friends = []
        self.__friends_keys = {}
        self.__friends_ivs = {}

        # Initializing list sent/received messages
        self.__sent_messages = {}
        self.__received_messages = {}

        # Initializing person in global MESSAGES
        MESSAGES[self.name] = {}

    def send_message(self, receiver, message):

        # If an empty object is passed
        if receiver is None:
            return "Error...Trying to send a message to Undefined Person."

        # If secure channel is not yet established
        if receiver.name not in self.__friends:
            return f"Secure channel is not yet established with {receiver.name}."

        key = self.__friends_keys[receiver.name]
        iv = self.__friends_ivs[receiver.name]

        cipher_text = Crypt.encrypt(key, iv, message)

        # Adding message to global MESSAGES as Receiver -> Sender -> Messages[]
        MESSAGES[receiver.name][self.name].append(cipher_text)

        # Adding messages to sent messages
        self.__sent_messages[receiver.name].append(message)

    def check_message(self):
        # Checking messages of all  friends
        for friend in MESSAGES[self.name]:

            key = self.__friends_keys[friend]
            iv = self.__friends_ivs[friend]

            # Decrypting all of messages sent by friend and adding to received messages
            for message in MESSAGES[self.name][friend]:
                decrypted_message = Crypt.decrypt(key, iv, message)
                self.__received_messages[friend].append(decrypted_message)

        my_new_messages = self.__received_messages.copy()

        for friend in MESSAGES[self.name]:
            # Clearing old messages
            self.__received_messages[friend] = []
            MESSAGES[self.name][friend] = []

        return my_new_messages

    def send_session_key(self, friend):
        # Initializing dictionaries
        MESSAGES[self.name][friend.name] = []

        self.__friends.append(friend.name)
        self.__sent_messages[friend.name] = []
        self.__received_messages[friend.name] = []

        # Generates new session key and iv
        key = os.urandom(32)
        iv = os.urandom(16)

        self.__friends_keys[friend.name] = key
        self.__friends_ivs[friend.name] = iv

        sender_pem_private_key = self.__pem_private_key
        receiver_pem_public_key = friend.pem_public_key

        # Encrypting the key
        key_cipher_text, iv_cipher_text, signature = Crypt.encrypt_key(sender_pem_private_key,
                                                                       receiver_pem_public_key, key, iv)

        # Adding key, iv and signatures to the Global messages
        MESSAGES[friend.name][self.name] = []
        MESSAGES[friend.name][self.name].append(key_cipher_text)
        MESSAGES[friend.name][self.name].append(iv_cipher_text)
        MESSAGES[friend.name][self.name].append(signature)

    def receive_session_key(self, friend):
        # Initializing dictionaries
        self.__friends.append(friend.name)
        self.__sent_messages[friend.name] = []
        self.__received_messages[friend.name] = []

        # Encrypted key, iv and signature
        key_cipher_text = MESSAGES[self.name][friend.name][0]
        iv_cipher_text = MESSAGES[self.name][friend.name][1]
        signature = MESSAGES[self.name][friend.name][2]

        # Emptying messages
        MESSAGES[self.name][friend.name] = []

        # If key was sent by someone other than the intended person
        if (Crypt.decrypt_key(friend.pem_public_key,
                              self.__pem_private_key, key_cipher_text, iv_cipher_text, signature) is False):
            return f"Key is not from {friend.name}. This channel is not secure"

        key, iv = Crypt.decrypt_key(friend.pem_public_key,
                                    self.__pem_private_key, key_cipher_text, iv_cipher_text, signature)

        # Adding friend to friends list
        self.__friends.append(friend.name)

        # Adding key and iv to their respective lists
        self.__friends_keys[friend.name] = key
        self.__friends_ivs[friend.name] = iv

    # Deletes secure channel and all records of messages between them
    def delete_friend(self, friend):
        if friend.name in self.__friends:
            self.__friends.remove(friend.name)
            del self.__sent_messages[friend.name]
            del self.__received_messages[friend.name]
        if friend.name in MESSAGES[self.name]:
            del MESSAGES[self.name][friend.name]
        if self.name in MESSAGES[friend.name]:
            del MESSAGES[friend.name][self.name]

        if friend.name in self.__friends_keys:
            del self.__friends_keys[friend.name]
            del self.__friends_ivs[friend.name]


def new_window():
    print("\n" * 20)


def print_help_menu():
    print("""
Help menu ->
    1 -> Add new person using 'add <name>' command
    2 -> Add N new people using 'add <name1> <name2> <name3> ... <nameN>' command
    3 -> To Enter into a specific user use 'select <name>' command
    4 -> Go to help menu using 'help' command
    5 -> List all users using 'list' command
    6 -> Exit the application using 'exit' command
    """)


def print_user_help_menu():
    print("""
Help menu ->
    1 -> Add Friend using 'friend <name>' command
    2 -> Add multiple friends using 'friend <name1> <name2> <name3> ... <nameN>' command
    3 -> Check messages using 'check' command
    4 -> To send a message to a friend use 'send <name> <"message">' command'
        (Use inverted commas around message)
    5 -> To delete a friend use 'delete <friend>' command
    6 -> To go back to main menu using 'main_menu' command
    7 -> Go to help menu using 'help' command
    """)


def print_main_menu():
    print('Please enter your commands (enter "help" to check out full command list) ...')


def get_command(user):
    return input(user + '>').split()


def enter_user(user, users):
    while True:
        cmd = get_command(user.name)
        if len(cmd) == 1:
            cmd = cmd[0]
            if cmd == 'help':
                print_user_help_menu()
                continue
            elif cmd == 'main_menu':
                return
            elif cmd == 'check':
                my_messages = user.check_message()
                if len(my_messages) == 0:
                    print("You don't have any new messages!")
                    continue
                else:
                    for friend in my_messages:
                        print(f"You have {len(my_messages[friend])} new messages from {friend}...")
                        for message in my_messages[friend]:
                            print(message)
                        print("\n")

            else:
                print('Sorry that is not a command...')
                print('Enter help to check out commands')
                continue
        else:
            if cmd[0] == 'friend':
                is_valid = False
                for friend in cmd[1:]:
                    is_valid = False
                    for u in users:
                        if u.name == friend:
                            is_valid = True
                    if not is_valid:
                        print(f'Sorry {friend} is not a user')
                        break
                if not is_valid:
                    continue
                for friend in cmd[1:]:
                    for f in users:
                        if f.name == friend:
                            friend = f
                            break
                    print(Crypt.secure_channel(user, friend))
            elif cmd[0] == 'send':
                if len(cmd) < 3:
                    print('Sorry that is not a command...')
                    print('Enter help to check out commands')
                    continue
                friend = cmd[1]
                for f in users:
                    if f.name == friend:
                        friend = f
                        break
                message = ""
                for m in cmd[2:]:
                    message += m
                    message += " "
                String.remove_spaces(message)
                if user.send_message(friend, message) is not None:
                    print(user.send_message(friend, message))
                    print("Use friend command to add a new friend.")
                    continue
            elif cmd[0] == 'delete':
                friend = cmd[1]
                for f in users:
                    if f.name == friend:
                        friend = f
                        break
                user.delete_friend(friend)
                continue
            else:
                print('Sorry that is not a command...')
                print('Enter help to check out commands')


def main():
    users = []
    key_words = ['add', 'main_menu', 'friend', 'select', 'check', 'help', 'exit', 'list', 'send', 'delete']
    print_main_menu()
    while True:
        cmd = get_command('main menu')
        if len(cmd) == 1:
            cmd = cmd[0]
            if cmd.lower() == 'exit':
                print("Thank you for using the application. Have a good day!")
                sleep(2)
                exit()
            elif cmd == 'list':
                if len(users) == 0:
                    print("There are not registered users")
                else:
                    print("All Registered users are...")

                for user in users:
                    print(f"{users.index(user) + 1} -> ", user.name)
            elif cmd == 'help':
                print_help_menu()
                continue
            else:
                print("Sorry that is not a command...")
                print('Enter help to check out commands')
                continue
        else:
            if cmd[0].lower() == 'select':
                name = cmd[1]
                is_valid = False
                for user in users:
                    if user.name == name:
                        is_valid = True
                        name = user
                        break
                if is_valid:
                    enter_user(name, users)
            elif cmd[0].lower() == 'add':
                is_valid = True
                for name in cmd[1:]:
                    if name in key_words:
                        is_valid = False
                        print(f"Sorry can't use name : {name}")
                if is_valid:
                    for person in cmd[1:]:
                        users.append(Person(person))
                else:
                    print(f'Sorry {name} is not a registered user...')
            else:
                print("Sorry that is not a command...")
                print('Enter help to check out commands')
                continue


if __name__ == '__main__':
    main()
