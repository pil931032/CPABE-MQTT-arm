import yaml

class alice:
    def userAlice(self):
        usralice = dict()
        usralice['user'] = "Alice"
        usralice['password'] = "aaa123"
        with open('subscriber_user_password.yaml', 'w') as f:
            yaml.dump(usralice, f)
        print("switch to user Alice")
if __name__ == '__main__':
    ua = alice()
    ua.userAlice()