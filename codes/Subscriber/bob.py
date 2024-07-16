import yaml

class bob:
    def userBob(self):
        usrbob = dict()
        usrbob['user'] = "Bob"
        usrbob['password'] = "bbb123"
        with open('subscriber_user_password.yaml', 'w') as f:
            yaml.dump(usrbob, f)
        print("switch to user Bob")
if __name__ == '__main__':
    ub = bob()
    ub.userBob()


