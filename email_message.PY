#single email
class EmailMessage:
    def __init__(self,sender, subject, body):
        self.sender = sender #store who sent the email
        self.subject = subject #store subject line of email
        self.body = body #store content of email
