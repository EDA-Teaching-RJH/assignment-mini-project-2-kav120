import re


class rule:
    def __init__(self, name, score):
        self.name = name

        self.score = score


    def check(self, email):
        return 0, None 
    
class UrgencyRule(rule):
    def __init__(self):
        super().__init__("Urgency Rule", 10)

        self.patterns = [
            r"urgent",
            r"asap"
            r"final warning"
            r"limited time"
            r"security alert"
            r"last chance"
            r"within 24 hours"
            r'failure to respond'
            r'click the link below immediately'
        ]
    def check(self, email):
        text = (email.subject + " " + email.body).lower()

        for pattern in self.patterns:
            if re.search(pattern,text):
                return self.score, "suspicious language detected"
            
        return 0, None
        

