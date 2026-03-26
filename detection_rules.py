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


class SenderRule(rule):
    def __init__(self):
        super().__init__("Sender Rule", 20)

        self.suspicious_domains = [
            ".xyz",
            ".online",
            ".site",
            ".tk",
            ".ru",
            ".click",
            ".tech",
            ".info",
            ".today",
            ".work",
            ".biz",
            ".live",
            ".paypa1",
            ".g00gle",
        ]

    def check(self, email):
        sender = email.sender.lower()

        for domain in self.suspicious_domains:
            if domain in sender:
                return self.score, "Suspicious sender domain detected"

        return 0, None
    
class LinkRule(rule):
    def __init__(self):
        super().__init__("Link Rule", 20)

        self.url_pattern = r"https?://[^\s]+"

        self.shorteners = [
            "goo.gl",
            "cutt.ly",
            "t.co",
            "bit.ly",
            "ow.ly",

        ]
    def check(self, email):
        text = email.body.lower()

        urls = re.findall(self.url_pattern, text)
        
        for url in urls:
            for word in self.suspicious_keywords:
                if word in url:
                    return self.score,
            
            for short in self.shorteners:
                if short in url:
                    return self.score,
        return 0, None

        


    
    







    





      



        

