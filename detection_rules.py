import re #Import regex library


class rule: # Base class
    def __init__(self, name, score):
        self.name = name #stores name of rule

        self.score = score #store how many points this rule adds


    def check(self, email):
        return 0, None 
    
class UrgencyRule(rule):
    def __init__(self):
        super().__init__("Urgency Rule", 20)

        self.patterns = [ #List of regex patterns that indicate urgency or pressure
            r"\burgent\b",
            r"\basap\b"
            r"\bfinal warning\b"
            r"\blimited time\b"
            r"\bsecurity alert\b"
            r"\blast chance\b"
            r"\bwithin 24 hours\b"
            r"\bfailure to respond\b"
            r"\bclick the link below immediately\b"
        ]
    def check(self, email): #checks if email contains any phrases of urgency
        text = (email.subject + " " + email.body).lower() #combines subject and body into one string and converts to lowercase

        for pattern in self.patterns: #loop through each pattern
            if re.search(pattern,text): #if pattern is found in the text
                return self.score, "suspicious language detected"
            
        return 0, None #if no match is found


class SenderRule(rule):
    def __init__(self):
        super().__init__("Sender Rule", 25)
        
        #List of domains commonly used in phishing emails
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

    def check(self, email): # checks if sender email contains suspicious domain       
        sender = email.sender.lower()

        for domain in self.suspicious_domains:
            if domain in sender:
                return self.score, "Suspicious sender domain detected"
       
        #if no suspicious domain found
        return 0, None
    
class LinkRule(rule): #Detects links and shortened URLs
    def __init__(self):
        super().__init__("Link Rule", 25)

        self.url_pattern = r"https?://[^\s]+" #Regex pattern finds URLs in text
        #common URLs used in scams
        self.shorteners = [
            "goo.gl",
            "cutt.ly",
            "t.co",
            "bit.ly",
            "ow.ly",

        ]
    def check(self, email):  #check for links in email body
        text = email.body.lower() #convert body text to lowercase

        urls = re.findall(self.url_pattern, text) #Find all URLs
        
        for url in urls:
            
            for short in self.shorteners: #check if URL is a shortened link
                if short in url:
                    return self.score, "shortened link detected"
            if urls:
                return 10, "link detected in email"   
        return 0, None #no links found

        


    
    







    





      



        

