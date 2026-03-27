from detection_rules import UrgencyRule, SenderRule, LinkRule #import all detection rule classes

class ScamDetector: #main class controlling scam detection process
   def __init__(self):
      self.rules = [ #store all rule objects in a list, each rule applied to email
           UrgencyRule(),
            SenderRule(),
            LinkRule()
      ]
   def classify_score(self, score): # Convert a numerical score into classification label
        if score >= 50:
            return "Likely Scam" #high risk email
        elif score >= 20:
            return "Suspicious" #medium risk email
        else:
            return "Possibly Safe" #low risk email
            
   def analyse(self, email): #analyse email
        total_score = 0 #total risk score
        reasons = []  #list of reasons giving why email is suspicious

        for rule in self.rules:
            score, reason = rule.check(email) #apply rule to email
            total_score += score #add score from email

            
            if reason:
                reasons.append(reason) #if rule triggered store the reason

       
        label = self.classify_score(total_score) #determine final label

        return total_score, label, reasons #return results 

         
  
     