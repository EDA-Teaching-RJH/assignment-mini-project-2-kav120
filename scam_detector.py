from detection_rules import UrgencyRule, SenderRule, LinkRule

class ScamDetector:
   def __init__(self):
      self.rules = [
           UrgencyRule(),
            SenderRule(),
            LinkRule()
      ]
   def classify_score(self, score):
        if score >= 50:
            return "Likely Scam"
        elif score >= 20:
            return "Suspicious"
        else:
            return "Possibly Safe"
            
   def analyse(self, email):
        total_score = 0
        reasons = [] 

        for rule in self.rules:
            score, reason = rule.check(email)
            total_score += score

            
            if reason:
                reasons.append(reason)

       
        label = self.classify_score(total_score)

        return total_score, label, reasons 

         
  
     