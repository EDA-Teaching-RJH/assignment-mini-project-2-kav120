from email_message import EmailMessage #from email_message import EmailMessage
from scam_detector import ScamDetector #import ScamDetector to analyse the email


def main():  #main function to run the program
    sender = input("Enter sender email: ") 
    subject = input("Enter subject: ")
    body = input("Enter email body: ")

    email = EmailMessage(sender, subject, body) #create EmailMessage using user input

    detector = ScamDetector()
    score, label, reasons = detector.analyse(email) #analyse email and get score, label and reasons

    print("\n--- Result ---") #print results to user
    print("Sender:", email.sender)
    print("Subject:", email.subject)
    print("Score:", score)
    print("Label:", label)
    print("Reasons:")

    if reasons:
        for reason in reasons:
            print("-", reason) #prints each label if there is reason
    else:
        print("- No suspicious signs detected") #if no rules triggered show safe message

if __name__ == "__main__":
    main() #Run the program only if this file is executed properly
