from email_message import EmailMessage
from scam_detector import ScamDetector


def main():
    sender = input("Enter sender email: ")
    subject = input("Enter subject: ")
    body = input("Enter email body: ")

    email = EmailMessage(sender, subject, body)

    detector = ScamDetector()
    score, label, reasons = detector.analyse(email)

    print("\n--- Result ---")
    print("Sender:", email.sender)
    print("Subject:", email.subject)
    print("Score:", score)
    print("Label:", label)
    print("Reasons:")

    if reasons:
        for reason in reasons:
            print("-", reason)
    else:
        print("- No suspicious signs detected")


if __name__ == "__main__":
    main()