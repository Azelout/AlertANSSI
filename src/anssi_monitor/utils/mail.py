import smtplib
from email.message import EmailMessage
from dotenv import load_dotenv
import os
import mimetypes

from anssi_monitor.config.config import load_config

config = load_config()

load_dotenv()
USER = os.getenv("MAIL_USER")
PASSWORD = os.getenv("MAIL_PASSWORD")

mails = []

def prepare_mail(receiver="", subject="", body="", html_body=None, files=[], send_now=True):
    msg = EmailMessage()
    msg['Subject'] = subject
    msg['From'] = USER
    msg['To'] = receiver

    if html_body:
        msg.set_content(html_body, subtype='html')
    else:
        msg.set_content(body)

    # Adding files
    for file_path in files:
        try:
            ctype, encoding = mimetypes.guess_type(file_path)
            if ctype is None or encoding is not None:
                ctype = 'application/octet-stream'
            maintype, subtype = ctype.split('/', 1)

            with open(file_path, 'rb') as f:
                msg.add_attachment(
                    f.read(),
                    maintype=maintype,
                    subtype=subtype,
                    filename=os.path.basename(file_path)
                )
        except Exception as e:
            print(f"Error reading file : {e}")

    if not config["mail"]["send_mail"]:
        return True
    
    if send_now: # If we send multiple mails, we should just save the message then send everything in one
        try:
            with smtplib.SMTP(config["mail"]["SMTP"], config["mail"]["SMTP_PORT"]) as server:
                server.starttls() 
                server.login(USER, PASSWORD)
                
                server.send_message(msg)
            
            return True
                
        except Exception as e:
            print(f"Error : {e}")
            return False
    else:
        mails.append(msg)

def send_mails():
    if not config["mail"]["send_mail"]:
        return True
    
    if mails:
        try:
            with smtplib.SMTP('smtp.gmail.com', 587) as server:
                server.starttls()
                server.login(USER, PASSWORD)
                
                for msg in mails:
                    server.send_message(msg)
                    if config["debug"]:
                        print(f"Mail sent to {msg['To']}")
            
            mails = [] # Flush
            return True
                    
        except Exception as e:
            print(f"Error : {e}")
            return False