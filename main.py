import numpy as np
import pandas as pd
import json
import os

from src.anssi_monitor.config.config import load_config
from src.anssi_monitor.utils.loader import create_database
from src.anssi_monitor.utils.pdf_generator import generate_pdf_report
from src.anssi_monitor.utils.mail import prepare_mail, send_mails

config = load_config()
df = None

if config["load_csv"]:
    df = pd.read_csv("./data/DB.csv", sep=";")
    
else:
    df = create_database()

    df = df.explode("affected_product")

    df["vendor"] = df["affected_product"].apply(lambda x: x["vendor"] if pd.notna(x) else np.nan)
    df["versions"] = df["affected_product"].apply(lambda x: x["versions"] if pd.notna(x) else np.nan)
    df["product"] = df["affected_product"].apply(lambda x: x["product"] if pd.notna(x) else np.nan)

    df.to_csv('./data/DB.csv', 
          index=False, 
          sep=';',           # Uses the semicolon (convenient for Excel)
          encoding='utf-8-sig') # 'utf-8-sig' ensures characters display correctly in Excel

# Load users
with open('./data/users.json', 'r') as f:
    users_data = json.load(f)

def scan_users():
    # Iterate through each user registered in the DB
    for user in users_data['users']:
        # Check if the vendor is in the 'companies' list using a mask
        # OR (|) if the product name is in the user's subscription products list.
        mask = (df['vendor'].isin(user['subscriptions']['companies'])) | (df['product'].isin(user['subscriptions']['products']))
        
        user_alerts = df[mask].copy() # Create a df with only the rows for products and companies the user subscribed to
        
        if not user_alerts.empty: # Verify that the df is not empty
            user_alerts['base_severity'] = user_alerts['base_severity'].fillna('Unknown')
            user_alerts = user_alerts.drop_duplicates(subset=['cve'])

            user_alerts = user_alerts.sort_values(by=['cvss_score', 'anssi_published'], ascending=[False, False])

            if config["debug"]:
                print(f"Sending {len(user_alerts)} alerts to {user['email']}")
            
            pdf_filename = generate_pdf_report(user['email'], user_alerts)
            csv_filename = pdf_filename.with_suffix(".csv")

            df.to_csv(csv_filename, sep = ",", encoding='utf-8-sig')

            html_body = f"""
                <html>
                <body style="font-family: Arial, sans-serif; color: #333;">
                    <p>Hello,</p>
                    <p>The daily analysis detected <strong>{len(df)} new vulnerabilities</strong>.</p>
                    
                    <p><strong>Summary:</strong></p>
                    <ul style="list-style-type: none; padding-left: 0;">
                    <li>🔴 Critical: <strong>{len(df[df["base_severity"] == "Critical"])}</strong></li>
                    <li>🟠 High: <strong>{len(df[df["base_severity"] == "High"])}</strong></li>
                    <li>🟡 Medium: <strong>{len(df[df["base_severity"] == "Medium"])}</strong></li>
                    <li>🟢 Low: <strong>{len(df[df["base_severity"] == "Low"])}</strong></li>
                    </ul>
                    
                    <p>The risk matrix and technical details can be found in the <strong>attached PDF</strong>.</p>
                    
                    <p>Best regards,<br>
                </body>
                </html>
                """
            prepare_mail(receiver=user["email"], subject="🔴 Security Alert Report", html_body=html_body, files=[pdf_filename, csv_filename], send_now=False)
            send_mails()
            
            if config["mail"]["send_mail"]:
                os.remove(pdf_filename)
                os.remove(csv_filename)
            


if __name__ == "__main__":
    scan_users()