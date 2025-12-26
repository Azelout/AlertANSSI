from fpdf import FPDF
import pandas as pd
import matplotlib.pyplot as plt
import matplotlib.patches as patches
from datetime import datetime
import os
from random import randint
import numpy as np

from anssi_monitor.config.config import load_config, ROOT_DIR
from anssi_monitor.locales.locale import load_language

config = load_config()
t = load_language()

colors_map = {
    'Low': '#2ecc71',
    'Medium': '#f1c40f',
    'High': '#e67e22',
    'Critical': '#e74c3c'
}


def generate_risk_matrix(df):
    severity_order = ["Low", "Medium", "High", "Critical"]
    _, ax = plt.subplots(figsize=(10, 6))

    # Critical zone
    rect = patches.Rectangle((2.5, 0.5), 1, 0.6, linewidth=0, edgecolor='none', facecolor='#c0392b', alpha=0.1)
    ax.add_patch(rect)
    ax.text(2.6, 1.05, t["pdf"]["critical_zone"], color='#c0392b', fontsize=9, fontweight='bold', alpha=0.6)

    np.random.seed(42) # To ensure "randomness" is always the same

    # Transform categories into numbers (0, 1, 2, 3) to place points on the X axis
    for i, severity in enumerate(severity_order):
        subset = df[df['base_severity'] == severity]

        if not subset.empty:
            x_jitter = np.random.uniform(-0.15, 0.15, size=len(subset))
            plt.scatter(
                x=[i] + x_jitter,      # All points are aligned on column i
                y=subset['epss_score'],   # Height according to EPSS score
                color=colors_map.get(severity, 'gray'),
                s=100,                    # Point size
                alpha=0.7,                # Transparency (useful if points overlap)
                label=severity            # For the legend (optional)
            )

    plt.title(t["pdf"]["risk_graph_title"])
    plt.ylabel(t["pdf"]["risk_graph_ylabel"])
    plt.xlabel(t["pdf"]["risk_graph_xlabel"])
    
    plt.xticks(range(len(severity_order)), severity_order)
    plt.ylim(-0.05, 1.1)
    
    # Add an alert threshold line (Example: EPSS > 0.5 is dangerous)
    plt.axhline(y=0.5, color='gray', linestyle='--', linewidth=0.8)
    plt.text(3.5, 0.52, t["pdf"]["threshold"] + " (0.5)", color='gray', fontsize=8)

    plt.grid(True, linestyle='--', alpha=0.5)

    ax.spines['top'].set_visible(False)
    ax.spines['right'].set_visible(False)
    ax.spines['left'].set_color('#dddddd')
    ax.spines['bottom'].set_color('#dddddd')

    ax.set_xticks(range(len(severity_order)))
    ax.set_xticklabels(severity_order, fontsize=11, fontweight='bold')
    ax.tick_params(axis='x', colors='#555555') # Axis text color
    
    ax.grid(True, axis='y', linestyle=':', color='#aaaaaa', alpha=0.5)
    ax.grid(False, axis='x') # No vertical grid

    img_name = ROOT_DIR / "data" / "reports" / f"risk_graph_{randint(1000, 9999)}.png"
    plt.savefig(img_name, format='png', dpi=100)
    plt.close()
    
    return img_name

    
class PDF(FPDF):
    def header(self):
        self.set_font("helvetica", "B", 16)
        self.cell(0, 10, t["pdf"]["title"], align="C")
        self.ln(15)
    
    def footer(self):
        self.set_y(-15)
        self.set_font("helvetica", "I", 8)
        self.set_text_color(128)
        date_str = datetime.now().strftime("%d/%m/%Y à %H:%M")
        self.cell(0, 10, t["pdf"]["generated_on"].format(date=date_str), align='L', ln=False)
        
        self.set_x(self.l_margin)
        self.cell(0, 10, t["pdf"]["page"] + f" {self.page_no()} / {{nb}}", align='R')

def generate_pdf_report(user_email, df):
    safe_email = user_email.replace('@', '_at_').replace('.', '_')
    date_str = datetime.now().strftime('%Y%m%d')
    pdf_filename = ROOT_DIR / "data" / "reports" / f"report_{safe_email}_{date_str}.pdf"

    pdf = PDF()
    pdf.add_page()
    pdf.set_font("helvetica", size=10)

    # Recap of vulnerabilities
    pdf.cell(0, 10, text=t["pdf"]["vulnabilities_detected"].format(amount=len(df)), ln=True)

    # # Risk graph
    graph_name = generate_risk_matrix(df)
    pdf.image(graph_name, x=4, w=200)
    os.remove(graph_name)

    # Top 10
    pdf.set_font("helvetica", "B", 12)
    pdf.cell(0, 10, text=t["pdf"]["top_10_title"], ln=True)
    with pdf.table(col_widths=(60, 20, 20)) as table:
        
        # --- Table header ---
        row = table.row()
        for header_name in [t["columns_label"]["anssi_title"], t["columns_label"]["base_severity"], t["columns_label"]["epss_score"]]:
            # Set to bold and light gray for the header
            pdf.set_font("helvetica", "B", 10) 
            pdf.set_fill_color(240, 240, 240) 
            row.cell(header_name)
        
        # Reset
        pdf.set_font("helvetica", size=10)
        pdf.set_fill_color(0, 0, 0) 
        
        # Data insertion
        for index, data_row in df.head(10).iterrows():
            row = table.row()
            
            title = str(data_row["anssi_title"])
            severity = str(data_row["base_severity"])
            score = str(data_row["epss_score"])
            
            row.cell(title, link=data_row["anssi_link"] or None)
            row.cell(severity)
            row.cell(score)

    pdf.output(pdf_filename)
    if config["debug"]:
        print("PDF successfully generated")
    
    return pdf_filename


if __name__ == "__main__":
    df = pd.read_csv(ROOT_DIR / "data" / "DB.csv", sep=";")
    df = df.sort_values(by=["cvss_score", "anssi_published"], ascending=[False, False])

    generate_pdf_report("mark.john@email.com", df.head(15))