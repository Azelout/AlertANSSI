import feedparser # To retrieve data from an RSS feed
import numpy as np
import pandas as pd
import time
import datetime
import requests # To make API requests

from anssi_monitor.config.config import load_config

config = load_config()
session = requests.Session() # Creating a session helps reduce execution time during many requests

def set_severity(cvss_score):
    if pd.isna(cvss_score):
        return np.nan
    
    if cvss_score >= 9:
        return "Critical"
    elif cvss_score >= 7:
        return "High"
    elif cvss_score >= 4:
        return "Medium"
    else:
        return "Low"
    
def get_cve(anssi_url):
    if not isinstance(anssi_url, str) or not anssi_url.strip(): # Ensuring the validity of the input argument
        return []

    target_url = anssi_url.rstrip("/") + "/json/" # Retrieving the json of the page
    
    try:
        # Using the global session
        response = session.get(target_url, timeout=5) 
        
        if response.status_code == 200: # If the request succeeds
            # Method 1: using REGEX
            # return list(set(re.findall(r"CVE-\d{4}-\d{4,7}", response.text)) )# set() for deduplication, list() for the final format
        
            # Method 2: Going through the cves key:
            return [ v["name"] for v in response.json()["cves"] ]
            
    except requests.RequestException: # In case of network error (timeout, 404...), we return an empty list
        print("Nothing was found on ", anssi_url)
        return []
    
    return []

def get_epss_data(cve):    
    target_url = config["api"]["epss"] + cve
    
    try:
        res = session.get(target_url, timeout=5)

        if res.status_code != 200:
            print(res.status_code)
            return {}

        data = res.json()
        
        epss_data = data.get("data", [])

        if epss_data != []:
            return float(epss_data[0]["epss"]) or np.nan

        return np.nan
    except Exception:
        print("Nothing was found for ", cve)
        return np.nan

def get_mitre_data(cve):
    if pd.isna(cve):
        return {}
    
    target_url = config["api"]["mitre"] + cve
    
    try:
        res = session.get(target_url, timeout=5)
        if res.status_code != 200:
            return {}

        data = res.json()

        # We verify the state of the CVE
        cveMetadata = data.get("cveMetadata", {})
        if cveMetadata != {}:
            if cveMetadata["state"] != "PUBLISHED": # If it is not published, we ignore it
                return {}

        cna = data.get("containers", {}).get("cna", {})
        
        # Secure extraction of the description
        descriptions = cna.get("descriptions", [])
        desc = descriptions[0].get("value", None) if descriptions else None

        # Secure extraction of the CWE
        problem_types = cna.get("problemTypes", [])
        cwe_id = np.nan
        cwe_desc = np.nan
        
        if problem_types:
            # We often take the first listed problem type
            desc_list = problem_types[0].get("descriptions", [])
            if desc_list:
                cwe_id = desc_list[0].get("cweId", np.nan)
                cwe_desc = desc_list[0].get("description", np.nan)

        metrics = cna.get("metrics", [])
        cvss_score = None
        if metrics != []:
            metrics = metrics[0]
            for k in metrics.keys():
                if "cvss" in k.lower():
                    cvss_score = float(metrics[k]["baseScore"])
                    break

        # Construction of the final dictionary
        return {
            "cve": cve,
            "cwe": cwe_id,
            "cwe_desc": cwe_desc,
            "cvss_score": cvss_score,
            "mitre_desc": desc,
            "affected_product": [ # By list comprehension method
                {
                    "vendor": prod.get("vendor"),
                    "product": prod.get("product"),
                    "versions": [v.get("version") for v in prod.get("versions", []) if v.get("status") == "affected"]
                }
                for prod in cna.get("affected", [])
            ]
        }
    except Exception:
        return {}

def create_database():
    ### ANSSI FEED
    anssi_feed = feedparser.parse(config["api"]["anssi"])

    for i in range(len(anssi_feed.entries)):
        # Some data is stored in sub-lists or sub-dictionaries, we retrieve only part of this data
        if "title_detail" in anssi_feed.entries[i] and type(anssi_feed.entries[i]["title_detail"]) == feedparser.util.FeedParserDict:
            anssi_feed.entries[i]["title"] = anssi_feed.entries[i]["title_detail"]["value"]

        if "summary_detail" in anssi_feed.entries[i] and type(anssi_feed.entries[i]["summary_detail"]) == feedparser.util.FeedParserDict:
            anssi_feed.entries[i]["summary_detail"] = anssi_feed.entries[i]["summary_detail"]["value"]

        if "published_parsed" in anssi_feed.entries[i]:
            anssi_feed.entries[i]["published"] = pd.to_datetime(datetime.datetime.fromtimestamp(time.mktime(anssi_feed.entries[i]["published_parsed"]))) # Transformation of the date to datetime format
            del anssi_feed.entries[i]["published_parsed"] # We prefer to keep only the date in datetime type and keep published as the key name

        # We remove what we don't need:
        if "summary" in anssi_feed.entries[i]:
            del anssi_feed.entries[i]["summary"]
        if "id" in anssi_feed.entries[i]:
            del anssi_feed.entries[i]["id"]
        if "guidislink" in anssi_feed.entries[i]:
            del anssi_feed.entries[i]["guidislink"]
        if "title_detail" in anssi_feed.entries[i]:
            del anssi_feed.entries[i]["title_detail"]
        if "links" in anssi_feed.entries[i]:
            del anssi_feed.entries[i]["links"]

    anssi_df = pd.DataFrame.from_dict(anssi_feed.entries)
    anssi_df.sort_index(ascending=False)

    conditions = [
        anssi_df["link"].str.contains("alerte", case=False, na=False),
        anssi_df["link"].str.contains("avis", case=False, na=False)
    ]
    anssi_df["type_publication"] = np.select(conditions, ["alerte", "avis"], default=None)

    anssi_df = anssi_df.dropna(subset=["type_publication"]) # We remove everything that is neither an advisory nor an alert

    anssi_df["cve"] = anssi_df["link"].transform(get_cve) # Returns the list of CVEs

    anssi_df = anssi_df.explode("cve")
    anssi_df = anssi_df.reset_index(drop=True) # We reset the index because explode "duplicates" the indices. The drop argument removes the old index
    
    ### EPSS SCORE
    anssi_df["epss_score"] = anssi_df["cve"].transform(lambda x: get_epss_data(x) if (pd.notna(x)) else np.nan) # We apply the function only if the CVE is not null
    
    ### MITRE DATA
    mitre_data = []
    if config["multithread"]:
        from concurrent.futures import ThreadPoolExecutor

        liste_cves = anssi_df['cve'].unique().tolist()

        with ThreadPoolExecutor(max_workers=15) as executor:
            mitre_data = list(executor.map(get_mitre_data, liste_cves))
    else:
        mitre_data = [ get_mitre_data(cve) for cve in anssi_df["cve"] ] # This execution takes time because it makes requests for each row of the df

    mitre_df = pd.DataFrame(mitre_data) # We transform our data into a df 
    mitre_df = mitre_df.dropna(subset=['cve']) # This line removes rejected and reserved CVEs
    mitre_df = mitre_df.reset_index(drop=True)

    anssi_df.columns = ['anssi_title', 'anssi_link', 'anssi_desc', 'anssi_published', 'type_publication', 'cve', 'epss_score'] # Renaming column names

    # Final merge
    DB = anssi_df.merge(mitre_df, on='cve', how='left')

    DB["base_severity"] = DB["cvss_score"].transform(set_severity)

    return DB