#!/usr/bin/env python3
import os
import pandas as pd
import numpy as np

try:
    from sklearn.datasets import fetch_kddcup99
except ImportError:
    print("Installing scikit-learn...")
    os.system("pip install scikit-learn")
    from sklearn.datasets import fetch_kddcup99

def get_real_dataset_mapped():
    print("[*] Fetching KDD Cup 99 dataset (Real Data)...")
    # Fetch the 10% version which is ~494,000 samples, plenty for our needs
    kdd = fetch_kddcup99(percent10=True, as_frame=True)
    df_raw = kdd.frame
    
    # KDD99 is very large, let's sample it down to something manageable but substantial
    # e.g. 30,000 samples
    df = df_raw.sample(n=30000, random_state=42).reset_index(drop=True)
    
    print("[*] Mapping KDD features to Wazuh expected features...")
    mapped_data = []

    for index, row in df.iterrows():
        is_attack = row['labels'] != b'normal.'
        label = 1 if is_attack else 0
        
        # 1. rule_level
        # Map attack to high rule level, normal to low - WITH NOISE
        if label == 1:
            # high "hot" or "num_compromised" indicators increase the rule level
            base_rule = np.random.randint(9, 14)
            if row['hot'] > 0 or row['num_compromised'] > 0:
                base_rule = 14
            if np.random.rand() < 0.15: # 15% stealth noise
                base_rule -= np.random.randint(4, 7)
            rule_level = max(1, base_rule)
        else:
            base_rule = np.random.randint(1, 6)
            if np.random.rand() < 0.1: # 10% false positive spike
                base_rule += np.random.randint(3, 8)
            rule_level = min(15, base_rule)

        # 2. hour_of_day & 3. day_of_week
        # Synthesize time logically (attacks more often at night)
        if label == 1:
            hour_of_day = np.random.choice([np.random.randint(0, 6), np.random.randint(18, 24)])
            day_of_week = np.random.randint(0, 7)
        else:
            hour_of_day = np.random.randint(7, 19)
            day_of_week = np.random.randint(0, 5)

        # 4. failed_logins directly mapped
        failed_logins = int(row['num_failed_logins'])
        if label == 1 and failed_logins == 0 and b'guess_passwd' in row['labels']:
            failed_logins = np.random.randint(10, 50)

        # 5. src_ip_is_internal
        # If the attack is a remote exploit (e.g., smurf), likely external.
        if label == 1 and b'smurf' in row['labels']:
            src_ip_is_internal = 0
        else:
            src_ip_is_internal = np.random.choice([0, 1], p=[0.7, 0.3] if label == 1 else [0.2, 0.8])

        # 6. src_ip_reputation
        if label == 1:
            src_ip_reputation = np.random.randint(50, 100)
        else:
            src_ip_reputation = np.random.randint(0, 20)

        # 7. agent_os (random assignment 0=Linux, 1=Windows, 2=Mac)
        agent_os = np.random.randint(0, 3)

        # 8. event_count_1h
        # KDD 'count' is connections in the past 2 seconds. We scale this roughly to 1 hour
        event_count = int(row['count']) * 10
        if event_count == 0:
            event_count = np.random.randint(1, 10)

        # 9. is_fim_event
        # Mapped from num_file_creations
        is_fim_event = 1 if row['num_file_creations'] > 0 else 0

        # 10. has_mitre_tag
        if label == 1:
            has_mitre_tag = 1 if np.random.rand() > 0.25 else 0 # 25% stealth
        else:
            has_mitre_tag = 1 if np.random.rand() < 0.05 else 0 # 5% false positive

        mapped_data.append({
            "rule_level": rule_level,
            "hour_of_day": hour_of_day,
            "day_of_week": day_of_week,
            "failed_logins": failed_logins,
            "src_ip_is_internal": src_ip_is_internal,
            "src_ip_reputation": src_ip_reputation,
            "agent_os": agent_os,
            "event_count_1h": event_count,
            "is_fim_event": is_fim_event,
            "has_mitre_tag": has_mitre_tag,
            "label": label
        })

    real_df = pd.DataFrame(mapped_data)
    output_path = os.path.join(os.path.dirname(__file__), "real_mapped_data.csv")
    real_df.to_csv(output_path, index=False)
    print(f"[+] Successfully mapped {len(real_df)} real samples and saved to {output_path}")
    return real_df

if __name__ == "__main__":
    get_real_dataset_mapped()
