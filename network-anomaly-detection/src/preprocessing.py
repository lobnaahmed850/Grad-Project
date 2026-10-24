import glob
import os
import numpy as np
import pandas as pd
from sklearn.preprocessing import LabelEncoder


def load_and_merge_csvs(data_dir="../data/CIC2017/", output_parquet="../data/raw/merged_raw.parquet"):
    
    if os.path.exists(output_parquet):
        print("Loading fast merged raw data from Parquet...")
        df = pd.read_parquet(output_parquet)
    else:
        print("Loading CSV files for the first time...")
        # every csv file inside data_dir
        path = os.path.join(data_dir, "*.csv")
        all_files = glob.glob(path)
        # no csv exists
        if not all_files:
            raise FileNotFoundError(f"No CSV files found in {data_dir}. Check your directory path!")
            
        df = pd.concat((pd.read_csv(f) for f in all_files), ignore_index=True)
        
        os.makedirs(os.path.dirname(output_parquet), exist_ok=True)
        print("Saving merged data to Parquet...")
        df.to_parquet(output_parquet, index=False)
        
    return df

#droping duplicates and cleaning the data (numericalization)
def clean_dataframe(df):

    df.columns = df.columns.str.strip().str.lower()
    df = df.drop_duplicates()
    for col in ["flow bytes/s", "flow packets/s"]:
        if col in df.columns:
            df[col] = pd.to_numeric(df[col], errors="coerce")
            
    df = df.replace([np.inf, -np.inf], np.nan).dropna()
    
    return df

#prepare data for Isolation Forest (binary classification)
def prepare_IF_data(df):
    y = (df['label'].str.strip().str.upper() != 'BENIGN').astype(int)
    X = df.drop(columns=['label'])
    return X, y

#prepare data for Random Forest (multi-class classification)
def prepare_rf_data(df):
    df_attacks = df[df["label"].str.strip().str.upper() != "BENIGN"]
    X = df_attacks.drop(columns=["label"])
    y = df_attacks["label"].str.strip()          # strip so "DoS Hulk" and "DoS Hulk " don't become 2 classes
    label_encoder = LabelEncoder()
    y_encoded = label_encoder.fit_transform(y)
    return X, y_encoded, label_encoder
