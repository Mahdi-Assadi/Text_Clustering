import pandas as pd
from sklearn.cluster import DBSCAN
from sentence_transformers import SentenceTransformer
import numpy as np
from joblib import dump, load
from fastapi import FastAPI
from typing import List, Dict
from flask import Flask, jsonify
import json



def reading_data(file_path):
    """
    Reads data from an SQL file, extracts relevant information, and converts it into a pandas DataFrame.

    Args:
        file_path (str): Path to the SQL file.

    Returns:
        pd.DataFrame: A DataFrame containing the extracted data with predefined columns.
    """
    # Path to the uploaded .sql file
    sql_file_path = file_path

    # Read the SQL file
    with open(sql_file_path, "r") as file:
        sql_content = file.read()

    # Extract the data section between 'COPY ... FROM stdin;' and '\.'
    start = sql_content.find("COPY public.vuln")
    end = sql_content.find("\\.", start)
    data_section = sql_content[start:end].splitlines()[2:]  # Skip the header lines

    # Parse the data into a list of rows
    data = [line.split("\t") for line in data_section if line.strip()]


    # Define the column names
    columns = ["id", "title", "description", "severity", "cve", "sensor", "endpoint"]

    # Create a DataFrame
    df = pd.DataFrame(data, columns=columns)

    return df


def prepare_text(df):
    """
    Prepares text data for clustering by combining relevant fields and handling lines with duplicate CVEs.

    Args:
        df (pd.DataFrame): The DataFrame containing the data.

    Modifies:
        df['text'] (str): Adds a combined text field for clustering.
    """
    #Combining title and description for clustering
    df['text'] = df['title'] + ' ' + df['description']


    #for lines with the same cve comine the texts so in the clustering process they will be put in the same cluster
    for cve in set(df.cve[df.cve != 'null']):
      combined_text = ''
      for text in df.text[df.cve == cve]:
        combined_text += text
      df.loc[df.cve == cve, 'text'] = combined_text


#each endpoint has its own clustering
def cluster_by_endpoint(df):
    """
    Performs clustering on the text data grouped by the endpoint field.

    Args:
        df (pd.DataFrame): The DataFrame containing the text data.

    Returns:
        tuple: A tuple containing:
            - pd.DataFrame: The DataFrame with cluster labels added.
            - dict: A dictionary of clustering models for each endpoint.
    """
    grouped_results = []
    clustering_models = {} #saving the models for future cluster assignments
    for endpoint, group in df.groupby('endpoint'):
        # Generate embeddings
        texts = group['text'].tolist()
        embeddings = model.encode(texts)

        # Clustering with DBSCAN
        clustering_model = DBSCAN(eps=0.3, min_samples=1, metric="cosine")
        cluster_labels = clustering_model.fit_predict(embeddings)

        #saving the clustering model for future predictions
        clustering_models[endpoint] = clustering_model

        # Add cluster labels back to the DataFrame
        group['cluster'] = cluster_labels
        grouped_results.append(group)
    
    return pd.concat(grouped_results), clustering_models


def add_tag(df):
    """
    Adds a unique tag for each (endpoint, cluster) pair to the DataFrame.

    Args:
        df (pd.DataFrame): The clustered DataFrame.

    Returns:
        pd.DataFrame: The updated DataFrame with a 'tag' column added.
    """
    #get endpoint and cluster pairs for tagging numbers
    tag_df = df[['endpoint', 'cluster']].drop_duplicates()
    tag_df = tag_df[['endpoint', 'cluster']].reset_index(drop=True)
    tag_df.sort_index(inplace=True)

    #add the group number to tag
    for i in range(len(tag_df)):
        tag_df.loc[i, 'tag'] = f'group_{i}'

    #adding tags to the main dataframe
    df_merged = pd.merge(clustered_df, tag_df, how='inner', on=['endpoint', 'cluster'])
    return df_merged



if __name__ == '__main__':
    """
    Main script to execute the pipeline:
    1. Read data from an SQL file.
    2. Prepare text data for clustering.
    3. Perform clustering by endpoint.
    4. Assign unique tags to clustered data.
    5. Serve the data through a Flask API endpoint.
    """
    df = reading_data(r"./vuln_data.sql")
    prepare_text(df)
    #loading sentence BERT for embedding the texts
    model = SentenceTransformer('all-MiniLM-L6-v2')
    clustered_df, clustering_models = cluster_by_endpoint(df)
    clustered_df.sort_values(by= ['endpoint', 'cluster'], inplace= True)
    # to cluster future data points, Save the dictionary to a file
    dump(clustering_models, "clustering_models.joblib")
    df_merged = add_tag(clustered_df)
    app = Flask(__name__)
    app.json.sort_keys = False

    @app.route('/vulnerabilities', methods=['GET'])
    def get_vulnerabilities():
        """
        API endpoint to fetch clustered vulnerability data.
        Returns:
            JSON response containing relevant data fields.
        """
        # Flask's jsonify to format the response as JSON
        return jsonify(df_merged[['title', 'endpoint', 'tag', 'description', 'cve', 'severity', 'sensor']].to_dict(orient="records")), 200

    app.run(debug=True)
