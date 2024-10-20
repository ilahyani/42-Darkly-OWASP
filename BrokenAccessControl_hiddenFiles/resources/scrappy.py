import requests
from bs4 import BeautifulSoup
import os

def get_files_from_url(url, file_name):
    """
    Recursively retrieves files with the specified file_name from the URL.
    
    Args:
    - url (str): The base URL to search.
    - file_name (str): The specific file name to search for (e.g., 'README').
    
    Returns:
    - files_content (dict): A dictionary with URLs as keys and file contents as values.
    """
    files_content = {}

    try:
        response = requests.get(url)
        response.raise_for_status()

        soup = BeautifulSoup(response.content, 'html.parser')

        for link in soup.find_all('a'):
            href = link.get('href')
            if href in ['../', './']:
                continue
            full_url = os.path.join(url, href)
            if href.endswith('/'):
                files_content.update(get_files_from_url(full_url, file_name))
            elif href == file_name:
                file_response = requests.get(full_url)
                file_response.raise_for_status()
                files_content[full_url] = file_response.text

    except Exception as e:
        print(f"Error accessing {url}: {e}")

    return files_content

if __name__ == "__main__":
    root_url = 'http://10.13.100.250:80/.hidden'
    target_file_name = 'README'
    extracted_files = get_files_from_url(root_url, target_file_name)
    for file_url, content in extracted_files.items():
        print(f"Content of {file_url}:\n{content}\n")
