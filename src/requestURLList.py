import requests
from pathlib import Path
import urllib.parse as up

WEBSITE_TXT_LIST = [
    "https://openphish.com/feed.txt",
    "https://raw.githubusercontent.com/mitchellkrogza/Phishing.Database/master/phishing-links-NEW-today.txt",
    "https://raw.githubusercontent.com/mitchellkrogza/Phishing.Database/master/phishing-links-ACTIVE-TODAY.txt",
    "https://raw.githubusercontent.com/mitchellkrogza/Phishing.Database/master/phishing-links-ACTIVE-today.txt",
    "https://phishunt.io/feed.txt"
]

URL_LIST_FILE_PATH = Path(__file__).parent.parent / 'data/url_list.txt'


class URLRequestor:
    def __init__(self):
        self.url_set = set()
        with open(URL_LIST_FILE_PATH, 'r', encoding='utf-8') as f:
            self.url_set = set(line.rstrip() for line in f)

    def write_file(self, use_filter=False):
        with open(URL_LIST_FILE_PATH, 'w', encoding='utf-8') as f:
            if use_filter:
                self.url_set = URLRequestor._filter_url_list(self.url_set)
            for url in self.url_set:
                f.write(f"{url}\n")

    def merge_file(self, phishing_url_filepath, write=True):
        old_length = len(self.url_set)
        with open(phishing_url_filepath, 'r', encoding='utf-8') as f:
            url_list = [line.rstrip() for line in f]
            self.update_url_set(url_list)
            print(f"{len(self.url_set) - old_length}/{len(url_list)} URLs have been added.")

        if write:
            self.write_file()

    def merge_list(self, url_list, write=True):
        old_length = len(self.url_set)
        self.update_url_set(url_list)
        print(f"{len(self.url_set) - old_length}/{len(url_list)} URLs have been added.")

        if write:
            self.write_file()

    def request_txt_files(self) -> None:
        for url in WEBSITE_TXT_LIST:
            old_length = len(self.url_set)
            request = requests.get(url)
            url_list = request.text.split()
            self.update_url_set(url_list)
            print(f"{len(self.url_set) - old_length}/{len(url_list)} URLs added (from source {url})")

        self.write_file()

    @staticmethod
    def remove_all_url():
        with open(URL_LIST_FILE_PATH, 'w', encoding='utf-8') as f:
            f.write('')

    def update_url_set(self, url_list):
        self.url_set.update(URLRequestor._filter_url_list(url_list))

    @staticmethod
    def _filter_url_list(url_list):
        def has_empty_path(url):
            # URL with empty path cannot have a phishing kit attached to domain name, so they are useless for our
            # usecase
            path = up.urlparse(url).path
            return path == "" or path == "/"

        def url_with_trailing_slash(url):
            # Helping the phishing kit searcher by placing a trailing slash at the end
            return url if url[-1] == "/" else f"{url}/"

        def remove_query(url):
            # Parameters, query and fragments are useless for finding kits
            parse = up.urlparse(url)
            return up.urlunparse((parse.scheme, parse.netloc, parse.path, None, None, None))

        return [url_with_trailing_slash(remove_query(url)) for url in url_list if not has_empty_path(url)]


if __name__ == "__main__":
    urlRequestor = URLRequestor()
    urlRequestor.request_txt_files()
    # urlRequestor.write_file(True)
    # urlRequestor.write_file(use_filter=True) # filter existing file
