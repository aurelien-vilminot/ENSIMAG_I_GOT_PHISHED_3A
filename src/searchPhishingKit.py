import requests
import urllib.parse as up
from pathlib import Path
import hashlib

ACCEPTABLE_HTTP_CODE = {100, 101, 201, 200, 202, 203, 204, 205, 206}
ORIGIN_FILE_PATH = Path(__file__).parent.parent / 'phishing-kits/origins.txt'
PK_FOLDER_PATH = Path(__file__).parent.parent / 'phishing-kits/'
DATA_RETRIEVED_FOLDER_PATH = Path(__file__).parent.parent / 'phishing-kits/data_retrieved/'
STATS_FILE_PATH = Path(__file__).parent.parent / 'phishing-kits/stats.csv/'


class SearchPhishingKit:
    all_compressed_ext = [".zip", ".tar.gz", ".tgz", ".rar", ".arc", ".arj", ".as", ".b64",
                          ".btoa", ".bz", ".bz2", ".cab", ".cpt", ".gz", ".hqx", ".iso",
                          ".lha", ".lzh", ".mim", ".mme", ".pak", ".pf", ".rpm", ".sea",
                          ".sit", ".sitx", ".tbz", ".tbz2", ".uu", ".uue", ".z", ".zipx", ".zoo"]

    main_compressed_ext = [".zip", ".tar.gz", ".rar"]

    def __init__(self, total_urls_number, console_output=False, use_all_compressed_ext=True):
        # All attributes are global to threads : do not modify attribute depending on a particular URL
        self.current_urls_number = 0
        self.total_urls_number = total_urls_number
        self.milestones = [(i * total_urls_number // 10) for i in range(1, 11)]
        self.compressed_ext = self.all_compressed_ext if use_all_compressed_ext else self.main_compressed_ext
        self.console_output = console_output
        with open(ORIGIN_FILE_PATH, "r") as log_file:
            self.origins_hash_set = set(line.rstrip()[:32] for line in log_file)

    def search_kit(self, url):
        self._print_milestone()
        complete_url = url.rstrip()
        current_url = url.rstrip()
        while current_url.count('/') > 3:
            pos = current_url.rfind('/')
            current_url = current_url[:pos]
            for ext in self.compressed_ext:
                if self._search_one_ext(current_url, complete_url, ext):
                    return

    def _search_one_ext(self, current_url, complete_url, ext) -> bool:
        if self.console_output:
            print(f"{current_url}{ext}")
        hashed_url = self._hash_url(current_url)
        file_name = f"{self._get_file_name(current_url, hashed_url)}{ext}"
        log_line = f"{hashed_url} - {file_name} - {complete_url}"

        # Perform request
        r = requests.get(current_url + ext, stream=True)
        if r.status_code in ACCEPTABLE_HTTP_CODE and self._check_is_file(r.content):
            if self._is_already_downloaded(hashed_url):
                print(f"PhishingKit already downloaded for URL: {current_url}{ext}")
                return True
            print(f"Downloading phishing kit : {log_line}")

            # Download phishing kit
            with open(f"{str(PK_FOLDER_PATH)}/{file_name}", 'wb') as phishing_kit_file:
                # Optimize file copy
                for chunk in r.iter_content(chunk_size=16 * 1024):
                    if chunk:
                        phishing_kit_file.write(chunk)

            # Write phishing kit
            self.origins_hash_set.add(hashed_url)
            with open(ORIGIN_FILE_PATH, "a") as log_file_write_mode:
                log_file_write_mode.write(f"{log_line}\n")

            r.close()
            return True
        r.close()
        return False

    def _is_already_downloaded(self, hashed_url) -> bool:
        if hashed_url in self.origins_hash_set:
            return True
        return False

    def _print_milestone(self):
        self.current_urls_number += 1
        for i in range(len(self.milestones)):
            if 0 < self.milestones[i] <= self.current_urls_number:
                print(f"{(i + 1) * len(self.milestones)}% done")
                self.milestones[i] = -1

    @staticmethod
    def _get_file_name(current_url, hashed_url):
        file_name = up.unquote(Path(up.urlparse(current_url).path).name)
        return f"{file_name}#{hashed_url[:5]}"

    @staticmethod
    def _check_is_file(content) -> bool:
        # Check if the request content is really a file !Not perfect!
        try:
            content.decode('utf-8')
            return False
        except Exception:
            unacceptable_content = {"<!DOCTYPE HTML>", "</html>"}
            for string in unacceptable_content:
                if string in str(content).capitalize():
                    return False
            return True

    @staticmethod
    def _hash_url(current_url):
        return hashlib.md5(current_url.encode()).hexdigest()[:32]
