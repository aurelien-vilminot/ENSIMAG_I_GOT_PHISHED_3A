#!/usr/bin/env python3
import fileinput
import searchPhishingKit
import requestURLList
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
import phishstats


def main(update_url=False, remove_all_url=True, console_output=False, use_all_compressed_ext=True):
    """Manage script run"""
    url_requestor = requestURLList.URLRequestor()

    # Clear all URLs before treatment
    if remove_all_url:
        url_requestor.remove_all_url()
        print('Removed all URLs')

    # Update URL List
    if update_url:
        # Request phishing URLs from .txt sources
        url_requestor.request_txt_files()
        # Request phishing URLs from phishstats.info API
        phishstats_api = phishstats.PhishstatsAPI()
        url_list = phishstats_api.get_url_list(
            min_score=2,
            min_date=datetime(datetime.now().year, datetime.now().month, datetime.now().day - 1),
            max_date=datetime.now()
        )
        url_requestor.merge_list(url_list=url_list, write=True)

    # Get iterator of URL links
    iterator_data = fileinput.input(requestURLList.URL_LIST_FILE_PATH)
    analyzer = searchPhishingKit.SearchPhishingKit(total_urls_number=len(url_requestor.url_set),
                                                   console_output=console_output,
                                                   use_all_compressed_ext=use_all_compressed_ext)
    with ThreadPoolExecutor() as executor:
        executor.map(analyzer.search_kit, iterator_data)
        executor.shutdown(wait=True)


if __name__ == "__main__":
    # Modifiable parameters
    update_url = True
    remove_all_url = True
    console_output = False
    use_all_compressed_ext = False
    # Do not modify to search
    main(update_url=update_url, remove_all_url=remove_all_url, console_output=console_output,
         use_all_compressed_ext=use_all_compressed_ext)
