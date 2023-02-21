import requests
import requestURLList
from time import sleep
from datetime import datetime
from pathlib import Path

PHISHSTATS_FILE_PATH = Path(__file__).parent.parent / 'data/phishstats.txt'
DATE_MIN = datetime(2022, 10, 7)
DATE_MAX = datetime.now()


def getDatetime(string):
    return datetime.strptime(string, '%Y-%m-%dT%H:%M:%S.%fZ')


def getString(date: datetime):
    return date.strftime('%Y-%m-%dT%H:%M:%S.%fZ')


def getUntilResponse(query):
    request = requests.get(query)
    while request.status_code == 503:
        sleep(0.5)
        request = requests.get(query)
    return request


class PhishstatsAPI:
    """
    Usage:

    phishstatsAPI = PhishstatsAPI()
    phishstatsAPI.writeFile(min_score=7, minDate=datetime(2022, 10, 8), maxDate=datetime.now(), eraseFile=True)
    This will grab every phishing URL from phishstats.info API, from 8th October 2022 00:00 to now with a minimum score of 7 (out of 10), and replace the file "data/phishstats.txt" with the incoming URLs. Settings eraseFile to False will not clear the file before adding new URLs
    OR 
    phishstatsAPI = PhishstatsAPI()
    phishstatsAPI.getUrlList(min_score=7, minDate=datetime(2022, 10, 8), maxDate=datetime.now())
    Same effect, but return URL list instead of writing to file
    """

    def __init__(self):
        self.baseURL = "https://phishstats.info:2096/api/phishing/distinct?_fields=url,score,date&"
        self.countURL = "https://phishstats.info:2096/api/phishing/count?_fields=url,score,date&"
        self.length = 0

    def iterate(self, json_callback, min_score=0, min_date=DATE_MIN, max_date=DATE_MAX):
        # score >= min_score && sort by date DESC (100 records max)
        page = 0
        size = 100
        response_json = []
        api_filter = f"_where=(score,gte,{min_score})~and(date,gte,{getString(min_date)})~and(date,lte,{getString(max_date)})"
        counter_query = self.countURL + api_filter
        try:
            count_request = getUntilResponse(counter_query)
            print(f"Expected number of records: {count_request.json()[0]['no_of_rows']}")
        except:
            print("Could not count number of records in advance")
        while page == 0 or len(response_json) != 0:
            query = self.baseURL + api_filter + f"&_sort=-date&_size={size}&_p={page}"
            request = getUntilResponse(query)
            response_json = request.json()
            json_callback(response_json)
            page += 1
            if len(response_json) == 0:
                break
            print(f"Page #{page} done. Last record: {response_json[-1]}")
            self.length += len(response_json)
            if len(response_json) < size:
                break

    def write_file(self, min_score=0, min_date=DATE_MIN, max_date=DATE_MAX, erase_file=True):
        def json_callback(response_json):
            with open(PHISHSTATS_FILE_PATH, 'a', encoding='utf-8') as f:
                for record in response_json:
                    f.write(f"{record['url']}\n")
        if erase_file:
            open(PHISHSTATS_FILE_PATH, 'w').close()
        self.iterate(json_callback=json_callback, min_score=min_score, min_date=min_date, max_date=max_date)

    def get_url_list(self, min_score=0, min_date=DATE_MIN, max_date=DATE_MAX):
        array = []

        def json_callback(response_json):
            for record in response_json:
                array.append(record['url'])
        self.iterate(json_callback=json_callback, min_score=min_score, min_date=min_date, max_date=max_date)
        return array


if __name__ == "__main__":
    write = True

    phishstatsAPI = PhishstatsAPI()
    # phishstatsAPI.write_file(min_score=0, min_date=datetime(2022, 10, 8), max_date=datetime.now(), erase_file=True)
    url_list = phishstatsAPI.get_url_list(min_score=5, min_date=datetime(2022, 10, 8), max_date=datetime.now())
    url_requestor = requestURLList.URLRequestor()
    # url_requestor.merge_file(PHISHSTATS_FILE_PATH, write=write)
    url_requestor.merge_list(url_list=url_list, write=True)
