import csv
import os
import re
import shutil
import tarfile
import tempfile
from zipfile import ZipFile
from searchPhishingKit import PK_FOLDER_PATH, STATS_FILE_PATH


class Indexes:
    FILENAME = 0
    ERROR = 1
    WRITEONFILE = 2
    SENDBYMAIL = 3
    SENDBYTELEGRAM = 4
    CONTAINTEXTFILE = 5
    RECURSECOPY = 6


class AnalysePhishingKit:
    main_compressed_ext = [".zip", ".tar.gz", ".rar"]

    def __init__(self):
        # Create temporary secured folder
        self.secure_temp_dir = tempfile.mkdtemp()

        # Load kits already analysed
        with open(STATS_FILE_PATH) as csv_stats:
            csv_reader = csv.reader(csv_stats, delimiter=",")
            next(csv_reader)
            self.analysed_kit = set(kit[Indexes.FILENAME] for kit in csv_reader if len(kit) > 0)

        self.new_kits = dict()

    def __del__(self):
        shutil.rmtree(self.secure_temp_dir)

    def extract_all_kits(self) -> None:
        print("-------------------BEGIN EXTRACTION-------------------")
        for ext in self.main_compressed_ext:
            files = [file for file in os.listdir(PK_FOLDER_PATH) if
                     file.endswith(ext) and file.replace(ext, "") not in self.analysed_kit]
            for file in files:
                self._extract_file(file, ext)
        print("-------------------END EXTRACTION-------------------")

    def _extract_file(self, file_name: str, extension: str) -> None:
        origin_file_path = f"{PK_FOLDER_PATH}/{file_name}"
        new_folder_name = file_name.replace(extension, "")
        folder_dest = f"{self.secure_temp_dir}/{new_folder_name}/"

        try:
            if extension == ".zip":
                with ZipFile(origin_file_path, "r") as zObject:
                    zObject.extractall(path=folder_dest)
            elif extension == ".tar.gz":
                tar_file = tarfile.open(origin_file_path)
                tar_file.extractall(folder_dest)
                tar_file.close()
        except Exception as errorMessage:
            self.new_kits[new_folder_name] = dict()
            self.new_kits[new_folder_name][Indexes.ERROR] = errorMessage
            self.new_kits[new_folder_name][Indexes.WRITEONFILE] = None
            self.new_kits[new_folder_name][Indexes.SENDBYMAIL] = None
            self.new_kits[new_folder_name][Indexes.SENDBYTELEGRAM] = None
            self.new_kits[new_folder_name][Indexes.CONTAINTEXTFILE] = None
            self.new_kits[new_folder_name][Indexes.RECURSECOPY] = None

    def analyze_files(self) -> None:
        print("-------------------BEGIN ANALYZE-------------------")
        kit_folders = [f for f in os.listdir(self.secure_temp_dir)]
        for kit in kit_folders:
            print(f"Analyse kit : {kit}")
            kit_path = f"{self.secure_temp_dir}/{kit}"

            contain_result_txt_file = False
            for (root, dirs, files) in os.walk(kit_path, topdown=True):
                self._analyze_files_content(files, root, kit)

                if not contain_result_txt_file:
                    contain_result_txt_file = self._check_if_contain_text_file_results(files)

            # Add information for csv stats file
            self.new_kits[kit][Indexes.ERROR] = None
            self.new_kits[kit][Indexes.CONTAINTEXTFILE] = contain_result_txt_file

        self._save_kit_information()
        print("-------------------END ANALYZE-------------------")

    @staticmethod
    def _check_if_contain_text_file_results(files: list):
        regexps = [".*result.*", ".*Result.*"]

        # Check if files match with regexps list
        for regexp in regexps:
            r = re.compile(regexp)
            regexp_file_list = list(filter(r.match, files))
            if len(regexp_file_list) > 0:
                return True
        return False

    def _analyze_files_content(self, files: list, kit_path: str, kit_name: str):
        mail_functions = ["mail("]
        write_on_file_functions = ["fwrite("]
        telegram = ["api.telegram"]
        recurse_copy_functions = ["recurse_copy"]

        is_mail_found = False
        is_write_on_file_found = False
        is_telegram_found = False
        is_recurse_copy = False

        for file in files:
            if file.endswith((".html", ".php")):
                try:
                    with open(os.path.join(kit_path, file), 'r') as file_content:
                        for line in file_content:
                            # Check mail
                            if not is_mail_found:
                                for mail_pattern in mail_functions:
                                    if mail_pattern in line:
                                        is_mail_found = file

                            # Check write on file
                            if not is_write_on_file_found:
                                for write_pattern in write_on_file_functions:
                                    if write_pattern in line:
                                        is_write_on_file_found = file

                            # Check Telegram
                            if not is_telegram_found:
                                for telegram_pattern in telegram:
                                    if telegram_pattern in line:
                                        is_telegram_found = file

                            # Check recurse copy
                            if not is_recurse_copy:
                                for recurse_copy_pattern in recurse_copy_functions:
                                    if recurse_copy_pattern in line:
                                        is_recurse_copy = True
                except Exception:
                    pass

            if is_mail_found and is_telegram_found and is_write_on_file_found and is_recurse_copy:
                break

        # Add information for csv stats
        if kit_name not in self.new_kits:
            self.new_kits[kit_name] = dict()
            self.new_kits[kit_name][Indexes.SENDBYMAIL] = is_mail_found
            self.new_kits[kit_name][Indexes.WRITEONFILE] = is_write_on_file_found
            self.new_kits[kit_name][Indexes.SENDBYTELEGRAM] = is_telegram_found
            self.new_kits[kit_name][Indexes.RECURSECOPY] = is_recurse_copy
        else:
            if not self.new_kits[kit_name][Indexes.SENDBYMAIL] and is_mail_found:
                self.new_kits[kit_name][Indexes.SENDBYMAIL] = is_mail_found

            if not self.new_kits[kit_name][Indexes.WRITEONFILE] and is_write_on_file_found:
                self.new_kits[kit_name][Indexes.WRITEONFILE] = is_write_on_file_found

            if not self.new_kits[kit_name][Indexes.SENDBYTELEGRAM] and is_telegram_found:
                self.new_kits[kit_name][Indexes.SENDBYTELEGRAM] = is_telegram_found

            if not self.new_kits[kit_name][Indexes.RECURSECOPY] and is_recurse_copy:
                self.new_kits[kit_name][Indexes.RECURSECOPY] = is_recurse_copy

    def _save_kit_information(self):
        # Save kits information into csv file
        with open(STATS_FILE_PATH, mode="a") as csv_stats:
            writer = csv.writer(csv_stats, delimiter=",", lineterminator="\n")
            for kit_name in self.new_kits:
                writer.writerow([
                    kit_name,
                    self.new_kits[kit_name][Indexes.ERROR],
                    self.new_kits[kit_name][Indexes.WRITEONFILE],
                    self.new_kits[kit_name][Indexes.SENDBYMAIL],
                    self.new_kits[kit_name][Indexes.SENDBYTELEGRAM],
                    self.new_kits[kit_name][Indexes.CONTAINTEXTFILE],
                    self.new_kits[kit_name][Indexes.RECURSECOPY]
                ])

    @staticmethod
    def print_stats():
        nb_kits = 0
        nb_write_on_file = 0
        nb_send_by_mail = 0
        nb_send_by_telegram = 0
        nb_contain_text_file = 0
        nb_recurse_copy = 0

        # Load kits analysed
        with open(STATS_FILE_PATH) as csv_stats:
            csv_reader = csv.reader(csv_stats, delimiter=",")
            next(csv_reader)
            for kit in csv_reader:
                # Line is empty
                if len(kit) == 0:
                    continue

                nb_kits += 1

                # Error during extraction
                if len(kit[Indexes.ERROR]) != 0:
                    continue

                if kit[Indexes.WRITEONFILE] != "False":
                    nb_write_on_file += 1
                if kit[Indexes.SENDBYMAIL] != "False":
                    nb_send_by_mail += 1
                if kit[Indexes.SENDBYTELEGRAM] != "False":
                    nb_send_by_telegram += 1
                if kit[Indexes.CONTAINTEXTFILE] != "False":
                    nb_contain_text_file += 1
                if kit[Indexes.RECURSECOPY] != "False":
                    nb_recurse_copy += 1

        print(f"-------------------Statistics about kits (total: {nb_kits})-------------------")
        print(f"• Write on file : {round((nb_write_on_file / nb_kits) * 100, 2)}%")
        print(f"• Send by email : {round((nb_send_by_mail / nb_kits) * 100, 2)}%")
        print(f"• Send on Telegram : {round((nb_send_by_telegram / nb_kits) * 100, 2)}%")
        print(f"• Contain text file : {round((nb_contain_text_file / nb_kits) * 100, 2)}%")
        print(f"• Do a recurse copy : {round((nb_recurse_copy / nb_kits) * 100, 2)}%")


if __name__ == "__main__":
    analyser = AnalysePhishingKit()
    analyser.extract_all_kits()
    analyser.analyze_files()
    analyser.print_stats()
