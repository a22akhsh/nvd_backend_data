# This module searches and fetches the nvd_web_front.nist.gov listed vulnerabilities
# then store them locally for analysis
import json
import os
import zipfile
from os.path import isfile, join

import requests
import re


# Utility function used
def contains_word(s, w):
    return (" " + w.lower() + " ") in (" " + s.lower() + " ")


class CveNvdAnalysis:
    def __init__(self):
        pass

    @staticmethod
    def unzip_data(source_zip_path: str = "", destination_json_data_path: str = ""):
        """
        This method extracts all the json data files in a new
        json/ directory that we can parse and analyse them
        :param destination_json_data_path: path for storing the json data files
        :param source_zip_path: zipped nvd_web_front cve files path
        :return:
        """
        os.makedirs(destination_json_data_path, exist_ok=True)
        if len(os.listdir(source_zip_path)) == len(os.listdir(destination_json_data_path)):
            return
        files = [f for f in os.listdir(source_zip_path) if isfile(join(source_zip_path, f))]
        files.sort()
        for file in files:
            archive = zipfile.ZipFile(join(source_zip_path, file), "r")
            with archive as f:
                f.extractall(path=destination_json_data_path)

    @staticmethod
    def get_nvd_data(url: str, file_path: str):
        """
        This method get the nvd_web_front data from the source website and stores locally
        :param url: url of source website
        :param file_path: local path where all files will be stored for further analysis
        Get the listed nvd_web_front vulnerabilities files from provided url feed
        :return:
        """
        r = requests.get(url + "vuln/data-feeds#JSON_FEED")
        os.makedirs(file_path, exist_ok=True)
        if len(re.findall("nvdcve-1.1-[0-9]*\.json\.zip", r.text)) == len(os.listdir(file_path)):
            return
        for filename in re.findall("nvdcve-1.1-[0-9]*\.json\.zip", r.text):
            r_file = requests.get(url + "feeds/json/cve/1.1/" + filename, stream=True)
            with open(file_path + filename, "wb") as f:
                for chunk in r_file:
                    f.write(chunk)

    @staticmethod
    def create_nvd_for_specific_year_dict(year: str, json_files_path: str = "", selection_ids: list = [],
                                          mandatory: bool = True):
        filename = join(json_files_path + "nvdcve-1.1-" + (year if year else "2023") + ".json")
        cve_dict: dict
        try:
            with open(filename, encoding="utf8") as json_file:
                cve_dict = json.load(json_file)
                CveNvdAnalysis.__extract_cve_id_and_problem_description(year, cve_dict=cve_dict,
                                                                        entry_selection=selection_ids,
                                                                        mandatory=mandatory
                                                                        )
        except FileNotFoundError as exp:
            raise ValueError("the input year not found, error number: " + str(exp.errno))
        return cve_dict

    @classmethod
    def __extract_cve_id_and_problem_description(cls, year, cve_dict, entry_selection: list, mandatory: bool):
        if not mandatory or len(entry_selection) == 0:
            return
        print("----------Displaying three chosen CVE entries ID and problem type with description data------------ ")
        for cve in cve_dict["CVE_Items"]:
            for entry in entry_selection:
                cve_id = "CVE-" + str(year) + "-" + str(entry)
                if cve_id.strip() == cve["cve"]["CVE_data_meta"]["ID"].strip():
                    print("-----------element Id " + entry + "   Start-----------------------")
                    print(cve["cve"]["CVE_data_meta"]["ID"])
                    print(cve["cve"]["problemtype"]["problemtype_data"])
                    print(cve["cve"]["description"]["description_data"])
                    print("-----------element Id " + entry + "   Finish-----------------------")
                    break
                    print("----------     end            ------------ ")

    @staticmethod
    def create_and_analyze_nvd_for_range_year_dict(year_range: str = "2002-2023", json_files_path: str = ""):
        """
        :param year_range:
        :param json_files_path:
        :return:
        """
        str_range = int(year_range.split("-")[0])
        end_range = int(year_range.split("-")[1])
        if (end_range - str_range) < 0:
            raise ValueError("Entered input in wrong range, provide range for example 2001-2004 i.e. "
                             "<low_year>-<high-year>")
        for year in range(str_range, end_range + 1):
            filename = join(json_files_path + "nvdcve-1.1-" + str(year) + ".json")
            with open(filename, encoding="utf8") as json_file:
                cve_dict = json.load(json_file)
            yield year, len(cve_dict["CVE_Items"]), cve_dict

    @staticmethod
    def search_description(expression: str, json_data_files_location: str, correlation_expression: tuple = None):
        """
        This method is for searching given expression in provided data sets as json files.
        Then the data set is returned to report graphically the scale of vulnerability instances for each of
        the following CPS component types: RTU, PLC, HMI, MTU, across all years.
        :param correlation_expression: sub-expression for co-relation with expression
        :param expression: expression to search in dataset
        :param json_data_files_location: location of json files
        :returns : year_basis_report, list_of_reports, component_based_cvss_score, sub_expression_report
        """
        # Get number of json files
        json_files_list = os.listdir(json_data_files_location)
        number_files = len(json_files_list) - 1

        # Various data structure initialization
        list_of_reports: list = []
        year_basis_report: dict = {}
        sub_expression_report: dict = {}
        component_based_cvss_score: dict = {}
        sub_expr_year: dict = {}

        # Considering CVE reports start from 2002. There are as many files as reporting years
        for year in range(2002, 2002 + number_files):
            cve_dict: dict = CveNvdAnalysis.create_nvd_for_specific_year_dict(year=str(year),
                                                                              json_files_path=json_data_files_location,
                                                                              mandatory=False)
            cve_items: json_files_list = cve_dict["CVE_Items"]
            version_based_dict: dict = {}
            for item in cve_items:
                description_list = item["cve"]["description"]["description_data"]
                if description_list:
                    CveNvdAnalysis.__match_expression_in_description_list(description_list, expression, item,
                                                                          list_of_reports, version_based_dict,
                                                                          year_basis_report, sub_expression_report,
                                                                          sub_expr_year,
                                                                          correlation_expression=correlation_expression)
            component_based_cvss_score[year] = version_based_dict
        return year_basis_report, list_of_reports, component_based_cvss_score, sub_expression_report

    @classmethod
    def __match_expression_in_description_list(cls, description_list, expression, item, list_of_reports,
                                               version_based_dict, year_basis_report, sub_expression_report,
                                               sub_expr_year, correlation_expression=None):
        description = description_list[0]["value"]
        published_year: str = item["publishedDate"].split("-")[0]
        if contains_word(description, expression):
            list_of_reports.append(item["cve"]["CVE_data_meta"]["ID"])
            if not correlation_expression:
                cls.__create_year_basis_report(item, published_year, version_based_dict, year_basis_report)
            if correlation_expression:
                for sub_expr in correlation_expression:
                    if contains_word(description, sub_expr):
                        cls.__create_year_basis_report(item, published_year, version_based_dict, year_basis_report)
                        if sub_expr in sub_expression_report.keys():
                            if published_year in sub_expression_report[sub_expr].keys():
                                sub_expression_report[sub_expr][published_year] = \
                                    sub_expression_report[sub_expr].get(published_year) + 1
                            else:
                                sub_expression_report[sub_expr][published_year] = 1
                        else:
                            sub_expression_report[sub_expr] = {published_year: 1}
        else:
            if published_year in year_basis_report.keys():
                pass
            else:
                year_basis_report[published_year] = 0

    @classmethod
    def __create_year_basis_report(cls, item, published_year, version_based_dict, year_basis_report):
        if published_year in year_basis_report.keys():
            year_basis_report[published_year] = year_basis_report.get(published_year) + 1
        else:
            year_basis_report[published_year] = 1
        if "impact" in item:
            CveNvdAnalysis.__cvss_score(item["impact"], version_based_dict)

    @classmethod
    def __cvss_score(cls, base_metric: dict, version_based_dict: dict):
        # print(item.keys())
        list_base_score: list = list()
        # print(base_metric)
        if "baseMetricV3" in base_metric.keys():
            version = base_metric["baseMetricV3"]["cvssV3"]["version"]
            base_score = base_metric["baseMetricV3"]["cvssV3"]["baseScore"]
            if version in version_based_dict:
                list_base_score: list = version_based_dict[version]
                list_base_score.append(base_score)
                version_based_dict[version] = list_base_score
            else:
                list_base_score.append(float(base_score))
                version_based_dict[version] = list_base_score
        if "baseMetricV2" in base_metric.keys():

            version = base_metric["baseMetricV2"]["cvssV2"]["version"]
            base_score = base_metric["baseMetricV2"]["cvssV2"]["baseScore"]
            if version in version_based_dict:
                list_base_score: list = version_based_dict[version]
                list_base_score.append(base_score)
                version_based_dict[version] = list_base_score
            else:
                list_base_score.append(float(base_score))
                version_based_dict[version] = list_base_score
