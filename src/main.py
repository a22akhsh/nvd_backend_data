# This is an analysis of online vulnerability analysis Python Project.
# Task 4 – Correlations
import os
import argparse

from flask import Flask
from backend_filter.analyse import CveNvdAnalysis
import backend_controller
from task_functions import task_3_1, task_3_2, task_3_2_2_and_4_3, task_4_1, task_4_2

# Initialize parser
parser = argparse.ArgumentParser()

# Adding optional argument
parser.add_argument("-r", "--Range", default="2002-2020",
                    help="Provide range of years to analyse in acceptable format for example "
                         "2001-2020")
parser.add_argument("-y", "--Year", default="",
                    help="Provide the specific year to analyse in acceptable format for example "
                         "2001-2020", required=False)
parser.add_argument("-select_id", "--SelectID", default="1,2,3", help="Provide the selection ID for CVE entries ID, "
                                                                      "problem type data and description to display on "
                                                                      "screen. Do not provide more than 3 ids to select"
                                                                      ", correct input is 1,2,3 or 49,10 like this.",
                    required=False)
parser.add_argument("-t", "--Task", default="",
                    help="Provide the task id to execute for example 3_x, 3.2.cvss or 4_x", required=False)

# Read arguments from command line
args = parser.parse_args()

if __name__ == '__main__':
    url = "https://nvd.nist.gov/"
    local_dir_path_for_zip_files = os.getcwd() + "/cve_nvd_zip_files/"
    local_dir_path_for_json_files = os.getcwd() + "/cve_nvd_json_data_files/"
    CveNvdAnalysis.get_nvd_data(url, local_dir_path_for_zip_files)
    CveNvdAnalysis.unzip_data(local_dir_path_for_zip_files, local_dir_path_for_json_files)
    print("execution started")
    args = {'Range': '2002-2023'}
    task_3_1(local_json_data_path=local_dir_path_for_json_files, args=args)
    task_3_2(local_json_data_path=local_dir_path_for_json_files)
    task_3_2_2_and_4_3(local_json_data_path=local_dir_path_for_json_files)
    task_4_1(local_json_data_path=local_dir_path_for_json_files)
    task_4_2(local_json_data_path=local_dir_path_for_json_files)
    task_3_2_2_and_4_3(local_json_data_path=local_dir_path_for_json_files, is_frequency_reported=True)

    app = Flask(__name__)

    app.add_url_rule("/v1/cve/backend/<task>",
                     view_func=backend_controller.BackEndDataController.
                     as_view("cve_nvd_analysis_critical_infrastructure_backend",
                             local_dir_path_for_json_files))
    app.run(host='0.0.0.0', port=8081, ssl_context='adhoc')
