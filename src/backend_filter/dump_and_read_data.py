import json
import os

from backend_filter import test_sqlite3


class DumpFilterAndRead:

    def __init__(self):
        pass

    @staticmethod
    def dump_file(task_number, data):
        file_path_name = os.getcwd() + '/json_data/' + task_number + ".json"
        # Dump the dictionary to a JSON file
        with open(file_path_name, 'w') as json_file:
            json.dump(data, json_file)

        test_sqlite3.insert_data_in_sqlite(task=task_number, data=data)

    @staticmethod
    def read_file(task_number, range=None):
        # Specify the path to the JSON file
        file_path_name = os.getcwd() + '/json_data/' + task_number + ".json"
        if not os.path.exists(file_path_name):
            return {}
        # os.makedirs(file_path_name)
        # Read the JSON file and load it into a dictionary
        with open(file_path_name, 'r') as json_file:
            loaded_data = json.load(json_file)
        if loaded_data:
            test_sqlite3.insert_data_in_sqlite(task=task_number, data=loaded_data)
        loaded_data = test_sqlite3.read_from_database(task=task_number, range=range)
        return loaded_data

    @staticmethod
    def check_if_data_present(task_number, year_range: list = None, expressions: tuple = None):
        data = DumpFilterAndRead.read_file(task_number)
        if year_range and data:
            print(year_range)
            if len(year_range) == 0:
                str_range = int(year_range.split("-")[0])
                end_range = int(year_range.split("-")[0])
            else:
                str_range = int(year_range.split("-")[0])
                end_range = int(year_range.split("-")[1])
            if str_range in data and end_range in data:
                return True
            else:
                False
        elif data:
            return DumpFilterAndRead.__check_expressions_present(expressions=expressions, data=data)
        else:
            return False

    @staticmethod
    def __check_expressions_present(expressions, data):
        missing_expressions = []
        for express in expressions:
            if express not in data:
                missing_expressions.append(express)
        return True if not missing_expressions else missing_expressions
