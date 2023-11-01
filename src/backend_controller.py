import os

from flask import request, render_template, jsonify
from flask.views import MethodView

from backend_filter.dump_and_read_data import DumpFilterAndRead
from task_functions import task_3_1, task_3_2, task_3_2_2_and_4_3, task_4_1, task_4_2


class BackEndDataController(MethodView):
    def __init__(self, local_dir_path_for_json_files):
        self.__local_file_paths: str = local_dir_path_for_json_files
        # self.__args = args

    def get(self, task):
        year = request.args.get('Year') if request.args.get('Year') else "2023"
        range = request.args.get('Range') if request.args.get('Range') else "2002-2020"
        select_id = request.args.get('SelectID') if request.args.get('SelectID') else "3,9,10"
        expr = request.args.get('expr') if request.args.get('expr') else ""
        sub_expr = request.args.get('sub_expr') if request.args.get('sub_expr') else ""
        params = {'Year': year, 'Range': range, 'SelectID': select_id}
        local_file_path = self.__local_file_paths
        print(task)
        print(range)
        if task == "3.1":
            task_3_1(local_json_data_path=local_file_path, args=params)
            return jsonify(DumpFilterAndRead.read_file("3_1", range=range))
        elif task == "3.2":
            task_3_2(local_json_data_path=local_file_path, expr=expr)
            return jsonify((DumpFilterAndRead.read_file("3_2")))
        elif task == "3.2.cvss":
            task_3_2_2_and_4_3(local_json_data_path=local_file_path, expr=expr)
            return jsonify(DumpFilterAndRead.read_file("task_3_2_2_and_4_3"))
        elif task == "4.1":
            task_4_1(local_json_data_path=local_file_path, expr=expr)
            return jsonify(DumpFilterAndRead.read_file("4_1"))
        elif task == "4.2":
            task_4_2(local_json_data_path=local_file_path, expr=expr, sub_expr=sub_expr)
            dict_1 = DumpFilterAndRead.read_file("4_2")
            dict_2 = DumpFilterAndRead.read_file("4_2_sub_exp")
            return jsonify(dict1=dict_1, dict2=dict_2)
        elif task == "4.3":
            task_3_2_2_and_4_3(local_json_data_path=local_file_path, is_frequency_reported=True, expr=expr)
            return jsonify(DumpFilterAndRead.read_file("task_3_2_2_and_4_3"))