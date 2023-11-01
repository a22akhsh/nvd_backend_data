from backend_filter.analyse import CveNvdAnalysis
from backend_filter.dump_and_read_data import DumpFilterAndRead


def task_3_1(local_json_data_path, args: dict = None):
    """
    # task-3.1 part 2: Choose three CVE entries and write the code to extract their respective CWE IDs
    # and one entry in the list of the problem type description. Report with a brief explanation your
    # understanding of the described problems.
    """
    # cve_dict = CveNvdAnalysis.create_nvd_for_specific_year_dict(year=args['Year'],
    #                                                            json_files_path=local_json_data_path,
    #                                                            selection_ids=args['SelectID'].split(","))
    """
    # task-3.1 part 1: Show graphically the scale of reported vulnerabilities from 2002 until 2020.
    # Use the provided python scripts to obtain the data that you will report graphically.
    # Write a brief comment summarizing your observation.
    """
    cve_year_basis_vul = {}
    total_reported = 0
    if not DumpFilterAndRead.check_if_data_present("3_1", args['Range']):
        for year, total_vul, cve_dict in \
                CveNvdAnalysis.create_and_analyze_nvd_for_range_year_dict(year_range=args['Range'] if args else "2002"
                                                                                                                "-2023",
                                                                          json_files_path=local_json_data_path):
            cve_year_basis_vul[year] = total_vul
            total_reported += total_vul
        DumpFilterAndRead.dump_file("3_1", cve_year_basis_vul)


def task_3_2(local_json_data_path, expr: str = ""):
    """
    RTU, PLC, HMI, MTU
    – Report graphically the scale of vulnerability instances for each of the
    following CPS component types: RTU, PLC, HMI, MTU, across all years.
    :param expr:
    :param local_json_data_path:
    :return:
    """
    expressions: tuple = ("RTU", "PLC", "HMI", "MTU")
    if expr:
        expressions: tuple = merge_and_remove_duplicates(("RTU", "PLC", "HMI", "MTU"), tuple(expr.split(",")))
    checked_data = DumpFilterAndRead.check_if_data_present(task_number='3_2', expressions=expressions)
    if type(checked_data) is list and len(checked_data) > 0:
        expressions = expand_tupple_expressions(expressions, checked_data)
        checked_data = False
        print(expressions)
    if not checked_data:
        extract_data_and_save(expressions, local_json_data_path, task_number="3_2")


def task_4_1(local_json_data_path, expr: str = ""):
    """
    Task 4.1: Threats Instances –Use the above search description()
    function to identify the following exploiting threats: overflow,
    denial of service, sql injection, Cross-Site, memory corruption.
    Propose a brief description of each of these threat instances and
    visualize graphically in a chart the number of vulnerability report
    instances corresponding to each of these threats.
    Hint: search description for threat types. Discuss briefly the resulting graphic
    :param expr:
    :param local_json_data_path:
    :return:
    """
    expressions = ("overflow", "denial of service", "sql injection", "Cross-Site", "memory corruption")
    if expr:
        expressions: tuple = merge_and_remove_duplicates(expressions, tuple(expr.split(",")))
    checked_data = DumpFilterAndRead.check_if_data_present(task_number='4_1', expressions=expressions)
    if type(checked_data) is list and len(checked_data) > 0:
        expressions = expand_tupple_expressions(expressions, checked_data)
        checked_data = False
        print(expressions)
    if not checked_data:
        extract_data_and_save(expressions, local_json_data_path, task_number="4_1")


def task_4_2(local_json_data_path, expr: str = "", sub_expr: str = ""):
    """
    Task 4.2: CPS threats –Correlate the above threat instances agains CPS vulnerabilities to
    visualize threats that apply only to CPS components. Discuss the results.
    You may utilise the functions shown below, or implement your own code.
    :param sub_expr:
    :param expr:
    :param local_json_data_path:
    :return:
    """
    root_expressions: tuple = ("RTU", "PLC", "HMI", "MTU")
    if expr:
        root_expressions: tuple = merge_and_remove_duplicates(root_expressions, tuple(expr.split(",")))
    correlation_expression: tuple = ("overflow", "denial of service", "sql injection", "Cross-Site",
                                     "memory corruption")
    if sub_expr:
        correlation_expression: tuple = merge_and_remove_duplicates(correlation_expression, tuple(sub_expr.split(",")))
    checked_data = DumpFilterAndRead.check_if_data_present(task_number="4_2", expressions=root_expressions)
    checked_data_sub = DumpFilterAndRead.check_if_data_present(task_number="4_2_sub_exp",
                                                               expressions=correlation_expression)
    if type(checked_data) is list and len(checked_data) > 0:
        root_expressions = expand_tupple_expressions(root_expressions, checked_data)
        checked_data = False
        print(root_expressions)
    print(checked_data_sub == correlation_expression)
    print(checked_data_sub)
    print(correlation_expression)
    if type(checked_data_sub) is list and len(checked_data_sub) > 0 and \
            tuple(checked_data_sub) != correlation_expression:
        correlation_expression = expand_tupple_expressions(correlation_expression, checked_data_sub)
        checked_data_sub = False
        print(correlation_expression)
    if not checked_data or not checked_data_sub:
        extract_data_and_save(root_expressions, local_json_data_path,
                              sub_expressions=correlation_expression, task_number="4_2")


def task_3_2_2_and_4_3(local_json_data_path, is_frequency_reported=False, expr: str = ""):
    """
    Task 3.2 (Part-2)
    – Compute the average CVSS scores for each of the above CPS component types, and briefly summarize your observations

    Task 4.3: Others –Propose any other interesting data correlation and a related graphical visualization along
    with a brief explanation.

    :param expr:
    :param local_json_data_path:
    :param is_frequency_reported:
    :return:
    """
    expressions: tuple = ("RTU", "PLC", "HMI", "MTU")
    if expr:
        expressions: tuple = merge_and_remove_duplicates(expressions, tuple(expr.split(",")))
    checked_data = DumpFilterAndRead.check_if_data_present(task_number="task_3_2_2_and_4_3", expressions=expressions)
    if type(checked_data) is list and len(checked_data) > 0:
        expressions = expand_tupple_expressions(expressions, checked_data)
        checked_data = False
        print(expressions)
    if not checked_data:
        cvss_data = extract_data_and_save(expressions, local_json_data_path, is_cvss_score=True)
        # PlotCveNvdGraphs.draw_plotify_based_graph(cvss_data, "CVSS Score Stats", sub_expressions=None,
        # is_cvss_score=True, is_frequency_report=is_frequency_reported)

        DumpFilterAndRead.dump_file(task_number="task_3_2_2_and_4_3", data=cvss_data)


def expand_tupple_expressions(root_expr, new_express):
    return tuple(list(root_expr) + new_express)


def extract_data_and_save(expressions, local_json_data_path, sub_expressions=None,
                          is_cvss_score: bool = False, task_number=None):
    extra_comparison = {}
    cvss_data = {}
    component_vuln = {}
    for expr in expressions:
        year_basis_report, list_of_reports, cvss_score, sub_expression_report = CveNvdAnalysis.search_description \
            (expr, local_json_data_path, correlation_expression=sub_expressions)

        component_vuln[expr] = year_basis_report
        cvss_data[expr] = cvss_score
        if sub_expressions:
            extra_comparison[expr] = sub_expression_report

    if not is_cvss_score:
        #    PlotCveNvdGraphs.draw_plotify_based_graph(component_vuln, "Vulnerabilities reported",
        #                                              sub_expressions=extra_comparison)
        DumpFilterAndRead.dump_file(task_number=task_number, data=component_vuln)
        if sub_expressions:
            DumpFilterAndRead.dump_file(task_number=task_number + '_sub_exp', data=extra_comparison)
    else:
        return cvss_data


def merge_and_remove_duplicates(express1, express2):
    merged_set = set(express1).union(express2)
    merged_tuple = tuple(merged_set)
    return merged_tuple
