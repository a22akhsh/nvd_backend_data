import os
import sqlite3
import ast


def insert_data_in_sqlite(task, data):
    db_file = os.getcwd() + '/sqlite_db/' + task + "_database.db"

    # Create a connection to the SQLite database (or create it if it doesn't exist)
    conn = sqlite3.connect(db_file)

    # Create a cursor object to interact with the database
    cursor = conn.cursor()
    create_table_string = '''CREATE TABLE IF NOT EXISTS dictionary_data (
                      key TEXT PRIMARY KEY,
                      value TEXT
                    )'''.replace('dictionary_data', 'data_table_' + task)
    # Create a table named 'my_table' with columns 'id', 'name', and 'value'
    cursor.execute(create_table_string)
    insert_into_table = 'INSERT OR IGNORE INTO dictionary_data (key, value) VALUES (?, ?)'. \
        replace('dictionary_data', 'data_table_' + task)
    # Insert the data from the dictionary into the table
    for key, value in data.items():
        print(key)
        print(value)
        if not key:
            key = "Total"
        if not value:
            value = "None"
        cursor.execute(insert_into_table, (key, str(value)))

    # Commit the changes and close the database connection
    conn.commit()
    conn.close()


def read_from_database(task, range: str = None):
    # Connect to the SQLite database
    conn = sqlite3.connect(os.getcwd() + '/sqlite_db/' + task + "_database.db")
    cursor = conn.cursor()

    # Retrieve data from the table
    if range:
        select_table_command: str = 'SELECT key, value FROM ' + 'data_table_' + task + ' WHERE key BETWEEN ' \
                                    + range.split("-")[0] + ' AND ' + range.split("-")[1]
    else:
        select_table_command: str = 'SELECT key, value FROM ' + 'data_table_' + task
    cursor.execute(select_table_command)
    rows = cursor.fetchall()

    # Convert the data to a dictionary
    data_dict = {}
    for row in rows:
        key, value = row
        if is_valid_dict_string(value):
            value = ast.literal_eval(value)
        data_dict[key] = value

    # Print the dictionary
    return data_dict

    # Close the database connection
    conn.close()


def is_valid_dict_string(input_string):
    try:
        # Attempt to convert the input string to a dictionary
        ast.literal_eval(input_string)
        return True
    except (SyntaxError, ValueError):
        return False
