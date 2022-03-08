from ..exceptions import InvalidNotebookIdFormat


def format_notebook_ids(notebook_ids):
    if not isinstance(notebook_ids, list):
        notebook_ids = [notebook_ids]
    final_notebooks = []
    for input_value in notebook_ids:
        if isinstance(input_value, dict):
            # In case a raw notebook object is passed, drill into the 'id' field for the part we need
            if isinstance(input_value, dict) and isinstance(input_value.get('id'), dict):
                input_value = input_value['id']
            if not input_value or 'id' not in input_value.keys() or not isinstance(input_value['id'], (int, str)):
                raise InvalidNotebookIdFormat(input_value)
            final_notebooks.append({'key': 'notebook', 'id': int(input_value['id'])})
        else:
            try:
                final_notebooks.append({'key': 'notebook', 'id': int(input_value)})
            except (ValueError, TypeError):
                raise InvalidNotebookIdFormat(input_value)
    return final_notebooks
