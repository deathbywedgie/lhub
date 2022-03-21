from ..exceptions import formatting
import re
import json
from multipledispatch import dispatch
from numbers import Number


def __id_string_to_int(var: str, lh_format_exception: formatting.BaseFormatError):
    var = var.strip()
    if not re.match(r'^(?:\S+-)?\d+$', var):
        raise lh_format_exception
    return int(re.search(r'\d+', var).group())


@dispatch(Number)
def format_alert_id(var):
    return int(var)


@dispatch(str)
def format_alert_id(var):
    return __id_string_to_int(var, formatting.InvalidAlertIdFormat(input_var=var))


# ToDo Put this to use in api & lhub
@dispatch(Number)
def format_case_id(var):
    return int(var)


# ToDo Add one for a dict in the format of {"key": "notebook", "id": int} (whatever is the equivalent for cases)
@dispatch(str)
def format_case_id(var):
    return __id_string_to_int(var, formatting.InvalidCaseIdFormat(input_var=var))


def format_case_id_with_prefix(case_id, case_prefix):
    return f"{case_prefix}-{format_case_id(case_id)}"


@dispatch(Number)
def format_notebook_id(var):
    return int(var)


@dispatch(str)
def format_notebook_id(var):
    return __id_string_to_int(var, formatting.InvalidNotebookIdFormat(input_var=var))


@dispatch(dict)
def format_notebook_id(var):
    # In case a raw notebook object is passed, drill into the 'id' field for the part we need
    if isinstance(var.get('id'), dict):
        return format_notebook_id(var['id'])
    if not var.get('id') or not var.get('key'):
        raise formatting.InvalidNotebookIdFormat(input_var=json.dumps(var))
    return int(var.get('id'))


def format_notebook_ids(var_list):
    if not isinstance(var_list, list):
        var_list = [var_list]
    return [{'key': 'notebook', 'id': format_notebook_id(var)} for var in var_list]


@dispatch(Number)
def format_playbook_id(var):
    return int(var)


@dispatch(str)
def format_playbook_id(var):
    return __id_string_to_int(var, formatting.InvalidPlaybookIdFormat(input_var=var))


@dispatch(Number, Number)
def format_rule_score(score, round_points=None):
    score = float(score)
    round_points = int(round_points)
    if not 0 <= score <= 10:
        raise formatting.InvalidRuleScore
    if round_points:
        score = round(score, round_points)
    return score


@dispatch(Number)
def format_rule_set_id(var):
    return int(var)


@dispatch(str)
def format_rule_set_id(var):
    return __id_string_to_int(var, formatting.InvalidRuleSetIdFormat(input_var=var))


@dispatch(Number)
def format_stream_id(var):
    return int(var)


@dispatch(str)
def format_stream_id(var):
    return __id_string_to_int(var, formatting.InvalidStreamIdFormat(input_var=var))


def sanitize_input_rule_field_mappings(field_mappings):
    if not isinstance(field_mappings, dict):
        try:
            field_mappings = json.loads(field_mappings)
        except Exception:
            raise formatting.InvalidRuleFormat(input_var=field_mappings)
    if not field_mappings:
        raise formatting.InvalidRuleFormat(input_var=field_mappings)
    return field_mappings


def sort_notebook_objects_by_id(notebooks):
    return sorted(notebooks, key=lambda x: (x['id']['id']))
