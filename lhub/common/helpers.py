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


@dispatch(Number)
def format_batch_id(var):
    return int(var)


@dispatch(str)
def format_batch_id(var):
    return __id_string_to_int(var, formatting.InvalidBatchIdFormat(input_var=var))


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
def format_connection_id(var):
    return int(var)


@dispatch(str)
def format_connection_id(var):
    return __id_string_to_int(var, formatting.InvalidConnectionIdFormat(input_var=var))


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


@dispatch(dict)
def format_stream_id(var):
    stream_id = None
    if var.get("streamId"):
        stream_id = var['streamId']
    elif var.get('id'):
        stream_id = var['id']
        if isinstance(stream_id, dict):
            stream_id = stream_id.get('id')
    if not stream_id:
        raise formatting.InvalidStreamIdFormat(input_var=var)
    return format_stream_id(stream_id)


@dispatch(list)
def format_stream_id(var):
    ordered_distinct_streams = []
    for s in [format_stream_id(v) for v in var]:
        if s not in ordered_distinct_streams:
            ordered_distinct_streams.append(s)
    return ordered_distinct_streams


@dispatch(Number)
def format_user_id(var):
    return int(var)


@dispatch(str)
def format_user_id(var):
    return __id_string_to_int(var, formatting.InvalidUserIdFormat(input_var=var))


@dispatch(dict)
def format_user_id(var):
    return format_user_id(var.get('userId'))


@dispatch(Number)
def format_user_group_id(var):
    return int(var)


@dispatch(str)
def format_user_group_id(var):
    return __id_string_to_int(var, formatting.InvalidUserIdFormat(input_var=var))


@dispatch(dict)
def format_user_group_id(var):
    return format_user_group_id(var.get('usersGroupId'))


@dispatch(Number)
def format_version(var):
    return str(var)


@dispatch(str)
def format_version(var):
    if re.match(r'^m?\d+\.\d+$', var):
        return var.replace('m', '')
    else:
        raise formatting.InvalidVersionFormat(input_var=var)


@dispatch(dict)
def format_version(var):
    return format_version(var["version"])


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
