from lhub import exceptions
import re
import json


def format_alert_id(alert_id):
    if isinstance(alert_id, str):
        if not re.match(r'^(?:alert-)?\d+$', alert_id):
            raise exceptions.Formatting.InvalidAlertIdFormat(alert_id)
        alert_id = re.sub(r'\D+', '', alert_id)
    return int(alert_id)


def format_case_id_with_prefix(case_id, case_prefix):
    if not case_id and not str(case_id).strip():
        raise ValueError("Case ID cannot be blank")
    case_id = str(case_id).strip()
    if '-' not in case_id:
        case_id = f"{case_prefix}-{case_id}"
    return case_id


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
                raise exceptions.Formatting.InvalidNotebookIdFormat(input_value)
            final_notebooks.append({'key': 'notebook', 'id': int(input_value['id'])})
        else:
            try:
                final_notebooks.append({'key': 'notebook', 'id': int(input_value)})
            except (ValueError, TypeError):
                raise exceptions.Formatting.InvalidNotebookIdFormat(input_value)
    return final_notebooks


def format_playbook_id(playbook_id):
    if isinstance(playbook_id, str):
        if not re.match(r'^(?:flow-)?\d+$', playbook_id):
            raise exceptions.Formatting.InvalidPlaybookIdFormat(playbook_id)
        playbook_id = re.sub(r'\D+', '', playbook_id)
    return int(playbook_id)


def format_stream_id(alert_id):
    if isinstance(alert_id, str):
        if not re.match(r'^(?:stream-)?\d+$', alert_id):
            raise exceptions.Formatting.InvalidStreamIdFormat(alert_id)
        alert_id = re.sub(r'\D+', '', alert_id)
    return int(alert_id)


def sanitize_input_rule_field_mappings(field_mappings):
    if not isinstance(field_mappings, dict):
        try:
            field_mappings = json.loads(field_mappings)
        except Exception:
            raise exceptions.Formatting.InvalidRuleFormat(field_mappings)
    if not field_mappings:
        raise exceptions.Formatting.InvalidRuleFormat(field_mappings)
    return field_mappings


def sanitize_input_rule_score(score, round_points: int = None):
    try:
        score = float(score)
        assert 0 <= score <= 10
    except (ValueError, TypeError, AssertionError):
        raise ValueError("Score must be a number between 0 and 10")
    if round_points:
        score = round(score, round_points)
    return score


def sanitize_input_rule_set_id(rule_set_id):
    if isinstance(rule_set_id, int):
        return rule_set_id
    rule_set_num_str = re.sub(r'\D+', '', str(rule_set_id))
    if not rule_set_num_str:
        raise ValueError("Invalid rule set ID")
    return int(rule_set_num_str)


def sort_notebook_objects_by_id(notebooks):
    return sorted(notebooks, key=lambda x: (x['id']['id']))
