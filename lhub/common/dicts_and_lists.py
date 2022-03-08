import ast
import json


def to_dict_recursive(obj, track_changes=False):
    to_dict_recursive.step_count = 0
    to_dict_recursive.changes = []

    def _crawl_nested_objects(_obj, _track_changes=False):
        to_dict_recursive.step_count += 1

        if type(_obj) is bytes:
            _obj = _obj.decode('utf-8')

        # First try strings as json
        if type(_obj) is str:
            try:
                _new = json.loads(_obj)
            except:
                pass
            else:
                if _new != _obj:
                    if _track_changes:
                        to_dict_recursive.changes.append({"change": "string changed by json.loads", "original": _obj})
                    _obj = _new

        # if still a string, try it with ast
        if type(_obj) is str:
            try:
                _new = ast.literal_eval(_obj)
            except (ValueError, TypeError, SyntaxError):
                return _obj
            else:
                if _track_changes:
                    to_dict_recursive.changes.append({"change": "string changed by ast", "original": _obj})
                _obj = _new

        # Tried only crawling if entries are strings, but if an entry is a dict or a list
        # and *its* entries need fixing then it doesn't work, so reanalyze all entries.
        if isinstance(_obj, list) or isinstance(_obj, tuple):
            _obj = [_crawl_nested_objects(entry, _track_changes) for entry in _obj]
        elif isinstance(_obj, dict):
            _obj = {k: _crawl_nested_objects(_obj[k], _track_changes) for k in _obj.keys()}

        return _obj

    return _crawl_nested_objects(_obj=obj, _track_changes=track_changes)


# Sort dicts and lists recursively with a self-calling function
def sort_dicts_and_lists(input_value):
    _output = input_value
    # If the object is not a list or a dict, just return the value
    if type(_output) not in (list, dict):
        return _output
    if isinstance(_output, dict):
        # Crawl and sort dict values before sorting the dict itself
        _output = {k: sort_dicts_and_lists(v) for k, v in _output.items()}
        # Sort dict by keys
        _output = {k: _output[k] for k in sorted(_output.keys())}
    elif isinstance(_output, list):
        # Crawl and sort list values before sorting the list itself
        _output = [sort_dicts_and_lists(val) for val in _output]
        try:
            # Try to simply sort the list (will fail if entries are dicts or nested lists)
            _output = sorted(_output)
        except TypeError:
            # Map string versions of entries to their real values
            temp_map_input_as_strings = {}
            for k in _output:
                try:
                    temp_map_input_as_strings[json.dumps(k)] = k
                except:
                    temp_map_input_as_strings[str(k)] = k

            # Sort real values by their string versions
            _output = [temp_map_input_as_strings[k] for k in sorted(temp_map_input_as_strings.keys())]
    return _output
