import configparser
from collections import OrderedDict
import json

class MultiOrderedDict(OrderedDict):
    def __setitem__(self, key, value):
        if key in self:
            if isinstance(value, list):
                self[key].extend(value)
        else:
            super(MultiOrderedDict, self).__setitem__(key, value)

class JsonConfigParser():
    def __init__(self, config_path, json_path):
        self.__config = configparser.ConfigParser(dict_type=MultiOrderedDict, interpolation=None, empty_lines_in_values=False, allow_no_value=False, strict=False)
        self.__config.read([config_path])

        with open(json_path) as j:
            self.__json = json.load(j)

    def parse_section(self, section_name):
        self.__parsed = dict()
        
        # Loop over each key within the section.
        for property in self.__config.items(section_name):
            # Set each property to a blank list.
            if property[0] not in self.__parsed:
                self.__parsed[property[0]] = []
                
            # Loop over each value for the key.
            for value in property[1]:
                # If there is a "," in the value, assume it is a JSON path.
                # Otherwise, just load the value directly.
                if "," in value:
                    value_list = value.split(",")
                    # Remove any blank elements from the value_list. This is needed
                    # if any of the JSON paths in the config file have a trailing ","
                    # to denote that we want to parse a top-level JSON key. Without the
                    # trailing comma, the code would assume it is not a JSON path but
                    # rather a normal string value.
                    value_list = [x for x in value_list if x]
                    result = self.__safe_parse(self.__json, value_list)
                    if result:
                        self.__parsed[property[0]].append(result)
                else:
                    self.__parsed[property[0]].append(value)
                        
    def get_value(self, key):
        results = []
        if key in self.__parsed:
            results.extend(self.__parsed[key])

        if len(results) == 1:
            return results[0]
        else:
            return results

    def __safe_parse(self, json_dict, json_keys, error=None):
        for key in json_keys:
            try:
                json_dict = json_dict[key]
            except KeyError:
                return error
            except TypeError:
                return error
        return json_dict