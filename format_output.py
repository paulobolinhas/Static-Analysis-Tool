import json
from io import StringIO

def format_illegal_flows(illegal_flows):
    output_string = StringIO()

    output_string.write("[\n")
    for idx, illegal_flow_dict in enumerate(illegal_flows):
        output_string.write("    {\n")
        for key, value in illegal_flow_dict.items():
            if isinstance(value, list):
                # Format lists in a single line without line breaks and with double quotes for strings
                formatted_value = json.dumps(value).replace("'", '"')
                output_string.write(f'        "{key}": {formatted_value},\n')
            else:
                # Format non-list values with indentation
                formatted_value = json.dumps(value, indent=4)
                output_string.write(f'        "{key}": {formatted_value},\n')

        # Remove the trailing comma if it's not the last dictionary in the list
        if idx != len(illegal_flows) - 1:
            output_string.seek(output_string.tell() - 2)
            output_string.write("\n")
        else:
            # If it's the last dictionary, remove the trailing comma and newline
            output_string.seek(output_string.tell() - 2)

        output_string.write("    }" if idx == len(illegal_flows) - 1 else "    },\n")

    output_string.write("\n]\n")

    formatted_output = output_string.getvalue()
    output_string.close()

    return formatted_output
