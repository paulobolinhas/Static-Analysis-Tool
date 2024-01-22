import ast
import json
import os
import sys

from numpy import cumsum
from format_output import format_illegal_flows
from classes.label import Label
from astexport import export
from classes.multi_label import MultiLabel
from classes.multi_labelling import MultiLabelling
from classes.nodes import *
from classes.pattern import Pattern
from classes.policy import Policy
from classes.nodes import If

from ast_traverse import convert_ast_dict_to_objects
from classes.vulnerabilities import Vulnerabilities

def perform_static_analysis(ast_tree, patterns):

    policies = Policy(patterns)

    currentLine = 0

    array_multilabelling = []
    multilabelling = MultiLabelling()
    array_multilabelling.append(multilabelling)

    vulnerabilities = Vulnerabilities()

    for line in ast_tree:
        currentLine += 1
        for multilabelling in array_multilabelling:
            if isinstance(line, If) or isinstance(line, While):
                temp_array_multilabelling, newCurrentLine = line.eval(policies, multilabelling, array_multilabelling, vulnerabilities, currentLine) # passar sempre uma multilabel vazia e retornar a multilabel atualizada
            else:
                line.eval(policies, multilabelling, vulnerabilities, currentLine)
                temp_array_multilabelling = array_multilabelling
                newCurrentLine = currentLine

            if not (isinstance(line, Assign) and isinstance(line.name, Attribute)):
                Name.nonDeclared = []
        
        currentLine = newCurrentLine

        array_multilabelling = temp_array_multilabelling

    return vulnerabilities

def init_analyzer(slice_filename, patterns_filename):

    # slice
    with open(slice_filename, 'r') as slice_file:
        slice_code = slice_file.read()
        ast_tree = ast.parse(slice_code)
        ast_dict = export.export_dict(ast_tree)
        ast_json = json.dumps(ast_dict, indent = 4) # formatted

        converted_ast = convert_ast_dict_to_objects(ast_dict)

    # pattern
    with open(patterns_filename, 'r') as patterns_file:
        patterns_json = json.load(patterns_file)

    patterns = []
    for data in patterns_json:
        name = data.get('vulnerability', '')
        sources = data.get('sources', [])
        sanitizers = data.get('sanitizers', [])
        sinks = data.get('sinks', [])
        implicit = data.get('implicit', '')

        instance = Pattern(name, sources, sanitizers, sinks, implicit)
        patterns.append(instance)

    vulnerabilities = perform_static_analysis(converted_ast, patterns)

    # List to store dictionaries representing IllegalFlow objects
    illegal_flows_json = []

    # Assuming vulnerabilities.illegalFlows is a list of IllegalFlow objects
    for illegal_flow in vulnerabilities.illegalFlows:
        illegal_flow_dict = illegal_flow.getIllegalFlowDict()
        illegal_flows_json.append(illegal_flow_dict)

    # Format
    formatted_output = format_illegal_flows(illegal_flows_json)

    # Save to JSON file
    output_filename = f'./output/{slice_filename.split("/")[1]}.output.json'
    with open(output_filename, 'w') as output_file:
        output_file.write(formatted_output)

def main():
    if len(sys.argv) != 3:
        print("Usage: python py_analyser.py <slice_file.py> <patterns_file.json>")
        sys.exit(1)

    # RUN - do this on bash
    slice_filename = sys.argv[1]
    patterns_filename = sys.argv[2]

    init_analyzer(slice_filename, patterns_filename)

if __name__ == "__main__":
    main()
