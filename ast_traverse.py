import ast
from classes.multi_label import MultiLabel
from classes.nodes import *

def convert_ast_dict_to_objects(ast_dict):
    if ast_dict["ast_type"] == "Module":
        return [convert_ast_dict_to_objects(node) for node in ast_dict["body"]]
    
    elif ast_dict["ast_type"] == "Name":
        return Name(ast_dict["id"])

    elif ast_dict["ast_type"] == "Constant":
        return Constant(ast_dict["value"])
    
    elif ast_dict['ast_type'] == "Assign":
        target = convert_ast_dict_to_objects(ast_dict["targets"][0])
        value = convert_ast_dict_to_objects(ast_dict["value"])
        return Assign(target, value)
    
    elif ast_dict['ast_type'] == "Expr":
        expr = convert_ast_dict_to_objects(ast_dict["value"])
        return Expr(expr)

    elif ast_dict["ast_type"] == "Call":
        func = convert_ast_dict_to_objects(ast_dict["func"])
        args = [convert_ast_dict_to_objects(arg) for arg in ast_dict["args"]]
        return Call(func, args)

    elif ast_dict['ast_type'] == "BinOp":
        left = convert_ast_dict_to_objects(ast_dict["left"])
        op = ast_dict["op"]['ast_type']
        right = convert_ast_dict_to_objects(ast_dict["right"])
        return BinOp(left,op,right)
    
    elif ast_dict["ast_type"] == "Attribute":
        value = convert_ast_dict_to_objects(ast_dict["value"])
        return Attribute(value, Name(ast_dict["attr"]))
    
    elif ast_dict["ast_type"] == "Compare":
        left = convert_ast_dict_to_objects(ast_dict["left"])
        ops = [op["ast_type"] for op in ast_dict["ops"]]
        comparators = [convert_ast_dict_to_objects(comp) for comp in ast_dict["comparators"]]
        return Compare(left, ops, comparators)

    elif ast_dict["ast_type"] == "If":
        test = convert_ast_dict_to_objects(ast_dict["test"])
        body = [convert_ast_dict_to_objects(node) for node in ast_dict["body"]]
        orelse = [convert_ast_dict_to_objects(node) for node in ast_dict["orelse"]]
        return If(test, body, orelse)
    
    elif ast_dict["ast_type"] == "While":
        test = convert_ast_dict_to_objects(ast_dict["test"])
        body = [convert_ast_dict_to_objects(node) for node in ast_dict["body"]]
        return While(test, body)
    
    elif ast_dict["ast_type"] == "UnaryOp":
        op = convert_ast_dict_to_objects(ast_dict["op"])
        operand = convert_ast_dict_to_objects(ast_dict["operand"])
        return UnaryOp(op, operand)
    
    elif ast_dict["ast_type"] == "UAdd":
        return UAdd()
    
    elif ast_dict["ast_type"] == "USub":
        return USub()
    
    elif ast_dict["ast_type"] == "Not":
        return Not()
    
    elif ast_dict["ast_type"] == "Invert":
        return Invert()

    elif ast_dict["ast_type"] == "BoolOp":
        op = convert_ast_dict_to_objects(ast_dict["op"])
        left = convert_ast_dict_to_objects(ast_dict["values"][0])
        right = convert_ast_dict_to_objects(ast_dict["values"][1])
        values= [left,right]
        return BoolOp(op, values)
    
    elif ast_dict["ast_type"] == "And":
        return And()
    
    elif ast_dict["ast_type"] == "Or":
        return Or()