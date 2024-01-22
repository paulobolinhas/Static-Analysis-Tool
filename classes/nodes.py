from ast import Mult
from audioop import mul
from os import name

from numpy import source
from classes.sanitizer import Sanitizer
from classes.illegalFlow import IllegalFlow
from classes.multi_label import MultiLabel
from classes.label import Label
from classes.policy import Policy
from classes.source import Source
from classes.multi_labelling import MultiLabelling

class Constant:
    def __init__(self, value):
        self.value = value

    def __repr__(self):
        return f"Constant({self.value})"
    
    def eval(self, policies, multilabelling, vulnerabilities, currentLine):

        return MultiLabel(policies.getPatterns())  
          
    def isConstant(obj):
        return isinstance(obj, Constant)

class Name:
    nonDeclared = [] # class variable

    def __init__(self, name):
        self.name = name

    def __repr__(self):
        return f"Name({self.name})"
    
    def eval(self, policies, multilabelling, vulnerabilities, currentLine):

        multilabel = multilabelling.get_multilabel_by_name(self.name)
        currentMultilabel = None
        if (multilabel == None):
            currentMultilabel = MultiLabel(policies.getPatterns())  
        else:
            currentMultilabel = multilabel

        if policies.get_patterns_with_source(self.name) != [] or self.name in Name.nonDeclared:
            source = Source(self.name, currentLine) 
            label = Label((source, []))

            if self.name in Name.nonDeclared:
                for pattern in policies.getPatterns():
                    currentMultilabel.update_label(label, pattern.get_vulnerabilityName())
            else:
                for pattern in policies.get_patterns_with_source(self.name):
                    currentMultilabel.update_label(label, pattern.get_vulnerabilityName())

        return currentMultilabel
    
    @classmethod
    def wasNonDeclared(cls, variable):
        if variable in cls.nonDeclared:
            return True
        return False
    
    @classmethod
    def addNonDeclared(cls, variable, multilabelling):
        if variable not in multilabelling.getKeys() and variable not in cls.nonDeclared:
            cls.nonDeclared.append(variable)       

class Assign:
    def __init__(self, name, exp):
        self.name = name
        self.exp = exp

    def __repr__(self):
        return 'Assign(%s, %s)' % (self.name, self.exp)

    def eval(self, policies, multilabelling, vulnerabilities, currentLine):
        multiLabel = MultiLabel(policies.getPatterns())  

        expMultiLabel = self.exp.eval(policies, multilabelling, vulnerabilities, currentLine)

        multiLabel = multiLabel.combine_multiLabels(expMultiLabel)

        names = []

        if (isinstance(self.name, Name)):

            multilabelling.update_multilabel_by_name(self.name.name, multiLabel)
            names.append(self.name.name)
            
        elif isinstance(self.name, Attribute):

            attrMultilabel = self.name.eval(policies, multilabelling, vulnerabilities, currentLine)
            multiLabel = multiLabel.combine_multiLabels(attrMultilabel)

            Name.addNonDeclared(self.name.value.name, multilabelling)
            multilabelling.update_multilabel_by_name(self.name.value.name, multiLabel)
            multilabelling.update_multilabel_by_name(self.name.attr.name, multiLabel)

            names.append(self.name.attr.name)
            names.append(self.name.value.name)


        for name in names:
            patterns_with_sink = policies.get_patterns_with_sink(name)
            if len(patterns_with_sink) != 0:
                sink_multilabel = multilabelling.get_multilabel_by_name(name)
                for pattern in patterns_with_sink:
                    createIllegalFlow(name, currentLine, pattern, sink_multilabel, vulnerabilities)

class Call:
    def __init__(self, functionName, arguments):
        self.functionName = functionName
        self.arguments = arguments or []

    def __repr__(self):
        return 'Call(%s, %s)' % (self.functionName, self.arguments)
    
    def eval(self, policies, multilabelling, vulnerabilities, currentLine):

        multiLabel = MultiLabel(policies.getPatterns())  

        if (isinstance(self.functionName, Name)):
            currentFunctionName = self.functionName.name
        elif (isinstance(self.functionName, Attribute)):
            currentFunctionName = self.functionName.attr.name
            Name.addNonDeclared(self.functionName.value.name, multilabelling)

        nameMultiLabel = self.functionName.eval(policies, multilabelling, vulnerabilities, currentLine)
        multiLabel = multiLabel.combine_multiLabels(nameMultiLabel)
        
        patterns_with_sink = policies.get_patterns_with_sink(currentFunctionName)
        is_sink = bool(patterns_with_sink) 

        patterns_with_sanitizer = policies.get_patterns_with_sanitizer(currentFunctionName)
        is_sanitizer = bool(patterns_with_sanitizer)

        for argument in self.arguments:

            if (isinstance(argument, Name)):
                Name.addNonDeclared(argument.name, multilabelling)

            argument_multilabel = argument.eval(policies, multilabelling, vulnerabilities, currentLine)
            multiLabel = multiLabel.combine_multiLabels(argument_multilabel)

            if (is_sink):
                for pattern in patterns_with_sink:
                    createIllegalFlow(currentFunctionName, currentLine, pattern, argument_multilabel, vulnerabilities)  
            
            if(is_sanitizer):
                sanitizer = Sanitizer(currentFunctionName, currentLine)
                for pattern in patterns_with_sanitizer:
                        currentLabel = multiLabel.get_label_by_vulnerability(pattern.get_vulnerabilityName())
                        for tuple in currentLabel.getTuples():
                            if (sanitizer not in tuple[1]):
                                tuple[1].append(sanitizer)

        return multiLabel
    
class Expr:
    def __init__(self, expr):
        self.expr = expr

    def __repr__(self):
        return 'Expr(%s)' % (self.expr)

    def eval(self, policies, multilabelling, vulnerabilities, currentLine):
        multiLabel = MultiLabel(policies.getPatterns())  

        expMultiLabel = self.expr.eval(policies, multilabelling, vulnerabilities, currentLine)
        if isinstance(self.expr, Call):
            multilabelling.update_multilabel_by_name(self.expr.functionName.name, expMultiLabel)

        return multiLabel.combine_multiLabels(expMultiLabel)
    
class BinOp:
    def __init__(self, left, op, right):
        self.left = left
        self.op = op
        self.right = right

    def __repr__(self):
        return 'BinOp(%s, %s, %s)' % (self.op, self.left, self.right)

    def eval(self, policies, multilabelling, vulnerabilities, currentLine):

        multiLabel = MultiLabel(policies.getPatterns())  

        if isinstance(self.right, Name):
            Name.addNonDeclared(self.right.name, multilabelling)

        left_multilabel = self.left.eval(policies, multilabelling, vulnerabilities, currentLine)
        
        if isinstance(self.right, Name):
            Name.addNonDeclared(self.right.name, multilabelling)
        
        right_multilabel = self.right.eval(policies, multilabelling, vulnerabilities, currentLine)
         
        multiLabel = left_multilabel.combine_multiLabels(right_multilabel)

        return multiLabel

class Attribute:
    def __init__(self, value, attr):
        self.value = value
        self.attr = attr

    def getValue(self):
        return self.value
    
    def getAttr(self):
        return self.attr
    
    def __repr__(self):
        return f"Attribute({self.value}, {self.attr})"
    
    def eval(self, policies, multilabelling, vulnerabilities, currentLine):
        
        multilabel = MultiLabel(policies.getPatterns())

        valueMultilabel = self.value.eval(policies, multilabelling, vulnerabilities, currentLine)
        attrMultilabel = self.attr.eval(policies, multilabelling, vulnerabilities, currentLine)

        multilabel = valueMultilabel.combine_multiLabels(multilabel)
        multilabel = attrMultilabel.combine_multiLabels(multilabel)

        return multilabel
    
class Compare:
    def __init__(self, left, ops, comparators):
        self.left = left
        self.ops = ops
        self.comparators = comparators

    def __repr__(self):
        return f"Compare({self.left}, {self.ops}, {self.comparators})"
    
    def eval(self, policies, multilabelling, vulnerabilities, currentLine):

        if (isinstance(self.left, Name)):
            Name.addNonDeclared(self.left.name, multilabelling)

        left_multilabel = self.left.eval(policies, multilabelling, vulnerabilities, currentLine)

        if (isinstance(self.comparators[0], Name)):
            Name.addNonDeclared(self.comparators[0].name, multilabelling)

        comparators_multilabel = self.comparators[0].eval(policies, multilabelling, vulnerabilities, currentLine)
        multiLabel = left_multilabel.combine_multiLabels_implicit(comparators_multilabel)

        return multiLabel


class If:
    def __init__(self, test, body, orelse):
        self.test = test
        self.body = body
        self.orelse = orelse

    def __repr__(self):
        return f"If({self.test}, {self.body}, {self.orelse})"
    
    def eval(self, policies, multilabelling, array_multilabelling, vulnerabilities, currentLine):

        filtered = policies.get_implicit()
        implicit_multiLabel = self.test.eval(filtered, multilabelling, vulnerabilities, currentLine)

        array_multilabellingCloned = []
        for item in array_multilabelling:
            if item == multilabelling:
                elseMultilabbeling = item.clone()
                array_multilabellingCloned.append(elseMultilabbeling)
            else:
                array_multilabellingCloned.append(item.clone())
        
        
        bodyMultilabelling = multilabelling.clone()
        ifArray = []
        ifArray.append(bodyMultilabelling)

        hasIf = False
        for line in self.body:
            currentLine += 1

            if isinstance(line, If) or isinstance(line, While):
                temp_array_multilabelling, newCurrentLine = line.eval(policies, bodyMultilabelling, ifArray, vulnerabilities, currentLine) # passar sempre uma multilabel vazia e retornar a multilabel atualizada
                currentLine = newCurrentLine
                hasIf = True
            else:
                line.eval(policies, bodyMultilabelling, vulnerabilities, currentLine)
                temp_array_multilabelling = array_multilabellingCloned

            Name.nonDeclared = []
            array_multilabellingCloned = combine_array_multilabellings(array_multilabellingCloned, temp_array_multilabelling)

        if len(self.orelse) > 0:
            currentLine += 1
            for line in self.orelse:
                currentLine += 1
                if isinstance(line, If) or isinstance(line, While):
                    temp_array_multilabelling, newCurrentLine = line.eval(policies, elseMultilabbeling, array_multilabellingCloned, vulnerabilities, currentLine) # passar sempre uma multilabel vazia e retornar a multilabel atualizada
                    currentLine = newCurrentLine
                else:
                    line.eval(policies, elseMultilabbeling, vulnerabilities, currentLine)
                    temp_array_multilabelling = array_multilabellingCloned
                
                Name.nonDeclared = []

            
            array_multilabellingCloned = temp_array_multilabelling

        if (not hasIf):
            array_multilabellingCloned.append(bodyMultilabelling)


        if not implicit_multiLabel.isEmpty():
            new_keys = []
            for ml in array_multilabellingCloned: 
                new_keys.append(ml.getKeys())
            old_keys = []
            for ml in array_multilabelling:
                old_keys.append(ml.getKeys())

            diff_keys = []
            for set1 in old_keys:
                for key in set1:
                    for setOfKeys in new_keys:
                        for key2 in setOfKeys:
                            if (key != key2) and (key2 not in diff_keys) and (key2 not in set1):
                                diff_keys.append(key2)

            for a in array_multilabellingCloned:
                for key in diff_keys:
                    if key in a.getKeys():
                        a.labelling_map[key] = implicit_multiLabel

        return array_multilabellingCloned, currentLine
    
class While:
    def __init__(self, test, body):
        self.test = test
        self.body = body
    
    def __repr__(self):
        return f"While({self.test}, {self.body})"
    
    def eval(self, policies, multilabelling, array_multilabelling, vulnerabilities, currentLine):

        #filtered = policies.get_implicit()
        #implicit_multiLabel = self.test.eval(filtered, multilabelling, vulnerabilities, currentLine)

        isAlwaysTrue = False
        if isinstance(self.test, Constant) and self.test.value == True:
            isAlwaysTrue = True
        
        array_multilabellingCloned = [item.clone() for item in array_multilabelling]

        initLine = currentLine

        maxIter = 3
        i = 1
        while i <= maxIter:
            currentLine = initLine
            for line in self.body:
                currentLine += 1

                for mlabelling in array_multilabellingCloned:
                    if isinstance(line, If) or isinstance(line, While):
                        temp_array_multilabelling, newCurrentLine = line.eval(policies, mlabelling, array_multilabellingCloned, vulnerabilities, currentLine) # passar sempre uma multilabel vazia e retornar a multilabel atualizada
                    else:
                        line.eval(policies, mlabelling, vulnerabilities, currentLine)
                        temp_array_multilabelling = array_multilabellingCloned
                        newCurrentLine = currentLine

                if isAlwaysTrue:
                    array_multilabellingCloned = temp_array_multilabelling
                else:
                    array_multilabellingCloned = combine_array_multilabellings(array_multilabellingCloned, temp_array_multilabelling)
                currentLine = newCurrentLine
            
            i+=1

            #if not implicit_multiLabel.isEmpty():
            #    for a in array_multilabellingCloned:
            #        for key in a.getKeys():
            #            a.labelling_map[key] = a.labelling_map[key].combine_multiLabels_implicit(implicit_multiLabel)

        return array_multilabellingCloned, currentLine

class UnaryOp:
    def __init__(self,op, operand):
        self.operand = operand
        self.op = op

    def __repr__(self):
        return f"UnaryOp({self.op ,self.operand})"
    
    def eval(self, policies, multilabelling, vulnerabilities, currentLine):
        print(self)
        pass

class UAdd:
    def __init__(self):
        pass

    def __repr__(self):
        return f"UAdd"
    
class USub:
    def __init__(self):
        pass

    def __repr__(self):
        return f"USub"
    
class Not:
    def __init__(self):
        pass

    def __repr__(self):
        return f"Not"

class Invert:
    def __init__(self):
        pass

    def __repr__(self):
        return f"Invert"

class BoolOp:
    def __init__(self,op, values):
        self.op = op
        self.values = values

    def __repr__(self):
        return f"BoolOp({self.op ,self.values})"
    
    def eval(self, policies, multilabelling, vulnerabilities, currentLine):
        print(self)
        pass

class And:
    def __init__(self):
        pass

    def __repr__(self):
        return f"And"
    
class Or:
    def __init__(self):
        pass

    def __repr__(self):
        return f"Or"

def createIllegalFlow(name, currentLine, pattern, multilabel, vulnerabilities):
        pattern = pattern.get_vulnerabilityName()
        currentLabel = multilabel.get_label_by_vulnerability(pattern)
        sources = currentLabel.getSources()

        if len(sources) == 0: #se a label tiver vazia é porque o argument não de sources então não cria illegal flow
            return

        sourcesUnsanitized = currentLabel.getSourcesUnsanitized()
        sourcesSanitized = currentLabel.getSanitized()

        result = removeReps(sourcesSanitized)

        if bool(sourcesSanitized):

            for source in result:
                mainList = []
                true_source = []
                for tuple in sourcesSanitized:
                    listFlows = []
                    if (tuple[0].getSource() == source):
                        true_source.append([tuple[0].getSource(), tuple[0].getLine()])
                        for sanitizer in tuple[1]:
                            listFlows.append([sanitizer.getSanitizer(), sanitizer.getLine()])
                        mainList.append(listFlows)

                different_source = True        
                if bool(sourcesUnsanitized):
                    for s in sourcesUnsanitized:
                        if [s.getSource(), s.getLine()] == true_source[0]:
                            different_source=False
                    if not different_source:
                        flag = "yes"
                    else:
                        flag = "no"
                else: 
                    flag = "no" 
                
                illegalFlow = IllegalFlow(pattern, true_source[0], [name, currentLine], flag, mainList)
                if not vulnerabilities.existsIllegalFlow(illegalFlow):
                    vulnerabilities.add_illegalFlow(illegalFlow)
        
        elif bool(sourcesUnsanitized):

            for tuple in sourcesUnsanitized:
                already_covered = False
                for illegal_flow in vulnerabilities.get_illegal_flows():
                    if( pattern in illegal_flow.get_vulnerabilityType() and
                        [tuple.getSource(), tuple.getLine()] == illegal_flow.get_source() and
                        [name, currentLine] == illegal_flow.get_sink() and
                        bool(illegal_flow.get_sanitized_flows())):
                        illegal_flow.update_unsanitized_flows("yes")
                        already_covered = True
                if(not already_covered):
                    illegalFlow = IllegalFlow(pattern, [tuple.getSource(), tuple.getLine()], [name, currentLine], "yes", [])

                    if not vulnerabilities.existsIllegalFlow(illegalFlow):
                        vulnerabilities.add_illegalFlow(illegalFlow)
        
        if(bool(sourcesSanitized) and bool(sourcesUnsanitized)):
            for tuple in sourcesUnsanitized:
                if Name.wasNonDeclared(tuple.getSource()):
                    illegalFlow = IllegalFlow(pattern, [tuple.getSource(), tuple.getLine()], [name, currentLine], "yes", [])
                    vulnerabilities.add_illegalFlow(illegalFlow)

def removeReps(sourcesUnsanitized):
    result = []
    for source in sourcesUnsanitized:
        if source[0].getSource() not in result:
            result.append(source[0].getSource())

    return result

def combine_array_multilabellings(fst, snd):
        for ml in snd:
            if ml not in fst:
                fst.append(ml)
        
        return fst



