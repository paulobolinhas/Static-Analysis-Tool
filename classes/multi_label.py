
from .label import Label
from .pattern import Pattern


class MultiLabel:
    def __init__(self, patterns):
        self.patterns = patterns or []
        self.dictionary = {}
        for pattern in patterns:
            self.dictionary[pattern.get_vulnerabilityName()] = Label()

    def isEmpty(self):
        if self.dictionary == {}:
            return True
        return False

    def getPattern(self, name):
        for pattern in self.patterns:
            if pattern.get_vulnerabilityName() == name:
                return pattern
        return None

    #para cada padrão vulnerabilidade, apenas adiciona os tuplos da label que têm source igual à do padrão
    def update_label(self, label, vulnerability):
        from classes.nodes import Name
        for tuple in label.getTuples():
            source = tuple[0].getSource()
            if (self.getPattern(vulnerability).is_source(source) and self.check_sanitizers_in_pattern(tuple[1],vulnerability)) or source in Name.nonDeclared:
                self.dictionary[vulnerability].add_tuple(tuple)

    def check_sanitizers_in_pattern(self, tuple_sanitizers, pattern):
        for sanitizer in tuple_sanitizers:
                if sanitizer.getSanitizer() not in self.getPattern(pattern).get_sanitizers():
                    return False
        return True
    
    def getDictionaryMultilabel(self):
        return self.dictionary

    def get_label_by_vulnerability(self, name):
        return self.dictionary.get(name, None)

    def getKeys(self):
        return self.dictionary.keys()

    def combine_multiLabels(self, other_multiLabel):

        newMultiLabel = MultiLabel(self.patterns)

        for vulnerability in self.dictionary.keys():
            newLabel = self.get_label_by_vulnerability(vulnerability).combine_labels(other_multiLabel.get_label_by_vulnerability(vulnerability))
            newMultiLabel.update_label(newLabel, vulnerability)

        return newMultiLabel
    
    def combine_multiLabels_implicit(self, other_multiLabel):

        newMultiLabel = MultiLabel(self.patterns)

        for vulnerability in self.dictionary.keys():
            newLabel = self.get_label_by_vulnerability(vulnerability).combine_labels(other_multiLabel.get_label_by_vulnerability(vulnerability))
            newMultiLabel.dictionary[vulnerability] = newLabel

        return newMultiLabel
    
    def getTaintedPatternsByKey(self, key):
        patterns = []
        for pattern in self.dictionary.keys(): #go patterns in variable
            label = self.dictionary.get(pattern)
            if (len(label.tuples_array) != 0):
                patterns.append(pattern)
        
        return patterns
    
    def __repr__(self):
        return f"MultiLabel({self.dictionary})"
    
    def __eq__(self, other):

        if not (isinstance(self, MultiLabel) and isinstance(other,MultiLabel)):
            return False
        
        if len(self.getKeys()) != len(other.getKeys()):
            return False
        
        for key1, key2 in zip(self.getKeys(), other.getKeys()):
            if self.get_label_by_vulnerability(key1) != other.get_label_by_vulnerability(key2):
                return False
            
        return True