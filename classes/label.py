import copy
class Label:
    def __init__(self, tuple=None):
        self.tuples_array = [tuple] if tuple is not None else []

    def add_source_sanitizers(self, source, sanitizers):
        for tuple in self.tuples_array:
            if tuple[0] == source:
                tuple[1].append(sanitizers)
                return

    def add_tuple(self, new_tuple):

        clonedTuple = copy.deepcopy(new_tuple)
        # If source already exists, replace it
        for i, existing_tuple in enumerate(self.tuples_array):
            #dantes comparava a source, a linha e os sanitizers
            #agora compara apenas a source e os sanitizers
            if existing_tuple[0].getSource() == new_tuple[0].getSource() and self._compare_sanitizers(existing_tuple[1], new_tuple[1]):
                self.tuples_array[i] = clonedTuple
                break
        else:
            self.tuples_array.append(clonedTuple)
    
    def _compare_sanitizers(self, list1, list2):
        # Compare two lists of sanitizers
        if len(list1) != len(list2):
            return False
        for s1, s2 in zip(list1, list2):
            if s1 != s2:
                return False
        return True
    
    def remove_tuple(self, tuple):
        self.tuples_array.remove(tuple)

    def isEmpty(self):
         return len(self.tuples_array) == 0

    def getTuples(self):
        return self.tuples_array.copy()
    
    def getSources(self):
        sources = []
        for tuple in self.getTuples():
            sources.append(tuple[0])
        return sources
    
    def getSourcesSanitized(self):
        tuples = self.getTuples()
        sources = []
        for tuple in tuples:
            if bool(tuple[1]):
                sources.append(tuple[0])
        return sources
    
    def getSanitized(self):
        tuples = self.getTuples()
        sources = []
        for tuple in tuples:
            if bool(tuple[1]):
                sources.append(tuple)
        return sources
    
    def getSourcesUnsanitized(self):
        tuples = self.getTuples()
        sources = []
        for tuple in tuples:
            if bool(tuple[1]) == False:
                sources.append(tuple[0])
        return sources


    def printLabel(self):
        print(self.tuples_array)

    def __repr__(self):
        return f"Label({self.tuples_array})"

    def combine_labels(self, other_label):
        newLabel = Label()
        for tuple in self.tuples_array:
            newLabel.add_tuple(tuple)

        for tuple in other_label.getTuples():
            newLabel.add_tuple(tuple)

        return newLabel

    def __eq__(self, other):

        if not (isinstance(self, Label) and isinstance(other,Label)):
            return False

        if len(self.getTuples()) != len(other.getTuples()):
            return False

        for tuple, other_tuple in zip(self.getTuples(), other.getTuples()):
            if not(tuple[0] == other_tuple[0] and self._compare_sanitizers(tuple[1], other_tuple[1])):
                return False

        return True
