
from .multi_label import MultiLabel
import copy

class MultiLabelling:
    def __init__(self):
        self.labelling_map = {}

    def get_multilabel_by_name(self, name):
        return self.labelling_map.get(name, None)

    def update_multilabel_by_name(self, name, multilabel):
        if name in self.labelling_map:
            self.labelling_map[name] = self.labelling_map[name].combine_multiLabels(multilabel)
        else:
            self.labelling_map[name] = multilabel

    def getKeys(self):
        return self.labelling_map.keys()
    

    def __repr__(self):
        return f"MultiLabelling({self.labelling_map})"
    
    def clone(self):
        cloned_multilabelling = MultiLabelling()
        cloned_multilabelling.labelling_map = copy.deepcopy(self.labelling_map)
        return cloned_multilabelling
    
    def __eq__(self, other):

        if not (isinstance(self, MultiLabelling) and isinstance(other,MultiLabelling)):
            return False

        if len(self.getKeys()) != len(other.getKeys()):
            return False

        for key1, key2 in zip(self.getKeys(), other.getKeys()):
            if self.get_multilabel_by_name(key1) != other.get_multilabel_by_name(key2):
                return False
            
        return True

