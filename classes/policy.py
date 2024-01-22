
from .multi_label import MultiLabel

class Policy:
    def __init__(self, patterns):
        self.patterns = patterns

    def get_all_vulnerability_names(self):
        return [pattern.name for pattern in self.patterns]

    def get_patterns_with_source(self, source_name):
        return [pattern for pattern in self.patterns if pattern.is_source(source_name)]

    def get_patterns_with_sanitizer(self, sanitizer_name):
        return [pattern for pattern in self.patterns if pattern.is_sanitizer(sanitizer_name)]

    def get_patterns_with_sink(self, sink_name):
        return [pattern for pattern in self.patterns if pattern.is_sink(sink_name)]

    def getPatterns(self):
        return self.patterns
    
    def get_implicit(self):
        patterns = []
        for pattern in self.patterns: 
            if pattern.is_implicit():
                patterns.append(pattern)
        return Policy(patterns)

    def detect_illegal_flows(self, name, multilabel):
        illegal_flows = MultiLabel()
        for pattern in self.patterns:
            if pattern.is_sink(name):
                illegal_flows.combine_labels(multilabel.get_labels_for_pattern(pattern.name))
        return illegal_flows