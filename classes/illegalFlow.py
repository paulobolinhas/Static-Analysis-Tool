import json


class IllegalFlow:

    def __init__(self, vulnerabilityName, source, sink, unsanitized_flows, sanitized_flows):
        self.vulnerabilityName = vulnerabilityName
        self.source = source
        self.sink = sink
        self.unsanitized_flows = unsanitized_flows
        self.sanitized_flows = sanitized_flows
    
    def update_vulnerabilityName(self, name):
        self.vulnerabilityName = name

    def __repr__(self):
        return f"IllegalFlow({self.vulnerabilityName}, {self.source}, {self.sink}, {self.unsanitized_flows}, {self.sanitized_flows})"

    def getIllegalFlowDict(self):
        return {
            "vulnerability": self.vulnerabilityName,
            "source": self.source, 
            "sink": self.sink,
            "unsanitized_flows": self.unsanitized_flows,
            "sanitized_flows": self.sanitized_flows
        }
    
    def get_source(self):
        return self.source
    
    def get_sanitized_flows(self):
        return self.sanitized_flows
    
    def update_unsanitized_flows(self, string):
        self.unsanitized_flows = string

    def update_sanitized_flows(self, sanitized_flows):
        self.sanitized_flows = sanitized_flows
    
    def get_sink(self):
        return self.sink

    def get_vulnerabilityType(self):
        return self.vulnerabilityName[0]

    def __eq__(self, other):
        if isinstance(other, IllegalFlow):
            self_prefix = self.vulnerabilityName.split('_')[0]
            other_prefix = other.vulnerabilityName.split('_')[0]

            return (
                self_prefix == other_prefix and
                self.source == other.source and
                self.sink == other.sink and
                self.unsanitized_flows == other.unsanitized_flows and
                self.sanitized_flows == other.sanitized_flows
            )
        return False