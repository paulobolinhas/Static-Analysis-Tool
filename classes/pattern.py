
class Pattern:
    def __init__(self, vulnerabilityName, sources=None, sanitizers=None, sinks=None, implicit=None):
        self.vulnerabilityName = vulnerabilityName
        self.sources = sources or []
        self.sanitizers = sanitizers or []
        self.sinks = sinks or []
        self.implicit = implicit

    def get_vulnerabilityName(self):
        return self.vulnerabilityName

    def get_sources(self):
        return self.sources

    def get_sanitizers(self):
        return self.sanitizers

    def get_sinks(self):
        return self.sinks

    def is_source(self, name):
        return name in self.sources

    def is_sanitizer(self, name):
        return name in self.sanitizers

    def is_sink(self, name):
        return name in self.sinks
    
    def is_implicit(self):
        if self.implicit == "yes":
            return True
        return False
