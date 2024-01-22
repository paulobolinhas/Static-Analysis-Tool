class Source:
    def __init__(self, source, line):
        self.source = source
        self.line = line
    
    def getSource(self):
        return self.source
    
    def getLine(self):
        return self.line
    
    def __repr__(self):
        return f"Source({self.source}, {self.line})"

    def __eq__(self, other):
        if isinstance(other, Source):
            return self.source == other.source and self.line == other.line
        return False
