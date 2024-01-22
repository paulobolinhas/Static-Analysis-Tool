class Sanitizer:
    sanitizers = []  # Class variable

    def __init__(self, sanitizer, line):
        self.sanitizer = sanitizer
        self.line = line
        Sanitizer.sanitizers.append(self)  # Add the instance to the class variable

    @classmethod
    def getSanitizerGlobal(cls, name):
        for sanitizer in cls.sanitizers:
            if sanitizer.sanitizer == name:
                return sanitizer
        return None  # Return None if sanitizer with the given name is not found
    
    def getSanitizer(self):
        return self.sanitizer

    def getLine(self):
        return self.line

    def __repr__(self):
        return f"Sanitizer({self.sanitizer}, {self.line})"
    
    def __eq__(self, other):
        if isinstance(other, Sanitizer):
            return self.sanitizer == other.sanitizer and self.line == other.line
        return False
