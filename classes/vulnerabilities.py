
class Vulnerabilities:
    def __init__(self):
        self.illegalFlows = []
        self.vulnerabilities_counter = {} 

    def __repr__(self):
        return f"Vulnerabilities({self.illegalFlows})"
    
    def add_illegalFlow(self, illegal_flow):
        if illegal_flow.vulnerabilityName not in self.vulnerabilities_counter.keys():
            self.vulnerabilities_counter[illegal_flow.vulnerabilityName] = 1
        else:
            self.vulnerabilities_counter[illegal_flow.vulnerabilityName] += 1

        newName = illegal_flow.vulnerabilityName + "_" + str(self.vulnerabilities_counter[illegal_flow.vulnerabilityName])

        illegal_flow.update_vulnerabilityName(newName)

        self.illegalFlows.append(illegal_flow)


    def get_illegal_flows(self):
        return self.illegalFlows.copy()

    def existsIllegalFlow(self, illegalFlow):
        for current in self.illegalFlows:
            if current == illegalFlow:
                return True
            elif (current.get_vulnerabilityType() == illegalFlow.get_vulnerabilityType()
                  and current.get_source() == illegalFlow.get_source() 
                  and current.get_sink() == illegalFlow.get_sink()) :
                current.update_unsanitized_flows("yes")
                current.update_sanitized_flows(illegalFlow.get_sanitized_flows())
                return True
        return False
    
    
        
        