# src/core/protocols.py
"""
Protocols from the PrivBox paper:
- Fig. 2: Rule Preparation Protocol (RG ↔ MB)
- Fig. 3: Preprocessing Protocol (MB ↔ Endpoints, first session)
- Fig. 5: Session Rule Preparation Protocol
"""

class RulePreparationProtocol:
    """Fig. 2: Setup between RG and MB to generate rule tuples"""
    
    def __init__(self):
        self.rg_state = {}
        self.mb_state = {}
    
    # Will be implemented after encryption is working
    
class PreprocessingProtocol:
    """Fig. 3: First session between MB and endpoints"""
    
    def __init__(self):
        pass
    
    # Will be implemented after encryption is working

class SessionRulePreparationProtocol:
    """Fig. 5: Generate session-specific rules I_i from obfuscated rules K_i"""
    
    def __init__(self):
        pass
    
    # Will be implemented after encryption is working