class SOCStateError(Exception):
    """Base exception for SOC state management errors"""
    
    def __init__(self, message: str, details: dict = None):
        super().__init__(message)
        self.message = message
        self.details = details or {}

class StateValidationError(SOCStateError):
    """Raised when state validation fails"""
    pass

class StateSerializationError(SOCStateError):
    """Raised when state serialization/deserialization fails"""
    pass

class StateVersionError(SOCStateError):
    """Raised when state versioning issues occur"""
    pass

class StateUpdateError(SOCStateError):
    """Raised when state update operations fail"""
    pass