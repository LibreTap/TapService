from enum import Enum

class FlowStatus(str, Enum):
    waiting_for_tag = "waiting_for_tag"
    tag_detected = "tag_detected"
    writing = "writing"
    success = "success"
    failed = "failed"
    error = "error"

