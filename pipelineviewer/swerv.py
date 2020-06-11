from .base import Pipeline
from .ctf import CTFReader

from attrdict import AttrDict

class PipelineSwervEL2(Pipeline):
  stages = ["IF", "DE", "EX", "WB"]
  event_name = { "IF": 0, "DE": 1, "EX": 2, "WB": 3 }

  def __init__(self, tracepath):
    log = {}

    self.ctf_reader = CTFReader(tracepath)
    for event in self.ctf_reader.get_events():
      id = 0
      pc = 0
      insn = ""
      insn_type = ""

      id = event["id"]
      timestamp = event['timestamp']
      insn_id = event["insn_id"]

      if id == self.event_name["IF"]:
        log[insn_id] = AttrDict(
            {"pc": event["pc"], "IF": timestamp, "DE": None, "EX": None, "WB": None, "end": None, "mode": "M", "insn": event["insn"]})

      if id == self.event_name["DE"]:
        log[insn_id].DE = timestamp

      if id == self.event_name["EX"]:
        log[insn_id].EX = timestamp

      if id == self.event_name["WB"]:
        log[insn_id].WB = timestamp
        log[insn_id].end = timestamp

    self.log = log
