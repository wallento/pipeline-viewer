from .base import Pipeline, riscv_priv_modes

from attrdict import AttrDict

class PipelineIbex(Pipeline):
  stages = ["IF", "IDEX"]
  event_name = {"IF": 0, "IDEX": 1,
                "IDEX_MULTCYCLE_START": 2, "IDEX_MULTCYCLE_END": 3}

  def __init__(self, tracepath):
    log = {}

    self.ctf_reader = CTFReader(tracepath)
    for event in self.ctf_reader.get_events():
      id = 0
      pc = 0
      insn = ""
      insn_type = ""

      id = event["id"]
      id_str = list(self.event_name)[id]
      timestamp = event['timestamp']
      pc = (event["pc"])

      if id_str == "IF":
        keys = event.keys()

        if "insn" in keys:
          insn = str(event["insn"])
        if "insn_type" in keys:
          insn_type = str(event["insn_type"])
        log[event["insn_id"]] = AttrDict(
          {"pc": pc, "insn_type": insn_type, "insn": insn, "mode": riscv_priv_modes[event["mode"]], "IF": timestamp, "IDEX": None, "end": None})

      elif id_str == "IDEX":
        log[event["insn_id"]]["IDEX"] = event["timestamp"]
        log[event["insn_id"]]["end"] = event["timestamp"]
      elif id_str == "IDEX_MULTCYCLE_START":
        log[event["insn_id"]]["IDEX"] = event["timestamp"]
      elif id_str == "IDEX_MULTCYCLE_END":
        log[event["insn_id"]]["end"] = event["timestamp"]

    self.log = log
