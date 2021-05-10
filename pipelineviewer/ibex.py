from .base import Pipeline, riscv_priv_modes
from .ctf import CTFReader

from attrdict import AttrDict

class PipelineIbex(Pipeline):
  event_name = {"IF": 0, "IDEX": 1, "WB": 2, "DONE": 3, "BRANCH_PREDICT": 4, "BRANCH_UPDATE": 5}

  def __init__(self, tracepath):
    log = {}

    self.hasWritebackStage = False

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
          {"pc": pc, "insn_type": insn_type, "insn": insn, "mode": riscv_priv_modes[event["mode"]], "IF": timestamp, "IDEX": None, "WB": None, "end": None, "BP": None})

      elif id_str == "IDEX":
        # single cycle idex in the standard pipeline
        log[event["insn_id"]]["IDEX"] = event["timestamp"]
      elif id_str == "WB":
        # idex starts in the pipeline with
        log[event["insn_id"]]["WB"] = event["timestamp"]
        self.hasWritebackStage = True
      elif id_str == "DONE":
        # idex starts in the pipeline with
        log[event["insn_id"]]["end"] = event["timestamp"]
      elif id_str == "BRANCH_PREDICT":
        log[event["insn_id"]]["BP"] = AttrDict(taken=event["taken"], mispredict=False)
      elif id_str == "BRANCH_UPDATE":
        log[event["insn_id"]]["BP"].mispredict = (event["mispredict"] != 0)

    self.log = log

  def get_stages(self):
      return ["IF", "IDEX", "WB"] if self.hasWritebackStage else ["IF", "IDEX"]
