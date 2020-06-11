from .base import Pipeline

import re

class PipelineBOOM(Pipeline):
  stages = ["IF", "DE", "RN", "IS", "C", "RE"]

  trace_if = re.compile(
      r"\s*(\d+); O3PipeView:fetch:\s*(\d+):0x([0-9A-Fa-f]+):0:\s*\d+:(.*)")
  trace_de = re.compile(r"\s*(\d+); O3PipeView:decode:\s*(\d+)")
  trace_rn = re.compile(r"\s*(\d+); O3PipeView:rename:\s*(\d+)")
  trace_is = re.compile(r"\s*(\d+); O3PipeView:dispatch:\s*(\d+)")
  trace_c = re.compile(r"\s*(\d+); O3PipeView:complete:\s*(\d+)")
  trace_re = re.compile(
      r"\s*(\d+); O3PipeView:retire:\s*(\d+):store: 0:(\d)")

  modemap = ["U", "S", "H", "M"]
  scale = 1000

  def __init__(self, file):
    log = {}
    guess_mode = "M"

    for line in file:
      m = self.trace_if.match(line)
      if m:
        id = int(m.group(1))
        log[id] = AttrDict({"pc": int(m.group(3), 16), "insn": m.group(4), "mode": guess_mode,
                            "IF": int(int(m.group(2))/self.scale), "DE": None, "RN": None, "IS": None, "C": None, "RE": None})
        continue
      m = self.trace_de.match(line)
      if m:
        id = int(m.group(1))
        log[id].DE = int(int(m.group(2))/self.scale)
      m = self.trace_rn.match(line)
      if m:
        id = int(m.group(1))
        log[id].RN = int(int(m.group(2))/self.scale)
      m = self.trace_is.match(line)
      if m:
        id = int(m.group(1))
        log[id].IS = int(int(m.group(2))/self.scale)
      m = self.trace_c.match(line)
      if m:
        id = int(m.group(1))
        log[id].C = int(int(m.group(2))/self.scale)
      m = self.trace_re.match(line)
      if m:
        id = int(m.group(1))
        log[id].RE = int(int(m.group(2))/self.scale)
        log[id].mode = self.modemap[int(m.group(3))]
        guess_mode = self.modemap[int(m.group(3))]

    self.log = log

