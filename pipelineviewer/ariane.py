# Ariane is currently not supported

class PipelineArianeText(Pipeline):
    stages = ["IF", "DE", "IS", "EX", "C"]

    # IF log is "<cycle> IF <id> <mode> <addr>"
    trace_if = re.compile(r"^\s*(\d+) IF \s*(\d+) (\w) ([0-9A-Fa-f]+)")
    # DE log is "<cycle> DE <id> <addr> <insn>"
    trace_de = re.compile(r"^\s*(\d+) DE \s*(\d+) ([0-9A-Fa-f]+) (.*)")
    # IS log is "<cycle> IS <id>"
    trace_is = re.compile(r"^\s*(\d+) IS \s*(\d+)")
    # EX log is "<cycle> EX <id>"
    trace_ex = re.compile(r"^\s*(\d+) EX \s*(\d+)")
    # C log is "<cycle> C <id>"
    trace_c = re.compile(r"^\s*(\d+) C \s*(\d+)")

    # BHT log is "<cycle> BHT <id> <pc> <index> <valid> <taken>: <old>-><new>"
    trace_bht = re.compile(
        r"^\s*(\d+) BHT\s+(\d+) ([0-9A-Fa-f]+)\s+(\d+) \[(\d)\] (\d): (\d+)->(\d+)")
    # BP STATIC log is  "<cycle> BP STATIC <id> <pc> <index> <direction>"
    trace_bp_static = re.compile(
        r"^\s*(\d+) BP STATIC \s*(\d+) ([0-9A-Fa-f]+)\s+(\d+) (\d)")
    # BP STATIC log is  "<cycle> BP DYNAMIC <id> <pc> <index> <direction>"
    trace_bp_dynamic = re.compile(
        r"^\s*(\d+) BP DYNAMIC \s*(\d+) ([0-9A-Fa-f]+)\s+(\d+) (\d+)")

    def __init__(self, file):
        log = {}

        for line in file:
            m = self.trace_if.match(line)
            if m:
                id = int(m.group(2))
                log[id] = AttrDict({"pc": int(m.group(4), 16), "insn": None, "mode": m.group(3), "IF": int(m.group(1)),
                                    "DE": None, "IS": None, "EX": None, "C": None, "BHT": None, "BP": None})
                continue
            m = self.trace_de.match(line)
            if m:
                id = int(m.group(2))
                pc = int(m.group(3), 16)
                assert pc & ~3 == log[id].pc, "{} pc = {:x} logpc = {:x}".format(
                    id, pc, log[id].pc)
                log[id].pc = pc
                log[id].DE = int(m.group(1))
                log[id].insn = m.group(4)
                continue
            m = self.trace_is.match(line)
            if m:
                id = int(m.group(2))
                log[id].IS = int(m.group(1))
                continue
            m = self.trace_ex.match(line)
            if m:
                id = int(m.group(2))
                log[id].EX = int(m.group(1))
                continue
            m = self.trace_c.match(line)
            if m:
                id = int(m.group(2))
                log[id].C = int(m.group(1))
                continue
            m = self.trace_bht.match(line)
            if m:
                id = int(m.group(2))
                log[id].BHT = AttrDict(index=int(m.group(4)), taken=int(m.group(6)), oldcounter=int(m.group(7), 2),
                                       newcounter=int(m.group(8), 2))
                continue
            m = self.trace_bp_static.match(line)
            if m:
                id = int(m.group(2))
                log[id].BP = AttrDict(type="static", index=int(
                    m.group(4)), taken=int(m.group(5)))
                continue
            m = self.trace_bp_dynamic.match(line)
            if m:
                id = int(m.group(2))
                log[id].BP = AttrDict(type="dynamic", index=int(
                    m.group(4)), taken=(int(m.group(5), 2) >= 2))
                continue

        self.log = log
