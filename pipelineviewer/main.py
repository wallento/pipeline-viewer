#!/usr/bin/env python3

import sys
import re
from attrdict import AttrDict
import colorama
import argparse

from signal import signal, SIGPIPE, SIG_DFL
signal(SIGPIPE, SIG_DFL)

display = {"IF": AttrDict(char="f", fore=colorama.Fore.WHITE, back=colorama.Back.BLUE),
           "DE": AttrDict(char="d", fore=colorama.Fore.WHITE, back=colorama.Back.YELLOW),
           "RN": AttrDict(char="n", fore=colorama.Fore.WHITE, back=colorama.Back.MAGENTA),
           "IS": AttrDict(char="i", fore=colorama.Fore.WHITE, back=colorama.Back.RED),
           "EX": AttrDict(char="e", fore=colorama.Fore.WHITE, back=colorama.Back.LIGHTMAGENTA_EX),
           "C": AttrDict(char="c", fore=colorama.Fore.WHITE, back=colorama.Back.CYAN),
           "RE": AttrDict(char="r", fore=colorama.Fore.WHITE, back=colorama.Back.BLUE),
           }


class Pipeline(object):
    def read(self, file):
        pass


class PipelineAriane(Pipeline):
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
    trace_bht = re.compile(r"^\s*(\d+) BHT\s+(\d+) ([0-9A-Fa-f]+)\s+(\d+) \[(\d)\] (\d): (\d+)->(\d+)")
    # BP STATIC log is  "<cycle> BP STATIC <id> <pc> <index> <direction>"
    trace_bp_static = re.compile(r"^\s*(\d+) BP STATIC \s*(\d+) ([0-9A-Fa-f]+)\s+(\d+) (\d)")
    # BP STATIC log is  "<cycle> BP DYNAMIC <id> <pc> <index> <direction>"
    trace_bp_dynamic = re.compile(r"^\s*(\d+) BP DYNAMIC \s*(\d+) ([0-9A-Fa-f]+)\s+(\d+) (\d+)")

    def __init__(self, file):
        log = {}

        for line in file:
            m = self.trace_if.match(line)
            if m:
                id = int(m.group(2))
                log[id] = AttrDict({"pc": int(m.group(4),16), "insn": None, "mode": m.group(3), "IF": int(m.group(1)),
                                    "DE": None, "IS": None, "EX": None, "C": None, "BHT": None, "BP": None})
                continue
            m = self.trace_de.match(line)
            if m:
                id = int(m.group(2))
                pc = int(m.group(3),16)
                assert pc & ~3 == log[id].pc, "{} pc = {:x} logpc = {:x}".format(id, pc, log[id].pc)
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
                log[id].BP = AttrDict(type="static", index=int(m.group(4)), taken=int(m.group(5)))
                continue
            m = self.trace_bp_dynamic.match(line)
            if m:
                id = int(m.group(2))
                log[id].BP = AttrDict(type="dynamic", index=int(m.group(4)), taken=(int(m.group(5), 2) >= 2))
                continue

        self.log = log


class PipelineBOOM(Pipeline):
    stages = ["IF", "DE", "RN", "IS", "C", "RE"]

    trace_if = re.compile(r"\s*(\d+); O3PipeView:fetch:\s*(\d+):0x([0-9A-Fa-f]+):0:\s*\d+:(.*)")
    trace_de = re.compile(r"\s*(\d+); O3PipeView:decode:\s*(\d+)")
    trace_rn = re.compile(r"\s*(\d+); O3PipeView:rename:\s*(\d+)")
    trace_is = re.compile(r"\s*(\d+); O3PipeView:dispatch:\s*(\d+)")
    trace_c = re.compile(r"\s*(\d+); O3PipeView:complete:\s*(\d+)")
    trace_re = re.compile(r"\s*(\d+); O3PipeView:retire:\s*(\d+):store: 0:(\d)")

    modemap = ["U", "S", "H", "M"]
    scale = 1000

    def __init__(self, file):
        log = {}
        guess_mode = "M"

        for line in file:
            m = self.trace_if.match(line)
            if m:
                id = int(m.group(1))
                log[id] = AttrDict({"pc": int(m.group(3),16), "insn": m.group(4), "mode": guess_mode,
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


pipelines = {"ariane": PipelineAriane, "boom": PipelineBOOM}


def render(pipeline, args):
    if args.colored:
        colorama.init(strip=False)
    else:
        colorama.init()

    in_snip = False
    count_retired = 0
    for i in pipeline.log.values():
        if i.mode not in args.modes:
            if not in_snip:
                args.outfile.write("~" * args.width + " snip (mode)\n")
                count_retired = 0
            in_snip = True
            continue
        in_snip = False
        line = list("." * args.width)
        for s in range(len(pipeline.stages)):
            stage = pipeline.stages[s]
            if stage in i and i[stage] is not None:
                line[i[stage] % args.width] = display[stage].fore + display[stage].back + display[stage].char + colorama.Style.RESET_ALL
                next = s + 1
                if next >= len(pipeline.stages):
                    continue
                next = pipeline.stages[next]
                if next in i and i[next] is not None:
                    for x in range(i[stage] + 1, i[next]):
                        line[x % args.width] = display[stage].fore + display[stage].back + "=" + colorama.Style.RESET_ALL
        line = "[" + "".join(line) + "]"

        if not args.no_mode:
            line += " {}".format(i.mode)

        if not args.no_count_retired:
            if "RE" in pipeline.stages:
                if i.RE is not None:
                    count_retired += 1
            elif "C" in pipeline.stages:
                if i.C is not None:
                    count_retired += 1
            line += " {}".format(count_retired)

        if not args.no_time:
            if pipeline.stages[-1] in i and i[pipeline.stages[-1]]:
                line += " {:8}-{:8}".format(i[pipeline.stages[0]], i[pipeline.stages[-1]])
            else:
                line += " {:8}---------".format(i[pipeline.stages[0]])

        if not args.no_pc:
            line += " {:016x}".format(i.pc)

        if not args.no_insn and i.insn:
            line += " " + i.insn

        if args.bp:
            if "BP" in i and i.BP:
                if i.BP.taken:
                    line += ", BP taken @{} ({})".format(i.BP.index, i.BP.type)
                else:
                    line += ", BP not taken @{} ({})".format(i.BP.index, i.BP.type)
            if "BHT" in i and i.BHT:
                if i.BHT.taken:
                    line += ", BHT @{} taken ({:02b}->{:02b})".format(i.BHT.index, i.BHT.oldcounter, i.BHT.newcounter)
                else:
                    line += ", BHT @{} not taken ({:02b}->{:02b})".format(i.BHT.index, i.BHT.oldcounter, i.BHT.newcounter)

        args.outfile.write(line+"\n")
    colorama.deinit()

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("format", choices=pipelines.keys())
    parser.add_argument("infile", nargs='?', help="file with pipeline trace", type=argparse.FileType('r'),
                        default=sys.stdin)
    parser.add_argument("outfile", nargs='?', help="file to render to", type=argparse.FileType('w'),
                        default=sys.stdout)
    parser.add_argument("-c", "--colored", action="store_true", help="force colored output")
    parser.add_argument("-w", "--width", type=int, default=80, help="column width of graph")
    parser.add_argument("--modes", default="MSU", help="only show from given modes")
    parser.add_argument("--no-mode", action="store_true", help="suppress mode in output")
    parser.add_argument("--no-time", action="store_true", help="suppress time frame in output")
    parser.add_argument("--no-pc", action="store_true", help="suppress program counter in output")
    parser.add_argument("--no-insn", action="store_true", help="suppress instruction in output")
    parser.add_argument("--no-count-retired", action="store_true", help="Show counter of retired instructions")
    parser.add_argument("--bp", action="store_true", help="include branch predictor in output")
    args = parser.parse_args()
    args.modes = list(args.modes)
    render(pipelines[args.format](args.infile), args)
