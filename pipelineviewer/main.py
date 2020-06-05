#!/usr/bin/env python3

import os
import sys
import re
from attrdict import AttrDict
import colorama
import argparse

try:
    from babeltrace import TraceCollection
except ImportError:
    print("babeltrace needed and needs to be installed manually (e.g., python3-babeltrace in Debian/Ubuntu)")
    exit(1)

from riscvmodel.code import decode
from riscvmodel.model import Model
from riscvmodel.variant import RV32I
import pygments
import pygments.lexers
import pygments.formatters

import itertools

from .version import version

from signal import signal, SIGPIPE, SIG_DFL
signal(SIGPIPE, SIG_DFL)

display = {"IF": AttrDict(char="f", fore=colorama.Fore.WHITE, back=colorama.Back.BLUE, legend="fetch"),
           "DE": AttrDict(char="d", fore=colorama.Fore.WHITE, back=colorama.Back.YELLOW),
           "RN": AttrDict(char="n", fore=colorama.Fore.WHITE, back=colorama.Back.MAGENTA),
           "IS": AttrDict(char="i", fore=colorama.Fore.WHITE, back=colorama.Back.RED),
           "EX": AttrDict(char="e", fore=colorama.Fore.WHITE, back=colorama.Back.LIGHTMAGENTA_EX),
           "IDEX": AttrDict(char="e", fore=colorama.Fore.WHITE, back=colorama.Back.LIGHTMAGENTA_EX, legend="decode/execute"),
           "C": AttrDict(char="c", fore=colorama.Fore.WHITE, back=colorama.Back.CYAN),
           "RE": AttrDict(char="r", fore=colorama.Fore.WHITE, back=colorama.Back.BLUE),
           }


class Pipeline(object):
    def read(self, file):
        pass


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


class PipelineArianeCTF(Pipeline):
    stages = ["IF", "DE", "IS", "EX", "C"]

    def __init__(self, file):
        log = {}

        # TODO

        self.log = log


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


"""
abstraction layer to read CTF format, underlaying library could be replaced easily
"""


class CTFReader():
    def __init__(self, path):
        self.babelreader = CTFBabeltrace(path)

    def get_events(self):
        for event in self.babelreader.get_events():
            yield event


"""
Utilizing babeltrace for reading CTF format
"""


class CTFBabeltrace():
    def __init__(self, path):
        self.traces = dict()
        self.tc = TraceCollection()
        if self.tc:
            # add traces to the collection
            if self.tc.add_traces_recursive(path, "ctf") is None:
                raise RuntimeError('Cannot add trace')
        else:
            print("no TraceCollection available...")

    def get_events(self):
        if self.tc:
            for event in self.tc.events:
                yield event


riscv_priv_modes = {3: "M", 2: "H", 1: "S", 0: "U"}

"""
IBEX Core
"""


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
                pass
            elif id_str == "IDEX_MULTCYCLE_START":
                log[event["insn_id"]]["IDEX"] = event["timestamp"]
                pass
            elif id_str == "IDEX_MULTCYCLE_END":
                log[event["insn_id"]]["end"] = event["timestamp"]
                pass

        self.log = log


pipelines = {"ariane": PipelineArianeCTF, "ariane-text": PipelineArianeText,
             "ibex": PipelineIbex, "boom": PipelineBOOM}


def render(pipeline, args):
    if args.colored:
        colorama.init(strip=False)
    else:
        colorama.init()

    model = Model(RV32I) if "e" in args.format else None

    header_legend = []
    length = 0  # need to keep track separately
    for s in pipeline.stages:
        leg = colorama.Style.BRIGHT + \
            display[s].fore + display[s].back + \
            display[s].char + colorama.Style.RESET_ALL
        leg += colorama.Style.BRIGHT + "=" + \
            display[s].legend + colorama.Style.RESET_ALL
        length += 2+len(display[s].legend)
        header_legend.append(leg)
    header_legend = " ".join(header_legend)
    header = " {}{} ".format(header_legend, " "*(args.width-length))

    col_width = {'m': 1, 'r': 8, 't': 17, 'p': 16, 'i': 20, 'e': 40 }

    col_pos = {}
    pos = args.width + 1
    for c in args.format:
        pos += 1
        col_pos[c] = pos
        pos += col_width[c]

    if "m" in args.format:
        print(" "*(col_pos['m']-1) + colorama.Style.BRIGHT +
                "mode" + colorama.Style.RESET_ALL)

    col_header = {'m': "|", 'r': "#retired",
                  't': "   cycle from-to ", 'p': ' pc             ', 'i': " insn"}

    for c in args.format:
        if c in col_header:
            header += colorama.Style.BRIGHT + \
                col_header[c] + colorama.Style.RESET_ALL
        header += " "

    print(header)

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
                line[i[stage] % args.width] = display[stage].fore + \
                    display[stage].back + display[stage].char + \
                    colorama.Style.RESET_ALL
                next = s + 1
                if next >= len(pipeline.stages) and "end" in i and i["end"] is not None:
                    for x in range(i[stage] + 1, i["end"]+1):
                        line[x % args.width] = display[stage].fore + \
                            display[stage].back + "=" + \
                            colorama.Style.RESET_ALL
                    continue
                next = pipeline.stages[next]
                if next in i and i[next] is not None:
                    for x in range(i[stage] + 1, i[next]):
                        line[x % args.width] = display[stage].fore + \
                            display[stage].back + "=" + \
                            colorama.Style.RESET_ALL

        line = "[" + "".join(line) + "]"

        col = args.width + 2
        for c in args.format:
            col += 1
            line += " "
            width = 0
            if c == "m":
                line += format(i.mode)
                width = 1
            elif c == "r":
                if "end" in i and i["end"]:
                    count_retired += 1
                elif "RE" in pipeline.stages:
                    if i.RE is not None:
                        count_retired += 1
                elif "C" in pipeline.stages:
                    if i.C is not None:
                        count_retired += 1
                line += "{:8}".format(count_retired)
                width = 8
            elif c == "t":
                if pipeline.stages[-1] in i and i[pipeline.stages[-1]]:
                    line += "{:8}-{:8}".format(i[pipeline.stages[0]],
                                                i[pipeline.stages[-1]])
                else:
                    line += "{:8}---------".format(i[pipeline.stages[0]])
                width = 17
            elif c == "p":
                line += "{:016x}".format(i.pc)
                width = 16
            elif c == "i" and i.insn:
                insn = str(decode(int(i.insn)))
                line += pygments.highlight(insn, pygments.lexers.GasLexer(
                ), pygments.formatters.TerminalFormatter()).strip()
                width = len(insn)
            elif c == "e":
                line += colorama.Style.DIM
                insn = decode(int(i.insn))
                inops = insn.inopstr(model)
                if len(inops) > 0:
                    line += "[i] " + inops
                    width += 4 + len(inops)
                model.issue(insn)
                outops = insn.outopstr(model)
                if len(outops) > 0:
                    if len(inops) > 0:
                        line += ""
                    line += "[o] " + outops
                    width += 4 + len(outops)
                line += colorama.Style.RESET_ALL
            elif c == "b":
                if "BP" in i and i.BP:
                    if i.BP.taken:
                        line += ", BP taken @{} ({})".format(i.BP.index,
                                                             i.BP.type)
                    else:
                        line += ", BP not taken @{} ({})".format(
                            i.BP.index, i.BP.type)
                if "BHT" in i and i.BHT:
                    if i.BHT.taken:
                        line += ", BHT @{} taken ({:02b}->{:02b})".format(
                            i.BHT.index, i.BHT.oldcounter, i.BHT.newcounter)
                    else:
                        line += ", BHT @{} not taken ({:02b}->{:02b})".format(
                            i.BHT.index, i.BHT.oldcounter, i.BHT.newcounter)
            if width < col_width[c]:
                line += " "*(col_width[c] - width)
            col += col_width[c]
        args.outfile.write(line+"\n")
    colorama.deinit()


def FileOrFolderType(f):
    if f == "-" or os.path.isfile(f):
        return argparse.FileType('r')(f)
    elif os.path.isdir(f):
        return f
    else:
        raise Exception("Cannot find: {}".format(f))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("core", choices=pipelines.keys())
    parser.add_argument("infile", nargs='?', help="file with pipeline trace", type=FileOrFolderType,
                        default="-")
    parser.add_argument("outfile", nargs='?', help="file to render to", type=argparse.FileType('w'),
                        default=sys.stdout)
    parser.add_argument('--version', action='version', version=version)
    parser.add_argument("-c", "--colored", action="store_true",
                        help="force colored output")
    parser.add_argument("-m", "--modes", default="MSU",
                        help="only show from given modes")
    parser.add_argument("-w", "--width", type=int,
                        default=80, help="column width of graph")
    parser.add_argument("-f", "--format", type=str, default="mrtpi")
    args = parser.parse_args()
    args.modes = list(args.modes)
    render(pipelines[args.core](args.infile), args)
