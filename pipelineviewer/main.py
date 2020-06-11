#!/usr/bin/env python3

import os
import sys
import re
from attrdict import AttrDict
import colorama
import argparse

from riscvmodel.code import decode
from riscvmodel.model import Model
from riscvmodel.variant import RV32I
import pygments
import pygments.lexers
import pygments.formatters

import itertools

from .ibex import PipelineIbex
from .boom import PipelineBOOM
from .swerv import PipelineSwervEL2

from .version import version

from signal import signal, SIGPIPE, SIG_DFL
signal(SIGPIPE, SIG_DFL)

display = {"IF": AttrDict(char="f", fore=colorama.Fore.WHITE, back=colorama.Back.BLUE, legend="fetch"),
           "DE": AttrDict(char="d", fore=colorama.Fore.WHITE, back=colorama.Back.YELLOW, legend="decode"),
           "RN": AttrDict(char="n", fore=colorama.Fore.WHITE, back=colorama.Back.MAGENTA),
           "IS": AttrDict(char="i", fore=colorama.Fore.WHITE, back=colorama.Back.RED),
           "EX": AttrDict(char="e", fore=colorama.Fore.WHITE, back=colorama.Back.LIGHTMAGENTA_EX, legend="execute"),
           "IDEX": AttrDict(char="e", fore=colorama.Fore.WHITE, back=colorama.Back.LIGHTMAGENTA_EX, legend="decode/execute"),
           "C": AttrDict(char="c", fore=colorama.Fore.WHITE, back=colorama.Back.CYAN),
           "RE": AttrDict(char="r", fore=colorama.Fore.WHITE, back=colorama.Back.BLUE),
           "WB": AttrDict(char="w", fore=colorama.Fore.WHITE, back=colorama.Back.BLUE, legend="write back"),
           }

pipelines = {"ibex": PipelineIbex, "boom": PipelineBOOM, "swerv-el2": PipelineSwervEL2}

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
    print(header_legend)

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

    header = " "*(args.width+3)
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
