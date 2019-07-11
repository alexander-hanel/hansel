"""
author: alexander hanel
version: 2.0
date: 2019-03-03 

"""

import idautils
import idaapi 
import datetime
import glob
import yara
import operator
import itertools
import inspect
import os
import sys
import json

DEBUG = False
if DEBUG:
    import traceback 
INIT = False

SEARCH_CASE = 4
SEARCH_REGEX = 8
SEARCH_NOBRK = 16
SEARCH_NOSHOW = 32
SEARCH_UNICODE = 64
SEARCH_IDENT = 128
SEARCH_BRK = 256

RULES_DIR = ""


class YaraIDASearch:
    def __init__(self):
        self.mem_results = ""
        self.mem_offsets = []
        if not self.mem_results:
            self._get_memory()

    def _wowrange(self, start, stop, step=1):
        # source https://stackoverflow.com/a/1482502
        if step == 0:
            raise ValueError('step must be != 0')
        elif step < 0:
            proceed = operator.gt
        else:
            proceed = operator.lt
        while proceed(start, stop):
            yield start
            start += step

    def _get_memory(self):
        print "Status: Loading memory for Yara."
        result = ""
        segments_starts = [ea for ea in idautils.Segments()]
        offsets = []
        start_len = 0
        for start in segments_starts:
            end = idc.get_segm_end(start)
            for ea in self._wowrange(start, end):
                result += chr(idc.Byte(ea))
            offsets.append((start, start_len, len(result)))
            start_len = len(result)
        print "Status: Memory has been loaded."
        self.mem_results = result
        self.mem_offsets = offsets

    def _to_virtual_address(self, offset, segments):
        va_offset = 0
        for seg in segments:
            if seg[1] <= offset < seg[2]:
                va_offset = seg[0] + (offset - seg[1])
        return va_offset

    def _init_sig(self, sig_type, pattern, sflag):
        if SEARCH_REGEX & sflag:
            signature = "/%s/" % pattern
            if SEARCH_CASE & sflag:
                # ida is not case sensitive by default but yara is
                pass
            else:
                signature += " nocase"
            if SEARCH_UNICODE & sflag:
                signature += " wide"
        elif sig_type == "binary":
            signature = " %s " % pattern
        elif sig_type == "text" and (SEARCH_REGEX & sflag) == False:
            signature = '"%s"' % pattern
            if SEARCH_CASE & sflag:
                pass
            else:
                signature += " nocase"
            # removed logic to check for ascii or wide, might as well do both. 
            #if SEARCH_UNICODE & sflag:
            signature += " wide ascii"
        yara_rule = "rule foo : bar { strings: $a = %s condition: $a }" % signature
        return yara_rule

    def _compile_rule(self, signature):
        try:
            rules = yara.compile(source=signature)
        except Exception as e:
            print "ERROR: Cannot compile Yara rule %s" % e
            return False, None
        return True, rules

    def _search(self, signature):
        status, rules = self._compile_rule(signature)
        if not status:
            return False, None
        values = []
        matches = rules.match(data=self.mem_results)
        if not matches:
            return False, None
        for rule_match in matches:
            for match in rule_match.strings:
                match_offset = match[0]
                values.append(self._to_virtual_address(match_offset, self.mem_offsets))
        return values

    def find_binary(self, bin_str, sflag=0):
        yara_sig = self._init_sig("binary", bin_str, sflag)
        offset_matches = self._search(yara_sig)
        return offset_matches

    def find_text(self, q_str, sflag=0):
        yara_sig = self._init_sig("text", q_str, sflag)
        offset_matches = self._search(yara_sig)
        return offset_matches

    def reload_scan_memory(self):
        self._get_memory()


def is_lib(ea):
    """
    is function a library 
    :param ea: 
    :return: if lib return True else return False
    """
    flags = idc.get_func_attr(ea, FUNCATTR_FLAGS)
    if flags & FUNC_LIB:
        return True
    else:
        return False


def get_func_symbols(ea):
    """
    get all symbol/api calls from a function  
    :param ea: offset within a function 
    :return: return list of symbol/api 
    """
    offsets = []
    dism_addr = list(idautils.FuncItems(ea))
    for addr in dism_addr:
        if ida_idp.is_call_insn(addr):
            op_type = idc.get_operand_type(addr, 0)
            if op_type == 1:
                temp = idc.generate_disasm_line(addr, 0)
                # hack to extract api name if added as a comment to call register
                # sadly, idaapi.is_tilcmt isn't populated for api names
                if ";" in temp:
                    temp_name = temp.split(";")[-1].strip()
                    if idc.get_name_ea_simple(temp_name) and "@" not in temp_name:
                        offsets.append((addr, temp_name))
                else:
                    continue
            elif op_type == 2:
                temp_name = Name(idc.get_operand_value(addr, 0))
                if "@" not in temp_name:
                    offsets.append((addr, temp_name))
            else:
                op_addr = idc.get_operand_value(addr, 0)
                if is_lib(op_addr):
                    temp_name = idc.get_func_name(op_addr)
                    if "@" not in temp_name:
                        offsets.append((addr, temp_name))
    return offsets


def get_func_str_hack(ea):
    """
    get all referenced strings within a function, actually works 
    :param ea: offset within a function 
    :return: return list of strings referenced in function 
    """
    offsets = []
    status, ea_st = get_func_addr(ea)
    if status:
        status, ea_end = get_func_addr_end(ea)
        if status:
            for _str in idautils.Strings():
                s_ea = _str.ea
                xref = idautils.XrefsTo(s_ea)
                for x in xref:
                    temp_addr = x.frm
                    if ea_st <= temp_addr <= ea_end:
                        offsets.append((temp_addr, _str))
    return offsets


def get_func_strings(ea):
    """
    get all referenced strings within a function, doesn't really work well 
    :param ea: offset within a function 
    :return: return list of strings referenced in a a function 
    """
    offsets = []
    dism_addr = list(idautils.FuncItems(ea))
    for addr in dism_addr:
        idaapi.decode_insn(addr)
        for count, op in enumerate(idaapi.cmd.Operands):
            # print count, op.type, hex(addr)[:-1], hex(idc.get_operand_value(addr, count))
            if op.type == idaapi.o_void:
                break
            if op.type == idaapi.o_imm or op.type == idaapi.o_mem:
                val_addr = idc.get_operand_value(addr, count)
                temp_str = idc.get_strlit_contents(val_addr)
                if temp_str:
                    if val_addr not in dism_addr and get_func_name(val_addr) == "":
                        offsets.append((addr, temp_str))
    return offsets


def get_func_values(ea):
    """
    get all integer values within a function
    :param ea: offset within a function 
    :return: return list of integer values within a function 
    """
    offsets = []
    dism_addr = list(idautils.FuncItems(ea))
    for addr in dism_addr:
        idaapi.decode_insn(addr)
        for c, v in enumerate(idaapi.cmd.Operands):
            if v.type == idaapi.o_void:
                break
            if v.type == idaapi.o_imm:
                value = idc.get_operand_value(addr, c)
                if not is_loaded(value):
                    offsets.append((addr, value))
            if v.type == idaapi.o_displ:
                value = idc.get_operand_value(addr, c)
                offsets.append((addr, value))
    return offsets


def generate_skeleton(ea):
    """
    auto generate all attributes from a function that can be used for rule creation
    :param ea: offset within a function 
    :return: return auto generated rule (likely needs to be edited)
    """
    skeleton = set([])
    status, ea = get_func_addr(ea)
    if status:
        for x in get_func_symbols(ea):
            skeleton.add("%s" % x[1])
        for x in get_func_str_hack(ea):
            skeleton.add("%s" % x[1])
        for x in get_func_strings(ea):
            skeleton.add("%s" % x[1])
        for x in get_func_values(ea):
            skeleton.add(int(x[1]))
    return list(skeleton)


def get_xrefsto(ea):
    """
    TODO
    :param ea:
    :return:
    """
    if ea:
        return [x.frm for x in idautils.XrefsTo(ea, 1)]
    else:
        return [] 


def get_func_addr(ea):
    """
    get function offset start
    :param ea: address
    :return: returns offset of the start of the function 
    """
    if ea:
        tt = idaapi.get_func(ea)
        if tt:
            return True, tt.startEA
    return False, None


def get_func_addr_end(ea):
    """
    get funtion offset end 
    :param ea: address
    :return: returns offset of the end of the function 
    """
    tt = idaapi.get_func(ea)
    if tt:
        return True, tt.end_ea
    return False, None


def func_xref_api_search(offset_list, api_list):
    """
    hmm apparently this isn't needed 
    :param offset_list:
    :param api_list:
    :return:
    """
    matches = []
    for offset in offset_list:
        xref_offset = get_xrefsto(offset)
        for xref_offset in xref_offset:
            func_calls = get_func_symbols(xref_offset)
            api_name = [x[1] for x in func_calls]
            if set(api_list).issubset(api_name):
                matches.append(idc.get_func_name(xref_offset))
    return matches


def search_binary(query):
    """
    search using yara patterns
    """
    global yara_search
    match = yara_search.find_binary(query)
    if match:
        func_match = []
        for offset in match:
            offset_xref = get_xrefsto(offset)
            if offset_xref:
                [func_match.append(x) for x in offset_xref]
            else:
                func_match.append(offset)
        if func_match:
            return True, func_match
    return False, None


def search_string(query):
    """
    search string, check if Name or string is present
    :param query:
    :return:
    """
    global yara_search
    name_offset = idc.get_name_ea_simple(query)
    if name_offset != BADADDR:
        match = get_xrefsto(name_offset)
        if match:
            func_match = match
            return True, func_match
    match = yara_search.find_text(query)
    if match:
        func_match = []
        for offset in match:
            offset_xref = get_xrefsto(offset)
            [func_match.append(x) for x in offset_xref]
        if func_match:
            return True, func_match
    return False, None


def search_value(value_list, dict_match):
    """
    search if value exists in function returns str of list
    :param value_list: list of values to search for 
    :param dict_match:
    :return: (Status, Matches)
    """
    func_addr = []
    if dict_match:
        temp_list = [[i for i in dict_match[kk]] for kk in dict_match.keys()]
        xref_offset = set(itertools.chain(*temp_list))
        for xref in xref_offset:
            status, offset = get_func_addr(xref)
            if status:
                func_addr.append(offset)
    else:
        func_addr = list(idautils.Functions())
    for func in func_addr:
        temp_func_values = set([x[1] for x in get_func_values(func)])
        if set(value_list).issubset(temp_func_values):
            for v in value_list:
                if v not in dict_match:
                    dict_match[v] = set([func])
                else:
                    dict_match[v].add(func)
    if dict_match:
        return True, dict_match
    return False, None


def search(*search_terms, **kwargs):
    """

    :param search_terms: tuple of strings, integers, API/Symbols, etc to search for 
    :return: tuple(Status, List) Status could be True or False, List of function matches offset
    """
    dict_match = {}
    value_list = []
    temp_comment = False
    temp_context = False
    temp_rename = False
    temp_file = False
    if "comment" in kwargs.keys():
        temp_comment = kwargs["comment"]
    if "rename" in kwargs.keys():
        temp_rename = kwargs["rename"]
    if temp_rename == False and "context" in kwargs.keys():
        temp_comment =  kwargs["context"]
    if "context" in kwargs.keys():
        temp_context = kwargs["context"]
    if "filename" in kwargs.keys():
        temp_file = kwargs["filename"]
    # start search 
    status = False
    for term in search_terms:
        if isinstance(term, str):
            # start yara search 
            if term.startswith("{"):
                status, yara_results = search_binary(term)
                if not status:
                    return False, None
                else:
                    for ea in yara_results:
                        status, offset = get_func_addr(ea)
                        if status:
                            if term not in dict_match:
                                dict_match[term] = [offset]
                            else:
                                dict_match[term].append(offset)
                        # single yara byte pattern search 
                        if len(search_terms) == 1 and yara_results[0] and status == False:
                            label_binary(yara_results, temp_comment)
                            return True, yara_results

            else:
                # start string search 
                status, string_results = search_string(term)
                if not status:
                    return False, None
                else:
                    for ea in string_results:
                        status, offset = get_func_addr(ea)
                        if status:
                            if term not in dict_match:
                                dict_match[term] = [offset]
                            else:
                                dict_match[term].append(offset)
        elif isinstance(term, int) or isinstance(term, long) :
            value_list.append(term)
    # start integer search 
    if value_list:
        if DEBUG:
            print "value_list %s" % value_list
        status, temp_match = search_value(value_list, dict_match)
        if status:
            dict_match = temp_match
    if DEBUG:
        print dict_match
    # cross-reference matches to a single function 
    if dict_match:
        if len(dict_match.keys()) == len(search_terms):
            func_list = [set(dict_match[key]) for key in dict_match.keys()]
            if len(search_terms) == 1:
                label_(func_list[0], temp_comment, temp_rename)
                return True, func_list[0]
            func_match = set.intersection(*func_list)
            if func_match:
                label_(func_match, temp_comment, temp_rename)
                return True, func_match
    return False, None


def label_(func_match, temp_comment, temp_rename):
    """
    adds comment or renames function 
    :param func_match: function offset 
    :param temp_comment: string comment 
    :param temp_rename: string function name 
    :return:
    """
    for match in func_match:
        if temp_comment:
            comm_func(match, temp_comment)
        if temp_rename:
            name_func(match, temp_rename)


def name_func(ea, name):
    """
    Rename a function, appends string if already renamed
    :param ea: start offset to a function 
    :param name:
    :return:
    TODO check warnings and increment if name is present 
    """
    f = idc.get_full_flags(ea)
    if not idc.hasUserName(f):
        idc.set_name(ea, name, SN_CHECK)
    else:
        temp = idc.get_name(ea)
        # do not rename WinMain 
        if name in temp or "winmain" in temp.lower():
            return
        temp_name = temp + "_" + name
        idc.set_name(ea, temp_name, SN_CHECK)


def comm_func(ea, comment):
    """
    Add function comment 
    :param ea: start offset to a function 
    :param comment: string of comment to add 
    :return: None 
    """
    temp = idc.get_func_cmt(ea, True)
    if comment in temp:
        return
    if temp:
        tt = temp + " " + comment
        idc.set_func_cmt(ea, tt, True)
    else:
        idc.set_func_cmt(ea, comment, True)


def label_binary(yara_match, comment):
    if comment:
        for ea in yara_match:
            temp = idc.get_cmt(ea, True)
            if temp:
                if comment in temp:
                    continue 
                tt = temp + " " + comment 
                idc.set_cmt(ea, tt, True)
            else:
                idc.set_cmt(ea, comment, True)


def save_search(*search_terms, **kwargs):
    """
    save search to a file (specified with `file_name=FILENAME`)
    :param search_terms: search string. 
    :return: None 
    """
    temp_rule = ""
    if "filename" in kwargs.keys():
        temp_rule = kwargs["filename"]
        kwargs.pop("filename", None)
    save = {}
    save["search_terms"] = search_terms
    save["kwargs"] = kwargs
    rule_path = get_rules_dir()
    if temp_rule:
        file_name = temp_rule
        temp_name = os.path.join(rule_path, file_name)
        if os.path.exists(temp_name):
            with open(str(temp_name), "a+") as f_h:
                f_h.write(json.dumps(save))
                f_h.write("\n")
        else:
            with open(temp_name, "w") as f_h:
                f_h.write(json.dumps(save))
                f_h.write("\n")
    else:
        print 'ERROR: Must supply argument with file name filename="FOO.rule"'


def add_hotkey():
    """
    enable hotkey of ALT-/
    """
    ida_kernwin.add_hotkey("Alt-/", hotkey_rule)


def hotkey_rule():
    """
    create rule using date as file name using the current function as the input for the skelton rule 
    :return:
    """
    # get skelton 
    ea = here()
    skeleton = generate_skeleton(ea)
    save = {} 
    save["search_terms"] = skeleton
    # get context 
    function_addr = "0x%x" % (get_func_addr(ea)[1])
    context = "%s, %s" % (idc.get_idb_path(), function_addr)
    save["kwargs"] = {"context" : context}
    # get path and create file name
    rule_path = get_rules_dir()
    temp_name = str(datetime.datetime.now().strftime("%Y-%m-%d")) + ".rule"
    file_path = os.path.join(rule_path, temp_name)
    if os.path.exists(file_path):
        with open(str(file_path), "a+") as f_h:
            f_h.write(json.dumps(save))
            f_h.write("\n")
    else:
        with open(file_path, "w") as f_h:
            f_h.write(json.dumps(save))
            f_h.write("\n")


def get_rules_dir():
    """
    helper function that gets the rule directory 
    :return: string of the path to the rule directory 
    """
    if RULES_DIR:
        return RULES_DIR
    else:
        return os.path.join(os.path.dirname(inspect.getfile(inspect.currentframe())), "rules")


def run_rules():
    """
    run search using all rules in the rule directory 
    :return: None 
    """
    rule_path = get_rules_dir()
    paths = glob.glob(rule_path + "\*")
    for path in paths:
        if os.path.isdir(path):
            continue
        with open(path, "r") as rule:
            for line_search in rule.readlines():
                try:
                    # convert unicode to ascii
                    saved_rule = byteify(json.loads(line_search))
                    rule = saved_rule["search_terms"]
                    kwarg = saved_rule["kwargs"]
                    print saved_rule.keys()
                    status, match = search(*rule,**kwarg)
                    if status:
                        for m in match:
                            print "RULE(s): %s" % rule_path
                            print "\tSEARCH: %s" % rule
                            print "\tMatch at 0x%x" % m
                except Exception as e:
                    print "ERROR: Review file %s rule %s, %s" % (path, line_search.rstrip(), e)


def run_rule(rule_name):
    """
    search using a single file
    :param rule_name: string file name to save rule to 
    :return: None 
    """
    rule_dir = get_rules_dir()
    rule_path = os.path.join(rule_dir, rule_name)
    if os.path.isfile(rule_path):
        with open(rule_path, "r") as rule:
            for line_search in rule.readlines():
                try:
                    # convert unicode to ascii
                    saved_rule = byteify(json.loads(line_search))
                    rule = saved_rule["search_terms"]
                    kwarg = saved_rule["kwargs"]
                    status, match = search(*rule,**kwarg)
                    if status:
                        for m in match:
                            print "RULE(s): %s" % rule_path
                            print "\tSEARCH: %s" % rule
                            print "\tMatch at 0x%x" % m
                except Exception as e:
                    print "ERROR: Review file %s rule %s, %s" % (rule_path, line_search.rstrip(), e)
                    if DEBUG:
                        print traceback.format_exc()

    else:
        print "ERROR: File %s could not be found"


def cheat_sheet():
    print """
    search("query1", "query2", comment="My_Comment", rename="FUNCTION_NAME")
    save_search( "query1",file_name="RULE_NAME.rule", comment="My_Comment", rename="FUNCTION_NAME")
    run_rule("RULES_NAME.rule")
    run_rules() <- no arguments
    hot_key() <- saves output of generate_skelton(ea) to rules directory with the date as the name   
    added by hot_key() context="XYZ.idb, 0x40000 = func offset"
     """


def byteify(input):
    # source https://stackoverflow.com/a/13105359
    if isinstance(input, dict):
        return {byteify(key): byteify(value)
                for key, value in input.iteritems()}
    elif isinstance(input, list):
        return [byteify(element) for element in input]
    elif isinstance(input, unicode):
        return input.encode('utf-8')
    else:
        return input


if not INIT:
    yara_search = YaraIDASearch()
    add_hotkey()
    INIT = True 

