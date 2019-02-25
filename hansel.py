"""
hex-bytes, strings, api-name, integer values
TODO
 - yara rule error handling 
 - create report 

search attributes "file_name=", "comment=", "rename=", "name="
"""

import idautils
import datetime
import glob
import yara
import operator
import itertools
import inspect
import os
import sys
import json

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


# TODO - add logic for loading yara memory
yara_search = YaraIDASearch()


def search(*search_terms):
    """

    :param search_terms: tuple of strings, integers, API/Symbols, etc to search for 
    :return: tuple(Status, List) Status could be True or False, List of function matches offset
    """
    dict_match = {}
    value_list = []
    # remove non-search attributes for renaming or commenting matches
    comment = False
    rename_func = False
    context = False
    file_name = False
    # TODO - check that type is string and not int
    temp_comment = [x for x in search_terms if "comment=" in str(x)]
    temp_rename = [x for x in search_terms if "rename=" in str(x)]
    temp_context = [x for x in search_terms if "context=" in str(x)]
    temp_file = [x for x in search_terms if "file_name=" in str(x)]
    if temp_comment:
        search_terms = [x for x in search_terms if x != temp_comment[0]]
        temp_comment = temp_comment[0].replace("comment=", "")
    if temp_rename:
        search_terms = [x for x in search_terms if x != temp_rename[0]]
        temp_rename = temp_rename[0].replace("rename=", "")
    if temp_context:
        search_terms = [x for x in search_terms if x != temp_context[0]]
    if temp_file:
        search_terms = [x for x in search_terms if x != temp_file[0]]
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
        elif isinstance(term, int):
            value_list.append(term)
    # start integer search 
    if value_list:
        status, temp_match = search_value(value_list, dict_match)
        if status:
            dict_match = temp_match
    # cross-reference matches to a single function 
    if dict_match:
        if len(dict_match.keys()) == len(search_terms):
            func_list = [set(dict_match[key]) for key in dict_match.keys()]
            if len(search_terms) == 1:
                label_(func_match, temp_comment, temp_rename)
                return True, func_list[0]
            func_match = set.intersection(*func_list)
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
    """
    f = idc.get_full_flags(ea)
    if not idc.hasUserName(f):
        idc.set_name(ea, name, SN_CHECK)
    else:
        temp = idc.get_name(ea)
        if name in temp:
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


def save_search(*search_terms):
    """
    save search to a file (specified with `file_name=FILENAME`)
    :param search_terms: search string. 
    :return: None 
    """
    temp_rule = [x for x in search_terms if "file_name=" in x]
    rule_path = get_rules_dir()
    if temp_rule:
        file_name = temp_rule[0].replace("file_name=", "")
        temp_name = os.path.join(rule_path, file_name)
        rules = [x for x in search_terms if x != temp_rule[0]]
        if os.path.exists(temp_name):
            with open(str(temp_name), "a+") as f_h:
                f_h.write(json.dumps(rules))
                f_h.write("\n")
        else:
            with open(temp_name, "w") as f_h:
                f_h.write(json.dumps(rules))
                f_h.write("\n")
    else:
        print "ERROR: Must supply argument with file name `file_name=FOO.rule`"


def hotkey_rule():
    """
    TODO : add IDA Hotkey 
    create rule using date as file name using the current function as the input for the skelton rule 
    :return:
    """
    ea = here()
    skeleton = generate_skeleton(ea)
    function_addr = "0x%x" % (get_func_addr(ea)[1])
    context = "context=%s, %s" % (idc.get_idb_path(), function_addr)
    skeleton.append(context)
    rule_path = get_rules_dir()
    temp_name = str(datetime.datetime.now().strftime("%Y-%m-%d")) + ".rule"
    file_path = os.path.join(rule_path, temp_name)
    if os.path.exists(file_path):
        with open(str(file_path), "a+") as f_h:
            f_h.write(json.dumps(skeleton))
            f_h.write("\n")
    else:
        with open(file_path, "w") as f_h:
            f_h.write(json.dumps(skeleton))
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
        print "RULE(s): %s" % path
        with open(path, "r") as rule:
            for line_search in rule.readlines():
                try:
                    # convert unicode to ascii
                    rule = byteify(json.loads(line_search))
                    print "\tSEARCH: %s" % rule
                    status, match = search(*rule)
                    if status:
                        for m in match:
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
        print "RULE(s): %s" % rule_path
        with open(rule_path, "r") as rule:
            for line_search in rule.readlines():
                try:
                    # convert unicode to ascii
                    rule = byteify(json.loads(line_search))
                    print "\tSEARCH: %s" % rule
                    status, match = search(*rule)
                    if status:
                        for m in match:
                            print "\tMatch at 0x%x" % m
                except Exception as e:
                    print "ERROR: Review file %s rule %s, %s" % (rule_path, line_search.rstrip(), e)

    else:
        print "ERROR: File %s could not be found"


def format_search(*search_terms):
    """
    TODO 
    :param search_terms:
    :return:
    """
    status, func_match = search(search_terms)


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
