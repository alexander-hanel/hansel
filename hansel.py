
"""
hex-bytes, strings, api-name, integer values
TODO
 - function rename 
 - add comments 
 - yara rule error handling 
 - load search
 - create report 
"""


import idautils
import yara
import operator
import itertools
import inspect
import os 
import sys 

SEARCH_CASE = 4
SEARCH_REGEX = 8
SEARCH_NOBRK = 16
SEARCH_NOSHOW = 32
SEARCH_UNICODE = 64
SEARCH_IDENT = 128
SEARCH_BRK = 256

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
            if SEARCH_UNICODE & sflag:
                signature += " wide"
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
    flags = idc.get_func_attr(ea, FUNCATTR_FLAGS)
    if flags & FUNC_LIB:
        return True
    else:
        return False


def get_func_symbols(ea):
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
    offsets = []
    dism_addr = list(idautils.FuncItems(ea))
    for addr in dism_addr:
        length = idaapi.decode_insn(addr)
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
    # TODO
    return [x.frm for x in idautils.XrefsTo(ea, 1)]


def get_func_addr(ea):
    tt = idaapi.get_func(ea)
    if tt:
        return True, tt.startEA
    return False, None


def get_func_addr_end(ea):
    tt = idaapi.get_func(ea)
    if tt:
        return True, tt.end_ea
    return False, None


def func_xref_api_search(offset_list, api_list):
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
    """search using yara patterns"""
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
    """search string, check if Name or string is present"""
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
    """search if value exists in function
    returns str of list
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


# TODO how to deal with unicode strings?
#   - check if string is unicode then add flag? boom!

yara_search = YaraIDASearch()

def search(*search_terms):
    dict_match = {}
    value_list = []
    # remove non-search attributes for renaming or commenting matches
    comment = False
    rename_func = False
    temp_comment = [x for x in search_terms if "comment=" in x ]
    temp_rename = [x for x in search_terms if "rename=" in x ]
    if temp_comment:
    	search_terms = [x for x in search_terms if x != temp_comment[0]]
    if temp_rename:
    	search_terms = [x for x in search_terms if x != temp_rename[0] ]
    # start search 
    status = False 
    print
    print search_terms
    for term in search_terms:
        if isinstance(term, str):
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
    if value_list:
        status, temp_match = search_value(value_list, dict_match)
        if status:
            dict_match = temp_match
    if dict_match:
        if len(dict_match.keys()) == len(search_terms):
            func_list = [set(dict_match[key]) for key in dict_match.keys()]
            if len(search_terms) == 1:
                return True, func_list[0]
            func_match = set.intersection(*func_list)
            return True, func_match
    return False, None


def name_func(query, name):
    status, func_set = query
    for count, func in enumerate(func_set):
        temp_name = "%s_%s" % (name, count)
        idc.set_name(func, temp_name, SN_CHECK)


def comm_func(query, name):
    status, func_set = query
    for func in func_set:
        idc.MakeRptCmt(func, name)


def load_search(path):
	rule_path = get_rules_dir()


def save_search(*search_terms):
	temp_rule = [x for x in search_terms if "file_name=" in x ]
	rule_path = get_rules_dir()
	if temp_rule:
		file_name = temp_rule[0].replace("file_name=", "")
		temp_name = os.path.join(rule_path, file_name)
		rules = [x for x in search_terms if x != temp_rule[0]]
		print rules
		print temp_rule
		if os.path.exists(temp_name):
			with open(str(temp_name), "a+") as f_h:
				f_h.write(str(rules))
				f_h.write("\n")
		else:
			with open(temp_name, "w") as f_h:
				f_h.write(str(rules))
				f_h.write("\n")
	else:
		print "ERROR: Must supply argument with file name `file_name=FOO.rule`"


def get_rules_dir():
	return os.path.join(os.path.dirname(inspect.getfile(inspect.currentframe())), "rules")



