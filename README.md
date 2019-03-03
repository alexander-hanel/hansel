# Hansel 
A simple but flexible search for IDA. 

Bytes, strings, symbols and values from enumerated types are sometimes all that is needed to identify a function’s functionality. For example, cross-referencing `CreateToolhelp32Snapshot` and `TerminateProcess` to a single function can be used to inter that an executable might have functionality to kill a remote process. Or another example might be identifying a function as SHA256 because of the presence of `0x6a09e667` and `0xbb67ae85`. Overtime functionality can be quickly identified during the reverse engineering process because of the reappearing attributes. Hansel can be used to search for these attributes, label and comment functions with these attributes or automatically extract these attributes from a function. All of this starts with the search function. It can contain arguments of strings (`foo`), integers (`0xFFFFFFFF`) or byte patterns (`{55 8B EC}`). There are keywords that are covered later on. The goal of the search is to be as simple as possible. Nothing needs to be defined from a search perspective. The following snippet searches for `CreateToolhelp32Snapshot` and `TerminateProcess`. The return of `search` is a tuple. The first value is a bool stating if the search was `True` or `False`. The second value is a set of offsets that contains the start offset of function or functions the search matches on. 

```python
Python>search("CreateToolhelp32Snapshot", 0xFFFFFFFF, "TerminateProcess", )
(True, set([4249808L]))
```
To rename the function that matches the search add `”rename=NewFunctionName”`. To add a function comment that matches the search add `"comment=My Comment"`. Please note that these commands are within strings. The following snippet is the previous search with function comment and labeling added.
```python
search("CreateToolhelp32Snapshot", 0xFFFFFFFF, "TerminateProcess", "rename=kill_process", "comment=kill process" )
```

Searches can be saved to a rules file by calling `save_search()`. This function must contain `“file_name=FILE.rule”`. The following snippet is the working example saved to a file named ` kill_process.rule`. 
```python 
save_search("CreateToolhelp32Snapshot", 0xFFFFFFFF, "TerminateProcess", "file_name=kill_process.rule", "rename=kill_process", "comment=kill process" ) 
```
To search using rules saved in a file the function `run_rule(rule_name)` is used. 

```python 
Python>run_rule("kill_process.rule")
RULE(s): C:/Users/REMOVED/Documents/repo/hansel\rules\kill_process.rule
	SEARCH: ['CreateToolhelp32Snapshot', 4294967295L, 'TerminateProcess', 'rename=kill_process', 'comment=kill process']
	Match at 0x40d8d0
```
To run all rules the function `run_rules()` can be used. Attributes can be extracted from a function by calling `generate_skeleton(ea)`. 

```python
Python>generate_skeleton(here())
['CreateToolhelp32Snapshot', 0, 2, 1, 556, 'lstrlenW', 'Process32NextW', 'OpenProcess', 'CharUpperBuffW', 'Process32FirstW', 1600, 'lstrcpyW', 4294965704L, 4294965696L, 'CloseHandle', 'TerminateProcess', 'lstrcmpW', 4294965732L, 4294966252L, 4294966772L, 4294967292L, 4294967295L]
```
To quickly save attributes from a function and revisit them at a later date, the hotkey `ALT-/` can be used. The rules are saved in the rules directory within the working directory of the Hansel repo. The rule file name is the current date `YEAR-MONTH-DAY.rule` (example: ` 2019-03-03.rule`). The search contains a field name `context` that has the IDB path and function offset.  The following is an example of a rule file. 
```
["CreateToolhelp32Snapshot", 0, 2, 1, 556, "lstrlenW", "Process32NextW", "OpenProcess", "CharUpperBuffW", "Process32FirstW", 1600, "lstrcpyW", 4294965704, 4294965696, "CloseHandle", "TerminateProcess", "lstrcmpW", 4294965732, 4294966252, 4294966772, 4294967292, 4294967295, "context=C:\\Users\\REMOVED\\Desktop\\EXAMPLE\\foo.idb, 0x40d8d0"]
```

The function `cheat_sheet()` can used to retrieve all the needed APIS and their keywords. 

```python  
Python>cheat_sheet()

    search("query1", "query2", "comment=My_Comment", "rename=FUNCTION_NAME")
    save_search( "query1","file_name=RULE_NAME.rule", "comment=My_Comment", "rename=FUNCTION_NAME")
    run_rule("RULES_NAME.rule")
    run_rules() <- no arguments
    hot_key() <- saves output of generate_skelton(ea) to rules directory with the date as the name   
    added by hot_key() "context=XYZ.idb"
```

Hansel uses Yara to search for strings and bytes. When loaded it copies data from the IDB into memory that Yara can search. On VMs with limited memory, the copying can take a second to load. A status is displayed on IDA’s command line. 
```
Status: Loading memory for Yara.
Status: Memory has been loaded.
```
If a rule throws an error it is likely because the search breaks Yara’s search syntax (mostly strings that need escape sequences). As previously mentioned Hansel returns the start of the function that contains the match. If the search is a single byte pattern rule and with no function cross-reference(s) than the byte pattern match is returned. 
```python
Python>search("{7F 7F 7F 7F 7F 7F 7F 7F  40 56 41 00 84 62 41 00 }")
(True, [4281968L])
```

## Status
- Stablish. I’m still testing all the possible combinations of searches and keywords.  
- Daily usage so bugs will be fixed. 
  

