
def check_public_key_blob():
    RSA_KEY_HEADER = "06 02 00 00 00 A4 00 00 52 53 41 31"
    blob_offset = ida_yara.yara_find_binary(here(), RSA_KEY_HEADER, 0)
    return blob_offset


def check_private_key_blob():
    RSA_PRIVATE_KEY_HEADER = "07 02 00 00 00 A4 00 00"
    blob_offset = ida_yara.yara_find_binary(here(), RSA_PRIVATE_KEY_HEADER, 0)
    return blob_offset


def check_public_key_pem():
    # IDA's regex appears to be limited on wildcard matches
    PATTERN = "-----BEGIN PUBLIC KEY-----"
    pem_offset = ida_yara.yara_find_text(here(), 0, 0, PATTERN)
    return pem_offset


def find_base64_usage():
    BASE64_TABLE = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'
    base64_offset = ida_yara.yara_find_text(here(), 0, 0, BASE64_TABLE)
    return base64_offset


def find_base64_usage():
    status = False
    offsets = set([])
    table_match = ida_yara.yara_find_text(here(), 0, 0,
                                          'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/')
    for offset in table_match:
        print "BASE64 Table at offset 0x%x" % offset
        base64_xrefs = get_xrefsto(offset)
        for xrefs in base64_xrefs:
            print "BASE64 Table references in function %s at offset 0x%x" % (idc.get_func_name(xrefs), xrefs)
            offsets.add(xrefs)
            status = True
    if status:
        return True, list(offsets)
    else:
        return False, None