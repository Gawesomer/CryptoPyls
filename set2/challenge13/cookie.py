def decode_cookie(encoded: str) -> dict:
    """
    params:
        encoded: formated as `var1=val1&var2=val2&...&varn=valn`
    returns:
        var to val dictionary
    """
    res = {}
    for e in encoded.strip('&').split('&'):
        try:
            var, val = e.split('=')[:2]
        except (ValueError):
            var = e.split('=')[0]
            val = ''
        res[var] = val
    return res


def encode_cookie(decoded: dict) -> str:
    """
    params:
        decoded
    returns:
        encoded string representation of `decoded`
        formated as `var1=val1&var2=val2&...&varn=valn`
    """
    res = ""
    for var, val in decoded.items():
        res += "{var}={val}&".format(var=var, val=val)
    return res[:len(res)-1]
