from utils.config import globalVars as gV
import re
def make_list(data):
    if 'str' in str(type(data)):
        return [data]
    else:
        return data


def var(name):
    return gV[name]

def deJSON(data):
    return data.replace('\\\\', '\\')

def script_extractor(response):
    """Extract js files from the response body"""
    scripts = []
    matches = re.findall(r'<(?:script|SCRIPT).*?(?:src|SRC)=([^\s>]+)', response)
    for match in matches:
        match = match.replace('\'', '').replace('"', '').replace('`', '')
        scripts.append(match)
    return scripts

def js_extractor(response):
    """Extract js code from the response body"""
    scripts = []
    matches = re.finditer(r'(?m)<(?:script|SCRIPT)[^>]*>(.*?)</(?:script|SCRIPT)>', response)
    for match in matches:
        scripts.append(match.group(1))
    return scripts