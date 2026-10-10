"""VULNERABLE SAMPLE: eval / exec code execution."""


def dangerous_eval(expr):
    # eval of (potentially) untrusted expression
    return eval(expr)


def dangerous_exec(code):
    # exec of arbitrary code
    exec(code)
