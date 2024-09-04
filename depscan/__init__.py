from importlib.metadata import distribution


def get_version():
    """
    Returns the version of depscan
    """
    return distribution("owasp-depscan").version
