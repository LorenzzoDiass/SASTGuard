"""VULNERABLE SAMPLE: Insecure deserialization."""
import pickle

import yaml


def load_pickle(blob):
    # Unpickling untrusted data -> RCE
    return pickle.loads(blob)


def load_yaml(stream):
    # yaml.load without SafeLoader -> arbitrary object construction
    return yaml.load(stream)
