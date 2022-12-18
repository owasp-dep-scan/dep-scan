import argparse
import json
import os
import sys
from jsonschema import validate
from jsonschema.exceptions import ValidationError


def build_args():
    """
    Constructs command line arguments for the comparison tool
    """
    parser = argparse.ArgumentParser(
        description="Validate VEX files against BOM 1.4 schema."
    )
    parser.add_argument(
        "--json",
        dest="vex_json",
        default="sbom-docker.vex.json",
        help="Vex json file.",
    )
    return parser.parse_args()


def vvex(vex_json):
    schema = os.path.join(os.path.dirname(__file__), "bom-1.4.schema.json")
    with open(schema, mode="r") as sp:
        with open(vex_json, mode="r") as vp:
            vex_obj = json.load(vp)
            try:
                validate(instance=vex_obj, schema=json.load(sp))
                print ("VEX file is valid")
            except ValidationError as ve:
                print(ve)
                sys.exit(1)


def main():
    args = build_args()
    vvex(args.vex_json)


if __name__ == "__main__":
    main()
