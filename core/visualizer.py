import json
import pprint

import core.utility as util

def visualize_dict_results(title: str, results: dict, outfile: str):
    """
    Print the results stored in the given dict and write them to the output file.
    """
    print(title)
    pprint.pprint(results)
    with open(outfile, "w") as file:
        file.write(json.dumps(results, ensure_ascii=False, indent=3))
    print()
