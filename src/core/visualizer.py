import json
import pprint

import core.utility as util

def visualize_dict_results(results: dict, outfile: str):
    """
    Print the results stored in the given dict and write them to the output file.
    """
    print(util.BRIGHT_BLUE + "Results:" + util.SANE)
    pprint.pprint(results)
    with open(outfile, "w") as file:
        file.write(json.dumps(results, ensure_ascii=False, indent=3))
    print()
