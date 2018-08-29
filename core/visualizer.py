import json
import pprint

import utility as util

def visualize_dict_results(results: dict, outfile: str):
    print(util.BRIGHT_BLUE + "Results:" + util.SANE)
    pprint.pprint(results)
    with open(outfile, "w") as f:
        f.write(json.dumps(results, ensure_ascii=False, indent=3))
    print()
