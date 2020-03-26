import json
import math
import os
import pty
import re
import shutil
import subprocess

from core.result_types import ResultType
import core.utility as util

# Constants for variable and results sharing
INTERMEDIATE_RESULTS = {ResultType.SCAN: {}, ResultType.WEBSERVER_MAP: {}}
CONFIG = {}
LOGGER = None
VERBOSE = True

# output files
SQLMAP_OUTFILE = "sqlmap_output.txt"
SQLMAP_OUTFILE_COLOR = "sqlmap_output_color.txt"
FOUND_SQLI_JSON = "found_sqli.json"
DATA_DUMP_FILE = "data_dump.txt"
SQLMAP_OUTPUT_DIR = "sqlmap_out_dir"
CREATED_FILES = [SQLMAP_OUTFILE, SQLMAP_OUTFILE_COLOR, FOUND_SQLI_JSON, DATA_DUMP_FILE, SQLMAP_OUTPUT_DIR]


def run(results: list):
    """ Entry point for module """

    webserver_map = INTERMEDIATE_RESULTS[ResultType.WEBSERVER_MAP]
    result = {}
    vuln_dict = {}
    sqlmap_out_fd = open(SQLMAP_OUTFILE, "w")
    sqlmap_out_color_fd = open(SQLMAP_OUTFILE_COLOR, "w")

    # loop over every target, identified by ip, hostname and port
    for ip in webserver_map:
        ip_vulnerable = False
        for portid in webserver_map[ip]:
            for host, host_node in webserver_map[ip][portid].items():
                # determine protocol from scan results if available
                protocol = "http"
                if (ip in INTERMEDIATE_RESULTS[ResultType.SCAN] and
                        portid in INTERMEDIATE_RESULTS[ResultType.SCAN][ip] and
                        "service" in INTERMEDIATE_RESULTS[ResultType.SCAN][ip][portid]):
                    protocol = INTERMEDIATE_RESULTS[ResultType.SCAN][ip][portid]["service"]

                # check host for SQLi
                base_url = "%s://%s:%s" % (protocol, host, portid)
                host_vuln_dict = check_host(base_url, host_node, sqlmap_out_fd, sqlmap_out_color_fd)
                if host_vuln_dict:
                    if ip not in vuln_dict:
                        vuln_dict[ip] = {}
                    if portid not in vuln_dict:
                        vuln_dict[ip][portid] = {}
                    vuln_dict[ip][portid][host] = host_vuln_dict
                    ip_vulnerable = True

        # assign vulnerability score to current ip if vulnerable to SQLi
        if ip_vulnerable:
            result[ip] = 9.8

    # store info about discovered SQLis
    with open(FOUND_SQLI_JSON, "w") as f:
        f.write(json.dumps(vuln_dict, indent=2))

    # dump information if there are SQLi vulns
    if vuln_dict and CONFIG["dump_data"].lower() == "true":
        dump_data(vuln_dict)

    # close sqlmap output files
    sqlmap_out_fd.close()
    sqlmap_out_color_fd.close()

    # return results
    results.append((ResultType.VULN_SCORE, result))


def check_host(base_url, host_node, sqlmap_out_fd, sqlmap_out_color_fd):
    """
    Check the host identified by given paramters for SQL Injections.

    :param base_url: URL of this host in the form of protocol://domain:port
    :param host_node: webserver_map node of the host (status_code:page_node pairs)
    :param sqlmap_out_fd: FD (file) of where to write uncolored sqlmap output to
    :param sqlmap_out_color_fd: FD (file) of where to write colored sqlmap output to
    :return: a dict containing discovered SQLi vulnerability data
    """

    def reader(fd):
        """Read from the given file descriptor"""
        try:
            while True:
                buffer = os.read(fd, 1024)
                if not buffer:
                    return
                yield buffer
        except (IOError, OSError) as e:
            pass

    # iterate over every web path and check its parameters for SQLi
    vuln_params = {}
    for status_code, pages_node in host_node.items():
        # only check paths with 2* or 5* status code
        if status_code.startswith("2") or status_code.startswith("5"):
            if not pages_node:
                continue

            for path, path_node in pages_node.items():
                # skip HTTP methods that are not GET or POST
                if ("GET" not in path_node) and ("POST" not in path_node):
                    continue

                # create sqlmap calls to execute
                sqlmap_calls = create_sqlmap_calls(base_url, path, path_node)
                if sqlmap_calls and VERBOSE:
                    util.acquire_print()
                    print(util.GREEN + "[+] " + util.SANE + "Checking " + util.YELLOW + base_url + path)
                    print(util.BRIGHT_BLUE + "    GET: " + util.SANE + ", ".join(path_node.get("GET", ["N/A"])) + "  ")
                    print(util.MAGENTA + "    POST: " + util.SANE + ", ".join(path_node.get("POST", ["N/A"])) + "\n")
                    util.release_print()
                    util.printit("\n")

                # execute created sqlmap calls one by one
                sqlmap_output = ""
                for call_nr, call in enumerate(sqlmap_calls):
                    if VERBOSE:
                        print_progress(call_nr, len(sqlmap_calls))

                    # run sqlmap call in separate PTY to capture colored ouput
                    # adapted from: https://stackoverflow.com/a/28925318
                    master, slave = pty.openpty()
                    with subprocess.Popen(call, stdout=slave, stderr=subprocess.STDOUT,
                                          bufsize=1, universal_newlines=True) as proc:
                        os.close(slave)
                        for line in reader(master):
                            line = line.decode()
                            if VERBOSE and CONFIG["show_sqlmap_output"].lower() == "true":
                                util.printit(line, end="")
                            sqlmap_out_color_fd.write(line)
                            line = util.strip_ansi_escape_seq(line)
                            sqlmap_out_fd.write(line)
                            sqlmap_output += line
                    os.close(master)

                # print final progress for this path (100%)
                if VERBOSE and sqlmap_calls:
                    print_progress(len(sqlmap_calls), len(sqlmap_calls))

                # extract vulnerable HTTP parameters from sqlmap output
                path_vuln_params = process_sqlmap_output(call, sqlmap_output)
                if path_vuln_params:
                    vuln_params[path] = path_vuln_params

                # either print full sqlmap output or a summary thereof
                if VERBOSE and CONFIG["show_sqlmap_output"].lower() == "true":
                    columns = shutil.get_terminal_size((80, 20)).columns
                    util.printit("=" * columns + "\n")
                elif VERBOSE:
                    if not path_vuln_params:
                        util.printit("    No SQLi found.", color=util.RED)
                    else:
                        util.printit(util.GREEN + "    Found SQLi:" + util.SANE)
                        for method in ("GET", "POST"):
                            if method in path_vuln_params:
                                for param in path_vuln_params[method]:
                                    sqli_vectors = path_vuln_params[method][param]["sqlis"]
                                    color = util.BRIGHT_BLUE if method == "GET" else util.MAGENTA
                                    util.printit(" "*8 + color + param + util.SANE + ":")
                                    for vector in sqli_vectors:
                                        util.printit(" " * 12 + "- " + vector["title"])

    return vuln_params


def print_progress(cur_nr, total):
    """ Print progress of testing a path for SQLi """

    bar_count = shutil.get_terminal_size((80, 20)).columns // 2  # half the terminal width
    completed_bars, remaining_bars = cur_nr, total - cur_nr
    if total > bar_count:
        completed_bars = int(cur_nr * bar_count / total)
        remaining_bars = bar_count - completed_bars

    if CONFIG.get("show_sqlmap_output", "false").lower() == "false":
        util.clear_previous_line()
        util.clear_previous_line()
    print_str = "    Progress: [" + util.GREEN + completed_bars * "=" + util.SANE + remaining_bars * "·" + "] "
    print_str += "(%d/%d sqlmap calls)\n" % (cur_nr, total)
    util.printit(print_str)


def create_sqlmap_calls(base_url, path, path_node):
    """
    Create all sqlmap calls that test for SQLis at the given path.

    :param base_url: URL of this host in the form of protocol://domain:port
    :param path: the path to test
    :param path_node: entry in webserver map for the given path
    :return: a list of sqlmap calls
    """

    def build_call(inject_params=None):
        """ Build sqlmap call from HTTP queries, cookies and config parameters """

        nonlocal get_query, post_query, cookie_str

        # build base call and append queries, cookies and config values
        refresh_intent_answer = "N" if CONFIG.get("follow_refresh_intent", "false").lower() == "false" else "Y"
        sqlmap_call = ["sqlmap", "-u", base_url + path + get_query, "--batch", "-o", "--answers=is vulnerable. Do you want to keep testing the others=Y,crack=N,want to update=N,got a refresh intent=%s" % refresh_intent_answer]
        sqlmap_call.append("--output-dir=" + SQLMAP_OUTPUT_DIR)
        if post_query:
            sqlmap_call += ["--data=" + post_query, "--method=POST"]
        if cookie_str:
            sqlmap_call += ["--cookie=" + cookie_str]
        if "threads" in CONFIG:
            sqlmap_call += ["--threads=" + CONFIG["threads"]]
        if "user_agent" in CONFIG:
            sqlmap_call += ["--user-agent=" + CONFIG["user_agent"]]
        if CONFIG.get("ignore_code", "").strip():
            sqlmap_call += ["--ignore-code=%s" % CONFIG["ignore_code"].replace(" ", "")]
        if CONFIG.get("level", "").strip():
            sqlmap_call += ["--level=%d" % int(CONFIG["level"].strip())]
        if CONFIG.get("risk", "").strip():
            sqlmap_call += ["--risk=%d" % int(CONFIG["risk"].strip())]
        if inject_params:
            sqlmap_call += ["-p", ",".join(inject_params)]

        return sqlmap_call


    # get instance infos and parameter scores
    inst_infos, scores = score_params(path_node)

    # sort parameters based on commonality score
    sorted_params = {}
    sorted_params["GET"] = sorted(scores["GET"], key=lambda p: scores["GET"][p], reverse=True)
    sorted_params["POST"] = sorted(scores["POST"], key=lambda p: scores["POST"][p], reverse=True)

    # setup test parameters and common parameters
    test_params = get_test_params(sorted_params)
    num_common_params = int(CONFIG.get("num_common_params", 1))
    common_params = {"GET": sorted_params["GET"][:num_common_params],
                     "POST": sorted_params["POST"][:num_common_params]}

    # create sqlmap calls
    sqlmap_calls = []
    max_per_param_tests = int(CONFIG.get("max_per_param_tests", 3))
    default_param_value = CONFIG.get("default_fill_value", "helloworld")
    prev_inj_params = {"GET": {p: [] for p in test_params["GET"]},
                       "POST": {p: [] for p in test_params["POST"]}}

    # loop over every instance and decide per instance which parameters to inject into
    for inst_nr, instance in enumerate(path_node.get("instances", [])):
        inst_params = {"GET": instance.get("GET", {}), "POST": instance.get("POST", {})}
        inject_params = {"GET": [], "POST": []}
        inst_cookies = instance.get("cookies", {})
        get_query, post_query, cookie_str = "?", "", CONFIG.get("cookie_str", "")

        # append semicolon to end of cookie string if not present
        if cookie_str and (not cookie_str.strip().endswith(";")):
            cookie_str += "; "

        # build GET/POST query from the instance's GET/POST parameters
        for ptype in ("GET", "POST"):
            for key, val in inst_params[ptype].items():
                if not val:
                    val = default_param_value
                if ptype == "GET":
                    get_query += "%s=%s&" % (key, val)
                else:
                    post_query += "%s=%s&" % (key, val)
        get_query = get_query[:-1]      # remove trailing "&" (or starting "?")
        post_query = post_query[:-1]    # remove trailing "&"

        # build cookie string from instance's cookie info and configured cookies
        for key, val in inst_cookies.items():
            if not val:
                val = default_param_value
            # prioritize preconfigured cookies
            if (key + "=" in cookie_str) or (key + " =" in cookie_str):
                continue
            cookie_str += "%s=%s; " % (key, val)
        cookie_str = cookie_str[:-2]    # remove trailing "; "

        # decide which GET / POST parameters to inject into
        for ptype in ("GET", "POST"):
            for key in prev_inj_params[ptype]:
                if key not in inst_params[ptype]:
                    continue
                inject = inject_into_param(ptype, max_per_param_tests, inst_infos[ptype][key][0], inst_params,
                                           prev_inj_params[ptype][key], inst_nr, common_params)
                if inject:
                    inject_params[ptype].append(key)

        # skip if no injections would be done
        if not inject_params["GET"] and not inject_params["POST"]:
            continue

        # store current instance parameters for every parameter that will be injected into
        for ptype in ("GET", "POST"):
            for param in inject_params[ptype]:
                prev_inj_params[ptype][param].append(inst_params)

        # build sqlmap call and append it to list of calls
        sqlmap_call = build_call(inject_params["GET"] + inject_params["POST"])
        sqlmap_calls.append(sqlmap_call)


    # build one final call from so far uninjected parameters (if any)
    get_query, post_query, cookie_str, inject_params = "?", "", "", {"GET": [], "POST": []}
    for ptype in ("GET", "POST"):
        for key, prev_params in prev_inj_params[ptype].items():
            if not prev_params:
                inject_params[ptype].append(key)
            if not val:
                val = default_param_value
            if ptype == "GET":
                get_query += key + "=&"
            else:
                post_query += key + "=&"
    get_query = get_query[:-1]      # remove trailing "&" (or starting "?")
    post_query = post_query[:-1]    # remove trailing "&"

    if (get_query or post_query) and (inject_params["GET"] or inject_params["POST"]):
        sqlmap_call = build_call(inject_params["GET"] + inject_params["POST"])
        sqlmap_calls.append(sqlmap_call)

    return sqlmap_calls


def get_test_params(sorted_params):
    """
    Return the parameters that should be tested, based on scored parameters,
    configured test rate and minimum number of parameters to test.
    """

    # determine count of parameters to test
    min_params_test_count = float(CONFIG.get("min_params_test_count", 4))
    test_rate = float(CONFIG.get("param_test_rate", 0.8))
    test_rate_get, test_rate_post = test_rate, test_rate
    if len(sorted_params["GET"]) > 0 and test_rate_get * len(sorted_params["GET"]) < min_params_test_count:
        test_rate_get = min_params_test_count / len(sorted_params["GET"])
    if len(sorted_params["POST"]) > 0 and test_rate_post * len(sorted_params["POST"]) < min_params_test_count:
        test_rate_post = min_params_test_count / len(sorted_params["POST"])
    half_count_get = test_rate_get*len(sorted_params["GET"]) / 2
    half_count_post = test_rate_post*len(sorted_params["POST"]) / 2

    # extract GET / POST params to test of the determined count
    test_params = {"GET": [], "POST": []}
    if 0 < half_count_get < 1:
        test_params["GET"] = list(set(sorted_params["GET"][:math.ceil(half_count_get)]))
    elif half_count_get >= 1:
        # first half consists of most common and second half of least common parameters
        test_params["GET"] = list(set((sorted_params["GET"][:math.ceil(half_count_get)] +
                                       sorted_params["GET"][-math.floor(half_count_get):])))
    if 0 < half_count_post < 1:
        test_params["POST"] = list(set((sorted_params["POST"][:math.ceil(half_count_post)])))
    elif half_count_post >= 1:
        # first half consists of most common and second half of least common parameters
        test_params["POST"] = list(set((sorted_params["POST"][:math.ceil(half_count_post)] +
                                        sorted_params["POST"][-math.floor(half_count_post):])))

    return test_params


def inject_into_param(ptype, max_tests, inst_idxs, inst_params, prev_inj_insts, cur_inst_idx, common_params):
    """
    Decide if the implicitly given parameter should be injected into.

    :param ptype: "GET" or "POST"
    :param max_tests: maximum times a parameter should be injected into
    :param inst_idxs: list of indices where the parameter is used in
    :param inst_params: info about parameters of the current instance
    :param prev_inj_insts: list of parameters of previous injections of the parameter
    :param cur_inst_idx: index of the current instance
    :param common_params: the list of common parameters
    :return: True if the parameter should be injected into, otherwise False
    """

    # inject into parameter if no other potential instances left
    inj_count = len(prev_inj_insts)
    rem_inst_count = len([idx for idx in inst_idxs if idx >= cur_inst_idx])
    if rem_inst_count <= max_tests - inj_count:
        if not any(prev_inst_params == inst_params for prev_inst_params in prev_inj_insts):
            return True
    elif inj_count >= max_tests:
        return False

    # inject into parameter if at least one common parameter has a different value than before
    check_ptypes = ("GET", ) if ptype == "GET" else ("GET", "POST")
    for ptype_check in check_ptypes:
        cur_common_params = [key for key in common_params[ptype_check] if key in inst_params[ptype_check]]
        for prev_inst_params in prev_inj_insts:
            # check if this instance has a common parameter that is not in any previous instance
            if any(common_key not in prev_inst_params[ptype_check] for common_key in cur_common_params):
                return True
            # check if this instance has common parameter with value different from previous instances
            if any(inst_params[ptype_check][common_key] != prev_inst_params[ptype_check][common_key]
                   for common_key in cur_common_params):
                return True

    return False


def process_sqlmap_output(call, output):
    """
    Process the sqlmap text output to extract vulnerability information.

    :param call: the sqlmap call that lead to the given output
    :param output: sqlmap's text output as string
    :return: a dict with SQLi vulnerability information, indexed by HTTP method and param name
    """

    # extract the found SQLi vuln descriptions via regex
    vulns_out = re.findall(r"^---\r\n[\S\s]*\r\n---", output, re.MULTILINE)
    if not vulns_out:
        return {}

    vulns_out = vulns_out[0]
    vuln_descrs = []
    start = None
    for match in re.finditer(r"^Parameter: ", vulns_out, re.MULTILINE):
        if start:
            vuln_descrs.append(vulns_out[start:match.start()])
        start = match.start()
    if start:
        vuln_descrs.append(vulns_out[start:-3])  # strip trailing "---"

    # parse the found vuln descriptions to extract SQLi type information
    vuln_dict = {}
    for descr in vuln_descrs:
        # extract vulnerable parameter name and put it into vuln_dict
        title_match = re.match(r"^Parameter: (\w+) \((\w+)\)", descr)
        param, method = title_match.group(1), title_match.group(2)
        if method not in vuln_dict:
            vuln_dict[method] = {}
        if param not in vuln_dict[method]:
            vuln_dict[method][param] = {"sqlmap_call": call, "sqlis": []}

        # extract reasons / SQLi types from description and put them into vuln_dict
        if "\r\n\r\n" in descr:
            reasons = descr.split("\r\n\r\n")
        else:
            reasons = [descr]

        for reason in reasons:
            reason_dict = {}
            for line in reason.split("\n"):
                line = line.strip()
                if not line:
                    continue

                key, val = line.split(":", maxsplit=1)
                key, val = key.strip().lower(), val.strip()
                if key != "parameter":
                    reason_dict[key] = val

            if reason_dict:
                vuln_dict[method][param]["sqlis"].append(reason_dict)
    return vuln_dict


def dump_data(vuln_dict):
    """
    Dump database and table data via the given SQLi vulnerabilities.
    The data is printed and directly written into corresponding output files.
    """

    def extract_tables(dump_out):
        """
        Extracts from the given sqlmap dump all DB and table information.
        """

        nonlocal dumped_data, ip, portid, host

        # search for DB and table data
        table_dump_data = re.findall(r"Database:\s*(\w+)\nTable:\s*(\w+)\n\[[\w ]*\]\n(\+\S+\+\n[\S ]*\n\+\S+\+\n(\|[\S ]+|\n)+\+\S+\+\n)", dump_out, re.MULTILINE)

        # if there is dumped data, create a dict entry for it
        if table_dump_data:
            if ip not in dumped_data:
                dumped_data[ip] = {}
            if portid not in dumped_data[ip]:
                dumped_data[ip][portid] = {}
            if host not in dumped_data[ip][portid]:
                dumped_data[ip][portid][host] = {}

        # properly store the dumped data in the dict for data dumps
        cur_host_data = dumped_data[ip][portid][host]
        for (dbname, tablename, table_str, _) in table_dump_data:
            if dbname not in cur_host_data:
                cur_host_data[dbname] = {}
            if tablename not in cur_host_data[dbname]:
                cur_host_data[dbname][tablename] = ""

            if len(cur_host_data[dbname][tablename]) < len(table_str):
                cur_host_data[dbname][tablename] = table_str

    def dump_data_for_host():
        """
        Invoke sqlmap to dump all available database data except for system DBs.
        Only non-time-based, non-blind and non-error-based SQLis are used to save time.
        """
        for path, path_node in host_node.items():
            for method in ("GET", "POST"):
                for param, pnode in path_node.get(method, {}).items():
                    for sqli_node in pnode["sqlis"]:
                        if "type" in sqli_node and (
                                ("time-based" not in sqli_node["type"].lower()) and
                                ("blind" not in sqli_node["type"].lower()) and
                                ("error-based" not in sqli_node["type"].lower())):
                            sqlmap_call = pnode["sqlmap_call"]
                            sqlmap_call += ["-p", param, "--dump-all", "--exclude-sysdbs"]
                            dump_out = subprocess.check_output(sqlmap_call, stderr=subprocess.STDOUT).decode()
                            extract_tables(dump_out)
                            return    # return after successful data dump


    # first extract the data via sqlmap
    util.printit(util.GREEN + "[+] " + util.SANE + "Extracting DB data via found SQLis")
    dumped_data = {}    # store dumped data
    for ip in vuln_dict:
        for portid in vuln_dict[ip]:
            for host, host_node in vuln_dict[ip][portid].items():
                dump_data_for_host()

    # then print the data to the screen and to store it in corresponding files
    util.printit(util.GREEN + "[+] " + util.SANE + "Dumping retrieved data:")
    with open(DATA_DUMP_FILE, "w") as f:
        for ip in dumped_data:
            for portid in dumped_data[ip]:
                for host, host_node in dumped_data[ip][portid].items():
                    title_str = util.YELLOW + "[+]%s %s:%s" % (util.SANE, ip, portid)
                    if host != ip:
                        title_str += " (hostname: %s)" % host
                    util.printit(title_str)
                    f.write(util.strip_ansi_escape_seq(title_str) + "\n\n")
                    for dbname in host_node:
                        for tablename, table_str in host_node[dbname].items():
                            table_id_str = "| Table: %s.%s |" % (dbname, tablename)
                            header = len(table_id_str) * "-" + "\n" + table_id_str + "\n" + len(table_id_str) * "-"
                            util.printit(header)
                            f.write(header + "\n")
                            util.printit(table_str)
                            f.write(table_str + "\n")

                f.write("\n\n")


def score_params(path_node):
    """
    Compute a commonality score for every param in path_node. The score takes
    into consideration how frequent a parameter is and how much its values vary.
    """


    # for every paramter extract indices of appearance in instance list
    # and a set of all its values
    inst_infos = {"GET": {}, "POST": {}}
    for i, instance in enumerate(path_node.get("instances", [])):
        inst_params = {"GET": instance.get("GET", {}), "POST": instance.get("POST", {})}
        for ptype in ("GET", "POST"):
            for name, val in inst_params[ptype].items():
                if name not in inst_infos[ptype]:
                    inst_infos[ptype][name] = [[], set()]
                inst_infos[ptype][name][0].append(i)
                inst_infos[ptype][name][1].add(val)


    # for every parameter compute commonality score
    num_instances = len(path_node.get("instances", []))
    scores = {"GET": {}, "POST": {}}
    for instance in path_node.get("instances", []):
        inst_params = {"GET": instance.get("GET", {}), "POST": instance.get("POST", {})}
        for ptype in ("GET", "POST"):
            for pname, (inst_idxs, vals) in inst_infos[ptype].items():
                # compute frequency and normalized variance
                freq = len(inst_idxs) / num_instances
                var = len(vals) / len(inst_idxs)
                var_optimal = float(CONFIG.get("var_optimal", 0.9))

                # normalize variance, also s.t. variances above optimal are slightly worse
                # than equally distant variances below the optimal variance
                if var <= var_optimal:
                    var = var / var_optimal
                else:
                    var = -var / var_optimal + 2*var_optimal

                # compute commonality score from frequency, variance and configured weights
                weight_freq, weight_var = float(CONFIG.get("weight_frequency")), float(CONFIG.get("weight_variance"))
                weight = weight_freq + weight_var
                score = (weight_freq / weight) * freq + (weight_var / weight) * var
                scores[ptype][pname] = score

    return inst_infos, scores
