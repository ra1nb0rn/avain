import socket
import os
import sys
import urllib.parse
import subprocess
import signal
import random
import glob
import time
import json
import requests
import selenium
from comment_parser import comment_parser
from comment_parser.parsers.common import UnterminatedCommentError
from scrapy.linkextractors import LinkExtractor

from core import utility as util
from . import ipc_operations

# socket address for IPC with crawl helper
UNIX_SOCK_ADDR = "./crawler_socket"

# javascript events that should be attempted to be triggered via Selenium
EVENTS = ["onerror", "onchange", "onsearch", "onsubmit", "onkeypress", "onkeyup", "onkeydown",
          "onclick", "onmouseover", "onwheel", "onmousedown", "onmouseup", "ondrop", "onended",
          "onplay", "onpause", "ontoggle"]


class Crawler():

    def __init__(self, base_url, start_urls, config, helper_outfile, verbose):
        """
        Creates a new crawler object with the given init parameters.

        :param base_url: the URL that builds the crawling base and
                         is a common prefix of the start_urls
        :param start_urls: the URLs to start crawling at
        :param config: the AVAIN config for the crawler module
        :param helper_outfile: the filename where the output of the crawler helper
                               is to be stored
        :param verbose: whether AVAIN is run in verbose mode
        """

        # setup class variables
        self.base_url = base_url
        self.start_urls = list(set([base_url] + start_urls))
        self.config = config
        self.helper_outfile = helper_outfile
        self.verbose = verbose
        self.found_urls = set()
        self.crawled_urls = {}
        self.crawled_paths = {}
        self.param_infos = {}
        self.helper_pid = None
        self.found_cookies = []
        self.comments = {}
        self.redirects = {}
        self.driver = None

        # figure out domain
        parsed_url = urllib.parse.urlparse(base_url)
        self.domain = parsed_url.hostname
        self.port = parsed_url.port
        if not self.port:
            self.port = 80 if parsed_url.scheme == "http" else 443
        self.protocol_prefix = "%s://" % parsed_url.scheme

        # parse cookies from config
        self.cookies = {}
        for key_val_pair in self.config["cookie_str"].split(";"):
            if not key_val_pair:
                continue
            if "=" not in key_val_pair:
                self.cookies[key_val_pair.strip()] = ""
            else:
                key, val = key_val_pair.strip().split("=")
                self.cookies[key.strip()] = val.strip()

        # create unix socket for IPC with crawler helper
        if os.path.exists(UNIX_SOCK_ADDR):
            os.remove(UNIX_SOCK_ADDR)
        self.socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.socket.bind(UNIX_SOCK_ADDR)

        # setup selenium if it is configured to be used
        if config["use_selenium"].lower() == "true":
            import logging
            logging.getLogger("seleniumwire").setLevel(logging.ERROR)
            from seleniumwire import webdriver
            from selenium.webdriver.chrome.options import Options
            chrome_options = Options()
            chrome_options.add_argument("--headless")
            chrome_options.add_argument("--user-agent=%s" % self.config["user_agent"])
            # on Linux running Selenium as root requires '--no-sandbox' option
            if os.geteuid() == 0 and sys.platform.startswith("linux"):
                chrome_options.add_argument("--no-sandbox")
            self.driver = webdriver.Chrome(options=chrome_options)
            # add cookies
            self.driver.get(self.base_url)  # initial request required to add cookies
            self.driver.delete_all_cookies()
            for key, val in self.cookies.items():
                self.driver.add_cookie({"name": key, "value": val, "domain": self.domain})

    def __del__(self):
        """
        Delete this crawler object and properly free the used resources.
        """

        # close socket
        try:
            self.socket.shutdown(socket.SHUT_RDWR)
            self.socket.close()
        except OSError:
            pass

        # quit selenium driver
        if self.driver:
            self.driver.quit()

        # make sure to delete linkfinder temporary files
        files = glob.glob("linkfinder_tmp*")
        for file in files:
            os.remove(file)

        # make sure helper process is dead
        try:
            os.kill(self.helper_pid, signal.SIGKILL)
        except ProcessLookupError:
            pass

        if os.path.exists(UNIX_SOCK_ADDR):
            os.remove(UNIX_SOCK_ADDR)

    def crawl(self):
        """
        Start crawling with the configuration set via the constructor.

        :return: a tuple as (webhost_map, new_netlocs, comments)
        """

        # create helper process and setup IPC
        self.socket.listen(1)
        help_out_fd = open(self.helper_outfile, "w")
        with subprocess.Popen("./crawl_helper.py", stdout=help_out_fd, stderr=subprocess.STDOUT) as proc:
            self.helper_pid = proc.pid
            try:
                conn, _ = self.socket.accept()
                # create initial params for crawler helper and send them
                new_urls = set()
                setup_params = {"start_urls": self.start_urls, "allowed_domains": [self.domain],
                                "cookies": self.cookies, "user_agent": self.config["user_agent"]}
                ipc_operations.send_object(conn, setup_params)

                # loop: receive a response object, then send new URLs to crawl. Catch & handle problems.
                while True:
                    try:
                        proc.wait(timeout=0.001)
                        break
                    except subprocess.TimeoutExpired:
                        response = ipc_operations.receive_object(conn)
                        if not response:  # socket is dead / closed
                            break
                        new_urls = self.process_response(response)
                        ipc_operations.send_object(conn, new_urls)
                    except socket.timeout:
                        util.printit("Unix socket connection to scrapy crawler unexpectedly broke. " +
                                     "Quitting crawling of %s" % self.base_url, color=util.RED)
                        break
            finally:
                # ensure connection is closed and helper process killed in any case
                conn.close()
                proc.kill()

        # after the actual crawling, extract all the gathered cookies from Selenium
        if self.config["use_selenium"].lower() == "true":
            selenium_cookies = self.driver.get_cookies()
            for cookie in selenium_cookies:
                if not any(cookie["name"] == c["name"] and cookie["path"] == c["path"] and
                           cookie["domain"] == c["domain"] for c in self.found_cookies):
                    parsed_cookie = {}
                    for key in ("name", "path", "domain", "httpOnly", "secure"):
                        parsed_cookie[key] = cookie[key]
                    self.found_cookies.append(parsed_cookie)

        help_out_fd.close()
        return self.create_results()

    def url_has_netloc(self, url):
        """
        Check if the given URL has the same network location as the base URL, i.e.
        if it has the same domain and port that are set in this crawler.
        """

        parsed_url = urllib.parse.urlparse(url)

        if parsed_url.scheme == "http":
            port = 80
        elif parsed_url.scheme == "https":
            port = 443
        if parsed_url.port:
            port = parsed_url.port

        domain = parsed_url.hostname
        if domain:
            if domain != self.domain or port != self.port:
                return False
            return True
        return False

    def to_absolute_url(self, path_url, urljoin_fnct):
        """
        Convert the given path or url (param:path_url) to an absolute URL. If path_url starts
        with '/' it is an absolute server path and is joined with the configured network location
        of this crawler. Otherwise the path is relative and made absolute via the given URL join
        function. In the former case, port 80 and 443 are omitted in the returned absolute URL.
        """

        abs_url = path_url
        if not "://" in path_url:
            if path_url.startswith("/"):
                if self.port in (80, 443):
                    abs_url = urllib.parse.urljoin(self.protocol_prefix + self.domain, path_url)
                else:
                    abs_url = urllib.parse.urljoin(self.protocol_prefix + self.domain +
                                                   ":" + str(self.port), path_url)
            else:
                abs_url = urljoin_fnct(abs_url)
        return abs_url

    def process_response(self, response):
        """
        Process the given scrapy response. Extract new URLs, HTTP parameters,
        new network locations, cookies and code comments.

        :return: a set of URLs that shall be crawled in the future
        """

        if response.status == 404:
            return set()

        # store response HTTP code if not redirect
        if not (response.status == 301 or response.status == 302):
            if response.url not in self.crawled_urls:
                self.crawled_urls[response.url] = response.status

        # some colorful printing
        if self.verbose:
            code = str(response.status)
            extra_print = ""
            if code[0] == "2":
                color = util.GREEN
            elif code[0] == "3":
                color = util.BRIGHT_CYAN
                extra_print = (util.BRIGHT_CYAN + " --> " + util.SANE +
                               response.headers["Location"].decode())
            elif code[0] == "4":
                color = util.RED
            elif code[0] == "5":
                color = util.MAGENTA
            else:
                color = util.SANE
            util.printit("  [", end="")
            util.printit(str(response.status), color=color, end="")
            util.printit("]  " + response.url + extra_print)

        # extract cookies from HTTP header response
        self.extract_cookies(response.headers.getlist("Set-Cookie"), response.url)

        # use scrapy's lxml linkextractor to extract links / URLs
        try:
            scrapy_links = LinkExtractor(allow_domains=[self.domain],
                                         tags=("a", "area", "script", "link", "source", "img"),
                                         attrs=("src", "href"),
                                         deny_extensions=set()).extract_links(response)
        except AttributeError as e:
            if str(e) == "Response content isn't text":
                # stop processing and return no new URLs
                return set()
            raise e

        # run the different URL / link discovery mechanisms
        linkfinder_urls, dynamic_urls, form_urls, sub_urls = set(), set(), set(), set()
        if self.config["use_linkfinder"].lower() == "true":
            linkfinder_urls = self.run_linkfinder(response.text, response.urljoin)
        if self.config["use_selenium"].lower() == "true":
            dynamic_urls = self.extract_dynamic_urls(response.url)
        if self.config["extract_info_from_forms"].lower() == "true":
            form_data = extract_form_data(response)
            # extract new URLs and HTTP parameters from parsed form data
            form_urls = self.process_form_data(form_data, response.urljoin)

        # extract sub URLs, i.e. URLs with parent paths
        sub_urls = extract_sub_urls(response.url)

        # extract comments if configured
        if self.config["extract_comments"].lower() == "true":
            self.extract_comments(response)

        # unite discovered URLs
        urls = set()
        for link in scrapy_links:
            urls.add(link.url)
        urls |= linkfinder_urls
        urls |= dynamic_urls
        urls |= form_urls
        urls |= sub_urls

        # store info about redirect and add redirect URL to discovered URLs
        if response.status == 301 or response.status == 302:
            location = response.headers["Location"].decode()
            self.redirects[response.url] = {"code": response.status, "to": location}
            urls.add(self.to_absolute_url(location, response.urljoin))

        # process all the discovered URLs, i.e. extract new information and decide which to crawl
        yield_urls = set()
        for url in urls:
            # strip anchor
            if "#" in url:
                url = url[:url.rfind("#")]

            # replace entities and parse URL
            url = url.replace("&amp;", "&")
            url = url.replace("&#038;", "&")
            parsed_url = urllib.parse.urlparse(url)

            # extract GET parameters and cut URL if option is configured
            params = {}
            if parsed_url.query:
                if self.config["crawl_parameter_links"].lower() != "true":
                    url = "%s://%s/%s" % (parsed_url.scheme, parsed_url.netloc, parsed_url.path)
                params = get_query_params(parsed_url.query)
            elif url.endswith("?"):
                url = url[:-1]

            # add URL as instance of its path
            if self.url_has_netloc(url) and params:
                self.add_path_instance(parsed_url.path, params, {}, {})

            # skip already crawled URLs
            if url in self.found_urls:
                continue
            self.found_urls.add(url)

            # skip URLs with different network location
            if not self.url_has_netloc(url):
                continue
            if url == response.url:
                continue

            # try to avoid going to a logout page if custom cookies are were supplied
            if self.cookies and "logout" in parsed_url.path.split("/")[-1].lower():
                continue

            # check whether to add this URL to the to-be-crawled URLs
            if url not in yield_urls:
                # limit the crawling depth
                max_depth = int(self.config["max_depth"])
                if max_depth > 0:
                    depth = parsed_url.path.count("/")
                    if depth > max_depth:
                        continue

                # limit the number of times a path can be crawled to avoid endless
                # crawling upon GET parameter variation
                if parsed_url.path not in self.crawled_paths:
                    self.crawled_paths[parsed_url.path] = 0
                self.crawled_paths[parsed_url.path] += 1
                if self.crawled_paths[parsed_url.path] > int(self.config["max_path_visits"]):
                    continue

                yield_urls.add(url)

        return yield_urls

    def extract_cookies(self, set_cookie_strings, url):
        """
        Extract cookie objects from the raw cookie strings returned in an HTTP
        response and append them to the list of discovered cookies.
        """

        # determine current domain
        url_parsed = urllib.parse.urlparse(url)
        domain_found = url_parsed.hostname

        # determine current path
        path_found = url_parsed.path
        if not path_found.endswith("/"):
            path_found = path_found[:path_found.rfind("/")]

        # extract cookies
        for cookie_string in set_cookie_strings:
            cookie_string = cookie_string.decode()
            name, path, domain, httpOnly, secure, sameSite = "", "", domain_found, False, False, ""
            items = cookie_string.split(";")
            # Iterate through the cookie properties within the current cookie string
            for item in items:
                item = item.strip()
                if "=" in item:
                    key, val = item.split("=")
                    if key.lower() == "path":
                        path = val
                    elif key.lower() == "domain":
                        domain = val
                    elif key == "SameSite":
                        sameSite = val
                    elif key not in ("expires", "Expires", "Max-Age", "max-age"):
                        name = key
                elif item.lower() == "secure":
                    secure = True
                elif item == "HttpOnly":
                    httpOnly = True

            # if a cookie, identified by its name, path and domain, is not stored yet, store it
            if not any(name == c["name"] and path == c["path"] and
                       domain == c["domain"] for c in self.found_cookies):
                self.found_cookies.append({"name": name, "path": path, "pathFound": path_found,
                                           "domain": domain, "httpOnly": httpOnly,
                                           "secure": secure, "sameSite": sameSite})

    def extract_comments(self, response):
        """
        Extract code comments from the response's content. Regardless of the response's
        content type, the content is searched for HTML comments '<!-- .... -->', JS line
        comments '//...' and JS block comments '/* ... */'.
        """

        # use the comment_parser package to extract HTML and JS comments
        try:
            html_comments = comment_parser.extract_comments_from_str(response.text, mime="text/html")
        except UnterminatedCommentError:
            html_comments = []
        try:
            js_comments = comment_parser.extract_comments_from_str(response.text, mime="application/javascript")
        except UnterminatedCommentError:
            js_comments = []

        # put the discovered comments together
        comments = list()
        for comment in html_comments:
            comments.append({"line": comment.line_number(), "comment": "<!--" + comment.text() + "-->"})
        for comment in js_comments:
            if comment.is_multiline():
                comments.append({"line": comment.line_number(), "comment": "/*" + comment.text() + "*/"})
            else:
                comments.append({"line": comment.line_number(), "comment": "//" + comment.text()})

        # store the discovered comments w.r.t. the response's path & query
        if comments:
            parsed_url = urllib.parse.urlparse(response.url)
            if self.config["crawl_parameter_links"].lower() == "true":
                self.comments[parsed_url.path + parsed_url.query] = comments
            else:
                self.comments[parsed_url.path] = comments

    def run_linkfinder(self, text, urljoin_fnct):
        """
        Use Linkfinder to discover new URLs in the given text. From experience, Linkfinder
        can produce a significant amount of false positives. The given url join function
        is used to constuct absolute URLs from discovered relative paths.
        """

        urls = set()
        # store the text in a separate file for Linkfinder
        tmp_filename_in = "linkfinder_tmp_%d.in" % random.randint(0, 2**32)
        with open(tmp_filename_in, "w") as f:
            f.write(text)

        # Run Linkfinder as subprocess and remove the input file thereafter
        linkfinder_out = ""
        try:
            linkfinder_out = subprocess.check_output(["python3 LinkFinder/linkfinder.py -i " +
                                                      tmp_filename_in + " -o cli 2>/dev/null"], shell=True)
            linkfinder_out = linkfinder_out.decode()
        except subprocess.CalledProcessError:
            pass
        os.remove(tmp_filename_in)

        # process Linkfinder's output
        for line in linkfinder_out.split("\n"):
            if not line:
                continue
            line = line.strip()
            line = self.to_absolute_url(line, urljoin_fnct)
            # if configured, check if the discovered URL is valid and exists
            if self.config["check_linkfinder"].lower() == "true":
                try:
                    timeout = float(self.config["linkfinder_check_timeout"])
                    if str(requests.head(line, timeout=timeout).status_code) != "404":
                        urls.add(line)
                except:
                    pass
            else:
                urls.add(line)

        return urls

    def extract_dynamic_urls(self, url):
        """
        Use Selenium to extract URLs that only become visible through requests made
        by executing a website's Javascript code.
        """

        # delete previous requests and visit the given URL
        del self.driver.requests
        self.driver.get(url)

        # iterate over all JS event attributes
        for event_attribute in EVENTS:
            # find all HTML elements with the current attribute
            try:
                elements = self.driver.find_elements_by_xpath("//*[@%s]" % event_attribute)
            except Exception as e:
                if "unexpected alert open:" in str(e):
                    continue
                raise e

            # run the javascript of every eventful HTML element
            if elements:
                for element in elements:
                    # try submit and click events directly and other attributes via a workaround
                    try:
                        if event_attribute == "onsubmit":
                            element.submit()
                        elif event_attribute == "onclick":
                            element.click()
                        else:
                            self.driver.execute_script("arguments[0].%s()" % event_attribute, element)
                    # except any errors and ignore them
                    except:
                        pass

                    # go back to the original URL by going back in history
                    # if that fails, try to revisit the original URL directly
                    i = -1
                    while True:
                        try:
                            if self.driver.current_url != url:
                                break
                            else:
                                self.driver.execute_script("window.history.go(%d)" % i)
                                i -= 1
                        except selenium.common.exceptions.UnexpectedAlertPresentException as e:
                            for j in range(5):
                                try:
                                    self.driver.get(url)
                                    break
                                except selenium.common.exceptions.UnexpectedAlertPresentException:
                                    time.sleep(j)

                    # if for some reason, the original URL could not be visited again, stop completely
                    if self.driver.current_url != url:
                        break

        # extract URLs, POST params and cookies by inspecting requests made by the Selenium driver
        visited_urls = set()
        for request in self.driver.requests:
            # add as path instance if POST parameters are available
            if self.url_has_netloc(request.path) and request.method == "POST" and request.body:
                try:
                    body = request.body.decode()
                    post_params = get_query_params(body)
                    if post_params:
                        parsed_path = urllib.parse.urlparse(request.path)
                        get_params = get_query_params(parsed_path.query)
                        # extract cookies sent by the Selenium driver
                        cookie_strs = request.headers["Cookie"].split(";")
                        cookies = {}
                        for cookie_str in cookie_strs:
                            k, v = cookie_str.strip(), ""
                            if "=" in cookie_str:
                                k, v = cookie_str.strip().split("=")
                            cookies[k] = v
                        # finally, add as instance of the visited website path
                        self.add_path_instance(parsed_path.path, get_params, post_params, cookies)
                except:
                    pass
            visited_urls.add(request.path)

        del self.driver.requests
        return visited_urls

    def process_form_data(self, form_data, urljoin_fnct):
        """
        Process the given form data by extracting new URLs and GET / POST parameters.
        """

        urls = set()
        for form_data_entry in form_data:
            # make the action absolute and add it to the found URLs
            abs_action = self.to_absolute_url(form_data_entry["action"], urljoin_fnct)
            urls.add(abs_action)

            if not self.url_has_netloc(abs_action):
                continue

            parsed_abs_action = urllib.parse.urlparse(abs_action)
            get_params = get_query_params(parsed_abs_action.query)
            post_params = {}

            # add the form's params to the GET / POST param info
            form_params = get_params if form_data_entry["method"] == "GET" else post_params
            for k, v in form_data_entry["params"].items():
                form_params[k] = v

            # check if the found path / parameter instance is new before appending it
            is_new_instance = True
            if parsed_abs_action.path in self.param_infos:
                if "instances" in self.param_infos[parsed_abs_action.path]:
                    for instance in self.param_infos[parsed_abs_action.path]["instances"]:
                        if (not get_params) or get_params == instance["GET"]:
                            post_keys = instance["POST"].keys()
                            if all(k in post_keys for k in post_params):
                                is_new_instance = False
            if is_new_instance:
                self.add_path_instance(parsed_abs_action.path, get_params, post_params, {})

        return urls

    def add_path_instance(self, path, get_params: dict, post_params: dict, cookies: dict):
        """
        Add the instance of the given path, i.e. a request of the path with the given
        parameters to the list of instances for that path. If the parameter names within
        the given parameters are unknown, store them as well.
        """

        # first, store any unknown parameter names
        if get_params:
            self.add_parameters(path, "GET", set(get_params.keys()))
        if post_params:
            self.add_parameters(path, "POST", set(post_params.keys()))
        if cookies:
            self.add_parameters(path, "cookies", set(cookies.keys()))

        # next, check if instance should be stored and store it
        if path not in self.param_infos:
            self.param_infos[path] = {}

        if (not get_params) and (not post_params) and (not cookies):
            return

        if "instances" not in self.param_infos[path]:
            self.param_infos[path]["instances"] = []

        if not any(d.get("GET", {}) == get_params and d.get("POST", {}) == post_params and
                   d.get("cookies", {}) == cookies for d in self.param_infos[path]["instances"]):
            instance = {"GET": get_params, "POST": post_params, "cookies": cookies}
            self.param_infos[path]["instances"].append(instance)

    def add_parameters(self, path, method, params: set):
        """
        Store the given HTTP parameters alongside their path and HTTP method.
        """
        if path not in self.param_infos:
            self.param_infos[path] = {}

        method = method.upper()
        if method not in self.param_infos[path]:
            self.param_infos[path][method] = set()

        self.param_infos[path][method] |= params

    def create_results(self):
        """
        Create the final crawling results that are to be returned in the end. The results
        are a tuple as (web map of host, new network locations, code comments).
        """

        webhost_map = {}
        # put the found paths into the webhost map
        self.process_crawled_urls(webhost_map)
        # put the found param infos into the webhost map
        self.process_param_infos(webhost_map)
        # put the found cookies into the webhost map and get as by product new domains
        new_domains = self.process_cookies(webhost_map)
        # get the newly discovered network locations
        new_netlocs = self.get_new_netlocs()

        # append new domains to the new network locations
        for new_domain in new_domains:
            if self.port != 80 and self.port != 443:
                new_netlocs.add(new_domains + ":" + self.port)
            else:
                new_netlocs.add(new_domain)

        # process discovered redirects and put into webhost map if appropriate
        for url, redirect in self.redirects.items():
            path = urllib.parse.urlparse(url).path
            if url + "/" == redirect["to"]:
                continue
            else:
                if not self.url_has_netloc(redirect["to"]):
                    redirect_to = redirect["to"]
                else:
                    redirect_to = urllib.parse.urlparse(redirect["to"]).path

                code = str(redirect["code"])
                if code not in webhost_map:
                    webhost_map[code] = {}
                if path not in webhost_map[code]:
                    webhost_map[code][path] = {}

                redirect_info = "redirect to %s" % redirect_to
                if "misc_info" not in webhost_map[code][path]:
                    webhost_map[code][path]["misc_info"] = redirect_info
                elif not any(val == redirect_info for val in webhost_map[code][path].values()):
                    for i in range(10):
                        alt_key = "misc_info_%d" % i
                        if alt_key not in webhost_map[code][path]:
                            webhost_map[code][path][alt_key] = redirect_info
                            break

        return webhost_map, new_netlocs, self.comments

    def process_crawled_urls(self, webhost_map):
        """
        Extract paths and GET parameters from all the crawled URLs and
        add them to the given web host map.
        """

        for url, status_code in self.crawled_urls.items():
            # store the URL's path in the web host map under the URL's status code
            status_code_str = str(status_code)
            parsed_url = urllib.parse.urlparse(url)
            if status_code_str not in webhost_map:
                webhost_map[status_code_str] = {}
            if parsed_url.path not in webhost_map[status_code_str]:
                webhost_map[status_code_str][parsed_url.path] = {}
            cur_node = webhost_map[status_code_str][parsed_url.path]

            # if a (GET) query is present, add its parameters to the web host map
            if parsed_url.query:
                get_params = get_query_params(parsed_url.query)
                if get_params:
                    if "GET" not in cur_node:
                        cur_node["GET"] = []
                    for param in get_params:
                        if param not in cur_node["GET"]:
                            cur_node["GET"].append(param)

                    if any(val for val in get_params.values()):
                        if "instances" not in cur_node:
                            cur_node["instances"] = []

                        if not any(i.get("GET", {}) == get_params for i in cur_node["instances"]):
                            instance = {"GET": get_params, "POST": {}, "cookies": {}}
                            cur_node["instances"].append(instance)

    def process_param_infos(self, webhost_map):
        """
        Process the stored parameter infos and add them to the given web host map.
        """

        for path, param_node in self.param_infos.items():
            # find corresponding webhost_map entry by common path and
            # save it as "cur_node"
            cur_node = None
            for _, pages_node in webhost_map.items():
                for map_path, cur_node_tmp in pages_node.items():
                    if map_path == path:
                        cur_node = cur_node_tmp
                        break
                if cur_node is not None:
                    break

            # technically, cur_node should always be not 'None', b/c the path should
            # have been added by the call to 'process_crawled_urls'.
            # just in case it is 'None' skip the current param node to avoid errors
            if not cur_node is not None:
                continue

            # put the GET and POST parameters and cookies from the current param node
            # into the central web host map and avoid duplicates
            for ptype in ("GET", "POST", "cookies"):
                if ptype in param_node:
                    if ptype in cur_node:
                        cur_node[ptype] = list(set(list(param_node[ptype]) + cur_node[ptype]))
                    else:
                        cur_node[ptype] = list(set(param_node[ptype]))

            # unite instances of the cuurent param node with the current web host map node
            if "instances" in param_node:
                # handle non-existent / empty instances node in aggregation webserver_map
                if "instances" not in cur_node:
                    cur_node["instances"] = []
                if not cur_node["instances"]:
                    cur_node["instances"] = param_node["instances"]
                    continue

                for cur_instance in param_node["instances"]:
                    get_params = cur_instance.get("GET", {})
                    post_params = cur_instance.get("POST", {})
                    cookies = cur_instance.get("cookies", {})

                    # skip empty instances
                    if (not get_params) and (not post_params) and (not cookies):
                        continue
                    if ((not any(val for val in get_params.values())) and
                            (not any(val for val in post_params.values())) and
                            (not any(val for val in cookies.values()))):
                        continue

                    # only add the current instance, if it is not a duplicate
                    if not any((inst.get("GET", {}) == get_params and
                                inst.get("POST", {}) == post_params and
                                inst.get("cookies", {}) == cookies)
                               for inst in cur_node["instances"]):
                        cur_node["instances"].append(cur_instance)

    def process_cookies(self, webhost_map):
        """
        Process the stored cookies by appending them to the web host map
        and extracting any new domains found within the cookie information.

        :return: a set of newly discovered domains
        """

        new_domains = set()
        for cookie in self.found_cookies:
            # if cookie is for a different domain, save that info and continue
            if cookie["domain"] != self.domain:
                new_domains.add(cookie["domain"])
                continue

            path = cookie["path"] if cookie["path"] else "/"
            # find corresponding webhost_map entry by common path and
            # save it as "page_node"
            page_node = None
            for _, pages_node in webhost_map.items():
                for map_path, page_node_tmp in pages_node.items():
                    if map_path == path:
                        page_node = page_node_tmp
                        break
                if page_node is not None:
                    break

            # store the info of the current cookie in the given web host map
            if page_node is not None:
                if "cookies" in page_node:
                    if cookie["name"] not in page_node["cookies"]:
                        page_node["cookies"].append(cookie["name"])
                else:
                    page_node["cookies"] = [cookie["name"]]
            else:
                # assume 200 status code for new path discovered through cookies
                if "200" not in webhost_map:
                    webhost_map["200"] = {}
                webhost_map["200"][path] = {"cookies": [cookie["name"]]}

        return new_domains

    def get_new_netlocs(self):
        """ Iterate over all discovered URLs to extract new network locations. """
        new_netlocs = set()
        for url in self.found_urls:
            parsed_url = urllib.parse.urlparse(url)
            if not self.url_has_netloc(url):
                new_netlocs.add(parsed_url.netloc)
        return new_netlocs


def get_query_params(query):
    """
    Extract (key, value) pairs from the given GET / POST query. Pairs
    can be split by '&' or ';'.
    """
    params = {}
    if query:
        delim = "&"
        if "&" not in query and ";" in query:
            delim = ";"
        for k_v in query.split(delim):
            k, v = k_v, ""
            if "=" in k_v:
                k, v = k_v.split("=")
            params[k] = v
    return params


def extract_sub_urls(url):
    """
    Extract the sub URLs that are part of the given URL.
    E.g. from http://example.org/a/b.php we get as sub URL http://example.org/a/
    """

    sub_urls = set()
    parsed_url = urllib.parse.urlparse(url)
    dirs = parsed_url.path.split("/")

    # strip empty dirs constructed from the above split
    if dirs and not dirs[0]:
        dirs = dirs[1:]
    if dirs and not dirs[-1]:
        dirs = dirs[:-1]

    for i in range(0, len(dirs)-1):
        sub_url = parsed_url.scheme + "://" + parsed_url.netloc + "/"
        sub_url += "/".join(dirs[:i+1]) + "/"
        sub_urls.add(sub_url)

    return sub_urls


def extract_form_data(response):
    """ Extract the HTML form information contained in the given response. """

    def add_param(element):
        """ Add the info of the given element to params if it has a name """
        nonlocal params
        name = element.attrib.get("name", None)
        value = element.attrib.get("value", "")
        if name:
            params[name] = value

    # find and iterate over all forms contained in the response
    form_data = []
    forms = response.xpath("//form")
    for form in forms:
        action = form.attrib.get("action", None)
        form_id = form.attrib.get("id", None)
        method = form.attrib.get("method", None)
        # only process forms with action and method attribute
        if (not action) or (not method):
            continue
        # adjust action and method strings
        if action == "#":
            action = response.url
        action = action.replace("&amp;", "&")
        action = action.replace("&#038;", "&")
        method = method.upper()

        # extract all the different parameters
        params = {}
        for _input in form.xpath("//input"):
            add_param(_input)

        for select in form.xpath("//select"):
            add_param(select)

        for textarea in form.xpath("//textarea"):
            add_param(textarea)

        # handle the use of form IDs
        if form_id:
            for _input in response.xpath("//input[@form='%s']" % form_id):
                add_param(_input)

            for select in response.xpath("//select[@form='%s']" % form_id):
                add_param(select)

            for textarea in response.xpath("//textarea[@form='%s']" % form_id):
                add_param(textarea)

        # if there is only one form, consider all inputs of the page to be part of this form
        if len(forms) == 1:
            for _input in response.xpath("//input"):
                add_param(_input)

            for select in response.xpath("//select"):
                add_param(select)

            for textarea in response.xpath("//textarea"):
                add_param(textarea)

        form_data.append({"action": action, "method": method, "params": params, "id": form_id})
    return form_data
