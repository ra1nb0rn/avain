#!/usr/bin/env python3

"""
This modules serves as a helper for the AVAIN crawler. It runs a simple scrapy spider
that crawls URLs, sends the responses to the AVAIN crawler that processes them and sends
back new URLs to crawl.
"""

import socket
import sys
from scrapy.crawler import CrawlerProcess
from scrapy.spiders import CrawlSpider
from scrapy.spidermiddlewares.httperror import HttpError
from scrapy.http import Request

import ipc_operations

UNIX_SOCK_ADDR = "./crawler_socket"
RECV_BUFFER_SIZE = 4096
ALLOWED_DOMAINS = []


class AvainCrawlSpider(CrawlSpider):
    name = "avain_crawl_spider"

    def __init__(self, cookies, **kwargs):
        super().__init__(**kwargs)
        self.cookies = cookies

    def parse(self, response):
        """ Parse the response by sending it to the AVAIN crawler module """
        response.request.callback = None  # needed for pickling
        response.request.errback = None  # needed for pickling

        ipc_operations.send_object(SOCK, response)  # send the response object
        yield_urls = ipc_operations.receive_object(SOCK)  # receive new URLs to crawl

        # prepare and yield a request for every new URL
        for url in yield_urls:
            req = self.get_request(url)
            yield req

    def on_error(self, failure):
        """ Overrides the default method to catch and process e.g. status 500 responses """

        if isinstance(failure.value, HttpError):
            response = failure.value.response
            return self.parse(response)
        return None

    def make_requests_from_url(self, url):
        """ Overrides the default method to catch by default discarded HTTP responses """

        return self.get_request(url)

    def get_request(self, url):
        """ Prepare a request with proper configuration and configured cookies """

        req = Request(url, callback=self.parse, dont_filter=True, errback=self.on_error,
                      meta={'dont_redirect': True, 'handle_httpstatus_list': [301, 302, 401, 403, 405]})
        for key, val in self.cookies.items():
            req.cookies[key] = val
        return req


if __name__ == "__main__":
    # create the IPC socket
    SOCK = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        SOCK.connect(UNIX_SOCK_ADDR)
    except socket.error as msg:
        sys.stderr.write(msg)
        sys.exit(1)

    # receive initial information
    init_dict = ipc_operations.receive_object(SOCK)
    # logging.getLogger("scrapy").propagate = False

    # start crawling
    process = CrawlerProcess({
        "USER_AGENT": init_dict["user_agent"]
    })
    process.crawl(AvainCrawlSpider, allowed_domains=init_dict["allowed_domains"],
                  start_urls=init_dict["start_urls"], cookies=init_dict["cookies"])
    process.start()

    # shutdown and close connection when finished
    SOCK.shutdown(socket.SHUT_RDWR)
    SOCK.close()
