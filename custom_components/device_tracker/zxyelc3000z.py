"""
Support for the zxyel C3000z centurylink modem/router.
For more details about this platform, please refer to the documentation at
https://home-assistant.io/components/device_tracker.arpscan_tracker/
"""
import logging
import re
import subprocess
from collections import namedtuple
from datetime import timedelta
import urllib
from requests import Request, Session

from html.parser import HTMLParser

class device(object):
    def __init__(self, string):
        v = string.split('/')
        self.type = v[0]
        self.name = v[1]
        self.ip = v[2]
        self.mac = v[3]
        self.conn = v[4]
        self.conn_t = v[5]

    def __str__(self):
        return '{}: t:{}, ip:{}, conn:{}-{}, mac:{}'.format(self.name, self.type, self.ip, self.conn, self.conn_t, self.mac)

class scriptParser(HTMLParser):
    def __init__(self, *args, **kwargs):
        super(scriptParser, self).__init__(*args, **kwargs)
        self.js = False
        self.data= None

    def handle_starttag(self, tag, attrs):
        if tag == 'script' and 'src' not in attrs:
            self.js = True

    def handle_endtag(self, tag):
        if self.js:
            self.js = False
    def handle_data(self, data):
        if self.js and self.data is None:
            self.data = data
            #print("Encountered some data  :", data)
            lines = data.splitlines()
            active_str = "var activeusers = '"
            inactive_str = "var inactiveusers = '"
            end_str = "';"
            for l in lines:
                if l.startswith(active_str):
                    l = l[len(active_str):-len(end_str)]
                    self.active_devices = [device(ds) for ds in l.split('|')]

                elif l.startswith(inactive_str):
                    l = l[len(inactive_str):-len(end_str)]
                    self.inactive_devices = [device(ds) for ds in l.split('|')]


import voluptuous as vol

import homeassistant.helpers.config_validation as cv
import homeassistant.util.dt as dt_util
from homeassistant.components.device_tracker import (
    DOMAIN, PLATFORM_SCHEMA, DeviceScanner)
from homeassistant.util import Throttle

_LOGGER = logging.getLogger(__name__)

CONF_EXCLUDE = 'exclude'
CONF_URL = 'url'
CONF_ADMIN = 'admin_username'
CONF_ADMIN_PASS = 'admin_password'

DEFAULT_ADMIN = 'admin'
DEFAULT_URL = 'http://192.168.0.1'

MIN_TIME_BETWEEN_SCANS = timedelta(seconds=5)

PLATFORM_SCHEMA = PLATFORM_SCHEMA.extend({
    vol.Optional(CONF_ADMIN, default=DEFAULT_ADMIN): cv.string,
    vol.Required(CONF_ADMIN_PASS): cv.string,
    vol.Optional(CONF_EXCLUDE, default=[]):
        vol.All(cv.ensure_list, [cv.string]),
    vol.Optional(CONF_URL, default=DEFAULT_URL):
        cv.string
})


def get_scanner(hass, config):
    """Validate the configuration and return a zxyelC300ZDeviceScanner scanner."""
    scanner = zxyelC300ZDeviceScanner(config[DOMAIN])

    return scanner if scanner.success_init else None


Device = namedtuple('Device', ['mac', 'name', 'ip', 'last_update'])


class zxyelC300ZDeviceScanner(DeviceScanner):
    """This class scans for devices using the router UI."""

    exclude = []

    def __init__(self, config):
        """Initialize the scanner."""
        self.last_results = []

        self._exclude = config[CONF_EXCLUDE]
        self._admin = config[CONF_ADMIN]
        self._admin_pass = config[CONF_ADMIN_PASS]
        self._url = config[CONF_URL]

        self.success_init = self._update_info()
        _LOGGER.debug("Init called")

    def scan_devices(self):
        """Scan for new devices and return a list with found device IDs."""
        self._update_info()

        _LOGGER.debug("Scan devices called")
        return [device.mac for device in self.last_results]

    def get_device_name(self, mac):
        """Return the name of the given device or None if we don't know."""
        filter_named = [device.name for device in self.last_results
                        if device.mac == mac]

        if filter_named:
            _LOGGER.debug("Filter named called")
            return filter_named[0]
        else:
            return None

    @Throttle(MIN_TIME_BETWEEN_SCANS)
    def _update_info(self):
        """Checks the router for devices.
        Returns boolean if scanning successful.
        """
        _LOGGER.debug("Update_info called")

        last_results = []
        exclude_macs = self._exclude
        admin = self._admin
        admin_pass = self._admin_pass
        baseurl = self._url
        now = dt_util.now()
       
        s = Session()

        params = urllib.parse.urlencode({'admin_username': admin, 'admin_password': admin_pass})
        headers = {"Content-Type": "application/x-www-form-urlencoded", "Accept": "text/html,application/xhtml+xml,application/xml"}

        r = s.post(baseurl+'/login.cgi', data=params, headers=headers)
        #print(r.text)
        r = s.get(baseurl+"/modemstatus_landevicelist.html")
        parser = scriptParser()
        parser.feed(r.text)
        s.close()

        for d in parser.active_devices:
            last_results.append(Device(d.mac, d.name, d.ip, now))

        self.last_results = last_results

        _LOGGER.debug("Update_info successful")
        return True