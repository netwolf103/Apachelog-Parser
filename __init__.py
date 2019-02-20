# -*- coding: utf-8 -*-
"""
    Apache Log Parser
    ~~~~~

    A simple Apache log analysis tool.

    :copyright: © 2019 by the Zhang Zhao<netwolf103@gmail.com>.
    :license: BSD, see LICENSE for more details.
"""
__version__ = '0.1'

from string import Template
import apache_log_parser

class LogParser(object):
	"""Parser webserver log for base class."""
	def __init__(self):
		pass

class ApacheLogParser(LogParser):
	"""Parser apache log."""

	def __init__(self, logfile, logformat):
		self.logfile = logfile
		self.logformat = logformat
		
		"""http response status."""
		self.http_status = {
			# http status code 1xx
			'100': 0,
			'101': 0,

			# http status code 2xx
			'200': 0,
			'201': 0,
			'202': 0,
			'203': 0,
			'204': 0,
			'205': 0,
			'206': 0,

			# http status code 3xx
			'300': 0,
			'301': 0,
			'302': 0,
			'303': 0,
			'304': 0,
			'305': 0,
			'306': 0,
			'307': 0,

			# http status code 4xx
			'400': 0,
			'401': 0,
			'402': 0,
			'403': 0,
			'404': 0,
			'405': 0,
			'406': 0,
			'407': 0,
			'408': 0,
			'409': 0,
			'410': 0,
			'411': 0,
			'412': 0,
			'413': 0,
			'414': 0,
			'415': 0,
			'416': 0,
			'417': 0,

			# http status code 5xx
			'500': 0,
			'501': 0,
			'502': 0,
			'503': 0,
			'504': 0,
			'505': 0,
			
			# http status code others
			'unknow': 0
		}
		
		"""http request methods."""
		self.http_request_methods = {
			'GET': 0,
			'HEAD': 0,
			'POST': 0,
			'PUT': 0,
			'DELETE': 0,
			'CONNECT': 0,
			'OPTIONS': 0,
			'TRACE': 0,
			'PATCH': 0,
		}

		"""user agent"""
		self.user_agents = {}

		"""remote ips"""
		self.remote_ips = {}

	def run(self, limit = 100, output = None):
		with open(self.logfile) as f:
			line = f.readline()
			
			counter = 1
			while line:
				line_parser = apache_log_parser.make_parser(self.logformat)
				log_line_data = line_parser(line)
				#pprint(log_line_data)

				self.processHttpResponseCode(log_line_data['status'])
				self.processHttpRequestMethod(log_line_data['request_method'], log_line_data['request_first_line'])
				self.processUserAgent(log_line_data['request_header_user_agent__os__family'], log_line_data['request_header_user_agent__os__version_string'], log_line_data['request_header_user_agent__is_mobile'])
				self.processRemoteIp(log_line_data['remote_host'])

				line = f.readline()

				if counter == limit:
					break

				counter += 1

			#pprint(self.http_status)
			#pprint(self.http_request_methods)
			#pprint(self.user_agents)
			#pprint(self.remote_ips)

			if output != None:
				self.output(output)

	def output(self, filename):
		htmlTemplate = """
		<html>
			<head>
				<title>Apache access status</title>
				<style type="text/css">
				table{width:500px;border-collapse:collapse;font-size:16px;border:1px #ddd solid;display:block;}
				table > thead{display:block;}
				table > tbody {height:500px;max-height:100%;overflow-y:scroll;display:block;}
				table > thead > tr, table > tbody > tr{display:flex}
				table > tbody > tr > td,table > thead > tr > th{text-align:center;line-height:1.4;width:100%;}
				table > tbody > tr > td {color:#808080;padding:5px 0;}
				table > thead > tr > th{text-transform:uppercase;padding:10px 0;background:#fa4251;color:#fff;}
				.data-items{display:flex;}
				.data-items > .data-item {display:inline-block;vertical-align:top;margin:0 5px;}
				.data-items > .data-item > h1{font-size:22px;margin-bottom:5px;}
				</style>
			</head>
			<body>
				<div class="data-items">
					<div class="data-item">
						<h1>Response Codes</h1>
						<table>
							<thead><th>Status Code</th><th>Counter</th></thead>
							<tbody>$response_code</tbody>
						</table>
					</div>
					<div class="data-item">
						<h1>Request Methods</h1>
						<table>
							<thead><th>Method</th><th>Counter</th></thead>
							<tbody>$request_methods</tbody>
						</table>
					</div>
					<div class="data-item">
						<h1>User Agents</h1>
						<table>
							<thead><th>OS</th><th>Version</th><th>Is Mobile</th><th>Counter</th></thead>
							<tbody>$user_agents</tbody>
						</table>
					</div>
					<div class="data-item">
						<h1>Remote Ips</h1>
						<table>
							<thead><th>IP</th><th>Counter</th></thead>
							<tbody>$remote_ips</tbody>
						</table>
					</div>
				</div>
			</body>
		</html>
		"""
		with open(filename, "w") as f:
			response_code = ""
			for status, counter in self.http_status.items():
				response_code += "<tr><td>{status}</td><td>{counter}</td></tr>".format(status = status, counter = counter)

			request_methods = ""
			for method, counter in self.http_request_methods.items():
				request_methods += "<tr><td>{method}</td><td>{counter}</td></tr>".format(method = method, counter = counter)

			user_agents = ""
			for key, agent in self.user_agents.items():
				user_agents += "<tr><td>{os}</td><td>{version}</td><td>{is_mobile}</td><td>{counter}</td></tr>".format(os = agent['os'], version = agent['os_version'], is_mobile = agent['is_mobile'], counter = agent['counter'])

			remote_ips = ""
			for ip, counter in self.remote_ips.items():
				remote_ips += "<tr><td>{ip}</td><td>{counter}</td></tr>".format(ip = ip, counter = counter)

			htmlTemplate = Template(htmlTemplate)

			f.write(htmlTemplate.substitute(response_code = response_code, request_methods = request_methods, user_agents = user_agents, remote_ips = remote_ips))

	def processHttpResponseCode(self, statusCode):
		if self.http_status.get(statusCode) != None:
			self.http_status[statusCode] += 1
		else:
			self.http_status['unknow'] = self.http_status['unknow'] + 1

	def processHttpRequestMethod(self, request_method, request_line):
		if request_method == '':
			request_method = request_line.replace('"', '').split()[0]

		if self.http_request_methods.get(request_method) != None:
			self.http_request_methods[request_method] = self.http_request_methods[request_method] + 1

	def processUserAgent(self, os_family, os_version, is_mobile):
		if self.http_request_methods.get(os_family + os_version) != None:
			self.user_agents[os_family + os_version] += 1
		else:
			self.user_agents[os_family + os_version] = {'os':os_family, 'os_version': os_version, 'is_mobile': is_mobile, 'counter': 1}

	def processRemoteIp(self, remote_ip):
		if self.remote_ips.get(remote_ip) != None:
			self.remote_ips[remote_ip] += + 1
		else:
			self.remote_ips[remote_ip] = 1
			
logParser = ApacheLogParser('access_log', u"%h %l %u %t %r %s %b \"%{Referer}i\" \"%{User-Agent}i\"")
logParser.run(3000, 'test.html')