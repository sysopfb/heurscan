#Scan code stolen from: https://github.com/tylerha97/yara_scan/blob/master/yara_scan.py
#Simple cut out some parts and added heuristic scanning + scoring based on tags
#To do: Add yaml configurations?


import os
import sys
import yaml
import yara
import argparse


def parse_args():
	parser = argparse.ArgumentParser(usage="Perform a heuristic scan on a directory")
	parser.add_argument('-s', '--scan_dir', action='store', default=os.getcwd(), help='Path to the directory to scan')
	parser.add_argument('-c', '--config', action='store', default='scan_config.yaml',help='Path to the configuration file')
	return parser

def scan_file(yaraobj, fname):
	scan_data = []
	matches = yaraobj.match(fname)
	for match in matches:
		temp = match.tags
		#Should probably join temp by ',' to have all tags if len greater than 1
		name = temp[0]
		meta_data = match.meta
		if 'score' in meta_data.keys():
			score = meta_data['score']
		else:
			score = 0
		scan_data.append((name,score))
	return scan_data


class FileScan:
	def __init__(self, fname):
		self.score = 0
		self.hits = {}
		self.fname = fname

	def run(self, rules):
		for scan_name in rules.keys():
			temp = scan_file(rules[scan_name], self.fname)
			for val in temp:
				self.score += val[1]
			#Can remove this check to see empty scan results
			if temp != []:
				self.hits[scan_name]=temp

	def get_score(self):
		return(self.score)

	def __str__(self):
		out = self.fname+':\n'
		for key in self.hits.keys():
			out += '\t'+key+':\n'
			for hit in self.hits[key]:
				out += '\t\t'+hit[0]+' '+str(hit[1])+'\n'
		return out


if __name__ == "__main__":
	args = parse_args().parse_args()
	conf_data = open(args.config)
	conf = yaml.load(open('scan_config.yaml', 'r'), Loader=yaml.FullLoader)
	all_rules = {}
	for yara_file in conf['scans']:
		all_rules[yara_file] = yara.compile(yara_file+'.yar')

	all_files = []
	try:
		for root, directories, files in os.walk(args.scan_dir):
			for file in files:
				work_file = os.path.join(root,file)
				all_files.append(work_file)
	except Exception as e:
		print "Scan Exception: {}".format(e)

	for file in all_files:
		scan_data = {}
		file_score = 0
		scanobj = FileScan(file)
		scanobj.run(all_rules)
		if scanobj.get_score() > 20:
			print(scanobj)
			
