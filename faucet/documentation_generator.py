import sys, os
import inspect
import faucet
from conf import Conf

#important classes are dp.py, port.py, vlan.py, watcher_conf.py

path=sys.argv[1]
to_check=[]
for cla in os.listdir(path):
	#print(cla[-3:])
	if cla[-3:]=='.py': #check python files only
		#check is subclass of Conf
		ifile=open(cla, 'rU')
		c=False
		for line in ifile.readlines():
			if 'from conf import Conf' in line:
				print(cla)
				c=True
		if c:
			if not 'documentation' in cla:
				to_check.append(cla)

print(to_check)
#now do just scan through all modules and output to .md
ofile=open('documentation.md','w')
for item in to_check:
	for name, obj in inspect.getmembers(sys.modules[item[:-3]]):
		if not inspect.isclass(obj):
            		continue
		if not issubclass(obj, Conf): #check is subclass of Conf
			continue
		if name == 'Conf':
			continue
		if not name.lower() in item.lower(): #only checks defined and not imported classes
			continue	
		#print([name, obj])
		ofile.write('\n\n')
		ofile.write('# **'+str(name)+'**'+'\n\n')
		#ofile.write('DEFAULT ATTRIBUTES\n\n')
		d=obj.defaults
		print(d)
		#start table
		ofile.write('| Attribute | Default | Description |'+'\n')
		ofile.write('| --------- | ------- | ----------- |'+'\n')
		for default in sorted(d.keys()):
			#ofile.write('* '+str(default)+': '+str(d[default])+'\n')
			ofile.write('| '+str(default)+' | '+str(d[default])+ '|')
			#now we need to scan through the parent file cna retrieve comments associated with that attribute
			comment='  '
			ifile=open(item, 'rU')
			s = ifile.readlines()
			for k in range(len(s)):
				#print(default+':')
				if default in s[k]:
					if ': '+str(d[default]) in s[k]:
						#print(s[k])
						#print(s[k+1])
						if '#' in s[k+1]:
							comment=comment+s[k+1].strip().replace('#', ' ')
							#TODO - replace comment character with something .rst appropriate
			ofile.write(comment+' | \n')
		#leaving the folloing in case we want methods in the future
		#ofile.write('METHODS\n')
		#meths=inspect.getmembers(obj, predicate=inspect.isfunction)		
		#print(meths)
		#for met in meths:
		#	ofile.write('* '+str(met)+'\n')
ofile.close()
