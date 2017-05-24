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
			#elif 'class Conf(object)' in line:
			#	print(cla)
			#	c=True
		#autogenerate documentation
		if c:
			if not 'documentation' in cla:
				to_check.append(cla)
			#first option or getting methods and attributes
			#attrsandmethods=dir(cla)
			#print(dir(cla))
			#attributes = [attr for attr in dir(cla) if not attr.startswith('__')]
			#print(attributes)
			#second method
			#ms=inspect.getmembers(cla, predicate=inspect.ismethod)
			#print(ms)
			#pydoc.writedoc(cla[:-3])
			#run report of defaults attribute of class
			#print(cla[:-3]+'.defaults')
			#print(watcher_conf.defaults())	 
			#print(dir(cla[:-3]+'.defaults'))
			#print(DP.defaults)

print(to_check)
#now do something not retarded and just scan through all modules
ofile=open('documentation.md','w')
for item in to_check:
	for name, obj in inspect.getmembers(sys.modules[item[:-3]]):
		#print(name)
		if not inspect.isclass(obj):
            		continue
		#print(name)
		if not issubclass(obj, Conf): #check is subclass of Conf
			continue
		#print(name)
		if name == 'Conf':
			continue	
		print([name, obj])
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
		#ofile.write('METHODS\n')
		#meths=inspect.getmembers(obj, predicate=inspect.isfunction)		
		#print(meths)
		#for met in meths:
		#	ofile.write('* '+str(met)+'\n')
#output to .rst file
ofile.close()
