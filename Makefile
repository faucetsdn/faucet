# Copyright 2015 Open Networking Foundation (http://www.opennetworking.org/
# Use is subject to License terms

fileinfo := Ryu Faucet Developers Makefile
author   := Shivaram Mysore (shivaram.mysore@gmail.com)

## Dependent programs
PYTHON = python
PYREVERSE = pyreverse
YAPF = yapf
PYLINT = pylint
RM := rm
MKDIR := mkdir -p
MV := mv

PROJECT_NAME = ryu_faucet

## Directories
DIST_DIR = dist
SRC_DIR = src

all: clobber sdist uml

uml:
	$(MKDIR) $(DIST_DIR)/doc
	$(PYREVERSE) -ASmn -o png -p $(PROJECT_NAME) $(SRC_DIR)/ryu_faucet/org/openflowsdn/faucet/*py
	$(MV) classes*png $(DIST_DIR)/doc
	$(MV) packages*png $(DIST_DIR)/doc

sdist:
	@echo Building Python package installable via "pip"
	$(MKDIR) $(DIST_DIR)
	$(PYTHON) setup.py sdist

codefmt:
	@echo Run below command manually to inline replace current code with newly formatted code per “pep8” guidelines
	@echo $(YAPF) --style pep8 -i \*py

codeerrors:
	@echo Finding errors in code now ...
	$(PYLINT) $(SRC_DIR)/ryu_faucet/org/openflowsdn/faucet/*py > $(DIST_DIR)/error_report.out
	@echo Code error report available at $(DIST_DIR)/error_report.out

## list target source: http://stackoverflow.com/questions/4219255/how-do-you-get-the-list-of-targets-in-a-makefile
.PHONY: list
list:
	@echo List of all targets in this Makefile:
	@$(MAKE) -pRrq -f $(lastword $(MAKEFILE_LIST)) : 2>/dev/null | awk -v RS= -F: '/^# File/,/^# Finished Make data base/ {if ($$1 !~ "^[#.]") {print $$1}}' | sort | egrep -v -e '^[^[:alnum:]]' -e '^$@$$' | xargs


clobber:
	@echo Removing $(DIST_DIR)
	$(RM) -rf $(DIST_DIR)
	$(RM) -rf ryu_faucet.egg-info


