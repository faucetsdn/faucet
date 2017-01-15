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
DOT := dot
## Git version 2.11+ is required
GIT := git
GIT_REL_TAG := $(shell $(GIT) describe --abbrev=0 --tags)
GIT_NUM_COMMITS := $(shell $(GIT) rev-list  `$(GIT) rev-list --tags --no-walk --max-count=1`..HEAD --count)
GIT_LOC := $(shell $(GIT) diff --shortstat `$(GIT) rev-list --tags --no-walk --max-count=1`)

PROJECT_NAME = ryu_faucet

## Directories
DIST_DIR = dist
SRC_DIR = src

all: clobber sdist uml dot

uml:
	$(MKDIR) $(DIST_DIR)/doc
	$(PYREVERSE) -ASmn -o png -p $(PROJECT_NAME) $(SRC_DIR)/ryu_faucet/org/onfsdn/faucet/*py
	$(MV) classes*png $(DIST_DIR)/doc
	$(MV) packages*png $(DIST_DIR)/doc

dot:
	$(DOT) -Tpng $(SRC_DIR)/docs/faucet_yaml.dot -o $(DIST_DIR)/doc/faucet_yaml.png
sdist:
	@echo Building Python package installable via "pip"
	$(MKDIR) $(DIST_DIR)
	$(PYTHON) setup.py sdist

sdistapps:
	@echo Building Python package installable via "pip" for faucet apps
	$(MKDIR) $(DIST_DIR)/apps
	$(PYTHON) setup_apps.py sdist

codefmt:
	@echo Run below command manually to inline replace current code with newly formatted code per “pep8” guidelines
	@echo $(YAPF) --style pep8 -i \*py

codeerrors:
	@echo Finding errors in code now ...
	$(PYLINT) $(SRC_DIR)/ryu_faucet/org/onfsdn/faucet/*py > $(DIST_DIR)/error_report.out
	@echo Code error report available at $(DIST_DIR)/error_report.out

stats:
	@echo 'Since last release tag $(value GIT_REL_TAG)'
	@echo 'number of commits = $(value GIT_NUM_COMMITS)' 
	@echo 'Net LOC added/removed = $(value GIT_LOC)'
	@echo 
	@echo 'Listing all commits since last tag ...'
	@$(GIT) log $(GIT_REL_TAG)..HEAD --oneline

## list target source: http://stackoverflow.com/questions/4219255/how-do-you-get-the-list-of-targets-in-a-makefile
.PHONY: list
list:
	@echo List of all targets in this Makefile:
	@$(MAKE) -pRrq -f $(lastword $(MAKEFILE_LIST)) : 2>/dev/null | awk -v RS= -F: '/^# File/,/^# Finished Make data base/ {if ($$1 !~ "^[#.]") {print $$1}}' | sort | egrep -v -e '^[^[:alnum:]]' -e '^$@$$' | xargs

clobber:
	@echo Removing $(DIST_DIR)
	$(RM) -rf $(DIST_DIR)
	$(RM) -rf ryu_faucet.egg-info
