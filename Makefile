fileinfo := Faucet Developers Makefile
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

PROJECT_NAME = faucet

## Directories
DIST_DIR = dist
SRC_DIR = .

all: clobber sdist docs

docs: uml dot

uml:
	$(MKDIR) $(DIST_DIR)/doc
	$(PYREVERSE) -ASmn -o png -p $(PROJECT_NAME) $(SRC_DIR)/faucet/*py $(SRC_DIR)/faucet/aruba/*py
	$(MV) classes*png $(DIST_DIR)/doc
	$(MV) packages*png $(DIST_DIR)/doc

dot:
	$(MKDIR) $(DIST_DIR)/doc
	$(DOT) -Tpng $(SRC_DIR)/docs/images/faucet-yaml.dot -o $(DIST_DIR)/doc/faucet-yaml.png

codefmt:
	@echo Run below command manually to inline replace current code with newly formatted code per “pep8” guidelines
	@echo $(YAPF) --style pep8 -i \*py

codeerrors:
	@echo Finding errors in code now ...
	$(MKDIR) $(DIST_DIR)
	$(PYLINT) $(SRC_DIR)/faucet/*py $(SRC_DIR)/faucet/aruba/*py > $(DIST_DIR)/error_report.out
	@echo Code error report available at $(DIST_DIR)/error_report.out

stats:
	@echo 'Since last release tag $(value GIT_REL_TAG)'
	@echo 'number of commits = $(value GIT_NUM_COMMITS)'
	@echo 'Net LOC added/removed = $(value GIT_LOC)'
	@echo
	@echo 'Listing all commits since last tag ...'
	@$(GIT) log $(GIT_REL_TAG)..HEAD --oneline
	
