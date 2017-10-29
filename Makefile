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
SED := sed
UNAME_S := $(shell uname -s)
## Git version 2.11+ is required
GIT := git
GIT_REL_TAG := $(shell $(GIT) describe --abbrev=0 --tags)
GIT_NUM_COMMITS := $(shell $(GIT) rev-list  `$(GIT) rev-list --tags --no-walk --max-count=1`..HEAD --count)
GIT_LOC := $(shell $(GIT) diff --shortstat `$(GIT) rev-list --tags --no-walk --max-count=1`)
GIT_BRANCH := $(shell $(GIT) rev-parse --abbrev-ref HEAD)
GIT_REMOTE := $(shell $(GIT) remote

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

release:
	@echo '"version" and "next_version" variables need to be passed in to perform release...'
	@echo 'e.g. make release version=1.6.8 next_version=1.6.9'
	@echo
	@test $(version)
	@test $(next_version)
	@echo 'Looks good, performing release'
	@echo
	@echo 'Current release tag $(value GIT_REL_TAG)'
	@echo 'Releasing version $(version)'
	@echo
ifeq ($(UNAME_S),Darwin)
	@$(SED) -i "" -e s/$(value GIT_REL_TAG)/$(version)/ docker-compose.yaml
	@$(SED) -i "" -e s/$(value GIT_REL_TAG)/$(version)/ docker-compose-pi.yaml
	@$(SED) -i "" -e s/$(value GIT_REL_TAG)/$(version)/ README.rst
else
	@$(SED) -i s/$(value GIT_REL_TAG)/$(version)/ docker-compose.yaml
	@$(SED) -i s/$(value GIT_REL_TAG)/$(version)/ docker-compose-pi.yaml
	@$(SED) -i s/$(value GIT_REL_TAG)/$(version)/ README.rst
endif
	@$(GIT) commit -a -m "$(version)"
	@$(GIT) tag -a $(version) -m "$(version)"
ifeq ($(UNAME_S),Darwin)
	@$(SED) -i "" -e s/$(version)/$(next_version)/ setup.cfg
else
	@$(SED) -i s/$(version)/$(next_version)/ setup.cfg
endif
	@$(GIT) commit -a -m "$(version)"
	@$(GIT) push $(GIT_REMOTE) $(GIT_BRANCH)
	@$(GIT) push $(GIT_REMOTE) $(version)
	@echo 'Done releasing version $(version)'
