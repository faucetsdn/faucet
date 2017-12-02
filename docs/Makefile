# Minimal makefile for Sphinx documentation
#

# You can set these variables from the command line.
SPHINXOPTS    =
APIDOC        = sphinx-apidoc
APIDOCOUTPUT  = source/apidoc
APIDOCMODPATH = ../faucet
APIDOCEXCLUDE =
SPHINXBUILD   = sphinx-build
SPHINXPROJ    = faucet
SOURCEDIR     = .
BUILDDIR      = _build

# Put it first so that "make" without argument is like "make help".
help:
	@$(SPHINXBUILD) -M help "$(SOURCEDIR)" "$(BUILDDIR)" $(SPHINXOPTS) $(O)

.PHONY: help Makefile

# Catch-all target: route all unknown targets to Sphinx using the new
# "make mode" option.  $(O) is meant as a shortcut for $(SPHINXOPTS).
%: Makefile
	@$(APIDOC) -o $(APIDOCOUTPUT) $(APIDOCMODPATH) $(APIDOCEXCLUDE)
	@$(SPHINXBUILD) -M $@ "$(SOURCEDIR)" "$(BUILDDIR)" $(SPHINXOPTS) $(O)
