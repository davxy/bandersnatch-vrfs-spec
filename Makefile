.PHONY: spec spec-docker

MD_FILE := specification.md
TEX_FILE := specification.tex
PDF_FILE := specification.pdf
BIB_FILE := references.bib
CSL_FILE := references.csl

all: spec

spec:
	pandoc $(MD_FILE) --to=latex --standalone --citeproc  --bibliography $(BIB_FILE) --csl $(CSL_FILE) --output $(TEX_FILE)
	pandoc $(TEX_FILE) --to=pdf --standalone --citeproc --bibliography $(BIB_FILE) --csl $(CSL_FILE) --output $(PDF_FILE)

spec-docker:
	docker run --rm -v$(CURDIR):/home -w/home pandoc-rust:latest make
