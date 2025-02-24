.PHONY: spec spec-docker all clean

MD_FILE := specification.md
TEX_FILE := specification.tex
PDF_FILE := specification.pdf
BIB_FILE := references.bib
CSL_FILE := references.csl

all: spec

spec:
	pandoc $(MD_FILE) --to=latex --standalone --citeproc --bibliography $(BIB_FILE) --csl $(CSL_FILE) --output $(TEX_FILE)
	pandoc $(TEX_FILE) --to=pdf --standalone --citeproc --bibliography $(BIB_FILE) --csl $(CSL_FILE) --output $(PDF_FILE)

docker-spec:
	docker run --rm -v$(CURDIR):/home -w/home davxy/texlive-ext make

clean:
	rm -rf $(TEX_FILE) $(PDF_FILE)
