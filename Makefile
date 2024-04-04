.PHONY: spec spec-docker

MD_FILE := specification.md
TEX_FILE := specification.tex
PDF_FILE := specification.pdf

all: spec

spec:
	pandoc $(MD_FILE) --to=latex --standalone --output $(TEX_FILE)
	pandoc $(TEX_FILE) --to=pdf --standalone --output $(PDF_FILE)

spec-docker:
	docker run --rm -v$(CURDIR):/home -w/home pandoc-rust:latest make
