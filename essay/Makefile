default: report.pdf

report.pdf: report.md bibliography.yaml
	pandoc --filter pandoc-citeproc \
		--csl harvard-bournemouth-university.csl \
		--bibliography=bibliography.yaml \
		--latex-engine=xelatex \
		-V geometry:a4paper \
		-V mainfont=Constantia \
		-V colorlinks \
		--number-sections \
		--toc \
		-s -o $@ $<

clean:
	rm -f report.{html,pdf}
