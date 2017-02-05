default: report.pdf

report.pdf: report.md bibliography.yaml
	pandoc --filter pandoc-citeproc \
		--bibliography=bibliography.yaml \
		--latex-engine=xelatex \
		-V geometry:a4paper \
		-V mainfont=Constantia \
		--number-sections \
		--toc \
		-s -o $@ $<

clean:
	rm -f report.{html,pdf}
