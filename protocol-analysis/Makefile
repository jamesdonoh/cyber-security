default: report.pdf

report.pdf: report.md bibliography.yaml
	pandoc --filter pandoc-citeproc \
		--bibliography=bibliography.yaml \
		-V geometry:a4paper \
		--latex-engine=xelatex \
		-V mainfont=Constantia \
		-s -o $@ $<

clean:
	rm -f report.{html,pdf}
