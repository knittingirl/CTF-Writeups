all: tableofcontents

tableofcontents: toc.cc
	clang++ $< -Wl,-z,now -fno-pie -o $@

clean:
	rm -f tableofcontents
