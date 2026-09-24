.PHONY : all build check

all : check build

build :
	python3 -m build

check :
	pycodestyle .
	pyflakes .
	mypy .
