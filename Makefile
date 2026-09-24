.PHONY : all build check

all : check build

build :
	python -m build

check :
	pycodestyle .
	pyflakes .
	mypy .
