PY ?= python

.PHONY: install demo test serve

install:
	$(PY) -m pip install -r requirements.txt

demo:
	$(PY) -m throughline demo
	$(PY) -m throughline --false-flag demo

test:
	$(PY) -m pytest -q

serve:
	$(PY) -m throughline serve
