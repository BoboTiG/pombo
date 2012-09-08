#!/bin/sh

for file in $(find python -name "*.pyc"); do
	rm -fv ${file}
done
