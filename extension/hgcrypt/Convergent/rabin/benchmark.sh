#!/bin/bash

for i in python python3 pypy; do
  echo $i
  $i benchmark.py
done
