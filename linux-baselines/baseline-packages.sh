#!/bin/sh

dpkg -l | awk '{ print $2 }' | sed 's/:.*$//' | tr -d '\r'
