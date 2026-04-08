#!/bin/sh

lsmod | awk '{ print $1 }' | sort | tr -d '\r'
