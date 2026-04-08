#!/bin/sh

systemctl --type=service,socket,timer | cat
