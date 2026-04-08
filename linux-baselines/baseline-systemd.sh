#!/bin/sh

systemctl --type=service,socket,timer | cat | tr -d '\r'
