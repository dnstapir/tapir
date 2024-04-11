#!/bin/sh
appversion=$1
appdate=$2

echo "package tapir" > version.go
echo "const appVersion = \"$appversion\"" >> version.go
echo "const appDate = \"$appdate\"" >> version.go
