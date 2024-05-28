#!/bin/sh
appversion=$1
appdate=$2

echo "package tapir" > version.go
echo "const AppVersion = \"$appversion\"" >> version.go
echo "const AppDate = \"$appdate\"" >> version.go
