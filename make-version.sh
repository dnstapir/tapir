#!/bin/sh
# Copyright 2024 Johan Stenstam, johan.stenstam@internetstiftelsen.se
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

appversion=$1
appdate=$2

echo "package tapir" > version.go
echo "const AppVersion = \"$appversion\"" >> version.go
echo "const AppDate = \"$appdate\"" >> version.go
