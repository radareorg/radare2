# Copyright 2019 Wason Technology, LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

if [ $# -eq 0 ]
  then
    echo "No bat file specified"
    return
fi

#echo `dirname "$(readlink -f "$_")"`
___update_env_func___() {
tmpbat=$(mktemp --suffix .bat)
rc=$?; if [[ $rc != 0 ]]; then 
  echo "Could not create temporary bat file"
  return $rc 
fi

echo "@echo off " >> $tmpbat
echo "call \"$@\" 1>&2 " >> $tmpbat
echo "if %errorlevel% neq 0 exit /b %errorlevel%" >> $tmpbat
echo "printenv " >> $tmpbat
echo "if %errorlevel% neq 0 exit /b %errorlevel%" >> $tmpbat
rc=$?; if [[ $rc != 0 ]]; then 
  echo "Could not write temporary bat file"
  return $rc
fi

tmpbat_win=$(basename $tmpbat)
env_data=$(cmd "/c call %TEMP%\\$tmpbat_win ")
rc=$?; if [[ $rc != 0 ]]; then 
  echo "Could not run temporary bat file"
  return $rc 
fi

echo
echo
echo

#Space at the end is lost for some reason,
#save and restore PS1
ps1_old=$PS1

while read -r line; do
    echo "export $line"
    export "$line"     
done <<< "$env_data"

export PS1="$ps1_old"
}

___update_env_func___ $@
unset -f ___update_env_func___
cd `pwd`
