# Copyright (C) 2015 Brad Cowie, Christopher Lorier and Joe Stringer.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

def dump(obj, level = 0):
    prefix = level*'*'+' ' if level > 0 else ''

    if type(obj) == dict:
        for k, v in obj.items():
            if hasattr(v, '__iter__'):
                print "%s%s" % (prefix, k)
                dump(v, level+1)
            else:
                print "%s%s : %s" % (prefix, k, v)
    elif type(obj) == list:
        for v in obj:
            if hasattr(v, '__iter__'):
                dump(v, level+1)
            else:
                print "%s%s" % (prefix, v)
    else:
        print "%s%s" % (prefix, obj)
