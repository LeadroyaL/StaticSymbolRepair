import idc, idaapi
import re

__author__ = "LeadroyaL"

data=[]
fd = open('/tmp/diff.log')
while True:
    line = fd.readline()
    if line == '':
        break
    data.append(line)
fd.close()

pattern = re.compile(r"(0000[\dA-F]+) ([_A-Za-z0-9]+)")

ms=[]
for d in data:
    ms.append(pattern.findall(d))

for m in ms:
    if len(m) != 2:
        print m, "Error"
        ms.remove(m)

succ_count = 0
for m in ms:
    unk_addr = int(m[1][0], 16)
    sym_name = m[0][1]
    # make sure you open libc.idb first, then bindiff with target.idb
    if "sub_" in sym_name:
        continue
    if MakeName(unk_addr, sym_name):
        succ_count += 1

print "Rename %d function" % succ_count
