import sys
import os

dirs = os.listdir('./')

for d in dirs:
  if d.find('slab-') >= 0 or d.find('use-after') >= 0:
    is_pthread = False

    print(d)
    os.chdir(d)

    repro = 'repro.c'
    f = open(repro, 'r')
    ll = f.readlines()
    f.close()

    f = open('repro_setpid.c', 'w')

    prev = ''

    for l in ll:
      if l.find('pthread.h') >= 0:
        is_pthread = True

      if prev.find('GNU_SOURCE') >= 0:
        f.write('#include "../../set_pid.h"\n')
      f.write(l)
      if prev.find('main(') >= 0:
        f.write('set_pid();\n');
      prev = l

    f.close()
   
    cmd = 'gcc -o repro_setpid repro_setpid.c ../../set_pid.c'

    if is_pthread:
      cmd += ' -lpthread'

    os.system(cmd)

    os.chdir('..')
