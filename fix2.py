f=open('main.py','r',encoding='utf-8') 
c=f.read() 
f.close() 
import re 
c=re.sub(r'[\x00-\x7F]', '', c) 
f=open('main.py','w',encoding='utf-8') 
f.write(c) 
f.close() 
print('Done!') 
