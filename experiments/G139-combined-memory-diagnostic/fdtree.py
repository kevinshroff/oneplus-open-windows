"""Bounded, read-only FDT v17 decoder for captured stock hardware descriptions."""
from pathlib import Path
import struct

class Fdt:
    def __init__(self, data):
        self.data=bytes(data)
        def fail(msg):raise ValueError(msg)
        if len(data)<40:fail('truncated FDT header')
        magic,total,so,st,ro,version,last,cpu,szst,szso=struct.unpack_from('>10I',data)
        if magic!=0xd00dfeed or version!=17 or last>17 or not 40<=total<=len(data):fail('FDT header identity/version/bounds')
        if so%4 or st>=total or so<40 or not 0<szso<=total-so or not 0<szst<=total-st:fail('FDT structure/string bounds')
        strings=data[st:st+szst];end=so+szso;cur=so;stack=[];self.nodes={};self.total=total
        def name(off,limit):
            n=data.find(b'\0',off,limit)
            if n<0:fail('unterminated node name')
            try:s=data[off:n].decode('ascii')
            except UnicodeDecodeError:fail('non-ASCII node name')
            return s,n+1
        while cur+4<=end:
            token=struct.unpack_from('>I',data,cur)[0];cur+=4
            if token==1:
                n,cur=name(cur,end);cur=(cur+3)&~3
                if (not stack and (n or self.nodes)) or '/' in n or len(stack)>=128:fail('node/root/depth')
                path=(stack[-1].rstrip('/')+'/'+n) if stack else '/'
                if path in self.nodes:fail('duplicate node path')
                self.nodes[path]={};stack.append(path)
            elif token==2:
                if not stack:fail('unbalanced end-node')
                stack.pop()
            elif token==3:
                if not stack or cur+8>end:fail('property header outside node/bounds')
                n,no=struct.unpack_from('>2I',data,cur);cur+=8
                if n>end-cur or no>=len(strings):fail('property data/name bounds')
                stop=strings.find(b'\0',no)
                if stop<0:fail('unterminated property name')
                try:k=strings[no:stop].decode('ascii')
                except UnicodeDecodeError:fail('non-ASCII property name')
                if not k or k in self.nodes[stack[-1]]:fail('empty/duplicate property')
                self.nodes[stack[-1]][k]=bytes(data[cur:cur+n]);cur=(cur+n+3)&~3
            elif token==4:continue
            elif token==9:
                if stack or not self.nodes:fail('unbalanced FDT end')
                break
            else:fail('invalid FDT token')
        else:fail('missing FDT end')
        if cur>end:fail('structure alignment exceeds bounds')
    @classmethod
    def read(cls,path):return cls(Path(path).read_bytes())
    def strings(self,path,key):
        b=self.nodes[path][key]
        if not b or b[-1]!=0:raise ValueError('not a terminated string list')
        return [x.decode('ascii') for x in b[:-1].split(b'\0')]
    def cells(self,path,key):
        b=self.nodes[path][key]
        if len(b)%4:raise ValueError('not a cell list')
        return list(struct.unpack('>'+str(len(b)//4)+'I',b))
    def phandles(self):
        result={}
        for path,props in self.nodes.items():
            values=[self.cells(path,k) for k in ['phandle','linux,phandle'] if k in props]
            if not values:continue
            if any(len(v)!=1 for v in values) or any(v!=values[0] for v in values):raise ValueError('conflicting phandle forms')
            h=values[0][0]
            if h in [0,0xffffffff] or h in result:raise ValueError('invalid/duplicate defined phandle')
            result[h]=path
        return result
