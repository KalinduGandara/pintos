#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "threads/synch.h"
#include "userprog/process.h"
#include "userprog/pagedir.h"
#include "filesys/free-map.h"
#include "filesys/directory.h"
#include "filesys/inode.h"
#include "filesys/filesys.h"
#include "filesys/file.h"

#define STDIN 0
#define STDOUT 1
#define STDERR 2

struct lock memory_lock;
static int fd_num = 2;

static void syscall_handler(struct intr_frame *);

static bool put_user(uint8_t *udst, uint8_t byte);
static int get_user(const uint8_t *uaddr);
int read_mem(void *dest, void *src, size_t size);
void check_memory(void *addr, size_t size);
bool check_validate(void *addr);

void sys_write(int fd_, void *buffer, int size, struct intr_frame *f);
void sys_read(int fd_, void *buffer, int size, struct intr_frame *f);
void sys_exec(char *cmd, struct intr_frame *f);
void sys_wait(int tid, struct intr_frame *f);
void sys_create(char *name, size_t size, struct intr_frame *f);
void sys_open(char *name, struct intr_frame *f);
void sys_close(int fd_, struct intr_frame *f);
void sys_filesize(int fd_, struct intr_frame *f);
void sys_seek(int fd_, int cnt, struct intr_frame *f UNUSED);
void sys_tell(int fd_, struct intr_frame *f);
void sys_remove(char *name, struct intr_frame *f);
void syscall_init(void)
{
  lock_init(&memory_lock);
  intr_register_int(0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler(struct intr_frame *f)
{
  int syscall_number;

  void *esp = f->esp;
  read_mem(&syscall_number, esp, sizeof(syscall_number));

  switch (syscall_number)
  {
  case SYS_READ:
  {
    int fd, size;
    void *buffer;
    read_mem(&fd, esp + 4, sizeof(fd));
    read_mem(&buffer, esp + 8, sizeof(fd));
    read_mem(&size, esp + 12, sizeof(fd));
    sys_read(fd, buffer, size, f);
    break;
  }
  case SYS_EXIT:
  {
    int exit_code;
    read_mem(&exit_code, esp + 4, sizeof(exit_code));
    sys_exit(exit_code, f);
    break;
  }
  case SYS_WRITE:
  {
    int fd, size;
    void *buffer;
    read_mem(&fd, esp + 4, sizeof(fd));
    read_mem(&buffer, esp + 8, sizeof(buffer));
    read_mem(&size, esp + 12, sizeof(size));
    sys_write(fd, buffer, size, f);
    break;
  }
  case SYS_HALT:
  {
    shutdown_power_off();
    break;
  }
  case SYS_EXEC:
  {
    void *cmd;
    read_mem(&cmd, esp + 4, sizeof(cmd));
    sys_exec(cmd, f);
    break;
  }
  case SYS_WAIT:
  {
    int tid;
    read_mem(&tid, esp + 4, sizeof(tid));
    sys_wait(tid, f);
    break;
  }
  case SYS_CREATE:
  {
    char *name;
    size_t size;
    read_mem(&name, esp + 4, sizeof(name));
    read_mem(&size, esp + 8, sizeof(size));
    sys_create(name, size, f);
    break;
  }
  case SYS_OPEN:
  {
    char *name;
    read_mem(&name, esp + 4, sizeof(name));
    sys_open(name, f);
    break;
  }
  case SYS_CLOSE:
  {
    int fd;
    read_mem(&fd, esp + 4, sizeof(fd));
    sys_close(fd, f);
    break;
  }
  case SYS_REMOVE:
  {
    char *name;
    read_mem(&name, esp + 4, sizeof(name));
    sys_remove(name, f);
    break;
  }
  case SYS_FILESIZE:
  {
    int fd;
    read_mem(&fd, esp + 4, sizeof(fd));
    sys_filesize(fd, f);
    break;
  }
  case SYS_SEEK:
  {
    int fd, cnt;
    read_mem(&fd, esp + 4, sizeof(fd));
    read_mem(&cnt, esp + 8, sizeof(cnt));
    sys_seek(fd, cnt, f);
    break;
  }
  case SYS_TELL:
  {
    int fd;
    read_mem(&fd, esp + 4, sizeof(fd));
    sys_tell(fd, f);
    break;
  }
  default:
  {
    int exit_code;
    read_mem(&exit_code, esp + 4, sizeof(exit_code));
    sys_exit(exit_code, NULL);
  }
  }
}
void sys_exit(int exit_code, struct intr_frame *f UNUSED)
{
  struct tcb *tcb = thread_current()->tcb;
  printf("%s: exit(%d)\n", thread_current()->name, exit_code);
  if (tcb)
  {
    tcb->exit_code = exit_code;
    sema_up(&tcb->parent->wait);
  }
  thread_exit();
}

void sys_exec(char *cmd, struct intr_frame *f)
{
  check_memory(cmd, sizeof(cmd));
  lock_acquire(&memory_lock);
  f->eax = process_execute((const char *)cmd);
  lock_release(&memory_lock);
}
void sys_wait(int tid, struct intr_frame *f)
{
  f->eax = process_wait(tid);
}
void sys_create(char *name, size_t size, struct intr_frame *f)
{
  check_memory(name, sizeof(name));
  lock_acquire(&memory_lock);
  f->eax = filesys_create((const char *)name, size);
  lock_release(&memory_lock);
}
void sys_open(char *name, struct intr_frame *f)
{
  struct file *open = NULL;
  struct filedesc *fd;
  check_memory(name, sizeof(name));
  lock_acquire(&memory_lock);
  fd = palloc_get_page(0);
  if (fd == NULL)
  {
    palloc_free_page(fd);
    f->eax = -1;
    lock_release(&memory_lock);
  }
  else
  {
    open = filesys_open(name);
    if (open == NULL)
    {
      f->eax = -1;
      lock_release(&memory_lock);
    }
    fd->f = open;
    fd->fd_num = ++fd_num;
    fd->master = thread_current();
    list_push_back(&(thread_current()->file_list), &(fd->elem));
    f->eax = fd->fd_num;
    lock_release(&memory_lock);
    return;
  }
}
void sys_close(int fd_, struct intr_frame *f UNUSED)
{
  struct list_elem *e;
  struct filedesc *fd;
  struct thread *cur = thread_current();
  if (!list_empty(&cur->file_list))
  {
    lock_acquire(&memory_lock);
    for (e = list_front(&cur->file_list); e != list_end(&cur->file_list); e = list_next(e))
    {
      fd = list_entry(e, struct filedesc, elem);
      if (fd->fd_num == fd_)
        break;
      if (e == list_tail(&cur->file_list) && (fd->fd_num != fd_))
      {
        lock_release(&memory_lock);
        return;
      }
    }
    if (cur->tid == fd->master->tid) // check master thread.
    {
      lock_release(&memory_lock);
      file_close(fd->f);
      list_remove(&fd->elem);
      palloc_free_page(fd);
    }
  }
}
void sys_write(int fd_, void *buffer, int size, struct intr_frame *f)
{
  check_memory(buffer, sizeof(buffer));
  lock_acquire(&memory_lock);
  if (fd_ == STDOUT)
  {
    putbuf(buffer, size);
    lock_release(&memory_lock);
    f->eax = size;
  }
  else if (fd_ == STDIN)
  {
    f->eax = -1;
    lock_release(&memory_lock);
    return;
  }
  else
  {
    struct list_elem *e;
    struct filedesc *fd = NULL;
    struct thread *cur = thread_current();
    if (!list_empty(&cur->file_list))
    {
      for (e = list_front(&cur->file_list); e != list_end(&cur->file_list); e = list_next(e))
      {
        fd = list_entry(e, struct filedesc, elem);
        if (fd->fd_num == fd_)
          break;
        if (e == list_tail(&cur->file_list) && (fd->fd_num != fd_))
        {
          lock_release(&memory_lock);
          f->eax = -1;
          return;
        }
      }
    }
    if (fd != NULL)
    {
      f->eax = file_write(fd->f, buffer, size);
      lock_release(&memory_lock);
      return;
    }
    else
    {
      lock_release(&memory_lock);
      f->eax = -1;
      return;
    }
  }
}
void sys_read(int fd_, void *buffer, int size, struct intr_frame *f)
{
  unsigned i;
  check_memory(buffer, sizeof(buffer));
  lock_acquire(&memory_lock);
  if (fd_ == STDIN)
  {
    for (i = 0; i < (unsigned)size; i++)
      put_user((unsigned char *)(buffer + i), input_getc());
    lock_release(&memory_lock);
    f->eax = size;
  }
  else if (fd_ == STDOUT)
  {
    f->eax = -1;
    lock_release(&memory_lock);
    return;
  }
  else
  {
    struct list_elem *e;
    struct filedesc *fd;
    struct thread *cur = thread_current();
    if (!list_empty(&cur->file_list))
    {
      for (e = list_front(&cur->file_list); e != list_end(&cur->file_list); e = list_next(e))
      {
        fd = list_entry(e, struct filedesc, elem);
        if (fd->fd_num == fd_)
          break;
        if (e == list_tail(&cur->file_list) && (fd->fd_num != fd_))
        {
          lock_release(&memory_lock);
          f->eax = -1;
          return;
        }
      }
      f->eax = file_read(fd->f, buffer, size);
      lock_release(&memory_lock);
      return;
    }
    lock_release(&memory_lock);
  }
}
void sys_filesize(int fd_, struct intr_frame *f)
{
  struct list_elem *e;
  struct filedesc *fd = NULL;
  struct thread *cur = thread_current();
  if (!list_empty(&cur->file_list))
  {
    lock_acquire(&memory_lock);
    for (e = list_front(&cur->file_list); e != list_end(&cur->file_list); e = list_next(e))
    {
      fd = list_entry(e, struct filedesc, elem);
      if (fd->fd_num == fd_)
        break;
      if (e == list_tail(&cur->file_list) && (fd->fd_num != fd_))
      {
        lock_release(&memory_lock);
        f->eax = -1;
        return;
      }
    }
  }
  if (fd == NULL)
    f->eax = -1;
  else
  {
    f->eax = file_length(fd->f);
  }
  lock_release(&memory_lock);
}
void sys_seek(int fd_, int cnt, struct intr_frame *f UNUSED)
{
  struct list_elem *e;
  struct filedesc *fd = NULL;
  struct thread *cur = thread_current();
  if (!list_empty(&cur->file_list))
  {
    lock_acquire(&memory_lock);
    for (e = list_front(&cur->file_list); e != list_end(&cur->file_list); e = list_next(e))
    {
      fd = list_entry(e, struct filedesc, elem);
      if (fd->fd_num == fd_)
        break;
      if (e == list_tail(&cur->file_list) && (fd->fd_num != fd_))
      {
        lock_release(&memory_lock);
        return;
      }
    }
  }
  if (fd->f != NULL)
  {
    file_seek(fd->f, cnt);
    lock_release(&memory_lock);
    return;
  }
  return;
}
void sys_tell(int fd_, struct intr_frame *f)
{
  struct list_elem *e;
  struct filedesc *fd = NULL;
  struct thread *cur = thread_current();
  lock_acquire(&memory_lock);
  if (!list_empty(&cur->file_list))
  {
    for (e = list_front(&cur->file_list); e != list_end(&cur->file_list); e = list_next(e))
    {
      fd = list_entry(e, struct filedesc, elem);
      if (fd->fd_num == fd_)
        break;
      if (e == list_tail(&cur->file_list) && (fd->fd_num != fd_))
      {
        f->eax = -1;
        lock_release(&memory_lock);
        return;
      }
    }
  }
  if (fd->f != NULL)
  {
    f->eax = file_tell(fd->f);
    lock_release(&memory_lock);
    return;
  }
  f->eax = -1;
  lock_release(&memory_lock);
}
void sys_remove(char *name, struct intr_frame *f)
{
  check_memory(name, sizeof(name));
  lock_acquire(&memory_lock);
  f->eax = filesys_remove(name);
  lock_release(&memory_lock);
}
static int
get_user(const uint8_t *uaddr)
{
  if (check_validate(uaddr))
  {
    int result;
    asm("movl $1f, %0; movzbl %1, %0; 1:"
        : "=&a"(result)
        : "m"(*uaddr));
    return result;
  }
  sys_exit(-1, NULL);
}
static bool
put_user(uint8_t *udst, uint8_t byte)
{
  if (check_validate(udst))
  {
    int error_code;
    asm("movl $1f, %0; movb %b2, %1; 1:"
        : "=&a"(error_code), "=m"(*udst)
        : "q"(byte));
    return error_code != -1;
  }
  sys_exit(-1, NULL);
}
int read_mem(void *dest, void *src, size_t size)
{
  size_t i;
  int value;
  check_memory(src, size);
  for (i = 0; i < size; i++)
  {
    value = get_user(src + i);
    if (value == -1)
      return -1;
    *(uint8_t *)(dest + i) = value;
  }
  return value;
}
void check_memory(void *addr, size_t size)
{
  unsigned i;
  unsigned char *_cmd = addr;
  for (i = 0; i < size; i++)
  {
    if (!check_validate((void *)(_cmd + i)))
      sys_exit(-1, NULL);
  }
}
bool check_validate(void *addr)
{
  if ((addr != NULL) && is_user_vaddr(addr))
  {
    if ((pagedir_get_page(thread_current()->pagedir, addr)) != NULL)
      return true;
    else
      return false;
  }
  return false;
}