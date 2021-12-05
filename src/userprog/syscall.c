#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "threads/synch.h"

#define STDIN 0
#define STDOUT 1
#define STDERR 2

struct lock memory_lock;

static void syscall_handler(struct intr_frame *);
void sys_exit(int, struct intr_frame *UNUSED);
// static bool put_user (uint8_t *udst, uint8_t byte);
static int get_user(const uint8_t *uaddr);
int read_mem(void *dest, void *src, size_t size);
void sys_write(int fd_, void *buffer, int size, struct intr_frame *f);

void syscall_init(void)
{
  intr_register_int(0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler(struct intr_frame *f)
{
  int syscall_number;

  void *esp = f->esp;
  if (!is_user_vaddr(esp) && !is_user_vaddr(esp + 4) && !is_user_vaddr(esp + 8) && !is_user_vaddr(esp + 12))
  {
    sys_exit(-1, NULL);
  }
  read_mem(&syscall_number, esp, sizeof(syscall_number));
  // printf("sys call - %i\n",syscall_number);
  int fd, size;
  void *buffer;

  switch (syscall_number)
  {
  case SYS_EXIT:
  {
    sema_up(&thread_current()->parent->wait);
    int exit_code;
    read_mem(&exit_code, esp + 4, sizeof(exit_code));
    sys_exit(exit_code, f);
    break;
  }
  case SYS_WRITE:
  {
    read_mem(&fd, esp + 4, sizeof(fd));
    read_mem(&buffer, esp + 8, sizeof(buffer));
    read_mem(&size, esp + 12, sizeof(size));
    // hex_dump(esp , esp , PHYS_BASE-esp , true);
    // printf("\n");
    // hex_dump(buffer , buffer , PHYS_BASE-buffer , true);
    // printf("fd - %i  size %i buf - %p esp - %p\n",fd,size,buffer,esp);
    putbuf(buffer, size);
    // printf("\n");
    break;
  }
  default:
    break;
  }
}
void sys_exit(int exit_code, struct intr_frame *f UNUSED)
{
  // struct tcb * tcb = thread_current()->tcb;
  printf("%s: exit(%d)\n", thread_current()->name, exit_code);
  // if(tcb) tcb->exit_code = exit_code;
  thread_exit();
}
int read_mem(void *dest, void *src, size_t size)
{
  size_t i;
  int value;
  for (i = 0; i < size; i++)
  {
    value = get_user(src + i);
    if (value == -1)
      return -1;
    *(uint8_t *)(dest + i) = value;
  }
  return value;
}
/* Reads a byte at user virtual address UADDR.
UADDR must be below PHYS_BASE.
Returns the byte value if successful, -1 if a segfault
occurred. */
static int
get_user(const uint8_t *uaddr)
{
  int result;
  asm("movl $1f, %0; movzbl %1, %0; 1:"
      : "=&a"(result)
      : "m"(*uaddr));
  return result;
}
/* Writes BYTE to user address UDST.
UDST must be below PHYS_BASE.
Returns true if successful, false if a segfault occurred. */
// static bool
// put_user (uint8_t *udst, uint8_t byte)
// {
// int error_code;
// asm ("movl $1f, %0; movb %b2, %1; 1:"
// : "=&a" (error_code), "=m" (*udst) : "q" (byte));
// return error_code != -1;
// }